//! Durable owner-coordinated workspace namespace changes.
//!
//! The Host verifies physical identities and performs filesystem effects
//! outside Store transactions. This module binds those proofs to one already
//! running native editor job and commits workspace roots, import aliases, and
//! the writer fence atomically.
use super::*;
use std::path::{Component, Path, PathBuf};

const MAX_DESKTOP_NAMESPACE_WORKSPACES: usize = 256;
const MAX_DESKTOP_NAMESPACE_INTENTS: usize = 256;
const MAX_DESKTOP_NAMESPACE_PLAN_BYTES: usize = 2 * 1024 * 1024;
const MAX_DESKTOP_NAMESPACE_PROOF_BYTES: usize = 256 * 1024;
const MAX_NAMESPACE_PATH_BYTES: usize = 4096;
const MAX_NAMESPACE_PIN_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum DesktopNamespaceEffect {
    Move {
        old_path: PathBuf,
        new_path: PathBuf,
    },
    Remove {
        old_path: PathBuf,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DesktopNamespaceWorkspace {
    pub workspace_id: WorkspaceId,
    pub old_path: PathBuf,
    pub new_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
enum DesktopNamespaceOriginWire {
    NativeEditor {
        operation_id: ipc::NativeIntentId,
        fence_id: ipc::NativeIntentId,
        host_runtime_id: RuntimeId,
        request_hash: String,
    },
    RemoteOperation {
        actor: ConsumerAuthorizationId,
        workspace_id: WorkspaceId,
        operation_id: OperationId,
        method: Method,
        parameter_hash: String,
        workspace_fence: u64,
        host_runtime_id: RuntimeId,
    },
}

impl DesktopNamespaceOriginWire {
    fn host_runtime_id(&self) -> RuntimeId {
        match self {
            Self::NativeEditor {
                host_runtime_id, ..
            }
            | Self::RemoteOperation {
                host_runtime_id, ..
            } => *host_runtime_id,
        }
    }

    fn request_hash(&self) -> &str {
        match self {
            Self::NativeEditor { request_hash, .. } => request_hash,
            Self::RemoteOperation { parameter_hash, .. } => parameter_hash,
        }
    }

    fn namespace_id(&self) -> Result<String> {
        let (prefix, bytes) = match self {
            Self::NativeEditor { operation_id, .. } => ("native", key(*operation_id)),
            Self::RemoteOperation {
                actor,
                workspace_id,
                operation_id,
                ..
            } => (
                "remote",
                format!(
                    "{}:{}:{}",
                    key(*actor),
                    key(*workspace_id),
                    key(*operation_id)
                ),
            ),
        };
        Ok(format!("{prefix}:{}", sha256(bytes.as_bytes())))
    }

    fn remote_binding_matches(&self, binding: &OperationBinding) -> bool {
        match self {
            Self::RemoteOperation {
                actor,
                workspace_id,
                operation_id,
                method,
                parameter_hash,
                ..
            } => {
                *actor == binding.rights.actor()
                    && *workspace_id == binding.rights.workspace()
                    && *operation_id == binding.rights.operation_id()
                    && *method == binding.rights.original_method()
                    && parameter_hash == &String::from(binding.parameter_hash.clone())
            }
            Self::NativeEditor { .. } => false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DesktopNamespacePlanWire {
    version: u32,
    origin: DesktopNamespaceOriginWire,
    effect: DesktopNamespaceEffect,
    workspaces: Vec<DesktopNamespaceWorkspace>,
    guarded_workspace_ids: Vec<WorkspaceId>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNamespacePlan {
    wire: DesktopNamespacePlanWire,
    plan_sha256: String,
}

/// A namespace plan bound to one actually running remote FilesRename or
/// FilesRemove operation. It has no native writer-fence identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDesktopNamespacePlan {
    inner: DesktopNamespacePlan,
}

impl RemoteDesktopNamespacePlan {
    pub fn namespace_id(&self) -> String {
        self.inner.namespace_id()
    }

    pub fn host_runtime_id(&self) -> RuntimeId {
        self.inner.host_runtime_id()
    }

    pub fn effect(&self) -> &DesktopNamespaceEffect {
        self.inner.effect()
    }

    pub fn workspaces(&self) -> &[DesktopNamespaceWorkspace] {
        self.inner.workspaces()
    }

    pub fn guarded_workspace_ids(&self) -> &[WorkspaceId] {
        self.inner.guarded_workspace_ids()
    }

    pub fn plan_sha256(&self) -> &str {
        self.inner.plan_sha256()
    }

    pub fn operation_binding(
        &self,
    ) -> Option<(
        ConsumerAuthorizationId,
        WorkspaceId,
        OperationId,
        Method,
        &str,
    )> {
        self.inner.remote_operation_binding()
    }

    pub fn workspace_fence(&self) -> Option<u64> {
        match &self.inner.wire.origin {
            DesktopNamespaceOriginWire::RemoteOperation {
                workspace_fence, ..
            } => Some(*workspace_fence),
            DesktopNamespaceOriginWire::NativeEditor { .. } => None,
        }
    }
}

impl DesktopNamespacePlan {
    pub fn operation_id(&self) -> ipc::NativeIntentId {
        match &self.wire.origin {
            DesktopNamespaceOriginWire::NativeEditor { operation_id, .. } => *operation_id,
            DesktopNamespaceOriginWire::RemoteOperation { .. } => {
                panic!("remote namespace plan has no native editor operation id")
            }
        }
    }

    pub fn fence_id(&self) -> ipc::NativeIntentId {
        match &self.wire.origin {
            DesktopNamespaceOriginWire::NativeEditor { fence_id, .. } => *fence_id,
            DesktopNamespaceOriginWire::RemoteOperation { .. } => {
                panic!("remote namespace plan has no native writer fence")
            }
        }
    }

    pub fn host_runtime_id(&self) -> RuntimeId {
        self.wire.origin.host_runtime_id()
    }

    pub fn request_hash(&self) -> &str {
        self.wire.origin.request_hash()
    }

    pub fn namespace_id(&self) -> String {
        self.wire.origin.namespace_id().expect("validated origin")
    }

    pub fn remote_operation_binding(
        &self,
    ) -> Option<(
        ConsumerAuthorizationId,
        WorkspaceId,
        OperationId,
        Method,
        &str,
    )> {
        match &self.wire.origin {
            DesktopNamespaceOriginWire::RemoteOperation {
                actor,
                workspace_id,
                operation_id,
                method,
                parameter_hash,
                ..
            } => Some((
                *actor,
                *workspace_id,
                *operation_id,
                *method,
                parameter_hash,
            )),
            DesktopNamespaceOriginWire::NativeEditor { .. } => None,
        }
    }

    pub fn effect(&self) -> &DesktopNamespaceEffect {
        &self.wire.effect
    }

    pub fn workspaces(&self) -> &[DesktopNamespaceWorkspace] {
        &self.wire.workspaces
    }

    pub fn guarded_workspace_ids(&self) -> &[WorkspaceId] {
        &self.wire.guarded_workspace_ids
    }

    pub fn plan_sha256(&self) -> &str {
        &self.plan_sha256
    }
}

/// Host-minted proof that source/destination identities were checked before
/// the filesystem effect. Its JSON is validated and hashed here; the bounded
/// proof and digests of the individual physical pins are stored. The proof is
/// retained so recovery and checked database backups contain the actual pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNamespacePhysicalProof {
    namespace_id: String,
    host_runtime_id: RuntimeId,
    plan_sha256: String,
    proof_sha256: String,
    proof_json: String,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_parent_pin_sha256: Option<String>,
}

impl DesktopNamespacePhysicalProof {
    /// Mint a proof only after the trusted Host has checked the physical pins.
    /// The bounded JSON must bind operation, fence, plan, and exact paths; its
    /// opaque OS identities are retained without interpretation by Store.
    pub fn from_host_verified_physical_pins(
        plan: &DesktopNamespacePlan,
        proof_json: &str,
    ) -> Result<Self> {
        Self::from_host_verified_physical_pins_inner(plan, proof_json)
    }

    pub fn from_host_verified_remote_physical_pins(
        plan: &RemoteDesktopNamespacePlan,
        proof_json: &str,
    ) -> Result<Self> {
        Self::from_host_verified_physical_pins_inner(&plan.inner, proof_json)
    }

    fn from_host_verified_physical_pins_inner(
        plan: &DesktopNamespacePlan,
        proof_json: &str,
    ) -> Result<Self> {
        if proof_json.is_empty() || proof_json.len() > MAX_DESKTOP_NAMESPACE_PROOF_BYTES {
            return Err(StoreError::Invalid);
        }
        let wire: HostNamespacePhysicalProofWire = decode(proof_json)?;
        validate_physical_proof(&wire, plan)?;
        Ok(Self {
            namespace_id: plan.namespace_id(),
            host_runtime_id: plan.host_runtime_id(),
            plan_sha256: plan.plan_sha256.clone(),
            proof_sha256: sha256(proof_json.as_bytes()),
            proof_json: proof_json.to_owned(),
            source_pin_sha256: sha256(wire.source_identity_pin.as_bytes()),
            source_parent_pin_sha256: sha256(wire.source_parent_identity_pin.as_bytes()),
            destination_parent_pin_sha256: wire
                .destination_parent_identity_pin
                .as_deref()
                .map(|pin| sha256(pin.as_bytes())),
        })
    }

    pub fn proof_sha256(&self) -> &str {
        &self.proof_sha256
    }
}

/// Host-minted proof of the exact namespace effect (or a verified no-change
/// outcome). The Store never treats an absent path alone as proof of removal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopNamespaceObservedEffect {
    Applied,
    NoChange,
    /// The requested native Remove partially changed the filesystem, so the
    /// registered workspace roots are retired while the physical outcome
    /// remains unknown.
    RetiredAfterPartialRemove,
    /// Recovery retired the requested workspace registrations after the old
    /// worker was proven stopped, without making a physical outcome claim.
    RetiredRequestedRecovery,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNamespaceAppliedProof {
    namespace_id: String,
    host_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    proof_sha256: String,
    observed: DesktopNamespaceObservedEffect,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_pin_sha256: Option<String>,
    destination_parent_pin_sha256: Option<String>,
    effect_receipt_sha256: Option<String>,
}

impl DesktopNamespaceAppliedProof {
    /// Mint only after the trusted Host has verified the post-effect pins
    /// against the prepared identity proof.
    pub fn from_host_verified_effect(
        plan: &DesktopNamespacePlan,
        prepared: &DesktopNamespacePhysicalProof,
        proof_json: &str,
    ) -> Result<Self> {
        Self::from_host_verified_effect_inner(plan, prepared, proof_json)
    }

    pub fn from_host_verified_remote_effect(
        plan: &RemoteDesktopNamespacePlan,
        prepared: &DesktopNamespacePhysicalProof,
        proof_json: &str,
    ) -> Result<Self> {
        Self::from_host_verified_effect_inner(&plan.inner, prepared, proof_json)
    }

    fn from_host_verified_effect_inner(
        plan: &DesktopNamespacePlan,
        prepared: &DesktopNamespacePhysicalProof,
        proof_json: &str,
    ) -> Result<Self> {
        if proof_json.is_empty() || proof_json.len() > MAX_DESKTOP_NAMESPACE_PROOF_BYTES {
            return Err(StoreError::Invalid);
        }
        if prepared.namespace_id != plan.namespace_id()
            || prepared.host_runtime_id != plan.host_runtime_id()
            || prepared.plan_sha256 != plan.plan_sha256
        {
            return Err(StoreError::Fenced);
        }
        let wire: HostNamespaceAppliedProofWire = decode(proof_json)?;
        validate_applied_proof(&wire, plan, prepared)?;
        Ok(Self {
            namespace_id: plan.namespace_id(),
            host_runtime_id: plan.host_runtime_id(),
            plan_sha256: plan.plan_sha256.clone(),
            prepared_proof_sha256: prepared.proof_sha256.clone(),
            proof_sha256: sha256(proof_json.as_bytes()),
            observed: wire.observed.into(),
            source_pin_sha256: sha256(wire.source_identity_pin.as_bytes()),
            source_parent_pin_sha256: sha256(wire.source_parent_identity_pin.as_bytes()),
            destination_pin_sha256: wire
                .destination_identity_pin
                .as_deref()
                .map(|pin| sha256(pin.as_bytes())),
            destination_parent_pin_sha256: wire
                .destination_parent_identity_pin
                .as_deref()
                .map(|pin| sha256(pin.as_bytes())),
            effect_receipt_sha256: wire.effect_receipt_sha256,
        })
    }

    pub fn observed(&self) -> DesktopNamespaceObservedEffect {
        self.observed
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DesktopNamespaceIntentState {
    Prepared,
    Applied,
    NoChange,
    RetiredAfterPartialRemove,
    RetiredRequestedRecovery,
}

#[derive(Debug, Clone)]
pub struct DesktopNamespaceIntentRecord {
    pub operation_id: ipc::NativeIntentId,
    pub fence_id: ipc::NativeIntentId,
    pub host_runtime_id: RuntimeId,
    pub plan: DesktopNamespacePlan,
    pub state: DesktopNamespaceIntentState,
    pub prepared_proof_sha256: String,
    pub prepared_proof_json: String,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_parent_pin_sha256: Option<String>,
    pub completion_proof_sha256: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
pub struct RemoteDesktopNamespaceIntentRecord {
    pub namespace_id: String,
    pub actor: ConsumerAuthorizationId,
    pub workspace_id: WorkspaceId,
    pub operation_id: OperationId,
    pub method: Method,
    pub host_runtime_id: RuntimeId,
    pub plan: RemoteDesktopNamespacePlan,
    pub state: DesktopNamespaceIntentState,
    pub prepared_proof_sha256: String,
    pub prepared_proof_json: String,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_parent_pin_sha256: Option<String>,
    pub completion_proof_sha256: Option<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone)]
struct NamespaceIntentRecord {
    namespace_id: String,
    origin: DesktopNamespaceOriginWire,
    host_runtime_id: RuntimeId,
    plan: DesktopNamespacePlan,
    state: DesktopNamespaceIntentState,
    prepared_proof_sha256: String,
    prepared_proof_json: String,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_parent_pin_sha256: Option<String>,
    completion_proof_sha256: Option<String>,
    created_at_ms: u64,
    updated_at_ms: u64,
}

impl DesktopNamespaceIntentRecord {
    pub fn source_pin_sha256(&self) -> &str {
        &self.source_pin_sha256
    }

    pub fn source_parent_pin_sha256(&self) -> &str {
        &self.source_parent_pin_sha256
    }

    pub fn destination_parent_pin_sha256(&self) -> Option<&str> {
        self.destination_parent_pin_sha256.as_deref()
    }
}

impl RemoteDesktopNamespaceIntentRecord {
    pub fn source_pin_sha256(&self) -> &str {
        &self.source_pin_sha256
    }

    pub fn source_parent_pin_sha256(&self) -> &str {
        &self.source_parent_pin_sha256
    }

    pub fn destination_parent_pin_sha256(&self) -> Option<&str> {
        self.destination_parent_pin_sha256.as_deref()
    }
}

/// Recovery handoff is produced only by Host code that holds the owner lock,
/// verifies retirement of the old no-exec worker, and checks the exact effect
/// against the persisted source/destination pins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopNamespaceRecoveryEvidence {
    operation_id: ipc::NativeIntentId,
    fence_id: ipc::NativeIntentId,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    proof_sha256: String,
    observed: DesktopNamespaceObservedEffect,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_pin_sha256: Option<String>,
    destination_parent_pin_sha256: Option<String>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    worker_retirement_receipt_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDesktopNamespaceRecoveryEvidence {
    namespace_id: String,
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    operation_id: OperationId,
    method: Method,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    proof_sha256: String,
    observed: DesktopNamespaceObservedEffect,
    source_pin_sha256: String,
    source_parent_pin_sha256: String,
    destination_pin_sha256: Option<String>,
    destination_parent_pin_sha256: Option<String>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    operation_retirement_receipt_sha256: String,
}

impl DesktopNamespaceRecoveryEvidence {
    /// Mint only after owner-lock acquisition, old worker retirement, and
    /// filesystem identity verification have all succeeded.
    pub fn from_host_verified_owner_lock_and_retirement(
        record: &DesktopNamespaceIntentRecord,
        current_runtime_id: RuntimeId,
        proof_json: &str,
    ) -> Result<Self> {
        if proof_json.is_empty() || proof_json.len() > MAX_DESKTOP_NAMESPACE_PROOF_BYTES {
            return Err(StoreError::Invalid);
        }
        if record.state != DesktopNamespaceIntentState::Prepared
            || record.host_runtime_id == current_runtime_id
        {
            return Err(StoreError::Fenced);
        }
        let wire: HostNamespaceRecoveryProofWire = decode(proof_json)?;
        validate_recovery_proof(&wire, record, current_runtime_id)?;
        if matches!(
            wire.observed,
            HostNamespaceObservedEffect::RetiredAfterPartialRemove
                | HostNamespaceObservedEffect::RetiredRequestedRecovery
        ) {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            operation_id: record.operation_id,
            fence_id: record.fence_id,
            old_runtime_id: record.host_runtime_id,
            current_runtime_id,
            plan_sha256: record.plan.plan_sha256.clone(),
            prepared_proof_sha256: record.prepared_proof_sha256.clone(),
            proof_sha256: sha256(proof_json.as_bytes()),
            observed: wire.observed.into(),
            source_pin_sha256: wire.source_identity_sha256,
            source_parent_pin_sha256: wire.source_parent_identity_sha256,
            destination_pin_sha256: wire.destination_identity_sha256,
            destination_parent_pin_sha256: wire.destination_parent_identity_sha256,
            effect_receipt_sha256: wire.effect_receipt_sha256,
            owner_lock_receipt_sha256: wire.owner_lock_receipt_sha256,
            worker_retirement_receipt_sha256: wire.worker_retirement_receipt_sha256,
        })
    }

    /// Mint only for conservative recovery of a requested native Remove.
    /// This retires registrations after positive old-worker retirement, while
    /// keeping the physical filesystem outcome unknown.
    pub fn from_host_verified_retire_requested_registrations_after_uncertain_remove(
        record: &DesktopNamespaceIntentRecord,
        current_runtime_id: RuntimeId,
        proof_json: &str,
    ) -> Result<Self> {
        if proof_json.is_empty() || proof_json.len() > MAX_DESKTOP_NAMESPACE_PROOF_BYTES {
            return Err(StoreError::Invalid);
        }
        if record.state != DesktopNamespaceIntentState::Prepared
            || record.host_runtime_id == current_runtime_id
            || !matches!(record.plan.effect(), DesktopNamespaceEffect::Remove { .. })
            || !matches!(
                record.plan.wire.origin,
                DesktopNamespaceOriginWire::NativeEditor { .. }
            )
        {
            return Err(StoreError::Fenced);
        }
        let wire: HostNamespaceRecoveryProofWire = decode(proof_json)?;
        validate_recovery_proof(&wire, record, current_runtime_id)?;
        if wire.observed != HostNamespaceObservedEffect::RetiredRequestedRecovery {
            return Err(StoreError::Invalid);
        }
        Ok(Self {
            operation_id: record.operation_id,
            fence_id: record.fence_id,
            old_runtime_id: record.host_runtime_id,
            current_runtime_id,
            plan_sha256: record.plan.plan_sha256.clone(),
            prepared_proof_sha256: record.prepared_proof_sha256.clone(),
            proof_sha256: sha256(proof_json.as_bytes()),
            observed: wire.observed.into(),
            source_pin_sha256: wire.source_identity_sha256,
            source_parent_pin_sha256: wire.source_parent_identity_sha256,
            destination_pin_sha256: wire.destination_identity_sha256,
            destination_parent_pin_sha256: wire.destination_parent_identity_sha256,
            effect_receipt_sha256: None,
            owner_lock_receipt_sha256: wire.owner_lock_receipt_sha256,
            worker_retirement_receipt_sha256: wire.worker_retirement_receipt_sha256,
        })
    }
}

impl RemoteDesktopNamespaceRecoveryEvidence {
    pub fn from_host_verified_owner_lock_and_retirement(
        record: &RemoteDesktopNamespaceIntentRecord,
        current_runtime_id: RuntimeId,
        proof_json: &str,
    ) -> Result<Self> {
        if proof_json.is_empty() || proof_json.len() > MAX_DESKTOP_NAMESPACE_PROOF_BYTES {
            return Err(StoreError::Invalid);
        }
        if record.state != DesktopNamespaceIntentState::Prepared
            || record.host_runtime_id == current_runtime_id
        {
            return Err(StoreError::Fenced);
        }
        let wire: HostRemoteNamespaceRecoveryProofWire = decode(proof_json)?;
        validate_remote_recovery_proof(&wire, record, current_runtime_id)?;
        Ok(Self {
            namespace_id: record.namespace_id.clone(),
            actor: record.actor,
            workspace_id: record.workspace_id,
            operation_id: record.operation_id,
            method: record.method,
            old_runtime_id: record.host_runtime_id,
            current_runtime_id,
            plan_sha256: record.plan.inner.plan_sha256.clone(),
            prepared_proof_sha256: record.prepared_proof_sha256.clone(),
            proof_sha256: sha256(proof_json.as_bytes()),
            observed: wire.observed.into(),
            source_pin_sha256: wire.source_identity_sha256,
            source_parent_pin_sha256: wire.source_parent_identity_sha256,
            destination_pin_sha256: wire.destination_identity_sha256,
            destination_parent_pin_sha256: wire.destination_parent_identity_sha256,
            effect_receipt_sha256: wire.effect_receipt_sha256,
            owner_lock_receipt_sha256: wire.owner_lock_receipt_sha256,
            operation_retirement_receipt_sha256: wire.operation_retirement_receipt_sha256,
        })
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostNamespacePhysicalProofWire {
    version: u32,
    #[serde(default)]
    operation_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    fence_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    namespace_id: Option<String>,
    host_runtime_id: RuntimeId,
    plan_sha256: String,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_pin: String,
    source_parent_identity_pin: String,
    destination_parent_identity_pin: Option<String>,
    /// For case-only moves this is exact entry-spelling absence established by
    /// the Host's parent-directory census, not a case-insensitive path lookup.
    destination_absent: Option<bool>,
}

#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum HostNamespaceObservedEffect {
    Applied,
    NoChange,
    RetiredAfterPartialRemove,
    RetiredRequestedRecovery,
}

impl From<HostNamespaceObservedEffect> for DesktopNamespaceObservedEffect {
    fn from(value: HostNamespaceObservedEffect) -> Self {
        match value {
            HostNamespaceObservedEffect::Applied => Self::Applied,
            HostNamespaceObservedEffect::NoChange => Self::NoChange,
            HostNamespaceObservedEffect::RetiredAfterPartialRemove => {
                Self::RetiredAfterPartialRemove
            }
            HostNamespaceObservedEffect::RetiredRequestedRecovery => Self::RetiredRequestedRecovery,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostNamespaceAppliedProofWire {
    version: u32,
    #[serde(default)]
    operation_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    fence_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    namespace_id: Option<String>,
    host_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: HostNamespaceObservedEffect,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_pin: String,
    source_parent_identity_pin: String,
    destination_identity_pin: Option<String>,
    destination_parent_identity_pin: Option<String>,
    /// On case-insensitive filesystems this means the old spelling is absent
    /// from the parent directory, even if path lookup aliases the new spelling.
    source_absent: Option<bool>,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostNamespaceRecoveryProofWire {
    version: u32,
    #[serde(default)]
    operation_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    fence_id: Option<ipc::NativeIntentId>,
    #[serde(default)]
    namespace_id: Option<String>,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: HostNamespaceObservedEffect,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_sha256: String,
    source_parent_identity_sha256: String,
    destination_identity_sha256: Option<String>,
    destination_parent_identity_sha256: Option<String>,
    /// Exact directory-entry spelling proof; path lookup alone is insufficient
    /// for a case-only rename on a case-insensitive filesystem.
    source_absent: Option<bool>,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    worker_retirement_receipt_sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct HostRemoteNamespaceRecoveryProofWire {
    version: u32,
    namespace_id: String,
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    operation_id: OperationId,
    method: Method,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: HostNamespaceObservedEffect,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_sha256: String,
    source_parent_identity_sha256: String,
    destination_identity_sha256: Option<String>,
    destination_parent_identity_sha256: Option<String>,
    source_absent: bool,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    operation_retirement_receipt_sha256: String,
}

impl HostStore {
    /// Old no-exec workers are recovered only by a fresh profile owner. Return
    /// their retained physical manifests; current-runtime effects are never
    /// eligible for this restart path.
    pub fn desktop_namespace_intents_requiring_recovery(
        &self,
    ) -> Result<Vec<DesktopNamespaceIntentRecord>> {
        let mut query = self.db.prepare(
            "SELECT namespace_id FROM desktop_namespace_intents
             WHERE origin='nativeEditor' AND state='prepared' AND host_runtime_id<>?1
             ORDER BY namespace_id LIMIT ?2",
        )?;
        let ids = query
            .query_map(
                params![key(self.runtime), MAX_DESKTOP_NAMESPACE_INTENTS as i64 + 1],
                |row| row.get::<_, String>(0),
            )?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() > MAX_DESKTOP_NAMESPACE_INTENTS {
            return Err(StoreError::ResourceExhausted);
        }
        ids.into_iter()
            .map(|id| {
                native_record(read_namespace_record(&self.db, &id)?.ok_or(StoreError::Storage)?)
            })
            .collect()
    }

    /// A joined native worker can have an unprovable namespace outcome. Make
    /// that uncertainty visible without releasing its namespace or writer
    /// fence. This deliberately retains the same recovery shape as a restart;
    /// only separately verified namespace recovery may release quarantine.
    pub fn quarantine_native_editor_namespace_after_join(
        &mut self,
        operation_id: ipc::NativeIntentId,
        proof: NativeEditorCompletionProof,
    ) -> Result<()> {
        if proof != NativeEditorCompletionProof::Joined {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let record = native_record(
            read_namespace_record(&tx, &native_namespace_id(operation_id))?
                .ok_or(StoreError::NotFound)?,
        )?;
        if record.state != DesktopNamespaceIntentState::Prepared
            || record.host_runtime_id != self.runtime
        {
            return Err(StoreError::Fenced);
        }
        let (state, fence, runtime, result, completion): (
            String,
            String,
            String,
            Option<String>,
            Option<String>,
        ) = tx.query_row(
            "SELECT state,fence_id,host_runtime_id,result_json,completion_proof
             FROM native_editor_jobs WHERE operation_id=?1",
            [key(operation_id)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                ))
            },
        )?;
        if fence != key(record.fence_id)
            || runtime != key(self.runtime)
            || !matches!(state.as_str(), "running" | "outcomeUnknown")
            || result.is_some()
            || completion.is_some()
        {
            return Err(StoreError::Fenced);
        }
        if tx.execute(
            "UPDATE native_intents SET state='quarantine'
             WHERE id=?1 AND state IN('active','quarantine')",
            [key(record.fence_id)],
        )? != 1
        {
            return Err(StoreError::Fenced);
        }
        tx.execute(
            "UPDATE native_editor_jobs SET state='outcomeUnknown',completed_at_ms=NULL
             WHERE operation_id=?1 AND state IN('running','outcomeUnknown')",
            [key(operation_id)],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Compute the exact current Store binding for a prospective namespace
    /// operation. The Host validates physical identity outside Store, then
    /// `prepare_desktop_namespace` rechecks this plan transactionally.
    pub fn plan_desktop_namespace(
        &self,
        operation_id: ipc::NativeIntentId,
        effect: DesktopNamespaceEffect,
    ) -> Result<DesktopNamespacePlan> {
        let origin = native_origin(&self.db, operation_id, self.runtime)?;
        build_namespace_plan(&self.db, origin, effect)
    }

    /// Plan a remote file rename/removal from its real accepted-to-running
    /// permit. This never creates or aliases a native editor job/fence.
    pub fn plan_desktop_namespace_remote(
        &self,
        permit: &ExternalPermit,
        effect: DesktopNamespaceEffect,
    ) -> Result<RemoteDesktopNamespacePlan> {
        let origin = remote_origin_from_permit(permit, self.runtime)?;
        validate_running_remote_binding(&self.db, &origin, permit, self.runtime)?;
        Ok(RemoteDesktopNamespacePlan {
            inner: build_namespace_plan(&self.db, origin, effect)?,
        })
    }

    /// Read-only preview of the exact workspace guards a namespace effect
    /// would acquire. This does not construct an origin, plan, or permit.
    pub fn desktop_namespace_guarded_workspaces(
        &self,
        effect: &DesktopNamespaceEffect,
    ) -> Result<Vec<WorkspaceId>> {
        ensure_namespace_effect_available(&self.db, effect)?;
        let all_projects = projects(&self.db)?;
        let (_, guarded_workspace_ids) = namespace_bindings_for_effect(&all_projects, effect)?;
        Ok(guarded_workspace_ids)
    }

    /// Persist the immutable plan before the Host performs the filesystem
    /// effect. Replays return the existing exact record and never authorize a
    /// second effect.
    pub fn prepare_desktop_namespace(
        &mut self,
        plan: &DesktopNamespacePlan,
        proof: &DesktopNamespacePhysicalProof,
    ) -> Result<DesktopNamespaceIntentRecord> {
        if !matches!(
            plan.wire.origin,
            DesktopNamespaceOriginWire::NativeEditor { .. }
        ) {
            return Err(StoreError::Invalid);
        }
        let record = self.prepare_namespace_inner(plan, proof, None)?;
        native_record(record)
    }

    pub fn prepare_desktop_namespace_remote(
        &mut self,
        permit: &ExternalPermit,
        plan: &RemoteDesktopNamespacePlan,
        proof: &DesktopNamespacePhysicalProof,
    ) -> Result<RemoteDesktopNamespaceIntentRecord> {
        if !matches!(
            plan.inner.wire.origin,
            DesktopNamespaceOriginWire::RemoteOperation { .. }
        ) {
            return Err(StoreError::Invalid);
        }
        let record = self.prepare_namespace_inner(&plan.inner, proof, Some(permit))?;
        remote_record(record)
    }

    fn prepare_namespace_inner(
        &mut self,
        plan: &DesktopNamespacePlan,
        proof: &DesktopNamespacePhysicalProof,
        permit: Option<&ExternalPermit>,
    ) -> Result<NamespaceIntentRecord> {
        validate_plan(plan)?;
        if proof.namespace_id != plan.namespace_id()
            || proof.host_runtime_id != plan.host_runtime_id()
            || proof.plan_sha256 != plan.plan_sha256
        {
            return Err(StoreError::Fenced);
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

        let namespace_id = plan.namespace_id();
        match (&plan.wire.origin, permit) {
            (DesktopNamespaceOriginWire::NativeEditor { .. }, None) => {
                validate_running_editor_binding(&tx, plan, true)?;
            }
            (origin @ DesktopNamespaceOriginWire::RemoteOperation { .. }, Some(permit)) => {
                validate_running_remote_binding(&tx, origin, permit, self.runtime)?;
            }
            _ => return Err(StoreError::Fenced),
        }

        if let Some(existing) = read_namespace_record(&tx, &namespace_id)? {
            let exact = existing.plan == *plan
                && existing.prepared_proof_sha256 == proof.proof_sha256
                && existing.source_pin_sha256 == proof.source_pin_sha256
                && existing.source_parent_pin_sha256 == proof.source_parent_pin_sha256
                && existing.destination_parent_pin_sha256 == proof.destination_parent_pin_sha256;
            tx.commit()?;
            return if exact {
                Ok(existing)
            } else {
                Err(StoreError::IdempotencyConflict)
            };
        }
        let current = build_namespace_plan(&tx, plan.wire.origin.clone(), plan.effect().clone())?;
        if current != *plan {
            return Err(StoreError::Fenced);
        }
        ensure_namespace_pre_effect_ready(&tx, plan)?;
        ensure_namespace_plan_is_unconflicted(&tx, plan)?;
        if count(
            &tx,
            "SELECT count(*) FROM desktop_namespace_intents WHERE state='prepared'",
        )? >= MAX_DESKTOP_NAMESPACE_INTENTS
        {
            return Err(StoreError::ResourceExhausted);
        }
        let plan_json = encode_plan(plan)?;
        let (source_pin_sha256, source_parent_pin_sha256, destination_parent_pin_sha256) =
            proof_pin_digests(proof);
        let origin_columns = namespace_origin_columns(&plan.wire.origin)?;
        tx.execute(
            "INSERT INTO desktop_namespace_intents(
                namespace_id,origin,native_operation_id,native_fence_id,
                remote_actor,remote_workspace,remote_operation_id,remote_method,
                remote_parameter_hash,remote_workspace_fence,host_runtime_id,plan_json,plan_sha256,
                prepared_proof_sha256,source_pin_sha256,source_parent_pin_sha256,
                destination_parent_pin_sha256,state,completion_proof_sha256,
                created_at_ms,updated_at_ms,prepared_proof_json
             ) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,
                      ?15,?16,?17,'prepared',NULL,?18,?18,?19)",
            params![
                namespace_id,
                origin_columns.kind,
                origin_columns.native_operation_id,
                origin_columns.native_fence_id,
                origin_columns.remote_actor,
                origin_columns.remote_workspace,
                origin_columns.remote_operation_id,
                origin_columns.remote_method,
                origin_columns.remote_parameter_hash,
                origin_columns.remote_workspace_fence,
                key(plan.host_runtime_id()),
                plan_json,
                plan.plan_sha256,
                proof.proof_sha256,
                source_pin_sha256,
                source_parent_pin_sha256,
                destination_parent_pin_sha256,
                now.to_string(),
                proof.proof_json,
            ],
        )?;
        let record = read_namespace_record(&tx, &namespace_id)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(record)
    }

    pub fn desktop_namespace_intent(
        &self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<DesktopNamespaceIntentRecord> {
        let namespace_id = native_namespace_id(operation_id);
        native_record(read_namespace_record(&self.db, &namespace_id)?.ok_or(StoreError::NotFound)?)
    }

    pub fn remote_desktop_namespace_intent(
        &self,
        binding: &OperationBinding,
    ) -> Result<RemoteDesktopNamespaceIntentRecord> {
        existing(&self.db, binding)?.ok_or(StoreError::NotFound)?;
        let namespace_id = remote_namespace_id(
            binding.rights.actor(),
            binding.rights.workspace(),
            binding.rights.operation_id(),
        );
        let record = read_namespace_record(&self.db, &namespace_id)?.ok_or(StoreError::NotFound)?;
        if !record.origin.remote_binding_matches(binding) {
            return Err(StoreError::Fenced);
        }
        remote_record(record)
    }

    pub fn remote_desktop_namespace_intents_requiring_recovery(
        &self,
    ) -> Result<Vec<RemoteDesktopNamespaceIntentRecord>> {
        let mut query = self.db.prepare(
            "SELECT namespace_id FROM desktop_namespace_intents
             WHERE origin='remoteOperation' AND state='prepared' ORDER BY namespace_id",
        )?;
        let ids = query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        if ids.len() > MAX_DESKTOP_NAMESPACE_INTENTS {
            return Err(StoreError::ResourceExhausted);
        }
        ids.into_iter()
            .map(|namespace_id| {
                let record =
                    read_namespace_record(&self.db, &namespace_id)?.ok_or(StoreError::Storage)?;
                remote_record(record)
            })
            .collect()
    }

    /// Complete a namespaced native editor job in the same transaction that
    /// commits every workspace root/alias update and releases its writer fence.
    pub fn complete_native_editor_namespace(
        &mut self,
        operation_id: ipc::NativeIntentId,
        state: NativeEditorJobState,
        proof: NativeEditorCompletionProof,
        result_json: Option<String>,
        evidence: &DesktopNamespaceAppliedProof,
    ) -> Result<()> {
        if state == NativeEditorJobState::Running
            || result_json
                .as_ref()
                .is_some_and(|value| value.len() > 131_072)
            || evidence.observed == DesktopNamespaceObservedEffect::RetiredRequestedRecovery
        {
            return Err(StoreError::Invalid);
        }
        if (evidence.observed == DesktopNamespaceObservedEffect::Applied
            && proof != NativeEditorCompletionProof::Joined)
            || (evidence.observed == DesktopNamespaceObservedEffect::NoChange
                && state != NativeEditorJobState::Failed)
        {
            return Err(StoreError::Invalid);
        }
        if evidence.observed == DesktopNamespaceObservedEffect::RetiredAfterPartialRemove {
            let Some(result_json) = result_json.as_deref() else {
                return Err(StoreError::Invalid);
            };
            let receipt_sha256 = sha256(result_json.as_bytes());
            if state != NativeEditorJobState::OutcomeUnknown
                || proof != NativeEditorCompletionProof::Joined
                || !is_exact_uncertain_desktop_result(result_json)
                || evidence.effect_receipt_sha256.as_deref() != Some(receipt_sha256.as_str())
            {
                return Err(StoreError::Invalid);
            }
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
        let record = native_record(
            read_namespace_record(&tx, &native_namespace_id(operation_id))?
                .ok_or(StoreError::NotFound)?,
        )?;
        if evidence.namespace_id != native_namespace_id(operation_id)
            || evidence.host_runtime_id != record.host_runtime_id
            || evidence.plan_sha256 != record.plan.plan_sha256
            || evidence.prepared_proof_sha256 != record.prepared_proof_sha256
            || evidence.source_pin_sha256 != record.source_pin_sha256
            || evidence.source_parent_pin_sha256 != record.source_parent_pin_sha256
            || evidence.destination_parent_pin_sha256 != record.destination_parent_pin_sha256
            || (evidence.observed == DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                && !matches!(record.plan.effect(), DesktopNamespaceEffect::Remove { .. }))
        {
            return Err(StoreError::Fenced);
        }
        if record.state != DesktopNamespaceIntentState::Prepared {
            let expected_namespace_state = match evidence.observed {
                DesktopNamespaceObservedEffect::Applied => DesktopNamespaceIntentState::Applied,
                DesktopNamespaceObservedEffect::NoChange => DesktopNamespaceIntentState::NoChange,
                DesktopNamespaceObservedEffect::RetiredAfterPartialRemove => {
                    DesktopNamespaceIntentState::RetiredAfterPartialRemove
                }
                DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                    return Err(StoreError::Invalid);
                }
            };
            let (job_state, result, job_proof, fence_state): (
                String,
                Option<String>,
                Option<String>,
                String,
            ) = tx.query_row(
                "SELECT jobs.state,jobs.result_json,jobs.completion_proof,intents.state
                 FROM native_editor_jobs jobs JOIN native_intents intents ON intents.id=jobs.fence_id
                 WHERE jobs.operation_id=?1",
                [key(operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )?;
            let exact = record.state == expected_namespace_state
                && record.completion_proof_sha256.as_deref()
                    == Some(evidence.proof_sha256.as_str())
                && job_state == native_editor_job_state_text(state)
                && result == result_json
                && job_proof.as_deref() == Some(native_editor_completion_proof_text(proof))
                && fence_state == "finished";
            tx.commit()?;
            return if exact {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        validate_running_editor_binding(&tx, &record.plan, false)?;
        apply_namespace_effect(&tx, &record.plan, evidence, self.limits)?;
        finish_editor_job_and_namespace(
            &tx,
            &record,
            state,
            proof,
            result_json,
            evidence.observed,
            evidence.proof_sha256.as_str(),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Complete the namespace change and the genuine remote FilesRename/
    /// FilesRemove receipt together. The operation reservation is released by
    /// the same transaction that remaps roots and import aliases.
    pub fn complete_remote_namespace(
        &mut self,
        permit: &ExternalPermit,
        state: OperationState,
        effect: Effect,
        result: Option<OperationResult>,
        evidence: &DesktopNamespaceAppliedProof,
    ) -> Result<OperationReceipt> {
        if permit.runtime != self.runtime || !state.is_final() {
            return Err(StoreError::Fenced);
        }
        // Positive physical evidence may release a stopped operation's
        // namespace reservation while its original receipt remains uncertain.
        // It never turns a lost response into a successful operation or replay.
        let uncertain = state == OperationState::OutcomeUnknown
            && effect == Effect::Unknown
            && result.is_none();
        match evidence.observed {
            DesktopNamespaceObservedEffect::NoChange
                if !uncertain
                    && (state != OperationState::Failed
                        || effect != Effect::None
                        || result.is_some()) =>
            {
                return Err(StoreError::Invalid);
            }
            DesktopNamespaceObservedEffect::Applied
                if !uncertain
                    && (!matches!(state, OperationState::Succeeded | OperationState::Failed)
                        || !matches!(effect, Effect::Committed | Effect::Partial)) =>
            {
                return Err(StoreError::Invalid);
            }
            DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
            | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                return Err(StoreError::Invalid);
            }
            _ => {}
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
        let namespace_id = remote_namespace_id(
            permit.binding.rights.actor(),
            permit.binding.rights.workspace(),
            permit.binding.rights.operation_id(),
        );
        let record = read_namespace_record(&tx, &namespace_id)?.ok_or(StoreError::NotFound)?;
        if !remote_permit_context_matches(&record.origin, permit, self.runtime) {
            return Err(StoreError::Fenced);
        }
        validate_applied_evidence_for_record(&record, evidence)?;
        if record.state != DesktopNamespaceIntentState::Prepared {
            let existing = existing(&tx, &permit.binding)?.ok_or(StoreError::NotFound)?;
            let reserved: i64 = tx.query_row(
                "SELECT reserved FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
                op_params(&permit.binding),
                |row| row.get(0),
            )?;
            let expected_namespace_state = match evidence.observed {
                DesktopNamespaceObservedEffect::Applied => DesktopNamespaceIntentState::Applied,
                DesktopNamespaceObservedEffect::NoChange => DesktopNamespaceIntentState::NoChange,
                DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                    return Err(StoreError::Invalid);
                }
            };
            let exact = record.state == expected_namespace_state
                && record.completion_proof_sha256.as_deref()
                    == Some(evidence.proof_sha256.as_str())
                && existing.state() == state
                && existing.effect() == effect
                && existing.result().cloned() == result
                && reserved == 0;
            tx.commit()?;
            return if exact {
                Ok(existing)
            } else {
                Err(StoreError::Fenced)
            };
        }
        // The Host rechecks its revoke/deadline gate immediately around the
        // filesystem effect. Store still validates the exact Running permit
        // binding here, but deliberately preserves a newer workspace fence or
        // consent change that happened after preparation.
        validate_running_remote_binding_after_effect(&tx, &record.origin, permit, self.runtime)?;
        apply_namespace_effect(&tx, &record.plan, evidence, self.limits)?;
        let receipt = super::complete_external_in_transaction(
            &tx,
            &permit.binding,
            state,
            effect,
            result,
            None,
        )?;
        mark_namespace_completed(
            &tx,
            &record,
            evidence.observed,
            evidence.proof_sha256.as_str(),
            now,
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Recover a prepared namespace intent only from typed Host evidence that
    /// binds the old job, plan, pins, owner lock, and old worker retirement.
    /// The native editor result remains OutcomeUnknown after restart.
    pub fn recover_desktop_namespace_intent(
        &mut self,
        evidence: &DesktopNamespaceRecoveryEvidence,
    ) -> Result<()> {
        if evidence.current_runtime_id != self.runtime
            || evidence.old_runtime_id == self.runtime
            || !valid_sha256(&evidence.owner_lock_receipt_sha256)
            || !valid_sha256(&evidence.worker_retirement_receipt_sha256)
        {
            return Err(StoreError::Fenced);
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
        let record = native_record(
            read_namespace_record(&tx, &native_namespace_id(evidence.operation_id))?
                .ok_or(StoreError::NotFound)?,
        )?;
        if record.state != DesktopNamespaceIntentState::Prepared {
            let exact = record.completion_proof_sha256.as_deref()
                == Some(evidence.proof_sha256.as_str())
                && record.state
                    == match evidence.observed {
                        DesktopNamespaceObservedEffect::Applied => {
                            DesktopNamespaceIntentState::Applied
                        }
                        DesktopNamespaceObservedEffect::NoChange => {
                            DesktopNamespaceIntentState::NoChange
                        }
                        DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                            DesktopNamespaceIntentState::RetiredRequestedRecovery
                        }
                        DesktopNamespaceObservedEffect::RetiredAfterPartialRemove => {
                            return Err(StoreError::Invalid);
                        }
                    };
            let fence: Option<String> = tx
                .query_row(
                    "SELECT state FROM native_intents WHERE id=?1",
                    [key(record.fence_id)],
                    |row| row.get(0),
                )
                .optional()?;
            tx.commit()?;
            return if exact && fence.as_deref() == Some("finished") {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        if record.state != DesktopNamespaceIntentState::Prepared
            || record.fence_id != evidence.fence_id
            || record.host_runtime_id != evidence.old_runtime_id
            || record.plan.plan_sha256 != evidence.plan_sha256
            || record.prepared_proof_sha256 != evidence.prepared_proof_sha256
            || record.source_pin_sha256 != evidence.source_pin_sha256
            || record.source_parent_pin_sha256 != evidence.source_parent_pin_sha256
            || record.destination_parent_pin_sha256 != evidence.destination_parent_pin_sha256
        {
            return Err(StoreError::Fenced);
        }
        let job: (String, String, String) = tx.query_row(
            "SELECT state,fence_id,host_runtime_id FROM native_editor_jobs WHERE operation_id=?1",
            [key(evidence.operation_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )?;
        if job.0 != "outcomeUnknown"
            || job.1 != key(record.fence_id)
            || job.2 != key(record.host_runtime_id)
        {
            return Err(StoreError::Fenced);
        }
        if evidence.observed == DesktopNamespaceObservedEffect::RetiredRequestedRecovery {
            let (result_json, completion_proof): (Option<String>, Option<String>) = tx.query_row(
                "SELECT result_json,completion_proof FROM native_editor_jobs WHERE operation_id=?1",
                [key(evidence.operation_id)],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )?;
            if result_json.is_some() || completion_proof.is_some() {
                return Err(StoreError::Fenced);
            }
        }
        let fence_state: String = tx.query_row(
            "SELECT state FROM native_intents WHERE id=?1",
            [key(record.fence_id)],
            |row| row.get(0),
        )?;
        if fence_state != "quarantine" {
            return Err(StoreError::Fenced);
        }
        apply_recovered_namespace_effect(&tx, &record, evidence, self.limits)?;
        mark_namespace_recovered(&tx, &record, evidence, now)?;
        tx.execute(
            "UPDATE native_intents SET state='finished' WHERE id=?1 AND state='quarantine'",
            [key(record.fence_id)],
        )
        .and_then(|changed| {
            if changed == 1 {
                Ok(changed)
            } else {
                Err(rusqlite::Error::QueryReturnedNoRows)
            }
        })?;
        tx.commit()?;
        Ok(())
    }

    /// Recover a remote namespace intent after independently retiring the old
    /// operation owner. Filesystem effects are never replayed. Applied effects
    /// keep an OutcomeUnknown operation receipt; verified no-change is Failed.
    pub fn recover_remote_desktop_namespace_intent(
        &mut self,
        evidence: &RemoteDesktopNamespaceRecoveryEvidence,
    ) -> Result<()> {
        if evidence.current_runtime_id != self.runtime
            || evidence.old_runtime_id == self.runtime
            || !valid_sha256(&evidence.owner_lock_receipt_sha256)
            || !valid_sha256(&evidence.operation_retirement_receipt_sha256)
        {
            return Err(StoreError::Fenced);
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
        let record =
            read_namespace_record(&tx, &evidence.namespace_id)?.ok_or(StoreError::NotFound)?;
        let binding = operation_binding_from_origin(&tx, &record.origin)?;
        if record.state != DesktopNamespaceIntentState::Prepared {
            let receipt = existing(&tx, &binding)?.ok_or(StoreError::NotFound)?;
            let (expected_state, expected_effect) = match evidence.observed {
                DesktopNamespaceObservedEffect::Applied => {
                    (OperationState::OutcomeUnknown, Effect::Unknown)
                }
                DesktopNamespaceObservedEffect::NoChange => {
                    (OperationState::OutcomeUnknown, Effect::Unknown)
                }
                DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                    return Err(StoreError::Invalid);
                }
            };
            let exact = record.completion_proof_sha256.as_deref()
                == Some(evidence.proof_sha256.as_str())
                && record.state
                    == match evidence.observed {
                        DesktopNamespaceObservedEffect::Applied => {
                            DesktopNamespaceIntentState::Applied
                        }
                        DesktopNamespaceObservedEffect::NoChange => {
                            DesktopNamespaceIntentState::NoChange
                        }
                        DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                        | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                            return Err(StoreError::Invalid);
                        }
                    }
                && receipt.state() == expected_state
                && receipt.effect() == expected_effect
                && receipt.result().is_none();
            tx.commit()?;
            return if exact {
                Ok(())
            } else {
                Err(StoreError::Fenced)
            };
        }
        if record.namespace_id != evidence.namespace_id
            || record.host_runtime_id != evidence.old_runtime_id
            || record.plan.plan_sha256 != evidence.plan_sha256
            || record.prepared_proof_sha256 != evidence.prepared_proof_sha256
            || record.source_pin_sha256 != evidence.source_pin_sha256
            || record.source_parent_pin_sha256 != evidence.source_parent_pin_sha256
            || record.destination_parent_pin_sha256 != evidence.destination_parent_pin_sha256
            || !matches!(
                record.origin,
                DesktopNamespaceOriginWire::RemoteOperation { .. }
            )
        {
            return Err(StoreError::Fenced);
        }
        validate_remote_recovery_origin(&tx, &record.origin)?;
        validate_remote_recovery_evidence_for_record(&record, evidence)?;
        let applied = DesktopNamespaceAppliedProof {
            namespace_id: record.namespace_id.clone(),
            host_runtime_id: record.host_runtime_id,
            plan_sha256: record.plan.plan_sha256.clone(),
            prepared_proof_sha256: record.prepared_proof_sha256.clone(),
            proof_sha256: evidence.proof_sha256.clone(),
            observed: evidence.observed,
            source_pin_sha256: evidence.source_pin_sha256.clone(),
            source_parent_pin_sha256: evidence.source_parent_pin_sha256.clone(),
            destination_pin_sha256: evidence.destination_pin_sha256.clone(),
            destination_parent_pin_sha256: evidence.destination_parent_pin_sha256.clone(),
            effect_receipt_sha256: evidence.effect_receipt_sha256.clone(),
        };
        apply_namespace_effect(&tx, &record.plan, &applied, self.limits)?;
        let (state, effect) = match evidence.observed {
            DesktopNamespaceObservedEffect::Applied => {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            }
            // Current source placement proves which namespace bindings to
            // retain, not that a lost mutation never happened and was undone.
            // Restart recovery preserves uncertainty for either observation.
            DesktopNamespaceObservedEffect::NoChange => {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            }
            DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
            | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                return Err(StoreError::Invalid);
            }
        };
        super::complete_external_in_transaction(&tx, &binding, state, effect, None, None)?;
        mark_namespace_completed(
            &tx,
            &record,
            evidence.observed,
            evidence.proof_sha256.as_str(),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Check a canonical workspace root before Host filesystem reads. The
    /// insertion path repeats this check under the write transaction.
    pub fn check_desktop_namespace_root(&self, root: &Path) -> Result<()> {
        ensure_namespace_root_available(&self.db, root)
    }
}

pub(super) fn ensure_namespace_root_available(db: &Connection, root: &Path) -> Result<()> {
    let mut query = db.prepare(
        "SELECT plan_json,plan_sha256 FROM desktop_namespace_intents WHERE state='prepared'",
    )?;
    let records = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (plan_json, plan_sha256) in records {
        let plan = decode_stored_plan(&plan_json, &plan_sha256)?;
        for protected in namespace_scope_roots(plan.effect()) {
            if paths_equal_or_descendant(root, protected) {
                return Err(StoreError::NativeWriterBusy);
            }
        }
    }
    Ok(())
}

pub(super) fn ensure_namespace_project_mutation_allowed(
    db: &Connection,
    root: &Path,
) -> Result<()> {
    super::workspace_removal::ensure_root_not_removing(db, root)?;
    let mut query = db.prepare(
        "SELECT plan_json,plan_sha256 FROM desktop_namespace_intents WHERE state='prepared'",
    )?;
    let plans = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (plan_json, plan_sha256) in plans {
        let plan = decode_stored_plan(&plan_json, &plan_sha256)?;
        if namespace_scope_roots(plan.effect())
            .iter()
            .any(|scope| paths_overlap(root, scope))
        {
            return Err(StoreError::NativeWriterBusy);
        }
    }
    Ok(())
}

pub(super) fn namespace_intent_exists(
    db: &Connection,
    operation_id: ipc::NativeIntentId,
) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM desktop_namespace_intents WHERE native_operation_id=?1)",
        [key(operation_id)],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub(super) fn namespace_intent_prepared(
    db: &Connection,
    operation_id: ipc::NativeIntentId,
) -> Result<bool> {
    db.query_row(
        "SELECT EXISTS(SELECT 1 FROM desktop_namespace_intents WHERE native_operation_id=?1 AND state='prepared')",
        [key(operation_id)],
        |row| row.get(0),
    )
    .map_err(Into::into)
}

pub(super) fn remote_namespace_intent_prepared(
    db: &Connection,
    binding: &OperationBinding,
) -> Result<bool> {
    let namespace_id = remote_namespace_id(
        binding.rights.actor(),
        binding.rights.workspace(),
        binding.rights.operation_id(),
    );
    let Some(record) = read_namespace_record(db, &namespace_id)? else {
        return Ok(false);
    };
    if !record.origin.remote_binding_matches(binding) {
        return Err(StoreError::Fenced);
    }
    Ok(record.state == DesktopNamespaceIntentState::Prepared)
}

pub(super) fn ensure_namespace_mutation_allowed(
    db: &Connection,
    binding: &OperationBinding,
) -> Result<()> {
    let workspace_id = binding.rights.workspace();
    super::workspace_removal::ensure_workspace_available(db, workspace_id)?;
    let harmless_domain_edit = is_domain_only_edit(binding.rights.original_method());
    let mut query = db.prepare(
        "SELECT plan_json,plan_sha256 FROM desktop_namespace_intents WHERE state='prepared'",
    )?;
    let plans = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (plan_json, plan_sha256) in plans {
        let plan = decode_stored_plan(&plan_json, &plan_sha256)?;
        if plan.guarded_workspace_ids().contains(&workspace_id) && !harmless_domain_edit {
            return Err(StoreError::NativeWriterBusy);
        }
    }
    Ok(())
}

pub(super) fn ensure_namespace_share_allowed(
    db: &Connection,
    workspace_id: WorkspaceId,
) -> Result<()> {
    let mut query = db.prepare(
        "SELECT plan_json,plan_sha256 FROM desktop_namespace_intents WHERE state='prepared'",
    )?;
    let plans = query
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (plan_json, plan_sha256) in plans {
        let plan = decode_stored_plan(&plan_json, &plan_sha256)?;
        if plan.guarded_workspace_ids().contains(&workspace_id) {
            return Err(StoreError::NativeWriterBusy);
        }
    }
    Ok(())
}

fn ensure_namespace_pre_effect_ready(db: &Connection, plan: &DesktopNamespacePlan) -> Result<()> {
    for id in plan.guarded_workspace_ids() {
        ensure_no_namespace_blocking_reservations(db, *id, &plan.wire.origin)?;
    }
    if matches!(plan.effect(), DesktopNamespaceEffect::Remove { .. }) {
        ensure_retired_workspace_terminals_stopped(db, plan)?;
        for workspace in plan.workspaces() {
            let id = workspace.workspace_id;
            if project(db, id)?.consent
                && !matches!(
                    plan.wire.origin,
                    DesktopNamespaceOriginWire::RemoteOperation {
                        method: Method::FilesRemove,
                        workspace_id,
                        ..
                    } if workspace_id == id
                )
            {
                return Err(StoreError::Busy);
            }
        }
    }
    if let DesktopNamespaceEffect::Move { old_path, new_path } = plan.effect() {
        let _ = shell_profile_cwd_updates(db, plan.workspaces(), old_path, new_path)?;
    }
    Ok(())
}

fn ensure_retired_workspace_terminals_stopped(
    db: &Connection,
    plan: &DesktopNamespacePlan,
) -> Result<()> {
    // Ancestor roots are guarded against concurrent namespace writers, but
    // are not retired when an ordinary child folder is removed. Their own
    // terminals and sharing policy remain live.
    for workspace in plan.workspaces() {
        if count_for_workspace(
            db,
            "SELECT count(*) FROM terminals WHERE workspace=?1 AND status='Running'",
            workspace.workspace_id,
        )? > 0
        {
            return Err(StoreError::Busy);
        }
    }
    Ok(())
}

fn remote_origin_is_operation(
    origin: &DesktopNamespaceOriginWire,
    workspace_id: WorkspaceId,
    actor: &str,
    operation: &str,
) -> bool {
    matches!(origin, DesktopNamespaceOriginWire::RemoteOperation {
        actor: origin_actor,
        workspace_id: origin_workspace,
        operation_id,
        ..
    } if *origin_workspace == workspace_id
        && key(*origin_actor) == actor
        && key(*operation_id) == operation)
}

fn ensure_no_namespace_blocking_reservations(
    db: &Connection,
    workspace_id: WorkspaceId,
    origin: &DesktopNamespaceOriginWire,
) -> Result<()> {
    let mut query =
        db.prepare("SELECT actor,id FROM operations WHERE workspace=?1 AND reserved>0")?;
    let reservations = query
        .query_map([key(workspace_id)], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (actor, operation_id) in reservations {
        // A reserved domain-only edit still needs its active project to
        // complete or recover. Only the real namespace origin may remain
        // reserved when removal tombstones that project. Atomic tab edits
        // already have reserved=0 and do not enter this query.
        if remote_origin_is_operation(origin, workspace_id, &actor, &operation_id) {
            continue;
        }
        return Err(StoreError::Busy);
    }
    Ok(())
}

fn is_domain_only_edit(method: Method) -> bool {
    matches!(method, Method::TerminalRename | Method::TerminalMove)
}

fn validate_physical_proof(
    wire: &HostNamespacePhysicalProofWire,
    plan: &DesktopNamespacePlan,
) -> Result<()> {
    let (source_path, destination_path) = namespace_effect_paths(plan.effect());
    if wire.version != 1
        || !wire_origin_matches(
            &plan.wire.origin,
            wire.namespace_id.as_deref(),
            wire.operation_id,
            wire.fence_id,
            &plan.namespace_id(),
        )
        || wire.host_runtime_id != plan.host_runtime_id()
        || wire.plan_sha256 != plan.plan_sha256
        || wire.source_path != path_text(source_path)?
        || wire.source_parent_path != path_text(source_path.parent().ok_or(StoreError::Invalid)?)?
        || wire.destination_path.as_deref() != destination_path.map(path_text).transpose()?
        || !valid_pin(&wire.source_identity_pin)
        || !valid_pin(&wire.source_parent_identity_pin)
    {
        return Err(StoreError::Invalid);
    }
    match plan.effect() {
        DesktopNamespaceEffect::Move { new_path, .. } => {
            if wire.destination_parent_path.as_deref()
                != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire
                    .destination_parent_identity_pin
                    .as_deref()
                    .is_none_or(|pin| !valid_pin(pin))
                || wire.destination_absent != Some(true)
                || (is_case_only_rename(source_path, new_path)
                    && wire
                        .destination_parent_identity_pin
                        .as_deref()
                        .is_none_or(|pin| {
                            sha256(pin.as_bytes())
                                != sha256(wire.source_parent_identity_pin.as_bytes())
                        }))
            {
                return Err(StoreError::Invalid);
            }
        }
        DesktopNamespaceEffect::Remove { .. } => {
            if wire.destination_parent_path.is_some()
                || wire.destination_parent_identity_pin.is_some()
                || wire.destination_absent.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
    }
    Ok(())
}

fn validate_applied_proof(
    wire: &HostNamespaceAppliedProofWire,
    plan: &DesktopNamespacePlan,
    prepared: &DesktopNamespacePhysicalProof,
) -> Result<()> {
    let (source_path, destination_path) = namespace_effect_paths(plan.effect());
    if wire.version != 1
        || !wire_origin_matches(
            &plan.wire.origin,
            wire.namespace_id.as_deref(),
            wire.operation_id,
            wire.fence_id,
            &plan.namespace_id(),
        )
        || wire.host_runtime_id != plan.host_runtime_id()
        || wire.plan_sha256 != plan.plan_sha256
        || wire.prepared_proof_sha256 != prepared.proof_sha256
        || wire.source_path != path_text(source_path)?
        || wire.source_parent_path != path_text(source_path.parent().ok_or(StoreError::Invalid)?)?
        || wire.destination_path.as_deref() != destination_path.map(path_text).transpose()?
        || !valid_pin(&wire.source_identity_pin)
        || !valid_pin(&wire.source_parent_identity_pin)
        || sha256(wire.source_identity_pin.as_bytes()) != prepared.source_pin_sha256
        || sha256(wire.source_parent_identity_pin.as_bytes()) != prepared.source_parent_pin_sha256
    {
        return Err(StoreError::Invalid);
    }
    match (plan.effect(), wire.observed) {
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::Applied) => {
            if wire.source_absent != Some(true)
                || wire.destination_absent != Some(false)
                || wire.destination_identity_pin.as_deref().is_none_or(|pin| {
                    !valid_pin(pin) || sha256(pin.as_bytes()) != prepared.source_pin_sha256
                })
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire
                    .destination_parent_identity_pin
                    .as_deref()
                    .is_none_or(|pin| {
                        !valid_pin(pin)
                            || Some(sha256(pin.as_bytes()))
                                != prepared.destination_parent_pin_sha256
                    })
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent != Some(false)
                || wire.destination_absent != Some(true)
                || wire.destination_identity_pin.is_some()
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire
                    .destination_parent_identity_pin
                    .as_deref()
                    .is_none_or(|pin| {
                        !valid_pin(pin)
                            || Some(sha256(pin.as_bytes()))
                                != prepared.destination_parent_pin_sha256
                    })
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::Applied) => {
            if wire.source_absent != Some(true)
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_pin.is_some()
                || wire.destination_parent_identity_pin.is_some()
                || wire.destination_absent.is_some()
                || !wire
                    .effect_receipt_sha256
                    .as_deref()
                    .is_some_and(valid_sha256)
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent != Some(false)
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_pin.is_some()
                || wire.destination_parent_identity_pin.is_some()
                || wire.destination_absent.is_some()
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (
            DesktopNamespaceEffect::Remove { .. },
            HostNamespaceObservedEffect::RetiredAfterPartialRemove,
        ) => {
            if !matches!(
                plan.wire.origin,
                DesktopNamespaceOriginWire::NativeEditor { .. }
            ) || wire.source_absent.is_some()
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_pin.is_some()
                || wire.destination_parent_identity_pin.is_some()
                || wire.destination_absent.is_some()
                || !wire
                    .effect_receipt_sha256
                    .as_deref()
                    .is_some_and(valid_sha256)
            {
                return Err(StoreError::Invalid);
            }
        }
        _ => return Err(StoreError::Invalid),
    }
    Ok(())
}

fn validate_recovery_proof(
    wire: &HostNamespaceRecoveryProofWire,
    record: &DesktopNamespaceIntentRecord,
    current_runtime: RuntimeId,
) -> Result<()> {
    let (source_path, destination_path) = namespace_effect_paths(record.plan.effect());
    if wire.version != 1
        || !wire_origin_matches(
            &record.plan.wire.origin,
            wire.namespace_id.as_deref(),
            wire.operation_id,
            wire.fence_id,
            &record.plan.namespace_id(),
        )
        || wire.old_runtime_id != record.host_runtime_id
        || wire.current_runtime_id != current_runtime
        || wire.old_runtime_id == wire.current_runtime_id
        || wire.plan_sha256 != record.plan.plan_sha256
        || wire.prepared_proof_sha256 != record.prepared_proof_sha256
        || wire.source_path != path_text(source_path)?
        || wire.source_parent_path != path_text(source_path.parent().ok_or(StoreError::Invalid)?)?
        || wire.destination_path.as_deref() != destination_path.map(path_text).transpose()?
        || !valid_sha256(&wire.source_identity_sha256)
        || wire.source_identity_sha256 != record.source_pin_sha256
        || !valid_sha256(&wire.source_parent_identity_sha256)
        || wire.source_parent_identity_sha256 != record.source_parent_pin_sha256
        || !valid_sha256(&wire.owner_lock_receipt_sha256)
        || !valid_sha256(&wire.worker_retirement_receipt_sha256)
    {
        return Err(StoreError::Invalid);
    }
    match (record.plan.effect(), wire.observed) {
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::Applied) => {
            if wire.source_absent != Some(true)
                || wire.destination_absent != Some(false)
                || wire.destination_identity_sha256.as_deref()
                    != Some(record.source_pin_sha256.as_str())
                || !wire
                    .destination_parent_identity_sha256
                    .as_deref()
                    .is_some_and(|digest| {
                        valid_sha256(digest)
                            && Some(digest) == record.destination_parent_pin_sha256.as_deref()
                    })
                || (is_case_only_rename(source_path, new_path)
                    && wire.destination_parent_identity_sha256.as_deref()
                        != Some(record.source_parent_pin_sha256.as_str()))
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent != Some(false)
                || wire.destination_absent != Some(true)
                || wire.destination_identity_sha256.is_some()
                || !wire
                    .destination_parent_identity_sha256
                    .as_deref()
                    .is_some_and(|digest| {
                        valid_sha256(digest)
                            && Some(digest) == record.destination_parent_pin_sha256.as_deref()
                    })
                || (is_case_only_rename(source_path, new_path)
                    && wire.destination_parent_identity_sha256.as_deref()
                        != Some(record.source_parent_pin_sha256.as_str()))
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::Applied) => {
            if wire.source_absent != Some(true)
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.is_some()
                || wire.destination_absent.is_some()
                || !wire
                    .effect_receipt_sha256
                    .as_deref()
                    .is_some_and(valid_sha256)
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent != Some(false)
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.is_some()
                || wire.destination_absent.is_some()
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (
            DesktopNamespaceEffect::Remove { .. },
            HostNamespaceObservedEffect::RetiredAfterPartialRemove,
        ) => {
            let _ = wire;
            return Err(StoreError::Invalid);
        }
        (
            DesktopNamespaceEffect::Remove { .. },
            HostNamespaceObservedEffect::RetiredRequestedRecovery,
        ) => {
            if !matches!(
                record.plan.wire.origin,
                DesktopNamespaceOriginWire::NativeEditor { .. }
            ) || wire.source_absent.is_some()
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.is_some()
                || wire.destination_absent.is_some()
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        _ => return Err(StoreError::Invalid),
    }
    Ok(())
}

fn validate_remote_recovery_proof(
    wire: &HostRemoteNamespaceRecoveryProofWire,
    record: &RemoteDesktopNamespaceIntentRecord,
    current_runtime: RuntimeId,
) -> Result<()> {
    let (source_path, destination_path) = namespace_effect_paths(record.plan.effect());
    if wire.version != 1
        || wire.namespace_id != record.namespace_id
        || wire.actor != record.actor
        || wire.workspace_id != record.workspace_id
        || wire.operation_id != record.operation_id
        || wire.method != record.method
        || wire.old_runtime_id != record.host_runtime_id
        || wire.current_runtime_id != current_runtime
        || wire.old_runtime_id == wire.current_runtime_id
        || wire.plan_sha256 != record.plan.inner.plan_sha256
        || wire.prepared_proof_sha256 != record.prepared_proof_sha256
        || wire.source_path != path_text(source_path)?
        || wire.source_parent_path != path_text(source_path.parent().ok_or(StoreError::Invalid)?)?
        || wire.destination_path.as_deref() != destination_path.map(path_text).transpose()?
        || !valid_sha256(&wire.source_identity_sha256)
        || wire.source_identity_sha256 != record.source_pin_sha256
        || !valid_sha256(&wire.source_parent_identity_sha256)
        || wire.source_parent_identity_sha256 != record.source_parent_pin_sha256
        || !valid_sha256(&wire.owner_lock_receipt_sha256)
        || !valid_sha256(&wire.operation_retirement_receipt_sha256)
    {
        return Err(StoreError::Invalid);
    }
    match (record.plan.effect(), wire.observed) {
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::Applied) => {
            if !wire.source_absent
                || wire.destination_absent != Some(false)
                || wire.destination_identity_sha256.as_deref()
                    != Some(record.source_pin_sha256.as_str())
                || wire.destination_parent_identity_sha256.as_deref()
                    != record.destination_parent_pin_sha256.as_deref()
                || (is_case_only_rename(source_path, new_path)
                    && wire.destination_parent_identity_sha256.as_deref()
                        != Some(record.source_parent_pin_sha256.as_str()))
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Move { new_path, .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent
                || wire.destination_absent != Some(true)
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.as_deref()
                    != record.destination_parent_pin_sha256.as_deref()
                || (is_case_only_rename(source_path, new_path)
                    && wire.destination_parent_identity_sha256.as_deref()
                        != Some(record.source_parent_pin_sha256.as_str()))
                || wire.destination_parent_path.as_deref()
                    != Some(path_text(new_path.parent().ok_or(StoreError::Invalid)?)?)
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::Applied) => {
            if !wire.source_absent
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.is_some()
                || wire.destination_absent.is_some()
                || !wire
                    .effect_receipt_sha256
                    .as_deref()
                    .is_some_and(valid_sha256)
            {
                return Err(StoreError::Invalid);
            }
        }
        (DesktopNamespaceEffect::Remove { .. }, HostNamespaceObservedEffect::NoChange) => {
            if wire.source_absent
                || wire.destination_path.is_some()
                || wire.destination_parent_path.is_some()
                || wire.destination_identity_sha256.is_some()
                || wire.destination_parent_identity_sha256.is_some()
                || wire.destination_absent.is_some()
                || wire.effect_receipt_sha256.is_some()
            {
                return Err(StoreError::Invalid);
            }
        }
        (
            DesktopNamespaceEffect::Remove { .. },
            HostNamespaceObservedEffect::RetiredAfterPartialRemove
            | HostNamespaceObservedEffect::RetiredRequestedRecovery,
        ) => return Err(StoreError::Invalid),
        _ => return Err(StoreError::Invalid),
    }
    Ok(())
}

fn validate_remote_recovery_origin(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
) -> Result<()> {
    validate_remote_origin_row(db, origin, false)
}

fn validate_remote_recovery_evidence_for_record(
    record: &NamespaceIntentRecord,
    evidence: &RemoteDesktopNamespaceRecoveryEvidence,
) -> Result<()> {
    let DesktopNamespaceOriginWire::RemoteOperation {
        actor,
        workspace_id,
        operation_id,
        method,
        ..
    } = &record.origin
    else {
        return Err(StoreError::Fenced);
    };
    if evidence.namespace_id != record.namespace_id
        || evidence.actor != *actor
        || evidence.workspace_id != *workspace_id
        || evidence.operation_id != *operation_id
        || evidence.method != *method
        || evidence.old_runtime_id != record.host_runtime_id
        || evidence.plan_sha256 != record.plan.plan_sha256
        || evidence.prepared_proof_sha256 != record.prepared_proof_sha256
        || evidence.source_pin_sha256 != record.source_pin_sha256
        || evidence.source_parent_pin_sha256 != record.source_parent_pin_sha256
        || evidence.destination_parent_pin_sha256 != record.destination_parent_pin_sha256
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn operation_binding_from_origin(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
) -> Result<OperationBinding> {
    let DesktopNamespaceOriginWire::RemoteOperation {
        actor,
        workspace_id,
        operation_id,
        parameter_hash,
        ..
    } = origin
    else {
        return Err(StoreError::Invalid);
    };
    let wire: String = db.query_row(
        "SELECT receipt FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
        params![key(*actor), key(*workspace_id), key(*operation_id)],
        |row| row.get(0),
    )?;
    let receipt: OperationReceipt = decode(&wire)?;
    let parameter_hash = OperationParameterHash::try_from(parameter_hash.clone())
        .map_err(|_| StoreError::Storage)?;
    let binding = OperationBinding {
        rights: receipt.stored_rights(),
        parameter_hash,
    };
    if !origin.remote_binding_matches(&binding) {
        return Err(StoreError::Fenced);
    }
    Ok(binding)
}

fn validate_applied_evidence_for_record(
    record: &NamespaceIntentRecord,
    evidence: &DesktopNamespaceAppliedProof,
) -> Result<()> {
    if evidence.namespace_id != record.namespace_id
        || evidence.host_runtime_id != record.host_runtime_id
        || evidence.plan_sha256 != record.plan.plan_sha256
        || evidence.prepared_proof_sha256 != record.prepared_proof_sha256
        || evidence.source_pin_sha256 != record.source_pin_sha256
        || evidence.source_parent_pin_sha256 != record.source_parent_pin_sha256
        || evidence.destination_parent_pin_sha256 != record.destination_parent_pin_sha256
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn validate_plan(plan: &DesktopNamespacePlan) -> Result<()> {
    let encoded = encode_plan(plan)?;
    if encoded.len() > MAX_DESKTOP_NAMESPACE_PLAN_BYTES
        || sha256(encoded.as_bytes()) != plan.plan_sha256
    {
        return Err(StoreError::Invalid);
    }
    validate_effect(&plan.wire.effect)?;
    if plan.wire.version != 1
        || !valid_sha256(plan.wire.origin.request_hash())
        || plan.wire.workspaces.len() > MAX_DESKTOP_NAMESPACE_WORKSPACES
        || plan.wire.guarded_workspace_ids.len() > MAX_DESKTOP_NAMESPACE_WORKSPACES
    {
        return Err(StoreError::Invalid);
    }
    match &plan.wire.origin {
        DesktopNamespaceOriginWire::NativeEditor { .. } => {}
        DesktopNamespaceOriginWire::RemoteOperation {
            method,
            workspace_fence,
            ..
        } if matches!(method, Method::FilesRename | Method::FilesRemove)
            && *workspace_fence > 0 => {}
        _ => return Err(StoreError::Invalid),
    }
    let mut previous = None;
    for workspace in &plan.wire.workspaces {
        validate_namespace_path(&workspace.old_path)?;
        if previous.is_some_and(|id| id >= workspace.workspace_id) {
            return Err(StoreError::Invalid);
        }
        previous = Some(workspace.workspace_id);
        match (&plan.wire.effect, &workspace.new_path) {
            (
                DesktopNamespaceEffect::Move {
                    old_path,
                    new_path: destination,
                },
                Some(new_path),
            ) => {
                validate_namespace_path(new_path)?;
                if !paths_equal_or_descendant(&workspace.old_path, old_path)
                    || remap_namespace_path(&workspace.old_path, old_path, destination)?
                        != *new_path
                {
                    return Err(StoreError::Invalid);
                }
            }
            (DesktopNamespaceEffect::Remove { old_path }, None) => {
                if !paths_equal_or_descendant(&workspace.old_path, old_path) {
                    return Err(StoreError::Invalid);
                }
            }
            _ => return Err(StoreError::Invalid),
        }
    }
    let mut previous_guard = None;
    for workspace_id in &plan.wire.guarded_workspace_ids {
        if previous_guard.is_some_and(|id| id >= *workspace_id) {
            return Err(StoreError::Invalid);
        }
        previous_guard = Some(*workspace_id);
    }
    if plan.wire.workspaces.iter().any(|workspace| {
        !plan
            .wire
            .guarded_workspace_ids
            .contains(&workspace.workspace_id)
    }) {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn wire_origin_matches(
    origin: &DesktopNamespaceOriginWire,
    namespace_id: Option<&str>,
    operation_id: Option<ipc::NativeIntentId>,
    fence_id: Option<ipc::NativeIntentId>,
    expected_namespace_id: &str,
) -> bool {
    match origin {
        DesktopNamespaceOriginWire::NativeEditor {
            operation_id: expected_operation,
            fence_id: expected_fence,
            ..
        } => {
            namespace_id.is_none_or(|value| value == expected_namespace_id)
                && operation_id == Some(*expected_operation)
                && fence_id == Some(*expected_fence)
        }
        DesktopNamespaceOriginWire::RemoteOperation { .. } => {
            namespace_id == Some(expected_namespace_id)
                && operation_id.is_none()
                && fence_id.is_none()
        }
    }
}

fn encode_plan(plan: &DesktopNamespacePlan) -> Result<String> {
    json(&plan.wire)
}

fn decode_stored_plan(plan_json: &str, expected_hash: &str) -> Result<DesktopNamespacePlan> {
    if plan_json.is_empty()
        || plan_json.len() > MAX_DESKTOP_NAMESPACE_PLAN_BYTES
        || !valid_sha256(expected_hash)
        || sha256(plan_json.as_bytes()) != expected_hash
    {
        return Err(StoreError::Storage);
    }
    let wire: DesktopNamespacePlanWire = decode(plan_json)?;
    let plan = DesktopNamespacePlan {
        wire,
        plan_sha256: expected_hash.to_owned(),
    };
    validate_plan(&plan).map_err(|_| StoreError::Storage)?;
    Ok(plan)
}

fn build_namespace_plan(
    db: &Connection,
    origin: DesktopNamespaceOriginWire,
    effect: DesktopNamespaceEffect,
) -> Result<DesktopNamespacePlan> {
    validate_effect(&effect)?;
    ensure_namespace_effect_available(db, &effect)?;
    match &origin {
        DesktopNamespaceOriginWire::NativeEditor { .. } => {
            validate_origin_native_row(db, &origin, true)?;
        }
        DesktopNamespaceOriginWire::RemoteOperation { .. } => {
            validate_remote_origin_row(db, &origin, true)?;
        }
    }

    let all_projects = projects(db)?;
    let (workspaces, guarded_workspace_ids) =
        namespace_bindings_for_effect(&all_projects, &effect)?;
    let wire = DesktopNamespacePlanWire {
        version: 1,
        origin,
        effect,
        workspaces,
        guarded_workspace_ids,
    };
    let encoded = json(&wire)?;
    if encoded.len() > MAX_DESKTOP_NAMESPACE_PLAN_BYTES {
        return Err(StoreError::ResourceExhausted);
    }
    Ok(DesktopNamespacePlan {
        wire,
        plan_sha256: sha256(encoded.as_bytes()),
    })
}

/// Reject namespace effects that overlap any incomplete removal root. These
/// roots are intentionally absent from `projects()`, so this independent
/// query must run both for previews and while rebuilding a plan under the
/// namespace preparation transaction.
fn ensure_namespace_effect_available(
    db: &Connection,
    effect: &DesktopNamespaceEffect,
) -> Result<()> {
    let scope_roots = namespace_scope_roots(effect);
    let mut query = db.prepare(
        "SELECT p.root FROM projects p
         JOIN workspace_removals r ON r.workspace=p.workspace
         WHERE r.state IN('stopping','uncertain')",
    )?;
    let roots = query
        .query_map([], |row| row.get::<_, String>(0))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if roots.iter().any(|root| {
        let root = Path::new(root);
        scope_roots.iter().any(|scope| paths_overlap(root, scope))
    }) {
        Err(StoreError::Busy)
    } else {
        Ok(())
    }
}

/// Shared effect validation and path-overlap computation for full plans and
/// read-only guard previews. This keeps previewed actor locks identical to the
/// guards later sealed into a namespace plan.
fn namespace_bindings_for_effect(
    all_projects: &[ProjectRecord],
    effect: &DesktopNamespaceEffect,
) -> Result<(Vec<DesktopNamespaceWorkspace>, Vec<WorkspaceId>)> {
    validate_effect(effect)?;
    let (old_path, new_path) = namespace_effect_paths(effect);
    let scope_roots = namespace_scope_roots(effect);
    let mut workspaces = Vec::new();
    let mut guarded_workspace_ids = Vec::new();
    for project in all_projects {
        if scope_roots
            .iter()
            .any(|scope| paths_overlap(&project.local_root, scope))
        {
            guarded_workspace_ids.push(project.state.context.workspace_id);
        }
        if paths_equal_or_descendant(&project.local_root, old_path) {
            let mapped = new_path
                .map(|new| remap_namespace_path(&project.local_root, old_path, new))
                .transpose()?;
            workspaces.push(DesktopNamespaceWorkspace {
                workspace_id: project.state.context.workspace_id,
                old_path: project.local_root.clone(),
                new_path: mapped,
            });
        }
    }
    workspaces.sort_by_key(|workspace| workspace.workspace_id);
    if workspaces.len() > MAX_DESKTOP_NAMESPACE_WORKSPACES {
        return Err(StoreError::ResourceExhausted);
    }
    guarded_workspace_ids.sort();
    guarded_workspace_ids.dedup();
    if guarded_workspace_ids.len() > MAX_DESKTOP_NAMESPACE_WORKSPACES {
        return Err(StoreError::ResourceExhausted);
    }
    if let Some(new_root) = new_path
        && all_projects.iter().any(|project| {
            paths_equal_or_descendant(&project.local_root, new_root)
                && !paths_equal_or_descendant(&project.local_root, old_path)
        })
    {
        return Err(StoreError::Busy);
    }
    Ok((workspaces, guarded_workspace_ids))
}

fn native_origin(
    db: &Connection,
    operation_id: ipc::NativeIntentId,
    runtime_id: RuntimeId,
) -> Result<DesktopNamespaceOriginWire> {
    let (fence_text, host_runtime_text, request_hash): (String, String, String) = db
        .query_row(
            "SELECT fence_id,host_runtime_id,request_hash FROM native_editor_jobs WHERE operation_id=?1",
            [key(operation_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    let origin = DesktopNamespaceOriginWire::NativeEditor {
        operation_id,
        fence_id: ipc::NativeIntentId::try_from(fence_text).map_err(|_| StoreError::Storage)?,
        host_runtime_id: RuntimeId::try_from(host_runtime_text).map_err(|_| StoreError::Storage)?,
        request_hash,
    };
    validate_origin_native_row(db, &origin, true)?;
    if origin.host_runtime_id() != runtime_id {
        return Err(StoreError::Fenced);
    }
    Ok(origin)
}

fn remote_origin_from_permit(
    permit: &ExternalPermit,
    runtime_id: RuntimeId,
) -> Result<DesktopNamespaceOriginWire> {
    let binding = &permit.binding;
    if permit.runtime != runtime_id
        || !matches!(
            binding.rights.original_method(),
            Method::FilesRename | Method::FilesRemove
        )
    {
        return Err(StoreError::Fenced);
    }
    Ok(DesktopNamespaceOriginWire::RemoteOperation {
        actor: binding.rights.actor(),
        workspace_id: binding.rights.workspace(),
        operation_id: binding.rights.operation_id(),
        method: binding.rights.original_method(),
        parameter_hash: String::from(binding.parameter_hash.clone()),
        workspace_fence: permit.fence,
        host_runtime_id: permit.runtime,
    })
}

fn validate_origin_native_row(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
    require_active: bool,
) -> Result<()> {
    let DesktopNamespaceOriginWire::NativeEditor {
        operation_id,
        fence_id,
        host_runtime_id,
        request_hash,
    } = origin
    else {
        return Err(StoreError::Invalid);
    };
    let (state, stored_fence, stored_runtime, stored_hash): (String, String, String, String) = db
        .query_row(
            "SELECT state,fence_id,host_runtime_id,request_hash FROM native_editor_jobs WHERE operation_id=?1",
            [key(*operation_id)],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?
        .ok_or(StoreError::NotFound)?;
    if state != "running"
        || stored_fence != key(*fence_id)
        || stored_runtime != key(*host_runtime_id)
        || stored_hash != *request_hash
        || !valid_sha256(request_hash)
    {
        return Err(StoreError::Fenced);
    }
    let fence_state: String = db.query_row(
        "SELECT state FROM native_intents WHERE id=?1",
        [key(*fence_id)],
        |row| row.get(0),
    )?;
    if (require_active && fence_state != "active")
        || (!require_active && !matches!(fence_state.as_str(), "active" | "quarantine"))
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn validate_remote_origin_row(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
    require_current_fence: bool,
) -> Result<()> {
    let DesktopNamespaceOriginWire::RemoteOperation {
        actor,
        workspace_id,
        operation_id,
        method,
        parameter_hash,
        workspace_fence,
        ..
    } = origin
    else {
        return Err(StoreError::Invalid);
    };
    if !matches!(method, Method::FilesRename | Method::FilesRemove) || !valid_sha256(parameter_hash)
    {
        return Err(StoreError::Invalid);
    }
    let (stored_method, hash, receipt_wire, fence, reserved):
        (String, String, String, String, i64) = db.query_row(
        "SELECT method,hash,receipt,fence,reserved FROM operations WHERE actor=?1 AND workspace=?2 AND id=?3",
        params![key(*actor), key(*workspace_id), key(*operation_id)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    ).optional()?.ok_or(StoreError::NotFound)?;
    let receipt: OperationReceipt = decode(&receipt_wire)?;
    let project = project(db, *workspace_id)?;
    if stored_method != method.as_str()
        || hash != json(parameter_hash)?
        || fence != workspace_fence.to_string()
        || reserved != 1
        || receipt.state() != OperationState::Running
        || (require_current_fence && project.fence != *workspace_fence)
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn validate_running_remote_binding(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
    permit: &ExternalPermit,
    runtime_id: RuntimeId,
) -> Result<()> {
    if !remote_permit_context_matches(origin, permit, runtime_id) {
        return Err(StoreError::Fenced);
    }
    let DesktopNamespaceOriginWire::RemoteOperation {
        workspace_fence,
        host_runtime_id,
        ..
    } = origin
    else {
        return Err(StoreError::Invalid);
    };
    if permit.fence != *workspace_fence || permit.runtime != *host_runtime_id {
        return Err(StoreError::Fenced);
    }
    // Reuse normal idempotency/rights validation in addition to the exact
    // Running receipt and reserved external permit checks.
    if existing(db, &permit.binding)?.is_none() {
        return Err(StoreError::NotFound);
    }
    validate_remote_origin_row(db, origin, true)
}

fn remote_permit_context_matches(
    origin: &DesktopNamespaceOriginWire,
    permit: &ExternalPermit,
    runtime_id: RuntimeId,
) -> bool {
    if permit.runtime != runtime_id || !origin.remote_binding_matches(&permit.binding) {
        return false;
    }
    matches!(origin, DesktopNamespaceOriginWire::RemoteOperation {
        workspace_fence, host_runtime_id, ..
    } if permit.fence == *workspace_fence && permit.runtime == *host_runtime_id)
}

fn validate_running_remote_binding_after_effect(
    db: &Connection,
    origin: &DesktopNamespaceOriginWire,
    permit: &ExternalPermit,
    runtime_id: RuntimeId,
) -> Result<()> {
    if !remote_permit_context_matches(origin, permit, runtime_id) {
        return Err(StoreError::Fenced);
    }
    if existing(db, &permit.binding)?.is_none() {
        return Err(StoreError::NotFound);
    }
    validate_remote_origin_row(db, origin, false)
}

fn native_namespace_id(operation_id: ipc::NativeIntentId) -> String {
    format!("native:{}", sha256(key(operation_id).as_bytes()))
}

fn remote_namespace_id(
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    operation_id: OperationId,
) -> String {
    let bytes = format!("{}:{}:{}", key(actor), key(workspace_id), key(operation_id));
    format!("remote:{}", sha256(bytes.as_bytes()))
}

struct NamespaceOriginColumns {
    kind: &'static str,
    native_operation_id: Option<String>,
    native_fence_id: Option<String>,
    remote_actor: Option<String>,
    remote_workspace: Option<String>,
    remote_operation_id: Option<String>,
    remote_method: Option<String>,
    remote_parameter_hash: Option<String>,
    remote_workspace_fence: Option<String>,
}

fn namespace_origin_columns(origin: &DesktopNamespaceOriginWire) -> Result<NamespaceOriginColumns> {
    Ok(match origin {
        DesktopNamespaceOriginWire::NativeEditor {
            operation_id,
            fence_id,
            ..
        } => NamespaceOriginColumns {
            kind: "nativeEditor",
            native_operation_id: Some(key(*operation_id)),
            native_fence_id: Some(key(*fence_id)),
            remote_actor: None,
            remote_workspace: None,
            remote_operation_id: None,
            remote_method: None,
            remote_parameter_hash: None,
            remote_workspace_fence: None,
        },
        DesktopNamespaceOriginWire::RemoteOperation {
            actor,
            workspace_id,
            operation_id,
            method,
            parameter_hash,
            workspace_fence,
            ..
        } => NamespaceOriginColumns {
            kind: "remoteOperation",
            native_operation_id: None,
            native_fence_id: None,
            remote_actor: Some(key(*actor)),
            remote_workspace: Some(key(*workspace_id)),
            remote_operation_id: Some(key(*operation_id)),
            remote_method: Some(method.as_str().to_owned()),
            remote_parameter_hash: Some(parameter_hash.clone()),
            remote_workspace_fence: Some(workspace_fence.to_string()),
        },
    })
}

fn validate_effect(effect: &DesktopNamespaceEffect) -> Result<()> {
    match effect {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            validate_namespace_path(old_path)?;
            validate_namespace_path(new_path)?;
            let case_only = is_case_only_rename(old_path, new_path);
            if (!case_only
                && (path_components_equal(old_path, new_path)
                    || paths_equal_or_descendant(old_path, new_path)
                    || paths_equal_or_descendant(new_path, old_path)))
                || old_path.parent().is_none()
                || new_path.parent().is_none()
            {
                return Err(StoreError::Invalid);
            }
        }
        DesktopNamespaceEffect::Remove { old_path } => {
            validate_namespace_path(old_path)?;
            if old_path.parent().is_none() {
                return Err(StoreError::Invalid);
            }
        }
    }
    Ok(())
}

fn is_case_only_rename(old_path: &Path, new_path: &Path) -> bool {
    let (Some(old_parent), Some(new_parent), Some(old_name), Some(new_name)) = (
        old_path.parent(),
        new_path.parent(),
        old_path.file_name(),
        new_path.file_name(),
    ) else {
        return false;
    };
    old_path.as_os_str() != new_path.as_os_str()
        && path_components_ascii_case_equal(old_path, new_path)
        && path_components_ascii_case_equal(old_parent, new_parent)
        && old_name != new_name
        && old_name
            .to_string_lossy()
            .eq_ignore_ascii_case(&new_name.to_string_lossy())
}

fn path_components_ascii_case_equal(left: &Path, right: &Path) -> bool {
    let left: Vec<_> = left.components().collect();
    let right: Vec<_> = right.components().collect();
    left.len() == right.len()
        && left
            .iter()
            .zip(&right)
            .all(|(left, right)| match (left, right) {
                (Component::Prefix(left), Component::Prefix(right)) => left
                    .as_os_str()
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&right.as_os_str().to_string_lossy()),
                (Component::RootDir, Component::RootDir)
                | (Component::CurDir, Component::CurDir) => true,
                (Component::Normal(left), Component::Normal(right)) => left
                    .to_string_lossy()
                    .eq_ignore_ascii_case(&right.to_string_lossy()),
                _ => false,
            })
}

fn validate_namespace_path(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.to_str().is_none()
        || path.as_os_str().to_string_lossy().len() > MAX_NAMESPACE_PATH_BYTES
        || path.as_os_str().to_string_lossy().contains('\0')
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(StoreError::Invalid);
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str().ok_or(StoreError::Invalid)
}

fn namespace_effect_paths(effect: &DesktopNamespaceEffect) -> (&Path, Option<&Path>) {
    match effect {
        DesktopNamespaceEffect::Move { old_path, new_path } => (old_path, Some(new_path)),
        DesktopNamespaceEffect::Remove { old_path } => (old_path, None),
    }
}

fn namespace_scope_roots(effect: &DesktopNamespaceEffect) -> Vec<&Path> {
    match effect {
        DesktopNamespaceEffect::Move { old_path, new_path } => vec![old_path, new_path],
        DesktopNamespaceEffect::Remove { old_path } => vec![old_path],
    }
}

fn paths_equal_or_descendant(path: &Path, root: &Path) -> bool {
    path_component_prefix(path, root)
}

pub(super) fn paths_overlap(left: &Path, right: &Path) -> bool {
    paths_equal_or_descendant(left, right) || paths_equal_or_descendant(right, left)
}

fn path_components_equal(left: &Path, right: &Path) -> bool {
    let left: Vec<_> = left.components().collect();
    let right: Vec<_> = right.components().collect();
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| components_equal(*left, *right))
}

fn path_component_prefix(path: &Path, root: &Path) -> bool {
    let path: Vec<_> = path.components().collect();
    let root: Vec<_> = root.components().collect();
    path.len() >= root.len()
        && path
            .iter()
            .zip(root.iter())
            .all(|(path, root)| components_equal(*path, *root))
}

fn components_equal(left: Component<'_>, right: Component<'_>) -> bool {
    match (left, right) {
        (Component::Prefix(left), Component::Prefix(right)) => {
            component_os_equal(left.as_os_str(), right.as_os_str())
        }
        (Component::RootDir, Component::RootDir)
        | (Component::CurDir, Component::CurDir)
        | (Component::ParentDir, Component::ParentDir) => true,
        (Component::Normal(left), Component::Normal(right)) => component_os_equal(left, right),
        _ => false,
    }
}

#[cfg(windows)]
fn component_os_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left.to_string_lossy()
        .eq_ignore_ascii_case(&right.to_string_lossy())
}

#[cfg(not(windows))]
fn component_os_equal(left: &std::ffi::OsStr, right: &std::ffi::OsStr) -> bool {
    left == right
}

fn remap_namespace_path(path: &Path, old_root: &Path, new_root: &Path) -> Result<PathBuf> {
    let path_components: Vec<_> = path.components().collect();
    let root_components: Vec<_> = old_root.components().collect();
    if path_components.len() < root_components.len()
        || !path_components
            .iter()
            .zip(root_components.iter())
            .all(|(path, root)| components_equal(*path, *root))
    {
        return Err(StoreError::Fenced);
    }
    let mut mapped = new_root.to_path_buf();
    for component in path_components.into_iter().skip(root_components.len()) {
        match component {
            Component::Normal(name) => mapped.push(name),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(StoreError::Invalid);
            }
        }
    }
    Ok(mapped)
}

fn relative_namespace_path(path: &Path, root: &Path) -> Result<PathBuf> {
    validate_namespace_path(path)?;
    validate_namespace_path(root)?;
    let path_components: Vec<_> = path.components().collect();
    let root_components: Vec<_> = root.components().collect();
    if path_components.len() < root_components.len()
        || !path_components
            .iter()
            .zip(root_components.iter())
            .all(|(path, root)| components_equal(*path, *root))
    {
        return Err(StoreError::Fenced);
    }
    let mut relative = PathBuf::new();
    for component in path_components.into_iter().skip(root_components.len()) {
        match component {
            Component::Normal(name) => relative.push(name),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) | Component::ParentDir => {
                return Err(StoreError::Invalid);
            }
        }
    }
    super::validate_shell_profile_cwd_override(&relative)?;
    Ok(relative)
}

fn ensure_namespace_plan_is_unconflicted(
    db: &Connection,
    candidate: &DesktopNamespacePlan,
) -> Result<()> {
    let mut query = db.prepare(
        "SELECT namespace_id,plan_json,plan_sha256 FROM desktop_namespace_intents WHERE state='prepared'",
    )?;
    let rows = query
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    for (namespace_id, plan_json, plan_sha) in rows {
        if namespace_id == candidate.namespace_id() {
            continue;
        }
        let existing = decode_stored_plan(&plan_json, &plan_sha)?;
        if namespace_scope_roots(candidate.effect())
            .iter()
            .any(|left| {
                namespace_scope_roots(existing.effect())
                    .iter()
                    .any(|right| paths_overlap(left, right))
            })
        {
            return Err(StoreError::NativeWriterBusy);
        }
    }
    Ok(())
}

fn validate_running_editor_binding(
    db: &Connection,
    plan: &DesktopNamespacePlan,
    require_active: bool,
) -> Result<()> {
    validate_origin_native_row(db, &plan.wire.origin, require_active)
}

fn read_namespace_record(
    db: &Connection,
    namespace_id: &str,
) -> Result<Option<NamespaceIntentRecord>> {
    type Row = (
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        Option<String>,
        String,
        String,
        String,
        String,
        String,
        String,
        Option<String>,
        String,
        Option<String>,
        String,
        String,
        String,
    );
    let row: Option<Row> = db
        .query_row(
            "SELECT origin,native_operation_id,native_fence_id,remote_actor,remote_workspace,
                    remote_operation_id,remote_method,remote_parameter_hash,remote_workspace_fence,
                    host_runtime_id,plan_json,plan_sha256,prepared_proof_sha256,
                    source_pin_sha256,source_parent_pin_sha256,destination_parent_pin_sha256,
                    state,completion_proof_sha256,created_at_ms,updated_at_ms,prepared_proof_json
             FROM desktop_namespace_intents WHERE namespace_id=?1",
            [namespace_id],
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
                    row.get(8)?,
                    row.get(9)?,
                    row.get(10)?,
                    row.get(11)?,
                    row.get(12)?,
                    row.get(13)?,
                    row.get(14)?,
                    row.get(15)?,
                    row.get(16)?,
                    row.get(17)?,
                    row.get(18)?,
                    row.get(19)?,
                    row.get(20)?,
                ))
            },
        )
        .optional()?;
    let Some((
        origin_kind,
        native_operation_text,
        native_fence_text,
        remote_actor_text,
        remote_workspace_text,
        remote_operation_text,
        remote_method_text,
        remote_parameter_hash,
        remote_workspace_fence,
        runtime_text,
        plan_json,
        plan_sha,
        prepared_sha,
        source_pin_sha,
        source_parent_pin_sha,
        destination_parent_pin_sha,
        state_text,
        completion_sha,
        created_text,
        updated_text,
        prepared_json,
    )) = row
    else {
        return Ok(None);
    };
    let host_runtime_id = RuntimeId::try_from(runtime_text).map_err(|_| StoreError::Storage)?;
    let plan = decode_stored_plan(&plan_json, &plan_sha)?;
    let prepared =
        DesktopNamespacePhysicalProof::from_host_verified_physical_pins(&plan, &prepared_json)
            .map_err(|_| StoreError::Storage)?;
    let columns = namespace_origin_columns(&plan.wire.origin).map_err(|_| StoreError::Storage)?;
    if plan.namespace_id() != namespace_id
        || columns.kind != origin_kind
        || columns.native_operation_id != native_operation_text
        || columns.native_fence_id != native_fence_text
        || columns.remote_actor != remote_actor_text
        || columns.remote_workspace != remote_workspace_text
        || columns.remote_operation_id != remote_operation_text
        || columns.remote_method != remote_method_text
        || columns.remote_parameter_hash != remote_parameter_hash
        || columns.remote_workspace_fence != remote_workspace_fence
        || plan.host_runtime_id() != host_runtime_id
        || prepared.namespace_id != namespace_id
        || !valid_sha256(&prepared_sha)
        || prepared.proof_sha256 != prepared_sha
        || prepared.source_pin_sha256 != source_pin_sha
        || prepared.source_parent_pin_sha256 != source_parent_pin_sha
        || prepared.destination_parent_pin_sha256 != destination_parent_pin_sha
        || !valid_sha256(&source_pin_sha)
        || !valid_sha256(&source_parent_pin_sha)
        || destination_parent_pin_sha
            .as_deref()
            .is_some_and(|value| !valid_sha256(value))
        || completion_sha
            .as_deref()
            .is_some_and(|value| !valid_sha256(value))
    {
        return Err(StoreError::Storage);
    }
    let state = match state_text.as_str() {
        "prepared" => DesktopNamespaceIntentState::Prepared,
        "applied" => DesktopNamespaceIntentState::Applied,
        "noChange" => DesktopNamespaceIntentState::NoChange,
        "retiredAfterPartialRemove" => DesktopNamespaceIntentState::RetiredAfterPartialRemove,
        "retiredRequestedRecovery" => DesktopNamespaceIntentState::RetiredRequestedRecovery,
        _ => return Err(StoreError::Storage),
    };
    let created_at_ms = canonical_u64(created_text)?;
    let updated_at_ms = canonical_u64(updated_text)?;
    if updated_at_ms < created_at_ms
        || (state == DesktopNamespaceIntentState::Prepared) != completion_sha.is_none()
        || (matches!(plan.effect(), DesktopNamespaceEffect::Move { .. })
            != destination_parent_pin_sha.is_some())
        || (matches!(
            state,
            DesktopNamespaceIntentState::RetiredAfterPartialRemove
                | DesktopNamespaceIntentState::RetiredRequestedRecovery
        ) && (origin_kind != "nativeEditor"
            || !matches!(plan.effect(), DesktopNamespaceEffect::Remove { .. })))
    {
        return Err(StoreError::Storage);
    }
    let origin = plan.wire.origin.clone();
    Ok(Some(NamespaceIntentRecord {
        namespace_id: namespace_id.to_owned(),
        origin,
        host_runtime_id,
        plan,
        state,
        prepared_proof_sha256: prepared_sha,
        prepared_proof_json: prepared_json,
        source_pin_sha256: source_pin_sha,
        source_parent_pin_sha256: source_parent_pin_sha,
        destination_parent_pin_sha256: destination_parent_pin_sha,
        completion_proof_sha256: completion_sha,
        created_at_ms,
        updated_at_ms,
    }))
}

fn native_record(record: NamespaceIntentRecord) -> Result<DesktopNamespaceIntentRecord> {
    let DesktopNamespaceOriginWire::NativeEditor {
        operation_id,
        fence_id,
        ..
    } = record.origin
    else {
        return Err(StoreError::Fenced);
    };
    Ok(DesktopNamespaceIntentRecord {
        operation_id,
        fence_id,
        host_runtime_id: record.host_runtime_id,
        plan: record.plan,
        state: record.state,
        prepared_proof_sha256: record.prepared_proof_sha256,
        prepared_proof_json: record.prepared_proof_json,
        source_pin_sha256: record.source_pin_sha256,
        source_parent_pin_sha256: record.source_parent_pin_sha256,
        destination_parent_pin_sha256: record.destination_parent_pin_sha256,
        completion_proof_sha256: record.completion_proof_sha256,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
    })
}

fn remote_record(record: NamespaceIntentRecord) -> Result<RemoteDesktopNamespaceIntentRecord> {
    if matches!(
        record.state,
        DesktopNamespaceIntentState::RetiredAfterPartialRemove
            | DesktopNamespaceIntentState::RetiredRequestedRecovery
    ) {
        return Err(StoreError::Fenced);
    }
    let DesktopNamespaceOriginWire::RemoteOperation {
        actor,
        workspace_id,
        operation_id,
        method,
        ..
    } = record.origin
    else {
        return Err(StoreError::Fenced);
    };
    Ok(RemoteDesktopNamespaceIntentRecord {
        namespace_id: record.namespace_id,
        actor,
        workspace_id,
        operation_id,
        method,
        host_runtime_id: record.host_runtime_id,
        plan: RemoteDesktopNamespacePlan { inner: record.plan },
        state: record.state,
        prepared_proof_sha256: record.prepared_proof_sha256,
        prepared_proof_json: record.prepared_proof_json,
        source_pin_sha256: record.source_pin_sha256,
        source_parent_pin_sha256: record.source_parent_pin_sha256,
        destination_parent_pin_sha256: record.destination_parent_pin_sha256,
        completion_proof_sha256: record.completion_proof_sha256,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
    })
}

fn shell_profile_cwd_updates(
    db: &Connection,
    workspaces: &[DesktopNamespaceWorkspace],
    old_root: &Path,
    new_root: &Path,
) -> Result<Vec<(String, PathBuf)>> {
    let moved_roots: std::collections::BTreeMap<_, _> = workspaces
        .iter()
        .map(|workspace| {
            let new_path = workspace.new_path.as_ref().ok_or(StoreError::Storage)?;
            Ok((
                workspace.workspace_id,
                (workspace.old_path.clone(), new_path.clone()),
            ))
        })
        .collect::<Result<_>>()?;
    let rows = {
        let mut query = db.prepare(
            "SELECT key,value FROM metadata WHERE key GLOB 'shell_profile/*' ORDER BY key",
        )?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    let mut registered_cwd_keys = std::collections::BTreeSet::new();
    let mut updates = Vec::new();
    for (metadata_key, value) in rows {
        let profile: ipc::LocalShellProfileRegister = decode(&value)?;
        if profile
            .derived_profile_id()
            .map_err(|_| StoreError::Storage)?
            != profile.profile_id
            || !Path::new(profile.cwd.as_str()).is_absolute()
            || profile.cwd.as_str().len() > MAX_NAMESPACE_PATH_BYTES
        {
            return Err(StoreError::Storage);
        }
        let expected_key = format!(
            "shell_profile/{}/{}",
            key(profile.workspace_id),
            profile.profile_id.as_str()
        );
        if metadata_key != expected_key {
            return Err(StoreError::Storage);
        }

        let cwd_key = format!(
            "shell_profile_cwd/{}/{}",
            key(profile.workspace_id),
            profile.profile_id.as_str()
        );
        registered_cwd_keys.insert(cwd_key.clone());

        let existing_suffix = metadata_value(db, &cwd_key)?
            .map(|wire| -> Result<PathBuf> {
                let suffix: PathBuf = decode(&wire)?;
                super::validate_shell_profile_cwd_override(&suffix)
                    .map_err(|_| StoreError::Storage)?;
                Ok(suffix)
            })
            .transpose()?;
        let removed: bool = db
            .query_row(
                "SELECT removed FROM projects WHERE workspace=?1",
                [key(profile.workspace_id)],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(StoreError::Storage)?;
        if removed {
            // Retired workspace profiles remain immutable audit metadata, but
            // they can no longer launch and must not block moves of the path.
            continue;
        }
        let project = project(db, profile.workspace_id).map_err(|error| match error {
            StoreError::NotFound => StoreError::Storage,
            other => other,
        })?;
        let (workspace_old_root, workspace_new_root) = moved_roots
            .get(&profile.workspace_id)
            .cloned()
            .unwrap_or_else(|| (project.local_root.clone(), project.local_root));
        validate_namespace_path(&workspace_old_root).map_err(|_| StoreError::Storage)?;
        validate_namespace_path(&workspace_new_root).map_err(|_| StoreError::Storage)?;
        let effective_cwd = existing_suffix
            .as_ref()
            .map(|suffix| workspace_old_root.join(suffix))
            .unwrap_or_else(|| PathBuf::from(profile.cwd.as_str()));
        if !paths_equal_or_descendant(&effective_cwd, old_root) {
            continue;
        }

        // A prior registration may have an external CWD. It is left alone
        // unless that exact directory is inside the moved namespace. In that
        // case it must still be representable under the registered workspace.
        let _ = relative_namespace_path(&effective_cwd, &workspace_old_root)
            .map_err(|_| StoreError::Storage)?;
        let moved_cwd = remap_namespace_path(&effective_cwd, old_root, new_root)
            .map_err(|_| StoreError::Storage)?;
        let suffix = relative_namespace_path(&moved_cwd, &workspace_new_root)
            .map_err(|_| StoreError::Fenced)?;
        super::validate_shell_profile_cwd_override(&suffix).map_err(|_| StoreError::Storage)?;
        updates.push((cwd_key, suffix));
    }

    let orphaned_cwd_keys = {
        let mut query = db.prepare(
            "SELECT key FROM metadata WHERE key GLOB 'shell_profile_cwd/*' ORDER BY key",
        )?;
        query
            .query_map([], |row| row.get::<_, String>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    if orphaned_cwd_keys
        .iter()
        .any(|key| !registered_cwd_keys.contains(key))
    {
        return Err(StoreError::Storage);
    }
    Ok(updates)
}

fn persist_shell_profile_cwd_updates(
    tx: &Transaction<'_>,
    updates: Vec<(String, PathBuf)>,
) -> Result<()> {
    for (key, suffix) in updates {
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, json(&suffix)?],
        )?;
    }
    Ok(())
}

fn apply_namespace_effect(
    tx: &Transaction<'_>,
    plan: &DesktopNamespacePlan,
    evidence: &DesktopNamespaceAppliedProof,
    limits: Limits,
) -> Result<()> {
    if evidence.observed == DesktopNamespaceObservedEffect::NoChange {
        return Ok(());
    }
    if matches!(plan.effect(), DesktopNamespaceEffect::Remove { .. }) {
        ensure_retired_workspace_terminals_stopped(tx, plan)?;
        for workspace_id in plan.guarded_workspace_ids() {
            ensure_no_namespace_blocking_reservations(tx, *workspace_id, &plan.wire.origin)?;
        }
    }
    match plan.effect() {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            let cwd_updates = shell_profile_cwd_updates(tx, plan.workspaces(), old_path, new_path)?;
            persist_shell_profile_cwd_updates(tx, cwd_updates)?;
            for workspace in plan.workspaces() {
                let new_root = workspace.new_path.as_deref().ok_or(StoreError::Storage)?;
                if tx.execute(
                    "UPDATE projects SET root=?2 WHERE workspace=?1 AND root=?3 AND removed=0",
                    params![
                        key(workspace.workspace_id),
                        path_text(new_root)?,
                        path_text(&workspace.old_path)?,
                    ],
                )? != 1
                {
                    return Err(StoreError::Fenced);
                }
            }
            rewrite_workspace_import_aliases(tx, plan.workspaces(), old_path, new_path)?;
        }
        DesktopNamespaceEffect::Remove { old_path } => {
            for workspace in plan.workspaces() {
                let mut project = project(tx, workspace.workspace_id)?;
                if project.local_root != workspace.old_path {
                    return Err(StoreError::Fenced);
                }
                if !paths_equal_or_descendant(&project.local_root, old_path) {
                    return Err(StoreError::Fenced);
                }
                if matches!(
                    evidence.observed,
                    DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                        | DesktopNamespaceObservedEffect::RetiredRequestedRecovery
                ) && project.consent
                {
                    return Err(StoreError::Fenced);
                }
                project.fence = increment(project.fence)?;
                rotate_workspace_epoch(&mut project.state)?;
                project.consent = false;
                save_project(tx, &project)?;
                force_event_room(tx, limits)?;
                append_event(tx, &project.state, None)?;
                queue_publication(tx, &project)?;
                if tx.execute(
                    "UPDATE projects SET removed=1 WHERE workspace=?1 AND removed=0",
                    [key(workspace.workspace_id)],
                )? != 1
                {
                    return Err(StoreError::Fenced);
                }
            }
        }
    }
    Ok(())
}

fn rewrite_workspace_import_aliases(
    tx: &Transaction<'_>,
    workspaces: &[DesktopNamespaceWorkspace],
    old_root: &Path,
    new_root: &Path,
) -> Result<()> {
    let affected: std::collections::BTreeMap<_, _> = workspaces
        .iter()
        .map(|workspace| (workspace.workspace_id, &workspace.old_path))
        .collect();
    let rows = {
        let mut query =
            tx.prepare("SELECT key,value FROM metadata WHERE key LIKE 'workspace_import/%'")?;
        query
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?
    };
    for (key_text, value) in rows {
        let alias: WorkspaceImportAlias = decode(&value)?;
        let Some(old_workspace_root) = affected.get(&alias.workspace_id) else {
            continue;
        };
        let alias_root = PathBuf::from(&alias.canonical_root);
        if &alias_root != *old_workspace_root || !paths_equal_or_descendant(&alias_root, old_root) {
            return Err(StoreError::Storage);
        }
        let mapped = remap_namespace_path(&alias_root, old_root, new_root)?;
        tx.execute(
            "UPDATE metadata SET value=?2 WHERE key=?1",
            params![
                key_text,
                json(&WorkspaceImportAlias {
                    workspace_id: alias.workspace_id,
                    canonical_root: path_text(&mapped)?.to_owned(),
                })?
            ],
        )?;
    }
    Ok(())
}

fn apply_recovered_namespace_effect(
    tx: &Transaction<'_>,
    record: &DesktopNamespaceIntentRecord,
    evidence: &DesktopNamespaceRecoveryEvidence,
    limits: Limits,
) -> Result<()> {
    if evidence.observed == DesktopNamespaceObservedEffect::NoChange {
        return Ok(());
    }
    if matches!(record.plan.effect(), DesktopNamespaceEffect::Remove { .. }) {
        ensure_retired_workspace_terminals_stopped(tx, &record.plan)?;
        for workspace_id in record.plan.guarded_workspace_ids() {
            ensure_no_namespace_blocking_reservations(tx, *workspace_id, &record.plan.wire.origin)?;
        }
    }
    match record.plan.effect() {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            let cwd_updates =
                shell_profile_cwd_updates(tx, record.plan.workspaces(), old_path, new_path)?;
            persist_shell_profile_cwd_updates(tx, cwd_updates)?;
            for workspace in record.plan.workspaces() {
                let new_root = workspace.new_path.as_deref().ok_or(StoreError::Storage)?;
                if tx.execute(
                    "UPDATE projects SET root=?2 WHERE workspace=?1 AND root=?3 AND removed=0",
                    params![
                        key(workspace.workspace_id),
                        path_text(new_root)?,
                        path_text(&workspace.old_path)?
                    ],
                )? != 1
                {
                    return Err(StoreError::Fenced);
                }
            }
            rewrite_workspace_import_aliases(tx, record.plan.workspaces(), old_path, new_path)?;
        }
        DesktopNamespaceEffect::Remove { old_path } => {
            for workspace in record.plan.workspaces() {
                let mut project = project(tx, workspace.workspace_id)?;
                if project.local_root != workspace.old_path
                    || !paths_equal_or_descendant(&project.local_root, old_path)
                {
                    return Err(StoreError::Fenced);
                }
                if matches!(
                    evidence.observed,
                    DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
                        | DesktopNamespaceObservedEffect::RetiredRequestedRecovery
                ) && project.consent
                {
                    return Err(StoreError::Fenced);
                }
                project.fence = increment(project.fence)?;
                rotate_workspace_epoch(&mut project.state)?;
                project.consent = false;
                save_project(tx, &project)?;
                force_event_room(tx, limits)?;
                append_event(tx, &project.state, None)?;
                queue_publication(tx, &project)?;
                if tx.execute(
                    "UPDATE projects SET removed=1 WHERE workspace=?1 AND removed=0",
                    [key(workspace.workspace_id)],
                )? != 1
                {
                    return Err(StoreError::Fenced);
                }
            }
        }
    }
    Ok(())
}

fn finish_editor_job_and_namespace(
    tx: &Transaction<'_>,
    record: &DesktopNamespaceIntentRecord,
    state: NativeEditorJobState,
    proof: NativeEditorCompletionProof,
    result_json: Option<String>,
    observed: DesktopNamespaceObservedEffect,
    proof_sha256: &str,
    now: u64,
) -> Result<()> {
    let (old_state, old_result, fence_text, runtime_text, old_proof): (
        String,
        Option<String>,
        String,
        String,
        Option<String>,
    ) = tx.query_row(
        "SELECT state,result_json,fence_id,host_runtime_id,completion_proof FROM native_editor_jobs WHERE operation_id=?1",
        [key(record.operation_id)],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?)),
    )?;
    if old_state != "running"
        || fence_text != key(record.fence_id)
        || runtime_text != key(record.host_runtime_id)
    {
        return Err(StoreError::Fenced);
    }
    let next_state = match evidence_state(state, proof) {
        Ok(state) => state,
        Err(error) => return Err(error),
    };
    let _ = (old_result, old_proof);
    if tx.execute(
        "UPDATE native_intents SET state='finished' WHERE id=?1 AND state IN('active','quarantine')",
        [key(record.fence_id)],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    let completion = native_editor_completion_proof_text(proof);
    if tx.execute(
        "UPDATE native_editor_jobs SET state=?2,result_json=?3,completion_proof=?4,
             completed_at_ms=?5 WHERE operation_id=?1 AND state='running'",
        params![
            key(record.operation_id),
            next_state,
            result_json,
            completion,
            now.to_string()
        ],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    tx.execute(
        "UPDATE native_file_stages SET state='expired' WHERE operation_id=?1 AND state='consumed'",
        [key(record.operation_id)],
    )?;
    let _state_text = match state {
        NativeEditorJobState::Succeeded => "succeeded",
        NativeEditorJobState::Failed => "failed",
        NativeEditorJobState::OutcomeUnknown => "outcomeUnknown",
        NativeEditorJobState::Running => return Err(StoreError::Invalid),
    };
    let namespace_state = match proof_sha256 {
        digest if !valid_sha256(digest) => return Err(StoreError::Invalid),
        _ => match observed {
            DesktopNamespaceObservedEffect::Applied => "applied",
            DesktopNamespaceObservedEffect::NoChange => "noChange",
            DesktopNamespaceObservedEffect::RetiredAfterPartialRemove => {
                "retiredAfterPartialRemove"
            }
            DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
                return Err(StoreError::Invalid);
            }
        },
    };
    if tx.execute(
        "UPDATE desktop_namespace_intents SET state=?2,completion_proof_sha256=?3,updated_at_ms=?4
         WHERE namespace_id=?1 AND state='prepared'",
        params![
            native_namespace_id(record.operation_id),
            namespace_state,
            proof_sha256,
            now.to_string()
        ],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn evidence_state(
    state: NativeEditorJobState,
    proof: NativeEditorCompletionProof,
) -> Result<&'static str> {
    if state == NativeEditorJobState::Running
        || (proof == NativeEditorCompletionProof::NotStarted
            && state != NativeEditorJobState::Failed)
    {
        return Err(StoreError::Invalid);
    }
    Ok(native_editor_job_state_text(state))
}

fn mark_namespace_recovered(
    tx: &Transaction<'_>,
    record: &DesktopNamespaceIntentRecord,
    evidence: &DesktopNamespaceRecoveryEvidence,
    now: u64,
) -> Result<()> {
    let state = match evidence.observed {
        DesktopNamespaceObservedEffect::Applied => "applied",
        DesktopNamespaceObservedEffect::NoChange => "noChange",
        DesktopNamespaceObservedEffect::RetiredRequestedRecovery => "retiredRequestedRecovery",
        DesktopNamespaceObservedEffect::RetiredAfterPartialRemove => {
            return Err(StoreError::Invalid);
        }
    };
    if tx.execute(
        "UPDATE desktop_namespace_intents SET state=?2,completion_proof_sha256=?3,updated_at_ms=?4
         WHERE namespace_id=?1 AND state='prepared'",
        params![
            native_namespace_id(record.operation_id),
            state,
            evidence.proof_sha256,
            now.to_string(),
        ],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn mark_namespace_completed(
    tx: &Transaction<'_>,
    record: &NamespaceIntentRecord,
    observed: DesktopNamespaceObservedEffect,
    proof_sha256: &str,
    now: u64,
) -> Result<()> {
    if !valid_sha256(proof_sha256) {
        return Err(StoreError::Invalid);
    }
    let state = match observed {
        DesktopNamespaceObservedEffect::Applied => "applied",
        DesktopNamespaceObservedEffect::NoChange => "noChange",
        DesktopNamespaceObservedEffect::RetiredAfterPartialRemove
        | DesktopNamespaceObservedEffect::RetiredRequestedRecovery => {
            return Err(StoreError::Invalid);
        }
    };
    if tx.execute(
        "UPDATE desktop_namespace_intents SET state=?2,completion_proof_sha256=?3,updated_at_ms=?4
         WHERE namespace_id=?1 AND state='prepared'",
        params![record.namespace_id, state, proof_sha256, now.to_string()],
    )? != 1
    {
        return Err(StoreError::Fenced);
    }
    Ok(())
}

fn is_exact_uncertain_desktop_result(result_json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(result_json) else {
        return false;
    };
    value.as_object().is_some_and(|object| {
        object.len() == 1
            && object.get("kind").and_then(serde_json::Value::as_str) == Some("uncertain")
    })
}

fn proof_pin_digests(proof: &DesktopNamespacePhysicalProof) -> (String, String, Option<String>) {
    (
        proof.source_pin_sha256.clone(),
        proof.source_parent_pin_sha256.clone(),
        proof.destination_parent_pin_sha256.clone(),
    )
}

fn valid_pin(value: &str) -> bool {
    !value.is_empty() && value.len() <= MAX_NAMESPACE_PIN_BYTES && !value.contains('\0')
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

/// Return requested workspaces affected or guarded by any durable prepared
/// namespace plan. Decode each bounded plan once, rather than rescanning all
/// intents once per import ID.
pub(super) fn namespace_pending_workspace_ids(
    db: &Connection,
    workspace_ids: &[WorkspaceId],
) -> Result<std::collections::HashSet<WorkspaceId>> {
    use std::collections::HashSet;

    let requested = workspace_ids.iter().copied().collect::<HashSet<_>>();
    if requested.is_empty() {
        return Ok(HashSet::new());
    }
    let mut query = db.prepare(
        "SELECT plan_json,plan_sha256 FROM desktop_namespace_intents
         WHERE state='prepared' ORDER BY namespace_id LIMIT ?1",
    )?;
    let plans = query
        .query_map([MAX_DESKTOP_NAMESPACE_INTENTS as i64 + 1], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    if plans.len() > MAX_DESKTOP_NAMESPACE_INTENTS {
        return Err(StoreError::ResourceExhausted);
    }
    let mut pending = HashSet::new();
    for (plan_json, plan_sha256) in plans {
        let plan = decode_stored_plan(&plan_json, &plan_sha256)?;
        for workspace_id in plan.guarded_workspace_ids().iter().copied().chain(
            plan.workspaces()
                .iter()
                .map(|workspace| workspace.workspace_id),
        ) {
            if requested.contains(&workspace_id) {
                pending.insert(workspace_id);
            }
        }
    }
    Ok(pending)
}
