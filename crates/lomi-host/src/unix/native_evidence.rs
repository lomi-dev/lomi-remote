use super::{
    LocalError, LocalResult,
    owner_domain::Operation,
    rpc,
    shared_owner::{self, SharedOwner},
};
use lomi_platform::{
    native_evidence_runtime::{
        NativeEvidenceMode, capture_trusted_native_runtime_with_cancellation,
        restore_trusted_native_runtime,
    },
    unix::OwnerEndpoint,
};
use lomi_remote_protocol::ipc::{self, NativeBindJobRequest, NativeIntentId, NativeWriterState};
use serde::Deserialize;
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const MAX_BINDING_JSON_BYTES: usize = 128 * 1024 - 256;
const MAX_DESCRIPTOR_JSON_BYTES: usize = 16 * 1024;

/// Host-only coordinator for the fixed Capture/Verify helper. Retaining the
/// endpoint also retains the profile OwnerLock for the complete child lifetime.
pub(super) struct NativeEvidenceHost {
    profile: PathBuf,
    owner: Arc<SharedOwner>,
    _endpoint: Arc<OwnerEndpoint>,
    stopping: Arc<AtomicBool>,
}

impl NativeEvidenceHost {
    pub(super) fn new(
        profile: PathBuf,
        owner: Arc<SharedOwner>,
        endpoint: Arc<OwnerEndpoint>,
        stopping: Arc<AtomicBool>,
    ) -> Self {
        Self {
            profile,
            owner,
            _endpoint: endpoint,
            stopping,
        }
    }

    pub(super) fn bind_job(
        &self,
        operation: &Operation<'_>,
        connection: ipc::IpcNonce,
        accepted_stream: &std::os::unix::net::UnixStream,
        request: NativeBindJobRequest,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        if self.stopping.load(Ordering::Acquire) {
            return Err(LocalError::Unavailable);
        }
        let store_root = request.store_root.as_str();
        if !Path::new(store_root).is_absolute() {
            return Err(LocalError::InvalidArgument);
        }
        let parent_operation_id = request.parent_operation_id.as_str();

        // Exact retries return the durable lease without launching a second
        // capture helper. The transaction below repeats all state checks.
        if let Some(lease) = rpc::owner_call(operation, || {
            self.owner.native_bind_preflight(
                operation,
                request.intent_id,
                connection,
                store_root,
                parent_operation_id,
            )
        })
        .map_err(super::owner_error)?
        {
            return Ok(LocalResult::NativeLease(lease));
        }

        let runtime = match capture_trusted_native_runtime_with_cancellation(
            &self.profile,
            accepted_stream,
            operation.deadline(),
            operation.cancellation_latch(),
        ) {
            Ok(runtime) => runtime,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        let input = serde_json::to_vec(&CaptureRequest {
            store_root,
            parent_operation_id,
        })
        .map_err(|_| LocalError::Unavailable)?;
        let output = match runtime.run_with_cancellation(
            NativeEvidenceMode::Capture,
            &input,
            operation.deadline(),
            operation.cancellation_latch(),
        ) {
            Ok(output) => output,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let envelope: HelperEnvelope = match serde_json::from_slice(&output) {
            Ok(envelope) => envelope,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        if envelope.kind != "captured" {
            return self.reject_before_activation(operation, request.intent_id, connection);
        }
        let binding: CapturedBindingIdentity = match serde_json::from_value(envelope.value.clone())
        {
            Ok(binding) => binding,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        if binding.schema != 1
            || binding.store_root != PathBuf::from(store_root)
            || binding.operation_id != parent_operation_id
            || binding.task_id.is_empty()
            || binding.attempt_id.is_empty()
            || binding.account_id.is_empty()
            || binding.generation == 0
            || binding.auth_revision == 0
            || binding.host.boot.is_empty()
            || binding.host.release.is_empty()
            || binding.host.build.is_empty()
            || binding.host.version.is_empty()
        {
            return self.reject_before_activation(operation, request.intent_id, connection);
        }
        let binding_json = match serde_json::to_string(&envelope.value) {
            Ok(binding_json) => binding_json,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        if binding_json.len() > MAX_BINDING_JSON_BYTES {
            return self.reject_before_activation(operation, request.intent_id, connection);
        }
        let runtime_descriptor_json = match runtime.descriptor_json() {
            Ok(descriptor) => descriptor,
            Err(_) => {
                return self.reject_before_activation(operation, request.intent_id, connection);
            }
        };
        if runtime_descriptor_json.len() > MAX_DESCRIPTOR_JSON_BYTES {
            return self.reject_before_activation(operation, request.intent_id, connection);
        }
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let lease = match rpc::owner_call(operation, || {
            self.owner.native_bind_registered(
                operation,
                request.intent_id,
                connection,
                store_root,
                parent_operation_id,
                &binding_json,
                &runtime_descriptor_json,
            )
        }) {
            Ok(lease) => lease,
            Err(shared_owner::Error::Store(
                lomi_host_store::StoreError::NativeWriterBusy
                | lomi_host_store::StoreError::ResourceExhausted,
            )) => return self.reject_before_activation(operation, request.intent_id, connection),
            Err(error) => return Err(super::owner_error(error)),
        };
        Ok(LocalResult::NativeLease(lease))
    }

    fn reject_before_activation(
        &self,
        operation: &Operation<'_>,
        intent_id: NativeIntentId,
        connection: ipc::IpcNonce,
    ) -> Result<LocalResult, LocalError> {
        match rpc::owner_call(operation, || {
            self.owner
                .reject_unbound_native_intent(operation, intent_id, connection)
        }) {
            Ok(()) => Err(LocalError::NativeBindRejected),
            Err(_) => Err(LocalError::Unavailable),
        }
    }

    /// Move the writer into durable Quarantine before Verify I/O. Only a
    /// correctly tagged and exactly matching helper result can finish it.
    pub(super) fn verify_finish(
        &self,
        operation: &Operation<'_>,
        intent_id: NativeIntentId,
    ) -> Result<LocalResult, LocalError> {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let (lease, binding) = rpc::owner_call(operation, || {
            self.owner
                .native_quarantine_for_verification(operation, intent_id)
        })
        .map_err(super::owner_error)?;
        if lease.state == NativeWriterState::Finished {
            return Ok(LocalResult::NativeLease(lease));
        }
        let Some(binding) = binding else {
            return Ok(LocalResult::NativeLease(lease));
        };
        if lease.state != NativeWriterState::Quarantine || self.stopping.load(Ordering::Acquire) {
            return Ok(LocalResult::NativeLease(lease));
        }
        let runtime =
            match restore_trusted_native_runtime(&self.profile, &binding.runtime_descriptor_json) {
                Ok(runtime) => runtime,
                Err(_) => return Ok(LocalResult::NativeLease(lease)),
            };
        let captured_value: Value = match serde_json::from_str(&binding.binding_json) {
            Ok(value) => value,
            Err(_) => return Ok(LocalResult::NativeLease(lease)),
        };
        let captured: CapturedBindingIdentity = match serde_json::from_value(captured_value.clone())
        {
            Ok(captured) => captured,
            Err(_) => return Ok(LocalResult::NativeLease(lease)),
        };
        if binding.intent_id != intent_id
            || captured.store_root != PathBuf::from(&binding.store_root)
            || captured.operation_id != binding.parent_operation_id
        {
            return Ok(LocalResult::NativeLease(lease));
        }
        let input = serde_json::to_vec(&VerifyRequest {
            binding: captured_value,
        })
        .map_err(|_| LocalError::Unavailable)?;
        if input.len() > 128 * 1024 {
            return Ok(LocalResult::NativeLease(lease));
        }
        let output = match runtime.run_with_cancellation(
            NativeEvidenceMode::Verify,
            &input,
            operation.deadline(),
            operation.cancellation_latch(),
        ) {
            Ok(output) => output,
            Err(_) => return Ok(LocalResult::NativeLease(lease)),
        };
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let envelope: HelperEnvelope = match serde_json::from_slice(&output) {
            Ok(envelope) => envelope,
            Err(_) => return Ok(LocalResult::NativeLease(lease)),
        };
        if envelope.kind != "verified" {
            return Ok(LocalResult::NativeLease(lease));
        }
        let evidence: NativeCompletionEvidence = match serde_json::from_value(envelope.value) {
            Ok(evidence) => evidence,
            Err(_) => return Ok(LocalResult::NativeLease(lease)),
        };
        if !evidence.matches(&captured) {
            return Ok(LocalResult::NativeLease(lease));
        }
        operation.check().map_err(|_| LocalError::Unavailable)?;
        let finished = rpc::owner_call(operation, || {
            self.owner
                .native_finish_verified(operation, intent_id, &binding.binding_sha256)
        })
        .map_err(super::owner_error)?;
        Ok(LocalResult::NativeLease(finished))
    }
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct CaptureRequest<'a> {
    store_root: &'a str,
    parent_operation_id: &'a str,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct VerifyRequest {
    binding: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HelperEnvelope {
    #[serde(rename = "type")]
    kind: String,
    value: Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CapturedBindingIdentity {
    schema: u32,
    store_root: PathBuf,
    operation_id: String,
    task_id: String,
    attempt_id: String,
    generation: u64,
    account_id: String,
    auth_revision: u64,
    host: KernelWitness,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KernelWitness {
    boot: String,
    release: String,
    build: String,
    version: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct NativeCompletionEvidence {
    schema: u32,
    operation_id: String,
    task_id: String,
    attempt_id: String,
    generation: u64,
    account_id: String,
    auth_revision: u64,
    boot: String,
    outcome: CompletionOutcome,
    retired_coalitions: Vec<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum CompletionOutcome {
    Completed,
    Stopped,
}

impl NativeCompletionEvidence {
    fn matches(&self, binding: &CapturedBindingIdentity) -> bool {
        let _verified_outcome = &self.outcome;
        self.schema == 1
            && self.operation_id == binding.operation_id
            && self.task_id == binding.task_id
            && self.attempt_id == binding.attempt_id
            && self.generation == binding.generation
            && self.account_id == binding.account_id
            && self.auth_revision == binding.auth_revision
            && self.boot == binding.host.boot
            && !self.retired_coalitions.is_empty()
            && self
                .retired_coalitions
                .iter()
                .all(|coalition| *coalition > 1)
            && self
                .retired_coalitions
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                == self.retired_coalitions.len()
    }
}
