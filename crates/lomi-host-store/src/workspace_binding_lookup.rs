//! Read-only owner-local import binding and NativeEditor stop classification.
//!
//! This module trusts only durable Store rows. It performs no filesystem,
//! provider, or process operations and cannot establish a new binding.

use super::*;
use std::collections::BTreeSet;

const MAX_IMPORT_ALIAS_BYTES: usize = 8 * 1024;
const MAX_WORKSPACE_STATE_BYTES: usize = 1024 * 1024;

struct ResolvedImport {
    import_id: WorkspaceId,
    workspace_id: WorkspaceId,
    root_path: ipc::LocalRootPath,
    removed: bool,
}

impl HostStore {
    /// Resolve stable imported IDs against the owner-local alias journal and
    /// project rows. It never falls back to path or project-ID guessing.
    pub fn workspace_bindings_read(
        &self,
        import_ids: &[WorkspaceId],
    ) -> Result<ipc::WorkspaceBindingsSnapshot> {
        if import_ids.len() > 256 {
            return Err(StoreError::Invalid);
        }
        let mut seen = BTreeSet::new();
        let mut resolved = Vec::with_capacity(import_ids.len());
        for import_id in import_ids {
            if !seen.insert(*import_id) {
                return Err(StoreError::Invalid);
            }
            let alias_key = format!("workspace_import/{}", key(*import_id));
            let Some(wire) = metadata_value(&self.db, &alias_key)? else {
                resolved.push(None);
                continue;
            };
            if wire.len() > MAX_IMPORT_ALIAS_BYTES {
                return Err(StoreError::Storage);
            }
            let alias: WorkspaceImportAlias = decode(&wire)?;
            let (root, state_json, removed): (String, String, bool) = self
                .db
                .query_row(
                    "SELECT root,state,removed FROM projects WHERE workspace=?1",
                    [key(alias.workspace_id)],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()?
                .ok_or(StoreError::Storage)?;
            if root.len() > 4096
                || alias.canonical_root != root
                || state_json.len() > MAX_WORKSPACE_STATE_BYTES
            {
                return Err(StoreError::Storage);
            }
            let state: WorkspaceState = decode(&state_json)?;
            state.validate().map_err(|_| StoreError::Storage)?;
            if state.context.workspace_id != alias.workspace_id {
                return Err(StoreError::Storage);
            }
            let root_path = local_canonical_root(&root)?;
            resolved.push(Some(ResolvedImport {
                import_id: *import_id,
                workspace_id: alias.workspace_id,
                root_path,
                removed,
            }));
        }

        let workspace_ids = resolved
            .iter()
            .filter_map(|entry| entry.as_ref().map(|entry| entry.workspace_id))
            .collect::<Vec<_>>();
        let pending = desktop_namespace::namespace_pending_workspace_ids(&self.db, &workspace_ids)?;
        let bindings = resolved
            .into_iter()
            .zip(import_ids.iter().copied())
            .map(|(entry, import_id)| match entry {
                None => ipc::WorkspaceBinding::Missing { import_id },
                Some(entry) if pending.contains(&entry.workspace_id) => {
                    ipc::WorkspaceBinding::Pending {
                        import_id: entry.import_id,
                        workspace_id: entry.workspace_id,
                    }
                }
                Some(entry) if entry.removed => ipc::WorkspaceBinding::Retired {
                    import_id: entry.import_id,
                    workspace_id: entry.workspace_id,
                },
                Some(entry) => ipc::WorkspaceBinding::Active {
                    import_id: entry.import_id,
                    workspace_id: entry.workspace_id,
                    root_path: entry.root_path,
                },
            })
            .collect();

        Ok(ipc::WorkspaceBindingsSnapshot {
            host_id: self.identity.host_id,
            runtime_id: self.runtime,
            bindings: BoundedList(bindings),
        })
    }

    /// Return the durable NativeEditor journal state and conservative
    /// retirement classification for an exact operation ID.
    pub fn native_editor_disposition_read(
        &self,
        operation_id: ipc::NativeIntentId,
    ) -> Result<ipc::NativeEditorDisposition> {
        let namespace_record = read_native_namespace_record(self, operation_id)?;
        native_editor_disposition_with_namespace(
            &self.db,
            self.runtime,
            operation_id,
            namespace_record.as_ref(),
        )
    }
}

/// Shared with NativeEditor ACK so a journal is acknowledged only after the
/// same durable proof used by the read API establishes that its writer stopped.
pub(super) fn native_editor_disposition_with_namespace(
    db: &Connection,
    current_runtime: RuntimeId,
    operation_id: ipc::NativeIntentId,
    namespace_record: Option<&DesktopNamespaceIntentRecord>,
) -> Result<ipc::NativeEditorDisposition> {
    let row: Option<(
        String,
        Option<String>,
        String,
        String,
        Option<String>,
        Option<String>,
    )> = db
        .query_row(
            "SELECT state,result_json,fence_id,host_runtime_id,completion_proof,completed_at_ms
             FROM native_editor_jobs WHERE operation_id=?1",
            [key(operation_id)],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((state_text, result_json, fence_text, runtime_text, proof_text, completed_text)) = row
    else {
        return Err(StoreError::NotFound);
    };

    let state = native_editor_job_state(&state_text)?;
    let fence_id =
        ipc::NativeIntentId::try_from(fence_text.clone()).map_err(|_| StoreError::Storage)?;
    if key(fence_id) != fence_text {
        return Err(StoreError::Storage);
    }
    let job_runtime = RuntimeId::try_from(runtime_text.clone()).map_err(|_| StoreError::Storage)?;
    if key(job_runtime) != runtime_text {
        return Err(StoreError::Storage);
    }
    let completed_at = completed_text.map(canonical_u64).transpose()?;
    let proof = match proof_text.as_deref() {
        None => None,
        Some("joined") => Some(NativeEditorCompletionProof::Joined),
        Some("notStarted") => Some(NativeEditorCompletionProof::NotStarted),
        Some(_) => return Err(StoreError::Storage),
    };
    let (lease, _connection, _writer_state, _expiry) = native_intent_row(db, fence_id)?;
    let fence_finished = lease.state == ipc::NativeWriterState::Finished;

    let namespace_exists = desktop_namespace::namespace_intent_exists(db, operation_id)?;
    if namespace_exists != namespace_record.is_some() {
        return Err(StoreError::Storage);
    }
    let namespace_prepared = if let Some(record) = namespace_record {
        if record.operation_id != operation_id
            || record.fence_id != fence_id
            || record.host_runtime_id != job_runtime
        {
            return Err(StoreError::Storage);
        }
        validate_namespace_record_in_db(db, record)?;
        record.state == DesktopNamespaceIntentState::Prepared
    } else {
        false
    };

    let retirement = if namespace_prepared || !fence_finished {
        ipc::NativeEditorRetirement::Unresolved
    } else if completed_at.is_some()
        && state != NativeEditorJobState::Running
        && proof == Some(NativeEditorCompletionProof::Joined)
    {
        ipc::NativeEditorRetirement::Joined
    } else if completed_at.is_some()
        && state == NativeEditorJobState::Failed
        && proof == Some(NativeEditorCompletionProof::NotStarted)
    {
        ipc::NativeEditorRetirement::NotStarted
    } else if namespace_record.is_some_and(|record| {
        record.state != DesktopNamespaceIntentState::Prepared
            && record.completion_proof_sha256.is_some()
    }) && state == NativeEditorJobState::OutcomeUnknown
        && result_json.is_none()
        && proof.is_none()
        && completed_at.is_none()
        && job_runtime != current_runtime
    {
        ipc::NativeEditorRetirement::Recovered
    } else {
        ipc::NativeEditorRetirement::Unresolved
    };

    Ok(ipc::NativeEditorDisposition {
        operation_id,
        state: match state {
            NativeEditorJobState::Running => ipc::LocalNativeEffectState::Running,
            NativeEditorJobState::Succeeded => ipc::LocalNativeEffectState::Succeeded,
            NativeEditorJobState::Failed => ipc::LocalNativeEffectState::Failed,
            NativeEditorJobState::OutcomeUnknown => ipc::LocalNativeEffectState::OutcomeUnknown,
        },
        retirement,
    })
}

fn read_native_namespace_record(
    store: &HostStore,
    operation_id: ipc::NativeIntentId,
) -> Result<Option<DesktopNamespaceIntentRecord>> {
    if !desktop_namespace::namespace_intent_exists(&store.db, operation_id)? {
        return Ok(None);
    }
    store.desktop_namespace_intent(operation_id).map(Some)
}

fn validate_namespace_record_in_db(
    db: &Connection,
    record: &DesktopNamespaceIntentRecord,
) -> Result<()> {
    let row: Option<(String, Option<String>, Option<String>, String, String, Option<String>)> = db
        .query_row(
            "SELECT origin,native_operation_id,native_fence_id,host_runtime_id,state,completion_proof_sha256
             FROM desktop_namespace_intents WHERE namespace_id=?1",
            [record.plan.namespace_id()],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                ))
            },
        )
        .optional()?;
    let Some((origin, operation, fence, runtime, state, completion)) = row else {
        return Err(StoreError::Storage);
    };
    let expected_state = match record.state {
        DesktopNamespaceIntentState::Prepared => "prepared",
        DesktopNamespaceIntentState::Applied => "applied",
        DesktopNamespaceIntentState::NoChange => "noChange",
        DesktopNamespaceIntentState::RetiredAfterPartialRemove => "retiredAfterPartialRemove",
        DesktopNamespaceIntentState::RetiredRequestedRecovery => "retiredRequestedRecovery",
    };
    if origin != "nativeEditor"
        || operation.as_deref() != Some(key(record.operation_id).as_str())
        || fence.as_deref() != Some(key(record.fence_id).as_str())
        || runtime != key(record.host_runtime_id)
        || state != expected_state
        || completion.as_deref() != record.completion_proof_sha256.as_deref()
    {
        return Err(StoreError::Storage);
    }
    Ok(())
}

fn local_canonical_root(value: &str) -> Result<ipc::LocalRootPath> {
    use std::path::Component;
    let path = Path::new(value);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(StoreError::Storage);
    }
    ipc::LocalRootPath::try_from(value.to_owned()).map_err(|_| StoreError::Storage)
}
