//! Shared response bindings for additive owner-local methods. Unix sockets and
//! Windows pipes use this same admission logic after authenticating their peer.
use lomi_remote_protocol::{
    HostId, RuntimeId,
    ipc::{self, LocalCall, LocalResult},
};
use std::collections::BTreeSet;

pub(crate) fn matches(
    call: &LocalCall,
    result: &LocalResult,
    host_id: HostId,
    runtime_id: RuntimeId,
) -> Option<bool> {
    use LocalCall as C;
    use LocalResult as R;
    Some(match call {
        C::DoctorReport {} => matches!(result, R::DoctorReport(_)),
        C::OperatorSnapshot {} => matches!(result, R::OperatorSnapshot(snapshot)
            if snapshot.status.host_id == host_id && snapshot.status.runtime_id == runtime_id),
        C::DiagnosticLogs(read) => match result {
            R::DiagnosticLogs(page) => {
                let mut cursor = read.after_sequence.map(|cursor| cursor.0).unwrap_or(0);
                if read.limit == 0
                    || read.limit > 128
                    || page.entries.0.len() > usize::from(read.limit)
                {
                    return Some(false);
                }
                for entry in &page.entries.0 {
                    if entry.sequence.0 <= cursor {
                        return Some(false);
                    }
                    cursor = entry.sequence.0;
                }
                page.next_cursor.0 == cursor && (page.available || page.entries.0.is_empty())
            }
            _ => false,
        },
        C::WorkspaceDetails(read) => matches!(result, R::WorkspaceDetails(details)
            if details.workspace.workspace_id == read.workspace_id
                && std::path::Path::new(details.root_path.as_str()).is_absolute()),
        C::WorkspaceRemovalStatus(read) => matches!(result, R::WorkspaceRemovalStatus(status)
            if status.workspace_id == read.workspace_id && status.validate().is_ok()),
        C::WorkspaceRemove(target) => match result {
            R::Removed(id) => target.workspace_id == *id,
            R::WorkspaceRemovalStatus(status) => {
                status.workspace_id == target.workspace_id
                    && status.validate().is_ok()
                    && matches!(
                        status.phase,
                        ipc::LocalWorkspaceRemovalPhase::Stopping
                            | ipc::LocalWorkspaceRemovalPhase::Uncertain
                    )
            }
            _ => false,
        },
        C::WorkspacePublication(read) => matches!(result, R::WorkspacePublication(publication)
            if publication.host_id == host_id && publication.workspace_id == read.workspace_id),
        C::WorkspaceRename(rename) => matches!(result, R::Workspace(workspace)
            if workspace.workspace_id == rename.workspace_id && workspace.name == rename.name),
        C::WorkspaceBindingsRead(read) => match result {
            R::WorkspaceBindings(snapshot) => {
                let requested: BTreeSet<_> = read.import_ids.0.iter().copied().collect();
                let mut returned = BTreeSet::new();
                snapshot.host_id == host_id
                    && snapshot.runtime_id == runtime_id
                    && requested.len() == read.import_ids.0.len()
                    && snapshot.bindings.0.len() == requested.len()
                    && snapshot.bindings.0.iter().all(|binding| {
                        let id = match binding {
                            ipc::WorkspaceBinding::Missing { import_id }
                            | ipc::WorkspaceBinding::Active { import_id, .. }
                            | ipc::WorkspaceBinding::Pending { import_id, .. }
                            | ipc::WorkspaceBinding::Retired { import_id, .. } => *import_id,
                        };
                        requested.contains(&id) && returned.insert(id)
                    })
            }
            _ => false,
        },
        C::ShareAuthorized(consent) | C::UnshareAuthorized(consent) => {
            let sharing = if matches!(call, C::ShareAuthorized(_)) {
                ipc::LocalSharing::Enabled
            } else {
                ipc::LocalSharing::Disabled
            };
            matches!(result, R::Workspace(workspace)
                if consent.expected_host_id == host_id
                    && consent.expected_context.runtime_id == runtime_id
                    && consent.expected_context.workspace_id == consent.workspace_id
                    && workspace.workspace_id == consent.workspace_id
                    && workspace.sharing == sharing)
        }
        C::NativeEditorDispositionRead(read) => {
            matches!(result, R::NativeEditorDisposition(disposition)
            if disposition.operation_id == read.intent_id)
        }
        _ => return None,
    })
}
