//! Read-only selection binding for remote FilesRename/FilesRemove namespace
//! effects. All paths are derived from FileRoot registry entries, never from
//! caller-supplied paths.

use super::{remote_files, shared_owner::RemoteFilePlan};
use lomi_files::{
    self as engine, EntryRef,
    desktop::{DesktopFileKind, DesktopSourcePrecondition},
};
use lomi_host_store::DesktopNamespaceEffect;
use lomi_remote_protocol::{RemoteError, WorkspaceId, rpc::RpcCall};
use std::collections::BTreeSet;

const MAX_GUARDED_WORKSPACES: usize = 256;

/// Selection is a lock-planning hint, not admission. Stale entry references
/// must still reach authorized duplicate lookup without repeating an effect.
/// On a failed hint, lock the bounded current registry in canonical order;
/// the accepted request will recapture and validate its actual selection.
pub(super) fn mutation_lock_ids(
    coordinator: &super::Coordinator,
    operation: &super::owner_domain::Operation<'_>,
    plan: &RemoteFilePlan,
) -> Result<Vec<WorkspaceId>, RemoteError> {
    if let Ok(selection) = FileNamespaceSelection::capture_current(coordinator, operation, plan) {
        return Ok(selection.guarded_workspace_ids);
    }
    let projects = super::rpc::owner_call(operation, || coordinator.owner.workspaces(operation))
        .map_err(|_| remote_files::map_error(engine::Error::Changed))?;
    let mut ids: BTreeSet<_> = projects
        .into_iter()
        .map(|project| project.state.context.workspace_id)
        .collect();
    ids.insert(plan.workspace_id);
    if ids.len() > MAX_GUARDED_WORKSPACES {
        return Err(remote_files::map_error(engine::Error::Limit));
    }
    Ok(ids.into_iter().collect())
}

/// The source/destination binding captured from the actual remote file plan.
/// Store planning remains a separate operation and may only consume `effect`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileNamespaceSelection {
    pub(super) origin_workspace_id: WorkspaceId,
    pub(super) expected_source: Option<DesktopSourcePrecondition>,
    pub(super) effect: Option<DesktopNamespaceEffect>,
    pub(super) guarded_workspace_ids: Vec<WorkspaceId>,
}

impl FileNamespaceSelection {
    pub(super) fn capture_current(
        coordinator: &super::Coordinator,
        operation: &super::owner_domain::Operation<'_>,
        plan: &RemoteFilePlan,
    ) -> Result<Self, RemoteError> {
        let selection = Self::capture(&coordinator.files, plan)?;
        let ids = match selection.effect.as_ref() {
            Some(effect) => super::rpc::owner_call(operation, || {
                coordinator
                    .owner
                    .remote_namespace_guarded_workspaces(operation, effect)
            })
            .map_err(|_| remote_files::map_error(engine::Error::Changed))?,
            None => Vec::new(),
        };
        selection.with_guarded_ids(&ids)
    }
    /// Capture parent/source bindings from the pinned remote FileRoot. This
    /// method performs no Store access, provider call, or filesystem mutation.
    pub(super) fn capture(
        roots: &remote_files::Roots,
        plan: &RemoteFilePlan,
    ) -> Result<Self, RemoteError> {
        let files = roots
            .get_engine(plan.workspace_id, plan.epoch, &plan.root)
            .map_err(remote_files::map_error)?;
        let mut selection = Self {
            origin_workspace_id: plan.workspace_id,
            expected_source: None,
            effect: None,
            guarded_workspace_ids: vec![plan.workspace_id],
        };

        match &plan.call {
            RpcCall::FilesCreate(params) => {
                validate_new_name(params.name.as_str())?;
                let (_, parent) = files
                    .native_entry_binding(&plan.root, entry(&params.parent_entry_id))
                    .map_err(remote_files::map_error)?;
                require_directory(&parent)?;
            }
            RpcCall::FilesMkdir(params) => {
                validate_new_name(params.name.as_str())?;
                let (_, parent) = files
                    .native_entry_binding(&plan.root, entry(&params.parent_entry_id))
                    .map_err(remote_files::map_error)?;
                require_directory(&parent)?;
            }
            RpcCall::FilesRename(params) => {
                validate_new_name(params.name.as_str())?;
                let (source_path, source) = files
                    .native_entry_binding(&plan.root, entry(&params.entry_id))
                    .map_err(remote_files::map_error)?;
                let (source_parent_path, source_parent) = files
                    .native_entry_binding(&plan.root, entry(&params.source_parent_id))
                    .map_err(remote_files::map_error)?;
                let (target_parent_path, target_parent) = files
                    .native_entry_binding(&plan.root, entry(&params.target_parent_id))
                    .map_err(remote_files::map_error)?;
                require_directory(&source_parent)?;
                require_directory(&target_parent)?;
                require_parent(&source_path, &source_parent_path)?;
                selection.expected_source = Some(source.clone());
                if source.kind == DesktopFileKind::Directory {
                    selection.effect = Some(DesktopNamespaceEffect::Move {
                        old_path: source_path,
                        new_path: target_parent_path.join(params.name.as_str()),
                    });
                }
            }
            RpcCall::FilesRemove(params) => {
                let (source_path, source) = files
                    .native_entry_binding(&plan.root, entry(&params.entry_id))
                    .map_err(remote_files::map_error)?;
                let (parent_path, parent) = files
                    .native_entry_binding(&plan.root, entry(&params.parent_entry_id))
                    .map_err(remote_files::map_error)?;
                require_directory(&parent)?;
                require_parent(&source_path, &parent_path)?;
                selection.expected_source = Some(source.clone());
                if source.kind == DesktopFileKind::Directory {
                    selection.effect = Some(DesktopNamespaceEffect::Remove {
                        old_path: source_path,
                    });
                }
            }
            _ => return Err(remote_files::map_error(engine::Error::Invalid)),
        }

        Ok(selection)
    }

    /// Merge Store's read-only preview with the origin workspace. The returned
    /// IDs use the same bounded sorted order as namespace plans.
    pub(super) fn with_guarded_ids(
        mut self,
        previewed: &[WorkspaceId],
    ) -> Result<Self, RemoteError> {
        let mut ids = BTreeSet::new();
        ids.insert(self.origin_workspace_id);
        ids.extend(previewed.iter().copied());
        if ids.len() > MAX_GUARDED_WORKSPACES {
            return Err(remote_files::map_error(engine::Error::Limit));
        }
        self.guarded_workspace_ids = ids.into_iter().collect();
        Ok(self)
    }
}

fn entry(id: &lomi_remote_protocol::EntryId) -> EntryRef {
    EntryRef::from_bytes(id.to_bytes())
}

fn require_directory(source: &DesktopSourcePrecondition) -> Result<(), RemoteError> {
    if source.kind == DesktopFileKind::Directory && source.identity.is_valid() {
        Ok(())
    } else {
        Err(remote_files::map_error(engine::Error::Changed))
    }
}

fn require_parent(child: &std::path::Path, parent: &std::path::Path) -> Result<(), RemoteError> {
    if child.parent() == Some(parent) {
        Ok(())
    } else {
        Err(remote_files::map_error(engine::Error::Changed))
    }
}

fn validate_new_name(name: &str) -> Result<(), RemoteError> {
    if name.eq_ignore_ascii_case(".git") || engine::is_private_staging_name(name.as_bytes()) {
        return Err(remote_files::map_error(engine::Error::Protected));
    }
    if name.is_empty()
        || name.len() > 255
        || name == "."
        || name == ".."
        || name
            .chars()
            .any(|character| character == '/' || character == '\\' || character.is_control())
    {
        return Err(remote_files::map_error(engine::Error::Invalid));
    }
    Ok(())
}
