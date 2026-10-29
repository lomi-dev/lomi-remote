//! Shared workspace actors for an owner-local filesystem namespace effect.
//!
//! This graph deliberately does not own Coordinator or NativeEditorHost: an
//! effect thread may outlive the client, but must never become responsible for
//! dropping and joining its own executor.

use super::{Coordinator, LocalError, owner_domain::Operation, rpc, shared_owner};
use lomi_files::{LocalNativeFileCheckPhase, desktop::DesktopFileErrorCode};
use lomi_host_store::{DesktopNamespaceEffect, DesktopNamespacePlan, StoreError};
use lomi_remote_protocol::{
    TerminalContext, WorkspaceId,
    ipc::NativeIntentId,
    rpc::{PaneState, TerminalLayout},
};
use lomi_terminal::TerminalService;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, Weak},
};

pub(super) type WorkspaceActors = Mutex<BTreeMap<WorkspaceId, Weak<Mutex<()>>>>;

pub(super) fn workspace_lock(
    registry: &WorkspaceActors,
    id: WorkspaceId,
) -> Result<Arc<Mutex<()>>, LocalError> {
    let mut locks = registry.lock().map_err(|_| LocalError::Unavailable)?;
    if let Some(lock) = locks.get(&id).and_then(Weak::upgrade) {
        return Ok(lock);
    }
    locks.retain(|_, weak| weak.strong_count() > 0);
    if locks.len() >= 200 {
        return Err(LocalError::Unavailable);
    }
    let lock = Arc::new(Mutex::new(()));
    locks.insert(id, Arc::downgrade(&lock));
    Ok(lock)
}

#[derive(Clone)]
pub(super) struct NativeNamespaceRuntime {
    pub(super) owner: Arc<shared_owner::SharedOwner>,
    terminals: Arc<TerminalService>,
    actors: Arc<WorkspaceActors>,
    completions: Arc<Mutex<rpc::CompletionQueue>>,
}

impl NativeNamespaceRuntime {
    pub(super) fn new(coordinator: &Coordinator) -> Self {
        Self {
            owner: coordinator.owner.clone(),
            terminals: coordinator.terminals.clone(),
            actors: coordinator.workspace_locks.clone(),
            completions: coordinator.deferred_completions.clone(),
        }
    }

    /// All guards are acquired in the effect thread, in canonical order. The
    /// closure performs preparation and the exact filesystem effect while
    /// these guards remain held; no MutexGuard crosses the join boundary.
    pub(super) fn with_native_plan<T>(
        &self,
        operation: &Operation<'_>,
        operation_id: NativeIntentId,
        effect: DesktopNamespaceEffect,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
        action: impl FnOnce(
            DesktopNamespacePlan,
            Vec<(WorkspaceId, PathBuf)>,
            &mut dyn FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
        ) -> Result<T, DesktopFileErrorCode>,
    ) -> Result<T, DesktopFileErrorCode> {
        check(LocalNativeFileCheckPhase::Progress)?;
        let initial = rpc::owner_call(operation, || {
            self.owner
                .native_namespace_plan(operation, operation_id, effect.clone())
        })
        .map_err(owner_error)?;
        let mut guarded_ids = initial.guarded_workspace_ids().to_vec();
        guarded_ids.sort_by_key(|id| id.to_bytes());
        guarded_ids.dedup();
        let actors = guarded_ids
            .iter()
            .map(|id| workspace_lock(&self.actors, *id).map_err(|_| DesktopFileErrorCode::Limit))
            .collect::<Result<Vec<_>, _>>()?;
        let mut guards = Vec::with_capacity(actors.len());
        for actor in &actors {
            check(LocalNativeFileCheckPhase::Progress)?;
            guards.push(
                rpc::actor_lock(actor, operation).map_err(|_| DesktopFileErrorCode::Revoked)?,
            );
        }
        for id in &guarded_ids {
            rpc::ensure_workspace_queue_settled(&self.completions, *id)
                .map_err(|_| DesktopFileErrorCode::Changed)?;
        }
        if matches!(effect, DesktopNamespaceEffect::Remove { .. }) {
            // Quiescing changes consent and stops actual sessions, so it needs
            // authorization too. The publisher obtains a separate fresh
            // BeforeEffect decision after any slow cleanup has finished.
            check(LocalNativeFileCheckPhase::BeforeEffect)?;
            for workspace in initial.workspaces() {
                self.quiesce(operation, workspace.workspace_id, check)?;
            }
        }
        let plan = rpc::owner_call(operation, || {
            self.owner
                .native_namespace_plan(operation, operation_id, effect.clone())
        })
        .map_err(owner_error)?;
        let mut current_ids = plan.guarded_workspace_ids().to_vec();
        current_ids.sort_by_key(|id| id.to_bytes());
        if current_ids != guarded_ids || plan.workspaces() != initial.workspaces() {
            return Err(DesktopFileErrorCode::Changed);
        }
        let projects =
            rpc::owner_call(operation, || self.owner.workspaces(operation)).map_err(owner_error)?;
        let roots = guarded_ids
            .iter()
            .map(|id| {
                projects
                    .iter()
                    .find(|project| project.state.context.workspace_id == *id)
                    .map(|project| (*id, project.local_root.clone()))
                    .ok_or(DesktopFileErrorCode::Changed)
            })
            .collect::<Result<Vec<_>, _>>()?;
        check(LocalNativeFileCheckPhase::Progress)?;
        action(plan, roots, check)
    }

    fn quiesce(
        &self,
        operation: &Operation<'_>,
        id: WorkspaceId,
        check: &mut impl FnMut(LocalNativeFileCheckPhase) -> Result<(), DesktopFileErrorCode>,
    ) -> Result<(), DesktopFileErrorCode> {
        check(LocalNativeFileCheckPhase::Progress)?;
        let project = rpc::owner_call(operation, || self.owner.workspace(operation, id))
            .map_err(owner_error)?;
        if project.consent {
            let mut unshare =
                rpc::owner_call(operation, || self.owner.begin_unshare(operation, id))
                    .map_err(owner_error)?;
            rpc::owner_call(operation, || unshare.try_commit()).map_err(owner_error)?;
        }
        // Unshare rotates contexts. Never use a session context captured before
        // that committed policy change for the exit/retirement transitions.
        let project = rpc::owner_call(operation, || self.owner.workspace(operation, id))
            .map_err(owner_error)?;
        let mut sessions = Vec::new();
        for tab in &project.state.tabs.0 {
            active_sessions(&tab.layout, &mut sessions)?;
        }
        for terminal in sessions {
            check(LocalNativeFileCheckPhase::Progress)?;
            self.terminals
                .stop_checked(terminal.session_id, || operation.check().is_ok())
                .map_err(|_| DesktopFileErrorCode::Changed)?;
            // Successful stop_checked proves this exact service entry was
            // removed and cleaned up. A pending spawn or unknown cleanup never
            // reaches these durable state transitions.
            let mut exited = rpc::owner_call(operation, || {
                self.owner.begin_terminal_exit(operation, &terminal)
            })
            .map_err(owner_error)?;
            if !rpc::owner_call(operation, || exited.try_commit()).map_err(owner_error)? {
                return Err(DesktopFileErrorCode::Changed);
            }
            drop(exited);
            let mut retired = rpc::owner_call(operation, || {
                self.owner.begin_terminal_retired(operation, &terminal)
            })
            .map_err(owner_error)?;
            if !rpc::owner_call(operation, || retired.try_commit()).map_err(owner_error)? {
                return Err(DesktopFileErrorCode::Changed);
            }
        }
        Ok(())
    }
}

fn active_sessions(
    layout: &TerminalLayout,
    sessions: &mut Vec<TerminalContext>,
) -> Result<(), DesktopFileErrorCode> {
    match layout {
        TerminalLayout::Pane { pane } => match pane.state {
            PaneState::Starting | PaneState::Publishing => Err(DesktopFileErrorCode::Changed),
            PaneState::Running => {
                sessions.push(pane.session.clone().ok_or(DesktopFileErrorCode::Changed)?);
                Ok(())
            }
            PaneState::Exited | PaneState::Stopped | PaneState::Lost => Ok(()),
        },
        TerminalLayout::Split { first, second, .. } => {
            active_sessions(first, sessions)?;
            active_sessions(second, sessions)
        }
    }
}

fn owner_error(error: shared_owner::Error) -> DesktopFileErrorCode {
    match error {
        shared_owner::Error::Store(StoreError::ResourceExhausted) => DesktopFileErrorCode::Limit,
        shared_owner::Error::Store(StoreError::Invalid) => DesktopFileErrorCode::Invalid,
        shared_owner::Error::Store(
            StoreError::Fenced
            | StoreError::RevisionConflict
            | StoreError::NotFound
            | StoreError::Busy,
        ) => DesktopFileErrorCode::Changed,
        shared_owner::Error::Domain(super::owner_domain::Error::Deadline) => {
            DesktopFileErrorCode::DeadlineExceeded
        }
        shared_owner::Error::Domain(super::owner_domain::Error::Cancelled) => {
            DesktopFileErrorCode::Revoked
        }
        _ => DesktopFileErrorCode::Io,
    }
}
