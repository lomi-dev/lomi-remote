//! Host orchestration for durably fenced workspace removal.
//!
//! The caller of `remove_workspace` already owns the workspace actor and has
//! settled its deferred completion queue. Store transactions and terminal
//! retirement are separate phases: no Domain, Store, or terminal Core lock is
//! held while an exact session is being stopped.

use super::{Coordinator, LocalError, owner_domain::Operation, rpc, shared_owner};
use lomi_host_store::{
    WorkspaceRemovalRecord, WorkspaceRemovalSessionState, WorkspaceRemovalState,
};
use lomi_remote_protocol::{OperationId, WorkspaceId};
use std::{
    collections::BTreeSet,
    sync::{Mutex, OnceLock, TryLockError, atomic::Ordering},
};

const MAX_ACTIVE_REMOVALS: usize = 256;

type RemovalKey = (WorkspaceId, OperationId);

fn active_removals() -> &'static Mutex<BTreeSet<RemovalKey>> {
    static ACTIVE: OnceLock<Mutex<BTreeSet<RemovalKey>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(BTreeSet::new()))
}

/// In-memory processing observation only. It never authorizes terminal cleanup
/// and is dropped when the current Host worker ends.
struct ActiveRemoval(RemovalKey);

impl ActiveRemoval {
    fn register(key: RemovalKey) -> Option<Self> {
        let mut active = active_removals().try_lock().ok()?;
        if active.contains(&key) || active.len() >= MAX_ACTIVE_REMOVALS {
            return None;
        }
        active.insert(key);
        Some(Self(key))
    }

    fn contains(key: RemovalKey) -> bool {
        match active_removals().try_lock() {
            Ok(active) => active.contains(&key),
            Err(TryLockError::WouldBlock | TryLockError::Poisoned(_)) => false,
        }
    }

    fn current(&self) -> bool {
        Self::contains(self.0)
    }
}

impl Drop for ActiveRemoval {
    fn drop(&mut self) {
        match active_removals().lock() {
            Ok(mut active) => {
                active.remove(&self.0);
            }
            Err(poisoned) => {
                poisoned.into_inner().remove(&self.0);
            }
        }
    }
}

/// Record is safe to present as the persisted phase. Uncertain also covers an
/// unconfirmed Store write; its embedded record may still say Stopping, which
/// remains fenced and must never be represented as completed.
#[derive(Debug, Clone)]
pub(super) enum WorkspaceRemovalOutcome {
    Record(WorkspaceRemovalRecord),
    Uncertain(WorkspaceRemovalRecord),
}

impl WorkspaceRemovalOutcome {
    fn from_record(record: WorkspaceRemovalRecord, active: bool) -> Self {
        match record.state {
            WorkspaceRemovalState::Complete => Self::Record(record),
            WorkspaceRemovalState::Uncertain => Self::Uncertain(record),
            WorkspaceRemovalState::Stopping if active => Self::Record(record),
            WorkspaceRemovalState::Stopping => Self::Uncertain(record),
        }
    }
}

/// Begin or return status for a removal. The caller must hold the workspace
/// actor for this exact workspace and must not call it after dropping that
/// actor. Existing attempts never produce authority and never stop a session.
pub(super) fn remove_workspace(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    workspace_id: WorkspaceId,
) -> Result<WorkspaceRemovalOutcome, LocalError> {
    operation.check().map_err(|_| LocalError::Unavailable)?;

    if let Some(record) = rpc::owner_call(operation, || {
        coordinator
            .owner
            .workspace_removal_status(operation, workspace_id)
    })
    .map_err(super::owner_error)?
    {
        let begin = begin_existing_status(coordinator, operation, &record)?;
        debug_assert!(begin.authority.is_none());
        return Ok(WorkspaceRemovalOutcome::from_record(
            begin.record,
            ActiveRemoval::contains((workspace_id, record.attempt_id)),
        ));
    }

    // Preserve this exact trusted context/revision through the begin CAS. The
    // Store revalidates it and its actual quiescence under the write txn.
    let project = rpc::owner_call(operation, || {
        coordinator.owner.workspace(operation, workspace_id)
    })
    .map_err(super::owner_error)?;
    let mut begin_turn = rpc::owner_call(operation, || {
        coordinator.owner.begin_workspace_removal(
            operation,
            workspace_id,
            project.state.context.clone(),
            project.state.domain_revision,
        )
    })
    .map_err(super::owner_error)?;
    let begin = match rpc::owner_call(operation, || begin_turn.try_commit()) {
        Ok(begin) => begin,
        Err(error) => {
            if let Some(failed) = begin_turn.take_unconfirmed() {
                if let Some(completion) = failed.completion {
                    return Ok(mark_uncertain(&completion, failed.record, None));
                }
                return Ok(WorkspaceRemovalOutcome::Uncertain(failed.record));
            }
            return Err(super::owner_error(error));
        }
    };
    let Some(authority) = begin.authority else {
        return Ok(WorkspaceRemovalOutcome::from_record(
            begin.record.clone(),
            ActiveRemoval::contains((workspace_id, begin.record.attempt_id)),
        ));
    };

    // This capability is created before any terminal stop and is restricted to
    // exact Store checkpoints, uncertainty, finalization, and status reads.
    let completion = coordinator.owner.workspace_removal_completion(authority);
    let Some(active) = ActiveRemoval::register((workspace_id, begin.record.attempt_id)) else {
        return Ok(mark_uncertain(&completion, begin.record, None));
    };

    let mut record = begin.record;
    for session in record.sessions.clone() {
        if session.state != WorkspaceRemovalSessionState::Pending {
            continue;
        }
        // Once cancellation/deadline is observed, no further physical stop is
        // attempted. Completion bookkeeping uses the closed Store-only ticket.
        if coordinator.stopping.load(Ordering::Acquire)
            || operation.check().is_err()
            || !active.current()
        {
            return Ok(mark_uncertain(&completion, record, None));
        }
        let stop = coordinator.terminals.stop_exact_checked(
            session.session_id,
            session.session_epoch,
            || {
                !coordinator.stopping.load(Ordering::Acquire)
                    && operation.check().is_ok()
                    && active.current()
            },
        );
        if stop.is_err() {
            // SessionMissing and all other errors are unresolved, never proof.
            return Ok(mark_uncertain(
                &completion,
                record,
                Some((session.session_id, session.session_epoch)),
            ));
        }

        match completion.checkpoint(session.session_id, session.session_epoch) {
            Ok(updated) => record = updated,
            Err(_) => {
                // The terminal stopped once. A checkpoint retry is Store-only;
                // if it cannot be confirmed, do not call stop_exact_checked again.
                return Ok(mark_uncertain(
                    &completion,
                    record,
                    Some((session.session_id, session.session_epoch)),
                ));
            }
        }

        let more_pending = record
            .sessions
            .iter()
            .any(|candidate| candidate.state == WorkspaceRemovalSessionState::Pending);
        if more_pending
            && (coordinator.stopping.load(Ordering::Acquire)
                || operation.check().is_err()
                || !active.current())
        {
            return Ok(mark_uncertain(&completion, record, None));
        }
    }

    match completion.finalize() {
        Ok(record) => Ok(WorkspaceRemovalOutcome::Record(record)),
        Err(_) => {
            // Finalization is SQL-only and may complete after request expiry.
            // Confirm its post-state before choosing the response.
            if let Some(record) = completion.status().ok().flatten() {
                if record.state == WorkspaceRemovalState::Complete {
                    return Ok(WorkspaceRemovalOutcome::Record(record));
                }
            }
            Ok(mark_uncertain(&completion, record, None))
        }
    }
}

fn begin_existing_status(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    record: &WorkspaceRemovalRecord,
) -> Result<lomi_host_store::WorkspaceRemovalBegin, LocalError> {
    let mut turn = rpc::owner_call(operation, || {
        coordinator.owner.begin_workspace_removal(
            operation,
            record.workspace_id,
            record.source_context.clone(),
            record.source_revision,
        )
    })
    .map_err(super::owner_error)?;
    rpc::owner_call(operation, || turn.try_commit()).map_err(super::owner_error)
}

fn mark_uncertain(
    completion: &shared_owner::WorkspaceRemovalCompletion,
    fallback: WorkspaceRemovalRecord,
    unknown_session: Option<(
        lomi_remote_protocol::TerminalSessionId,
        lomi_remote_protocol::SessionEpoch,
    )>,
) -> WorkspaceRemovalOutcome {
    match completion.mark_uncertain(unknown_session) {
        Ok(record) => WorkspaceRemovalOutcome::from_record(record, false),
        Err(_) => match completion.status() {
            Ok(Some(record)) => WorkspaceRemovalOutcome::from_record(record, false),
            _ => WorkspaceRemovalOutcome::Uncertain(fallback),
        },
    }
}

/// Read status while the caller owns the same workspace actor used by removal.
/// A completed worker that left a durable Stopping row is surfaced as
/// operationally Uncertain without mutating that row or claiming persistence.
pub(super) fn workspace_removal_status(
    coordinator: &Coordinator,
    operation: &Operation<'_>,
    workspace_id: WorkspaceId,
) -> Result<Option<WorkspaceRemovalOutcome>, LocalError> {
    let record = rpc::owner_call(operation, || {
        coordinator
            .owner
            .workspace_removal_status(operation, workspace_id)
    })
    .map_err(super::owner_error)?;
    Ok(record.map(|record| {
        let active = ActiveRemoval::contains((workspace_id, record.attempt_id));
        WorkspaceRemovalOutcome::from_record(record, active)
    }))
}
