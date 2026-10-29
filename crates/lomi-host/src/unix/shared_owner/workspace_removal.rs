//! Classified Store turns for the Host workspace-removal protocol.
//!
//! The completion capability is minted only from a new Store authority. It
//! exposes exact Store bookkeeping and no terminal/process or arbitrary Store
//! operation. Each bookkeeping phase gets a short internal deadline because
//! it may need to finish after the client operation expires.

use super::{Error, Operation, SharedOwner, StoreTurn};
use lomi_host_store::{
    StoreError, WorkspaceRemovalAuthority, WorkspaceRemovalBegin, WorkspaceRemovalRecord,
};
use lomi_remote_protocol::{
    DecimalU64, SessionEpoch, TerminalSessionId, WorkspaceContext, WorkspaceId,
};
use std::{
    sync::{Arc, Mutex, atomic::AtomicBool},
    time::{Duration, Instant},
};

const COMPLETION_PHASE_BUDGET: Duration = Duration::from_secs(2);

#[must_use]
pub(in crate::unix) struct WorkspaceRemovalBeginWrite<'d, 'o> {
    turn: StoreTurn<'d, 'o, WorkspaceRemovalBegin>,
    owner: Arc<SharedOwner>,
    committed: Arc<Mutex<Option<WorkspaceRemovalBegin>>>,
}

pub(in crate::unix) struct WorkspaceRemovalBeginFailure {
    pub(in crate::unix) record: WorkspaceRemovalRecord,
    pub(in crate::unix) completion: Option<WorkspaceRemovalCompletion>,
}

impl WorkspaceRemovalBeginWrite<'_, '_> {
    pub(in crate::unix) fn try_commit(&mut self) -> Result<WorkspaceRemovalBegin, Error> {
        self.turn.try_commit()
    }

    /// Preserve a committed begin result after a later classified post-state
    /// failure. Authority is converted directly to the closed Store-only
    /// continuation, never returned to Host as stop authority.
    pub(in crate::unix) fn take_unconfirmed(&mut self) -> Option<WorkspaceRemovalBeginFailure> {
        let begin = self.committed.lock().ok()?.take()?;
        Some(WorkspaceRemovalBeginFailure {
            record: begin.record,
            completion: begin
                .authority
                .map(|authority| self.owner.workspace_removal_completion(authority)),
        })
    }
}

#[must_use]
pub(in crate::unix) struct WorkspaceRemovalCheckpointWrite<'d, 'o>(
    StoreTurn<'d, 'o, WorkspaceRemovalRecord>,
);

impl WorkspaceRemovalCheckpointWrite<'_, '_> {
    pub(in crate::unix) fn try_commit(&mut self) -> Result<WorkspaceRemovalRecord, Error> {
        self.0.try_commit()
    }
}

#[must_use]
pub(in crate::unix) struct WorkspaceRemovalUncertainWrite<'d, 'o>(
    StoreTurn<'d, 'o, WorkspaceRemovalRecord>,
);

impl WorkspaceRemovalUncertainWrite<'_, '_> {
    pub(in crate::unix) fn try_commit(&mut self) -> Result<WorkspaceRemovalRecord, Error> {
        self.0.try_commit()
    }
}

#[must_use]
pub(in crate::unix) struct WorkspaceRemovalFinalizeWrite<'d, 'o>(
    StoreTurn<'d, 'o, WorkspaceRemovalRecord>,
);

impl WorkspaceRemovalFinalizeWrite<'_, '_> {
    pub(in crate::unix) fn try_commit(&mut self) -> Result<WorkspaceRemovalRecord, Error> {
        self.0.try_commit()
    }
}

/// Store-only continuation for an already-created removal attempt. It cannot
/// expose or recreate its authority and has no API that can stop a terminal.
#[must_use]
pub(in crate::unix) struct WorkspaceRemovalCompletion {
    owner: Arc<SharedOwner>,
    authority: WorkspaceRemovalAuthority,
}

impl WorkspaceRemovalCompletion {
    pub(in crate::unix) fn checkpoint(
        &self,
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
    ) -> Result<WorkspaceRemovalRecord, Error> {
        let cancelled = AtomicBool::new(false);
        let operation = completion_operation(&cancelled)?;
        let mut turn = self.owner.begin_workspace_removal_checkpoint(
            &operation,
            self.authority,
            session_id,
            session_epoch,
        )?;
        super::super::rpc::owner_call(&operation, || turn.try_commit())
    }

    pub(in crate::unix) fn mark_uncertain(
        &self,
        unknown_session: Option<(TerminalSessionId, SessionEpoch)>,
    ) -> Result<WorkspaceRemovalRecord, Error> {
        let cancelled = AtomicBool::new(false);
        let operation = completion_operation(&cancelled)?;
        let mut turn = self.owner.begin_workspace_removal_uncertain(
            &operation,
            self.authority,
            unknown_session,
        )?;
        super::super::rpc::owner_call(&operation, || turn.try_commit())
    }

    pub(in crate::unix) fn finalize(&self) -> Result<WorkspaceRemovalRecord, Error> {
        let cancelled = AtomicBool::new(false);
        let operation = completion_operation(&cancelled)?;
        let mut turn = self
            .owner
            .begin_workspace_removal_finalize(&operation, self.authority)?;
        super::super::rpc::owner_call(&operation, || turn.try_commit())
    }

    pub(in crate::unix) fn status(&self) -> Result<Option<WorkspaceRemovalRecord>, Error> {
        let cancelled = AtomicBool::new(false);
        let operation = completion_operation(&cancelled)?;
        super::super::rpc::owner_call(&operation, || {
            self.owner
                .workspace_removal_status(&operation, self.authority.workspace_id())
        })
    }
}

fn completion_operation(cancelled: &AtomicBool) -> Result<Operation<'_>, Error> {
    let deadline = Instant::now()
        .checked_add(COMPLETION_PHASE_BUDGET)
        .ok_or(Error::Domain(super::domain::Error::Deadline))?;
    Ok(Operation::new(deadline, cancelled))
}

fn expected_removal_begin(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Fenced
            | StoreError::Invalid
            | StoreError::NotFound
            | StoreError::RevisionConflict
            | StoreError::NativeWriterBusy
            | StoreError::ResourceExhausted
    )
}

fn expected_removal_checkpoint(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy | StoreError::Fenced | StoreError::NotFound
    )
}

fn expected_removal_uncertain(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy | StoreError::Fenced | StoreError::NotFound
    )
}

fn expected_removal_finalize(error: StoreError) -> bool {
    matches!(
        error,
        StoreError::Busy
            | StoreError::Fenced
            | StoreError::Invalid
            | StoreError::NotFound
            | StoreError::ResourceExhausted
    )
}

impl SharedOwner {
    pub(in crate::unix) fn begin_workspace_removal<'d, 'o>(
        self: &'d Arc<Self>,
        operation: &'o Operation<'o>,
        workspace_id: WorkspaceId,
        expected_context: WorkspaceContext,
        expected_revision: DecimalU64,
    ) -> Result<WorkspaceRemovalBeginWrite<'d, 'o>, Error> {
        let committed = Arc::new(Mutex::new(None));
        let capture = committed.clone();
        let turn = self.begin_store_turn(
            operation,
            move |store| {
                let result = store.begin_workspace_removal(
                    workspace_id,
                    &expected_context,
                    expected_revision,
                );
                if let Ok(begin) = &result
                    && let Ok(mut committed) = capture.lock()
                {
                    *committed = Some(begin.clone());
                }
                result
            },
            expected_removal_begin,
        )?;
        Ok(WorkspaceRemovalBeginWrite {
            turn,
            owner: self.clone(),
            committed,
        })
    }

    pub(in crate::unix) fn workspace_removal_completion(
        self: &Arc<Self>,
        authority: WorkspaceRemovalAuthority,
    ) -> WorkspaceRemovalCompletion {
        WorkspaceRemovalCompletion {
            owner: self.clone(),
            authority,
        }
    }

    pub(in crate::unix) fn begin_workspace_removal_checkpoint<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authority: WorkspaceRemovalAuthority,
        session_id: TerminalSessionId,
        session_epoch: SessionEpoch,
    ) -> Result<WorkspaceRemovalCheckpointWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| {
                store.checkpoint_workspace_removal_session(&authority, session_id, session_epoch)
            },
            expected_removal_checkpoint,
        )
        .map(WorkspaceRemovalCheckpointWrite)
    }

    pub(in crate::unix) fn begin_workspace_removal_uncertain<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authority: WorkspaceRemovalAuthority,
        unknown_session: Option<(TerminalSessionId, SessionEpoch)>,
    ) -> Result<WorkspaceRemovalUncertainWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.mark_workspace_removal_uncertain(&authority, unknown_session),
            expected_removal_uncertain,
        )
        .map(WorkspaceRemovalUncertainWrite)
    }

    pub(in crate::unix) fn begin_workspace_removal_finalize<'d, 'o>(
        &'d self,
        operation: &'o Operation<'o>,
        authority: WorkspaceRemovalAuthority,
    ) -> Result<WorkspaceRemovalFinalizeWrite<'d, 'o>, Error> {
        self.begin_store_turn(
            operation,
            move |store| store.finalize_workspace_removal(&authority),
            expected_removal_finalize,
        )
        .map(WorkspaceRemovalFinalizeWrite)
    }

    pub(in crate::unix) fn workspace_removal_status(
        &self,
        operation: &Operation<'_>,
        workspace_id: WorkspaceId,
    ) -> Result<Option<WorkspaceRemovalRecord>, Error> {
        self.read(operation, |store| {
            store.workspace_removal_status(workspace_id)
        })
    }
}
