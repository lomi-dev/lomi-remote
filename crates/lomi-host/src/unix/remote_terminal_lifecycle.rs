//! Remote terminal.create / split / close / restart.
//!
//! These are the only remote operations with a physical effect (spawn or stop of
//! a host-owned PTY). They follow the closed rename/move boundary and add one
//! rule: a single retained Shared announcement spans
//!
//!   start (admit + Running, one permit) -> physical effect -> completion
//!
//! with Domain and Store released while the effect runs. The effect is gated by
//! the announcement's lock-free `effect_current` predicate, so a competing
//! writer, revoke, unshare, cancellation or deadline stops it before exec or
//! stop. A failed start or completion keeps the permit for persistence-only
//! reconciliation (`DeferredCompletion`); an uncertain effect is never replayed.
//!
//! Never call local `rpc::mutate`/dispatch: the consumer's signed rights and
//! the remote channel gate stay authoritative end to end.
use super::{
    Coordinator,
    auth::{
        RemoteWorkerEvidence,
        peer::VerifiedCurrentPeer,
        remote_connection::{QueuedRequest, RemoteConnectionState},
    },
    remote_terminal_rename::RemoteRenameOutcome,
    rpc::{self, CompletionSlot, DeferredCompletion},
    shared_owner::{
        RemoteEffectBegin, RemoteEffectCompletion, RemoteEffectOutcome, RemoteFilePlan,
        RemoteRenameError, RemoteTerminalEffectWrite,
    },
};
use lomi_remote_protocol::{Effect, OperationState, rpc::RpcRequest};
use std::time::{Duration, Instant};

fn is_busy(error: &RemoteRenameError) -> bool {
    matches!(
        error,
        RemoteRenameError::Owner(super::shared_owner::Error::Domain(
            super::owner_domain::Error::Busy
        )) | RemoteRenameError::Owner(super::shared_owner::Error::Store(
            lomi_host_store::StoreError::Busy
        ))
    )
}

fn pause(worker: &RemoteWorkerEvidence<'_, '_, '_, '_>) -> Result<(), RemoteRenameError> {
    worker
        .operation()
        .check()
        .map_err(|_| RemoteRenameError::Closed)?;
    std::thread::park_timeout(
        worker
            .operation()
            .deadline()
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(1)),
    );
    Ok(())
}

/// Caller holds the workspace actor and has already reconciled exited sessions.
pub(super) fn run<'d, 'o, 'e, 'w, 'p, 's>(
    coordinator: &Coordinator,
    connection: &mut RemoteConnectionState,
    worker: &'e RemoteWorkerEvidence<'w, 'p, 's, 'o>,
    peer: &'e VerifiedCurrentPeer,
    owner: &'d super::shared_owner::SharedOwner,
    original: &RpcRequest,
    queued: &QueuedRequest,
    file_guarded_ids: Option<&[lomi_remote_protocol::WorkspaceId]>,
) -> Result<RemoteRenameOutcome<'d, 'o, 'e, 'w, 'p, 's>, RemoteRenameError> {
    use lomi_remote_protocol::rpc::RpcCall;
    // (operation id, workspace, terminal domain revision CAS if any).
    let (_operation_id, workspace, expected_revision) = match &original.call {
        RpcCall::TerminalCreate(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            Some(p.mutation.expected_revision),
        ),
        RpcCall::TerminalSplit(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            Some(p.mutation.expected_revision),
        ),
        RpcCall::TerminalClose(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            Some(p.mutation.expected_revision),
        ),
        RpcCall::TerminalRestart(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            Some(p.mutation.expected_revision),
        ),
        RpcCall::FilesCreate(p) | RpcCall::FilesMkdir(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            None,
        ),
        RpcCall::FilesRename(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            None,
        ),
        RpcCall::FilesRemove(p) => (
            p.mutation.operation_id,
            p.mutation.context.workspace_id,
            None,
        ),
        _ => return Err(RemoteRenameError::Closed),
    };
    let is_file = expected_revision.is_none();
    if is_file && file_guarded_ids.is_none() {
        return Err(RemoteRenameError::Closed);
    }
    // A previous effect whose completion could not be persisted must settle
    // under maintenance before this workspace may run another effect.
    rpc::ensure_workspace_settled(coordinator, workspace).map_err(|_| RemoteRenameError::Closed)?;
    // Capacity for persistence-only recovery is reserved BEFORE any admission or
    // physical effect, so a failed completion can always retain its permit.
    let slot = CompletionSlot::reserve(coordinator, worker.operation(), workspace)
        .map_err(|_| RemoteRenameError::Closed)?;

    let begin = if is_file {
        owner.begin_remote_file_mutation(worker, peer, connection, original, queued)?
    } else {
        owner.begin_remote_terminal_lifecycle(worker, peer, connection, original, queued)?
    };
    let mut write = match begin {
        RemoteEffectBegin::Duplicate(receipt) => {
            return Ok(RemoteRenameOutcome::Duplicate(receipt));
        }
        RemoteEffectBegin::Rejected(error) => {
            return Ok(RemoteRenameOutcome::Rejected(error));
        }
        RemoteEffectBegin::Write(write) => write,
    };

    loop {
        if !worker.current() {
            defer_if_permit(&slot, &mut write, no_effect_failure(), None);
            return Err(RemoteRenameError::Closed);
        }
        match write.try_start() {
            Ok(()) => break,
            Err(error) if is_busy(&error) => {
                if let Err(error) = pause(worker) {
                    defer_if_permit(&slot, &mut write, no_effect_failure(), None);
                    return Err(error);
                }
            }
            Err(error) => {
                // A stale revision is rejected by the Store with no residue and
                // no permit: answer it, since nothing was journaled or run.
                if let Some(expected) = expected_revision
                    && matches!(
                        error,
                        RemoteRenameError::Owner(super::shared_owner::Error::Store(
                            lomi_host_store::StoreError::RevisionConflict
                        ))
                    )
                    && write.take_permit().is_none()
                {
                    return Ok(RemoteRenameOutcome::Rejected(
                        rpc::pre_effect_rejection(rpc::revision_conflict(
                            expected,
                            write.plan().before.domain_revision,
                        ))
                        .ok_or(RemoteRenameError::Closed)?,
                    ));
                }
                // Started only if the Store accepted it. The effect never ran,
                // so a retained permit is persisted as a known no-effect failure.
                defer_if_permit(&slot, &mut write, no_effect_failure(), None);
                return Err(error);
            }
        }
    }

    let mut namespace = None;
    let (outcome, file_error, spawn_refused) = match write.file_plan().cloned() {
        Some(plan) => {
            let (outcome, error) = match perform_file_effect(
                coordinator,
                &mut write,
                &plan,
                file_guarded_ids.ok_or(RemoteRenameError::Closed)?,
                &mut namespace,
            ) {
                Ok(outcome) => outcome,
                Err(error) => {
                    defer_if_permit(&slot, &mut write, no_effect_failure(), namespace.take());
                    return Err(error);
                }
            };
            (outcome, error, false)
        }
        None => perform_terminal_effect(coordinator, &write, worker.operation().deadline()),
    };

    if outcome.state == OperationState::Failed
        && outcome.effect == Effect::None
        && let Some(error) = file_error
    {
        write.set_refusal(super::remote_files::map_error(error));
    }
    if outcome.state == OperationState::Failed && outcome.effect == Effect::None && spawn_refused {
        // The shell really could not be started (for example execve failed):
        // a known no-effect failure, answered as an ordinary error.
        write.set_refusal(
            lomi_remote_protocol::RemoteError::new(
                lomi_remote_protocol::ErrorCode::HostBusy,
                false,
                Effect::None,
                lomi_remote_protocol::ErrorDetails::empty(),
                None,
            )
            .expect("static safe error"),
        );
    }

    loop {
        let evidence = namespace.as_ref().and_then(|namespace| {
            namespace
                .completion_proof(&outcome, &mut || {
                    worker
                        .operation()
                        .check()
                        .map_err(|_| lomi_files::desktop::DesktopFileErrorCode::Revoked)
                })
                .ok()
        });
        match write.try_complete(&outcome, evidence.as_ref()) {
            Ok(RemoteEffectCompletion::Delivered(receipt)) => {
                return Ok(RemoteRenameOutcome::Committed(receipt));
            }
            // Durable final receipt, not a committed success: withhold on this
            // connection; the client reads it back by exact duplicate lookup.
            Ok(RemoteEffectCompletion::Settled) => return Err(RemoteRenameError::Closed),
            Err(error) if is_busy(&error) => {
                if let Err(error) = pause(worker) {
                    defer_if_permit(&slot, &mut write, outcome, namespace.take());
                    return Err(error);
                }
            }
            Err(error) => {
                defer_if_permit(&slot, &mut write, outcome, namespace.take());
                return Err(error);
            }
        }
    }
}

/// Runs the one file syscall of the sealed request. Known refusals (identity,
/// revision, protection, existence) are Failed/None; an OS error after the
/// syscall started is uncertain and never replayed.
fn perform_file_effect(
    coordinator: &Coordinator,
    write: &mut RemoteTerminalEffectWrite<'_, '_, '_, '_, '_, '_>,
    plan: &RemoteFilePlan,
    guarded_ids: &[lomi_remote_protocol::WorkspaceId],
    namespace: &mut Option<Box<super::remote_namespace_effect::RemoteNamespaceEffect>>,
) -> Result<(RemoteEffectOutcome, Option<lomi_files::Error>), RemoteRenameError> {
    use super::remote_file_namespace::FileNamespaceSelection;
    use lomi_files::desktop::DesktopFileErrorCode;
    let mut selection = match FileNamespaceSelection::capture(&coordinator.files, plan) {
        Ok(selection) => selection,
        Err(error) => {
            write.set_refusal(error);
            return Ok((no_effect_failure(), None));
        }
    };
    if let Some(effect) = selection.effect.clone() {
        let (plan, roots) = write.file_namespace_plan(effect)?;
        if !plan
            .guarded_workspace_ids()
            .iter()
            .all(|id| guarded_ids.contains(id))
        {
            return Err(RemoteRenameError::Closed);
        }
        selection = selection
            .with_guarded_ids(plan.guarded_workspace_ids())
            .map_err(|_| RemoteRenameError::Closed)?;
        let captured = super::remote_namespace_effect::RemoteNamespaceEffect::capture(
            plan,
            &selection,
            &roots,
            &mut || {
                if write.effect_current() {
                    Ok(())
                } else {
                    Err(DesktopFileErrorCode::Revoked)
                }
            },
        )
        .map_err(|_| RemoteRenameError::Closed)?;
        *namespace = Some(captured);
        let captured = namespace.as_ref().ok_or(RemoteRenameError::Closed)?;
        write.prepare_file_namespace(&captured.plan, &captured.prepared_proof())?;
    }
    Ok(perform_file_plan(
        coordinator,
        plan,
        selection.expected_source.as_ref(),
        |phase| {
            if !write.effect_current() {
                return false;
            }
            if phase == lomi_files::LocalNativeFileCheckPhase::BeforeEffect
                && let Some(namespace) = namespace.as_ref()
                && namespace
                    .verify_before_effect(&mut || {
                        if write.effect_current() {
                            Ok(())
                        } else {
                            Err(DesktopFileErrorCode::Revoked)
                        }
                    })
                    .is_err()
            {
                return false;
            }
            write.effect_current()
        },
    ))
}

/// Execute one pinned FileRoot mutation through the same revision and identity
/// checks for local IPC and remote workspace requests. The caller supplies the
/// last-moment owner/cancellation fence; this function performs no journaling.
pub(super) fn perform_file_plan(
    coordinator: &Coordinator,
    plan: &RemoteFilePlan,
    expected_source: Option<&lomi_files::desktop::DesktopSourcePrecondition>,
    mut effect_current: impl FnMut(lomi_files::LocalNativeFileCheckPhase) -> bool,
) -> (RemoteEffectOutcome, Option<lomi_files::Error>) {
    use lomi_files::{EntryRef, Error as E};
    use lomi_remote_protocol::{EntryId, FileRevision, OperationResult, rpc::RpcCall};
    let fail = |error: E| {
        let (state, effect) = match error {
            E::Io(kind) if kind != std::io::ErrorKind::PermissionDenied => {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            }
            _ => (OperationState::Failed, Effect::None),
        };
        (
            RemoteEffectOutcome {
                state,
                effect,
                result: None,
                projection: None,
            },
            Some(error),
        )
    };
    let files = match coordinator
        .files
        .get_engine(plan.workspace_id, plan.epoch, &plan.root)
    {
        Ok(files) => files,
        Err(error) => return fail(error),
    };
    // Lock-free fence immediately before the syscall: a competing writer,
    // revoke, unshare, cancellation or deadline stops it. No engine error is
    // blamed on the client for a fence.
    if !effect_current(lomi_files::LocalNativeFileCheckPhase::Progress) {
        return (no_effect_failure(), None);
    }
    let entry = |id: &EntryId| EntryRef::from_bytes(id.to_bytes());
    let mut gate_denied = false;
    let mut check = |phase| {
        if !effect_current(phase) {
            gate_denied = true;
            false
        } else {
            true
        }
    };
    let outcome = match &plan.call {
        RpcCall::FilesCreate(p) => files.create_file_guarded(
            entry(&p.parent_entry_id),
            p.parent_revision.as_str(),
            p.name.as_str().as_bytes(),
            &mut check,
        ),
        RpcCall::FilesMkdir(p) => files.mkdir_guarded(
            entry(&p.parent_entry_id),
            p.parent_revision.as_str(),
            p.name.as_str().as_bytes(),
            &mut check,
        ),
        RpcCall::FilesRename(p) => files.rename_guarded(
            entry(&p.entry_id),
            p.file_revision.as_str(),
            entry(&p.source_parent_id),
            p.source_parent_revision.as_str(),
            entry(&p.target_parent_id),
            p.target_parent_revision.as_str(),
            p.name.as_str().as_bytes(),
            expected_source,
            &mut check,
        ),
        RpcCall::FilesRemove(p) => files
            .remove_guarded(
                entry(&p.entry_id),
                p.file_revision.as_str(),
                entry(&p.parent_entry_id),
                p.parent_revision.as_str(),
                expected_source,
                &mut check,
            )
            .map(|()| lomi_files::Meta {
                entry: entry(&p.entry_id),
                name: Vec::new(),
                kind: lomi_files::Kind::Other,
                size: 0,
                revision: p.file_revision.as_str().to_owned(),
                nlink: 0,
            }),
        _ => return fail(E::Invalid),
    };
    match outcome {
        Ok(meta) => {
            let result = EntryId::from_bytes(meta.entry.to_bytes())
                .ok()
                .zip(FileRevision::try_from(meta.revision).ok())
                .map(|(entry_id, file_revision)| OperationResult::File {
                    entry_id,
                    file_revision,
                });
            // The syscall happened; a result we cannot encode is uncertain
            // bookkeeping, never a replay.
            let Some(result) = result else {
                return fail(E::Io(std::io::ErrorKind::Other));
            };
            (
                RemoteEffectOutcome {
                    state: OperationState::Succeeded,
                    effect: Effect::Committed,
                    result: Some(result),
                    projection: None,
                },
                None,
            )
        }
        Err(_) if gate_denied => (no_effect_failure(), None),
        Err(error) => fail(error),
    }
}

pub(super) fn no_effect_failure() -> RemoteEffectOutcome {
    RemoteEffectOutcome {
        state: OperationState::Failed,
        effect: Effect::None,
        result: None,
        projection: None,
    }
}

fn defer_if_permit(
    slot: &CompletionSlot<'_>,
    write: &mut RemoteTerminalEffectWrite<'_, '_, '_, '_, '_, '_>,
    outcome: RemoteEffectOutcome,
    namespace: Option<Box<super::remote_namespace_effect::RemoteNamespaceEffect>>,
) {
    if let Some(permit) = write.take_permit() {
        if let Some(namespace) = namespace {
            slot.defer(DeferredCompletion::Namespace {
                binding: write.binding().clone(),
                permit,
                outcome,
                namespace,
            });
            return;
        }
        slot.defer(DeferredCompletion::Complete {
            binding: write.binding().clone(),
            permit,
            state: outcome.state,
            effect: outcome.effect,
            result: outcome.result,
            projection: outcome.projection,
        });
    }
}

/// Runs the stop and/or spawn of the sealed plan. Every PTY boundary re-checks
/// the lock-free predicate; the classification mirrors the local lifecycle so a
/// possible-but-unproven effect is recorded as unknown and never repeated.
/// Returns the outcome and whether it is a genuine spawn refusal (as opposed to
/// a fence, which never produces an answer for the client).
fn perform_terminal_effect(
    coordinator: &Coordinator,
    write: &RemoteTerminalEffectWrite<'_, '_, '_, '_, '_, '_>,
    deadline: Instant,
) -> (RemoteEffectOutcome, Option<lomi_files::Error>, bool) {
    let mut refused = false;
    let outcome = perform_effect(coordinator, write, deadline, &mut refused);
    (outcome, None, refused)
}

fn perform_effect(
    coordinator: &Coordinator,
    write: &RemoteTerminalEffectWrite<'_, '_, '_, '_, '_, '_>,
    deadline: Instant,
    refused: &mut bool,
) -> RemoteEffectOutcome {
    let lifecycle = write.plan();
    let plan = &lifecycle.plan;
    if let Some(target) = &plan.stop
        && let Err(error) = coordinator
            .terminals
            .stop_checked(target.session_id, || write.effect_current())
    {
        let (state, effect) = if error == lomi_terminal::Error::FenceRejected {
            (OperationState::Failed, Effect::None)
        } else {
            (OperationState::OutcomeUnknown, Effect::Unknown)
        };
        return RemoteEffectOutcome {
            state,
            effect,
            result: None,
            projection: None,
        };
    }
    if let Some((target, _)) = &plan.spawn {
        let stopped = || rpc::stopped_after_restart(&lifecycle.before, plan);
        if !write.effect_current() {
            let (state, effect) = if plan.stop.is_some() {
                (OperationState::OutcomeUnknown, Effect::Unknown)
            } else {
                (OperationState::Failed, Effect::None)
            };
            return RemoteEffectOutcome {
                state,
                effect,
                result: None,
                projection: stopped(),
            };
        }
        let Some(profile) = lifecycle.profile.as_ref() else {
            return no_effect_failure();
        };
        if let Err(error) = coordinator.terminals.spawn_with_checks_until(
            target.session_id,
            target.session_epoch,
            profile,
            deadline,
            || write.effect_current(),
            || Ok(()),
        ) {
            let (state, effect) =
                if plan.stop.is_some() || error == lomi_terminal::Error::SpawnOutcomeUnknown {
                    (OperationState::OutcomeUnknown, Effect::Unknown)
                } else {
                    *refused = error != lomi_terminal::Error::FenceRejected;
                    (OperationState::Failed, Effect::None)
                };
            return RemoteEffectOutcome {
                state,
                effect,
                result: None,
                projection: stopped(),
            };
        }
    }
    RemoteEffectOutcome {
        state: OperationState::Succeeded,
        effect: Effect::Committed,
        result: Some(plan.result.clone()),
        projection: Some(plan.state.clone()),
    }
}
