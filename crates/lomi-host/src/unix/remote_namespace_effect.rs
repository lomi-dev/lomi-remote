//! Retained physical evidence for one genuine remote filesystem operation.
//! This type never executes or repeats a mutation. It survives a lost receipt
//! so maintenance can only prove and persist what the original effect did.
use super::{
    desktop_namespace::PhysicalNamespacePins, remote_file_namespace::FileNamespaceSelection,
    shared_owner::RemoteEffectOutcome,
};
use lomi_files::desktop::DesktopFileErrorCode;
use lomi_host_store::{
    DesktopNamespaceAppliedProof, DesktopNamespaceEffect, RemoteDesktopNamespacePlan,
};
use lomi_remote_protocol::{Effect, OperationState, WorkspaceId};
use std::path::PathBuf;

pub(super) struct RemoteNamespaceEffect {
    pub(super) plan: RemoteDesktopNamespacePlan,
    pub(super) guarded_workspace_ids: std::sync::Arc<[WorkspaceId]>,
    pins: PhysicalNamespacePins,
}

impl RemoteNamespaceEffect {
    pub(super) fn capture(
        plan: RemoteDesktopNamespacePlan,
        selection: &FileNamespaceSelection,
        roots: &[(WorkspaceId, PathBuf)],
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<Box<Self>, DesktopFileErrorCode> {
        if selection.effect.as_ref() != Some(plan.effect())
            || selection.guarded_workspace_ids != plan.guarded_workspace_ids()
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        let pins = PhysicalNamespacePins::capture_remote(
            &plan,
            selection
                .expected_source
                .as_ref()
                .ok_or(DesktopFileErrorCode::Invalid)?,
            roots,
            check,
        )?;
        let guarded_workspace_ids = std::sync::Arc::from(plan.guarded_workspace_ids());
        Ok(Box::new(Self {
            plan,
            pins,
            guarded_workspace_ids,
        }))
    }

    pub(super) fn prepared_proof(&self) -> lomi_host_store::DesktopNamespacePhysicalProof {
        self.pins.prepared_proof()
    }

    pub(super) fn verify_before_effect(
        &self,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<(), DesktopFileErrorCode> {
        self.pins.verify_before_effect(check)
    }

    pub(super) fn completion_proof(
        &self,
        outcome: &RemoteEffectOutcome,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        if outcome.state == OperationState::Failed && outcome.effect == Effect::None {
            return self.pins.no_change_proof(check);
        }
        if outcome.state == OperationState::OutcomeUnknown && outcome.effect == Effect::Unknown {
            // Both alternatives require full positive pins and exact directory
            // censuses. Failure to observe one is never proof of the other.
            return self
                .applied_proof(outcome, check)
                .or_else(|_| self.pins.no_change_proof(check));
        }
        if outcome.state != OperationState::Succeeded || outcome.effect != Effect::Committed {
            return Err(DesktopFileErrorCode::Changed);
        }
        self.applied_proof(outcome, check)
    }

    fn applied_proof(
        &self,
        outcome: &RemoteEffectOutcome,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        match self.plan.effect() {
            DesktopNamespaceEffect::Move { .. } => self.pins.applied_move_proof(check),
            DesktopNamespaceEffect::Remove { .. } => {
                let receipt = serde_json::to_string(&serde_json::json!({
                    "state": outcome.state, "effect": outcome.effect, "result": outcome.result,
                }))
                .map_err(|_| DesktopFileErrorCode::Invalid)?;
                self.pins.applied_remove_proof(&receipt, None, check)
            }
        }
    }
}
