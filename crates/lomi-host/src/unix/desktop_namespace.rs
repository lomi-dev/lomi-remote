//! Read-only Host evidence for owner-coordinated desktop namespace changes.
//!
//! This module only pins and verifies filesystem identities. It never performs
//! a rename, removal, trash transfer, or other filesystem mutation.

use lomi_files::desktop::{
    DesktopDirectoryPin, DesktopDirectoryWitness, DesktopFileChange, DesktopFileErrorCode,
    DesktopFileKind, DesktopSourcePrecondition, DesktopTrashTicket,
};
use lomi_host_store::{
    DesktopNamespaceAppliedProof, DesktopNamespaceEffect, DesktopNamespacePhysicalProof,
    DesktopNamespacePlan, RemoteDesktopNamespacePlan,
};
use lomi_remote_protocol::{WorkspaceId, ipc::NativeIntentId};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};

const MAX_NAMESPACE_WORKSPACES: usize = 256;
const MAX_NAMESPACE_PIN_BYTES: usize = 128 * 1024;
const MAX_NAMESPACE_PROOF_BYTES: usize = 256 * 1024;
const MAX_EFFECT_RECEIPT_BYTES: usize = 131_072;

enum Plan {
    Native(DesktopNamespacePlan),
    Remote(RemoteDesktopNamespacePlan),
}

impl Plan {
    fn effect(&self) -> &DesktopNamespaceEffect {
        match self {
            Self::Native(plan) => plan.effect(),
            Self::Remote(plan) => plan.effect(),
        }
    }

    fn namespace_id(&self) -> String {
        match self {
            Self::Native(plan) => plan.namespace_id(),
            Self::Remote(plan) => plan.namespace_id(),
        }
    }

    fn runtime_id(&self) -> lomi_remote_protocol::RuntimeId {
        match self {
            Self::Native(plan) => plan.host_runtime_id(),
            Self::Remote(plan) => plan.host_runtime_id(),
        }
    }

    fn plan_sha256(&self) -> &str {
        match self {
            Self::Native(plan) => plan.plan_sha256(),
            Self::Remote(plan) => plan.plan_sha256(),
        }
    }

    fn workspaces(&self) -> &[lomi_host_store::DesktopNamespaceWorkspace] {
        match self {
            Self::Native(plan) => plan.workspaces(),
            Self::Remote(plan) => plan.workspaces(),
        }
    }

    fn guarded_workspace_ids(&self) -> &[WorkspaceId] {
        match self {
            Self::Native(plan) => plan.guarded_workspace_ids(),
            Self::Remote(plan) => plan.guarded_workspace_ids(),
        }
    }

    fn native_ids(&self) -> (Option<NativeIntentId>, Option<NativeIntentId>) {
        match self {
            Self::Native(plan) => (Some(plan.operation_id()), Some(plan.fence_id())),
            Self::Remote(_) => (None, None),
        }
    }

    fn request_operation_id(&self) -> Option<String> {
        match self {
            Self::Native(plan) => Some(String::from(plan.operation_id())),
            Self::Remote(plan) => plan
                .operation_binding()
                .map(|(_, _, operation_id, _, _)| String::from(operation_id)),
        }
    }

    fn from_host_physical_pins(
        &self,
        proof_json: &str,
    ) -> Result<DesktopNamespacePhysicalProof, DesktopFileErrorCode> {
        match self {
            Self::Native(plan) => {
                DesktopNamespacePhysicalProof::from_host_verified_physical_pins(plan, proof_json)
            }
            Self::Remote(plan) => {
                DesktopNamespacePhysicalProof::from_host_verified_remote_physical_pins(
                    plan, proof_json,
                )
            }
        }
        .map_err(|_| DesktopFileErrorCode::Invalid)
    }

    fn from_host_applied_proof(
        &self,
        prepared: &DesktopNamespacePhysicalProof,
        proof_json: &str,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        match self {
            Self::Native(plan) => {
                DesktopNamespaceAppliedProof::from_host_verified_effect(plan, prepared, proof_json)
            }
            Self::Remote(plan) => DesktopNamespaceAppliedProof::from_host_verified_remote_effect(
                plan, prepared, proof_json,
            ),
        }
        .map_err(|_| DesktopFileErrorCode::Invalid)
    }

    fn is_native(&self) -> bool {
        matches!(self, Self::Native(_))
    }
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct WorkspaceRootPinWire {
    pub(super) workspace_id: WorkspaceId,
    pub(super) relative_path: String,
    pub(super) witness: DesktopDirectoryWitness,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct GuardedRootPinWire {
    pub(super) workspace_id: WorkspaceId,
    pub(super) old_path: String,
    pub(super) witness: DesktopDirectoryWitness,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct SourcePinWire {
    pub(super) version: u8,
    pub(super) root: DesktopDirectoryWitness,
    pub(super) workspace_roots: Vec<WorkspaceRootPinWire>,
    pub(super) guarded_roots: Vec<GuardedRootPinWire>,
    #[serde(default)]
    pub(super) host_process: Option<lomi_platform::noexec_process::NoExecHostProcessWitness>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct NamespacePhysicalProofWire {
    pub(super) version: u32,
    pub(super) operation_id: Option<NativeIntentId>,
    pub(super) fence_id: Option<NativeIntentId>,
    pub(super) namespace_id: Option<String>,
    pub(super) host_runtime_id: lomi_remote_protocol::RuntimeId,
    pub(super) plan_sha256: String,
    pub(super) source_path: String,
    pub(super) source_parent_path: String,
    pub(super) destination_path: Option<String>,
    pub(super) destination_parent_path: Option<String>,
    pub(super) source_identity_pin: String,
    pub(super) source_parent_identity_pin: String,
    pub(super) destination_parent_identity_pin: Option<String>,
    pub(super) destination_absent: Option<bool>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct NamespaceAppliedProofWire {
    version: u32,
    operation_id: Option<NativeIntentId>,
    fence_id: Option<NativeIntentId>,
    namespace_id: Option<String>,
    host_runtime_id: lomi_remote_protocol::RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: &'static str,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_pin: String,
    source_parent_identity_pin: String,
    destination_identity_pin: Option<String>,
    destination_parent_identity_pin: Option<String>,
    source_absent: Option<bool>,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
}

struct GuardedRootPin {
    workspace_id: WorkspaceId,
    path: PathBuf,
    pin: DesktopDirectoryPin,
}

struct WorkspaceRootPin {
    workspace_id: WorkspaceId,
    old_path: PathBuf,
    new_path: Option<PathBuf>,
    relative_path: String,
}

/// Captured physical identity pins for one Store-selected namespace plan.
/// Instances retain no-follow directory handles until the effect is proved.
pub(super) struct PhysicalNamespacePins {
    plan: Plan,
    source_path: PathBuf,
    source_parent_path: PathBuf,
    destination_path: Option<PathBuf>,
    destination_parent_path: Option<PathBuf>,
    source_top: DesktopDirectoryPin,
    source_parent: DesktopDirectoryPin,
    destination_parent: Option<DesktopDirectoryPin>,
    guarded_roots: Vec<GuardedRootPin>,
    workspace_roots: Vec<WorkspaceRootPin>,
    source_identity_pin: String,
    source_parent_identity_pin: String,
    destination_parent_identity_pin: Option<String>,
    prepared: DesktopNamespacePhysicalProof,
}

impl PhysicalNamespacePins {
    pub(super) fn capture_native(
        plan: &DesktopNamespacePlan,
        expected_source: &DesktopSourcePrecondition,
        guarded_roots: &[(WorkspaceId, PathBuf)],
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<Self, DesktopFileErrorCode> {
        Self::capture(
            Plan::Native(plan.clone()),
            expected_source,
            guarded_roots,
            check,
        )
    }

    pub(super) fn capture_remote(
        plan: &RemoteDesktopNamespacePlan,
        expected_source: &DesktopSourcePrecondition,
        guarded_roots: &[(WorkspaceId, PathBuf)],
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<Self, DesktopFileErrorCode> {
        Self::capture(
            Plan::Remote(plan.clone()),
            expected_source,
            guarded_roots,
            check,
        )
    }

    fn capture(
        plan: Plan,
        expected_source: &DesktopSourcePrecondition,
        guarded_roots: &[(WorkspaceId, PathBuf)],
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<Self, DesktopFileErrorCode> {
        if expected_source.kind != DesktopFileKind::Directory
            || !expected_source.identity.is_valid()
            || plan.workspaces().len() > MAX_NAMESPACE_WORKSPACES
            || plan.guarded_workspace_ids().len() > MAX_NAMESPACE_WORKSPACES
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        check()?;

        let (source_path, destination_path) = effect_paths(plan.effect());
        let source_path = source_path.to_path_buf();
        let destination_path = destination_path.map(Path::to_path_buf);
        let source_parent_path = source_path
            .parent()
            .ok_or(DesktopFileErrorCode::Invalid)?
            .to_path_buf();
        let destination_parent_path = destination_path
            .as_deref()
            .map(|path| {
                path.parent()
                    .map(Path::to_path_buf)
                    .ok_or(DesktopFileErrorCode::Invalid)
            })
            .transpose()?;

        let source_parent = DesktopDirectoryPin::open(&source_parent_path)?;
        check()?;
        let source_top = DesktopDirectoryPin::open(&source_path)?;
        if &source_top.witness().identity != &expected_source.identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        check()?;
        require_entry(&source_parent, &source_path, Some(expected_source), check)?;

        let (destination_parent, destination_parent_identity_pin) =
            if let Some(parent_path) = destination_parent_path.as_ref() {
                let pin = DesktopDirectoryPin::open(parent_path)?;
                check()?;
                let identity_pin = encode_json(pin.witness())?;
                ensure_pin_size(&identity_pin)?;
                (Some(pin), Some(identity_pin))
            } else {
                (None, None)
            };

        let root_paths = validate_guarded_roots(&plan, guarded_roots)?;
        let mut pinned_roots = Vec::with_capacity(root_paths.len());
        for (workspace_id, path) in root_paths {
            check()?;
            let pin = DesktopDirectoryPin::open(&path)?;
            check()?;
            pin.verify_named()?;
            pinned_roots.push(GuardedRootPin {
                workspace_id,
                path,
                pin,
            });
        }
        pinned_roots.sort_by_key(|root| root.workspace_id);

        let mut workspace_roots = Vec::with_capacity(plan.workspaces().len());
        let root_by_id: BTreeMap<_, _> = pinned_roots
            .iter()
            .map(|root| (root.workspace_id, root))
            .collect();
        let (source_root, new_source_root) = match plan.effect() {
            DesktopNamespaceEffect::Move { old_path, new_path } => {
                (old_path.as_path(), Some(new_path.as_path()))
            }
            DesktopNamespaceEffect::Remove { old_path } => (old_path.as_path(), None),
        };
        for workspace in plan.workspaces() {
            check()?;
            let root = root_by_id
                .get(&workspace.workspace_id)
                .ok_or(DesktopFileErrorCode::Invalid)?;
            if root.path != workspace.old_path {
                return Err(DesktopFileErrorCode::Changed);
            }
            let relative_path = relative_utf8(&workspace.old_path, source_root)?;
            let expected_new_path = new_source_root.map(|new_root| new_root.join(&relative_path));
            if expected_new_path != workspace.new_path {
                return Err(DesktopFileErrorCode::Changed);
            }
            workspace_roots.push(WorkspaceRootPin {
                workspace_id: workspace.workspace_id,
                old_path: workspace.old_path.clone(),
                new_path: workspace.new_path.clone(),
                relative_path,
            });
        }

        let source_identity_pin =
            encode_source_identity_pin(source_top.witness(), &workspace_roots, &pinned_roots)?;
        let source_parent_identity_pin = encode_json(source_parent.witness())?;
        ensure_pin_size(&source_identity_pin)?;
        ensure_pin_size(&source_parent_identity_pin)?;
        let (operation_id, fence_id) = plan.native_ids();
        let (source_text, source_parent_text) =
            (path_text(&source_path)?, path_text(&source_parent_path)?);
        let physical_wire = NamespacePhysicalProofWire {
            version: 1,
            operation_id,
            fence_id,
            namespace_id: Some(plan.namespace_id()),
            host_runtime_id: plan.runtime_id(),
            plan_sha256: plan.plan_sha256().to_owned(),
            source_path: source_text,
            source_parent_path: source_parent_text,
            destination_path: destination_path.as_deref().map(path_text).transpose()?,
            destination_parent_path: destination_parent_path
                .as_deref()
                .map(path_text)
                .transpose()?,
            source_identity_pin: source_identity_pin.clone(),
            source_parent_identity_pin: source_parent_identity_pin.clone(),
            destination_parent_identity_pin: destination_parent_identity_pin.clone(),
            destination_absent: destination_path.as_ref().map(|_| true),
        };
        let physical_json = encode_proof(&physical_wire)?;
        let prepared = plan.from_host_physical_pins(&physical_json)?;
        let pins = Self {
            plan,
            source_path,
            source_parent_path,
            destination_path,
            destination_parent_path,
            source_top,
            source_parent,
            destination_parent,
            guarded_roots: pinned_roots,
            workspace_roots,
            source_identity_pin,
            source_parent_identity_pin,
            destination_parent_identity_pin,
            prepared,
        };
        pins.verify_before_effect(check)?;
        Ok(pins)
    }

    pub(super) fn prepared_proof(&self) -> DesktopNamespacePhysicalProof {
        self.prepared.clone()
    }

    pub(super) fn verify_before_effect(
        &self,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<(), DesktopFileErrorCode> {
        check()?;
        self.source_parent.verify_named()?;
        check()?;
        self.source_top.verify_named()?;
        require_entry(
            &self.source_parent,
            &self.source_path,
            Some(&DesktopSourcePrecondition {
                identity: self.source_top.witness().identity.clone(),
                kind: DesktopFileKind::Directory,
            }),
            check,
        )?;
        if let (Some(destination), Some(parent)) = (
            self.destination_path.as_ref(),
            self.destination_parent.as_ref(),
        ) {
            parent.verify_named()?;
            check()?;
            if census_entry(parent, destination, check)?.is_some() {
                return Err(DesktopFileErrorCode::Exists);
            }
        }
        self.verify_guarded_roots(RootDisposition::Original, check)?;
        Ok(())
    }

    pub(super) fn applied_move_proof(
        &self,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        let (DesktopNamespaceEffect::Move { new_path, .. }, Some(destination_parent)) =
            (self.plan.effect(), self.destination_parent.as_ref())
        else {
            return Err(DesktopFileErrorCode::Invalid);
        };
        self.destination_parent_path
            .as_ref()
            .ok_or(DesktopFileErrorCode::Invalid)?;
        check()?;
        self.source_parent.verify_named()?;
        if census_entry(&self.source_parent, &self.source_path, check)?.is_some() {
            return Err(DesktopFileErrorCode::Changed);
        }
        check()?;
        destination_parent.verify_named()?;
        let destination = require_entry(
            destination_parent,
            new_path,
            Some(&DesktopSourcePrecondition {
                identity: self.source_top.witness().identity.clone(),
                kind: DesktopFileKind::Directory,
            }),
            check,
        )?;
        if &destination.identity != &self.source_top.witness().identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        self.source_top.verify_at(new_path)?;
        check()?;
        self.verify_guarded_roots(RootDisposition::Moved, check)?;

        let wire = self.applied_wire(
            "applied",
            Some(true),
            Some(false),
            Some(self.source_identity_pin.clone()),
            self.destination_parent_identity_pin.clone(),
            None,
        )?;
        self.plan.from_host_applied_proof(&self.prepared, &wire)
    }

    pub(super) fn no_change_proof(
        &self,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        check()?;
        self.source_parent.verify_named()?;
        let source = require_entry(
            &self.source_parent,
            &self.source_path,
            Some(&DesktopSourcePrecondition {
                identity: self.source_top.witness().identity.clone(),
                kind: DesktopFileKind::Directory,
            }),
            check,
        )?;
        if source.identity != self.source_top.witness().identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        self.source_top.verify_named()?;
        self.verify_guarded_roots(RootDisposition::Original, check)?;
        if let (Some(destination), Some(parent)) = (
            self.destination_path.as_ref(),
            self.destination_parent.as_ref(),
        ) {
            parent.verify_named()?;
            if census_entry(parent, destination, check)?.is_some() {
                return Err(DesktopFileErrorCode::Changed);
            }
        }
        let (destination_path, destination_parent_pin) = match self.plan.effect() {
            DesktopNamespaceEffect::Move { new_path, .. } => (
                Some(path_text(new_path)?),
                self.destination_parent_identity_pin.clone(),
            ),
            DesktopNamespaceEffect::Remove { .. } => (None, None),
        };
        let wire = self.applied_wire(
            "noChange",
            Some(false),
            if destination_path.is_some() {
                Some(true)
            } else {
                None
            },
            None,
            destination_parent_pin,
            None,
        )?;
        self.plan.from_host_applied_proof(&self.prepared, &wire)
    }

    pub(super) fn applied_remove_proof(
        &self,
        exact_effect_receipt_json: &str,
        trash_ticket: Option<&DesktopTrashTicket>,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        if !matches!(self.plan.effect(), DesktopNamespaceEffect::Remove { .. })
            || exact_effect_receipt_json.is_empty()
            || exact_effect_receipt_json.len() > MAX_EFFECT_RECEIPT_BYTES
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        if self.plan.is_native() {
            self.validate_native_remove_receipt(exact_effect_receipt_json, trash_ticket)?;
        }
        if let Some(ticket) = trash_ticket {
            self.validate_trash_ticket(ticket, check)?;
        }
        check()?;
        self.source_parent.verify_named()?;
        if census_entry(&self.source_parent, &self.source_path, check)?.is_some() {
            return Err(DesktopFileErrorCode::Changed);
        }
        self.verify_guarded_roots(RootDisposition::Removed, check)?;
        let wire = self.applied_wire(
            "applied",
            Some(true),
            None,
            None,
            None,
            Some(sha256(exact_effect_receipt_json.as_bytes())),
        )?;
        self.plan.from_host_applied_proof(&self.prepared, &wire)
    }

    pub(super) fn retired_after_partial_remove_proof(
        &self,
        exact_uncertain_json: &str,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<DesktopNamespaceAppliedProof, DesktopFileErrorCode> {
        if !self.plan.is_native()
            || !matches!(self.plan.effect(), DesktopNamespaceEffect::Remove { .. })
            || exact_uncertain_json.len() > MAX_EFFECT_RECEIPT_BYTES
            || !is_exact_uncertain_json(exact_uncertain_json)
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        check()?;
        self.source_parent.verify_named()?;
        self.verify_guarded_roots(RootDisposition::Removed, check)?;
        check()?;
        let wire = self.applied_wire(
            "retiredAfterPartialRemove",
            None,
            None,
            None,
            None,
            Some(sha256(exact_uncertain_json.as_bytes())),
        )?;
        self.plan.from_host_applied_proof(&self.prepared, &wire)
    }

    fn applied_wire(
        &self,
        observed: &'static str,
        source_absent: Option<bool>,
        destination_absent: Option<bool>,
        destination_identity_pin: Option<String>,
        destination_parent_identity_pin: Option<String>,
        effect_receipt_sha256: Option<String>,
    ) -> Result<String, DesktopFileErrorCode> {
        let (operation_id, fence_id) = self.plan.native_ids();
        let (destination_path, destination_parent_path) = match self.plan.effect() {
            DesktopNamespaceEffect::Move { new_path, .. } => (
                Some(path_text(new_path)?),
                self.destination_parent_path
                    .as_deref()
                    .map(path_text)
                    .transpose()?,
            ),
            DesktopNamespaceEffect::Remove { .. } => (None, None),
        };
        let wire = NamespaceAppliedProofWire {
            version: 1,
            operation_id,
            fence_id,
            namespace_id: Some(self.plan.namespace_id()),
            host_runtime_id: self.plan.runtime_id(),
            plan_sha256: self.plan.plan_sha256().to_owned(),
            prepared_proof_sha256: self.prepared.proof_sha256().to_owned(),
            observed,
            source_path: path_text(&self.source_path)?,
            source_parent_path: path_text(&self.source_parent_path)?,
            destination_path,
            destination_parent_path,
            source_identity_pin: self.source_identity_pin.clone(),
            source_parent_identity_pin: self.source_parent_identity_pin.clone(),
            destination_identity_pin,
            destination_parent_identity_pin,
            source_absent,
            destination_absent,
            effect_receipt_sha256,
        };
        encode_proof(&wire)
    }

    fn validate_trash_ticket(
        &self,
        ticket: &DesktopTrashTicket,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<(), DesktopFileErrorCode> {
        ticket.validate_shape()?;
        if ticket.original_path != self.source_path
            || &ticket.parent_identity != &self.source_parent.witness().identity
            || &ticket.entry_identity != &self.source_top.witness().identity
            || ticket.kind != DesktopFileKind::Directory
            || self.plan.request_operation_id().as_deref() != Some(ticket.operation_id.as_str())
        {
            return Err(DesktopFileErrorCode::Changed);
        }

        check()?;
        let ticket_root = DesktopDirectoryPin::open(&ticket.root)?;
        if ticket_root.witness().identity != ticket.root_identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        ticket_root.verify_named()?;

        check()?;
        let staging = DesktopDirectoryPin::open(&ticket.staging_directory)?;
        if staging.witness().identity != ticket.staging_identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        staging.verify_named()?;
        require_entry(
            &self.source_parent,
            &ticket.staging_directory,
            Some(&DesktopSourcePrecondition {
                identity: ticket.staging_identity.clone(),
                kind: DesktopFileKind::Directory,
            }),
            check,
        )?;

        check()?;
        let staged_entry = require_entry(
            &staging,
            &ticket.staged_path,
            Some(&DesktopSourcePrecondition {
                identity: ticket.entry_identity.clone(),
                kind: ticket.kind,
            }),
            check,
        )?;
        if &staged_entry.identity != &self.source_top.witness().identity {
            return Err(DesktopFileErrorCode::Changed);
        }
        self.source_top.verify_at(&ticket.staged_path)?;

        // Trash moves the entire selected tree into its private staging
        // directory. Registered roots therefore have to remain positively
        // named beneath the staged entry before the system Trash handoff.
        for workspace in &self.workspace_roots {
            check()?;
            let staged_workspace = ticket.staged_path.join(&workspace.relative_path);
            let root = self
                .guarded_roots
                .iter()
                .find(|root| root.workspace_id == workspace.workspace_id)
                .ok_or(DesktopFileErrorCode::Invalid)?;
            root.pin.verify_at(&staged_workspace)?;
        }
        ticket_root.verify_named()?;
        staging.verify_named()?;
        self.source_parent.verify_named()?;
        Ok(())
    }

    fn validate_native_remove_receipt(
        &self,
        receipt_json: &str,
        trash_ticket: Option<&DesktopTrashTicket>,
    ) -> Result<(), DesktopFileErrorCode> {
        let receipt: DesktopFileChange =
            serde_json::from_str(receipt_json).map_err(|_| DesktopFileErrorCode::Invalid)?;
        let expected_operation_id = self
            .plan
            .request_operation_id()
            .ok_or(DesktopFileErrorCode::Invalid)?;
        if receipt.operation_id != expected_operation_id
            || receipt.old_path.as_deref() != Some(self.source_path.as_path())
            || receipt.new_path.is_some()
            || receipt.trash.as_ref() != trash_ticket
        {
            return Err(DesktopFileErrorCode::Changed);
        }
        Ok(())
    }

    fn verify_guarded_roots(
        &self,
        disposition: RootDisposition,
        check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
    ) -> Result<(), DesktopFileErrorCode> {
        for root in &self.guarded_roots {
            check()?;
            let workspace = self
                .workspace_roots
                .iter()
                .find(|workspace| workspace.workspace_id == root.workspace_id);
            let target = match (disposition, workspace) {
                (RootDisposition::Moved, Some(workspace)) => workspace
                    .new_path
                    .as_deref()
                    .ok_or(DesktopFileErrorCode::Changed)?,
                (RootDisposition::Removed, Some(workspace))
                    if is_same_or_descendant(&workspace.old_path, &self.source_path) =>
                {
                    // Recursive removal may have deleted or partially changed
                    // this registered descendant; the Store retires it.
                    continue;
                }
                _ => root.path.as_path(),
            };
            root.pin.verify_at(target)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
enum RootDisposition {
    Original,
    Moved,
    Removed,
}

fn effect_paths(effect: &DesktopNamespaceEffect) -> (&Path, Option<&Path>) {
    match effect {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            (old_path.as_path(), Some(new_path.as_path()))
        }
        DesktopNamespaceEffect::Remove { old_path } => (old_path.as_path(), None),
    }
}

fn validate_guarded_roots(
    plan: &Plan,
    guarded_roots: &[(WorkspaceId, PathBuf)],
) -> Result<Vec<(WorkspaceId, PathBuf)>, DesktopFileErrorCode> {
    if guarded_roots.len() != plan.guarded_workspace_ids().len()
        || guarded_roots.len() > MAX_NAMESPACE_WORKSPACES
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let expected: BTreeSet<_> = plan.guarded_workspace_ids().iter().copied().collect();
    let mut roots = BTreeMap::new();
    for (workspace_id, path) in guarded_roots {
        if !expected.contains(workspace_id) || roots.insert(*workspace_id, path.clone()).is_some() {
            return Err(DesktopFileErrorCode::Invalid);
        }
    }
    if roots.keys().copied().collect::<BTreeSet<_>>() != expected {
        return Err(DesktopFileErrorCode::Invalid);
    }
    for workspace in plan.workspaces() {
        if roots.get(&workspace.workspace_id) != Some(&workspace.old_path) {
            return Err(DesktopFileErrorCode::Changed);
        }
    }
    Ok(roots.into_iter().collect())
}

fn encode_source_identity_pin(
    source: &DesktopDirectoryWitness,
    workspace_roots: &[WorkspaceRootPin],
    guarded_roots: &[GuardedRootPin],
) -> Result<String, DesktopFileErrorCode> {
    let by_id: BTreeMap<_, _> = guarded_roots
        .iter()
        .map(|root| (root.workspace_id, root))
        .collect();
    let roots = workspace_roots
        .iter()
        .map(|workspace| {
            let root = by_id
                .get(&workspace.workspace_id)
                .ok_or(DesktopFileErrorCode::Invalid)?;
            Ok(WorkspaceRootPinWire {
                workspace_id: workspace.workspace_id,
                relative_path: workspace.relative_path.clone(),
                witness: root.pin.witness().clone(),
            })
        })
        .collect::<Result<Vec<_>, DesktopFileErrorCode>>()?;
    let guarded = guarded_roots
        .iter()
        .map(|root| {
            Ok(GuardedRootPinWire {
                workspace_id: root.workspace_id,
                old_path: path_text(&root.path)?,
                witness: root.pin.witness().clone(),
            })
        })
        .collect::<Result<Vec<_>, DesktopFileErrorCode>>()?;
    encode_json(&SourcePinWire {
        version: 1,
        root: source.clone(),
        workspace_roots: roots,
        guarded_roots: guarded,
        host_process: Some(
            lomi_platform::noexec_process::NoExecHostProcessWitness::capture_current()
                .map_err(|_| DesktopFileErrorCode::Unsupported)?,
        ),
    })
}

fn require_entry(
    parent: &DesktopDirectoryPin,
    target: &Path,
    expected: Option<&DesktopSourcePrecondition>,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopSourcePrecondition, DesktopFileErrorCode> {
    let Some(found) = census_entry(parent, target, check)? else {
        return Err(DesktopFileErrorCode::NotFound);
    };
    if expected.is_some_and(|expected| expected != &found) {
        return Err(DesktopFileErrorCode::Changed);
    }
    Ok(found)
}

/// Enumerate exact directory-entry spelling and capture its identity through
/// the same held parent handle. Path lookup alone is not sufficient for
/// case-only moves or resistant to parent-path replacement.
fn census_entry(
    parent: &DesktopDirectoryPin,
    target: &Path,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<Option<DesktopSourcePrecondition>, DesktopFileErrorCode> {
    let leaf = target.file_name().ok_or(DesktopFileErrorCode::Invalid)?;
    check()?;
    parent.verify_named()?;
    let current = parent.exact_child(leaf, check)?;
    parent.verify_named()?;
    check()?;
    Ok(current)
}

fn relative_utf8(path: &Path, root: &Path) -> Result<String, DesktopFileErrorCode> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| DesktopFileErrorCode::Changed)?;
    if relative.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::RootDir
        )
    }) {
        return Err(DesktopFileErrorCode::Invalid);
    }
    relative
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(DesktopFileErrorCode::Invalid)
}

fn is_same_or_descendant(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn path_text(path: &Path) -> Result<String, DesktopFileErrorCode> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(DesktopFileErrorCode::Invalid)
}

fn encode_json<T: Serialize>(value: &T) -> Result<String, DesktopFileErrorCode> {
    serde_json::to_string(value).map_err(|_| DesktopFileErrorCode::Invalid)
}

fn encode_proof<T: Serialize>(value: &T) -> Result<String, DesktopFileErrorCode> {
    let encoded = encode_json(value)?;
    if encoded.len() > MAX_NAMESPACE_PROOF_BYTES {
        return Err(DesktopFileErrorCode::Limit);
    }
    Ok(encoded)
}

fn ensure_pin_size(pin: &str) -> Result<(), DesktopFileErrorCode> {
    if pin.is_empty() || pin.len() > MAX_NAMESPACE_PIN_BYTES || pin.contains('\0') {
        return Err(DesktopFileErrorCode::Limit);
    }
    Ok(())
}

fn is_exact_uncertain_json(value: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(value) else {
        return false;
    };
    value.as_object().is_some_and(|object| {
        object.len() == 1
            && object.get("kind").and_then(serde_json::Value::as_str) == Some("uncertain")
    })
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}
