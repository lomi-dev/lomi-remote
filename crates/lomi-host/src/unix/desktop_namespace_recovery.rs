//! Read-only recovery checks for durable workspace namespace intents.
//!
//! This module never performs a filesystem effect or decides that an old
//! worker has stopped. The caller supplies receipts only after it has proved
//! owner-lock acquisition and old-worker retirement.

use super::desktop_namespace::{NamespacePhysicalProofWire, SourcePinWire};
use lomi_files::desktop::{
    DesktopDirectoryPin, DesktopDirectoryWitness, DesktopFileErrorCode, DesktopFileKind,
};
use lomi_host_store::{
    DesktopNamespaceEffect, DesktopNamespaceIntentRecord, DesktopNamespaceIntentState,
    DesktopNamespacePlan, DesktopNamespaceRecoveryEvidence, DesktopNamespaceWorkspace,
    RemoteDesktopNamespaceIntentRecord, RemoteDesktopNamespacePlan,
    RemoteDesktopNamespaceRecoveryEvidence,
};
use lomi_remote_protocol::{
    ConsumerAuthorizationId, Method, OperationId, RuntimeId, WorkspaceId, ipc::NativeIntentId,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

const MAX_RECOVERY_PROOF_BYTES: usize = 256 * 1024;
const MAX_PREPARED_PROOF_BYTES: usize = 256 * 1024;
const MAX_PIN_BYTES: usize = 128 * 1024;
const MAX_WORKSPACES: usize = 256;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryProofWire {
    version: u32,
    operation_id: Option<NativeIntentId>,
    fence_id: Option<NativeIntentId>,
    namespace_id: Option<String>,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: &'static str,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_sha256: String,
    source_parent_identity_sha256: String,
    destination_identity_sha256: Option<String>,
    destination_parent_identity_sha256: Option<String>,
    source_absent: Option<bool>,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    worker_retirement_receipt_sha256: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RemoteRecoveryProofWire {
    version: u32,
    namespace_id: String,
    actor: ConsumerAuthorizationId,
    workspace_id: WorkspaceId,
    operation_id: OperationId,
    method: Method,
    old_runtime_id: RuntimeId,
    current_runtime_id: RuntimeId,
    plan_sha256: String,
    prepared_proof_sha256: String,
    observed: &'static str,
    source_path: String,
    source_parent_path: String,
    destination_path: Option<String>,
    destination_parent_path: Option<String>,
    source_identity_sha256: String,
    source_parent_identity_sha256: String,
    destination_identity_sha256: Option<String>,
    destination_parent_identity_sha256: Option<String>,
    source_absent: bool,
    destination_absent: Option<bool>,
    effect_receipt_sha256: Option<String>,
    owner_lock_receipt_sha256: String,
    operation_retirement_receipt_sha256: String,
}

#[derive(Clone, Copy)]
enum MoveObservation {
    Applied,
    NoChange,
}

trait RecoveryPlanView {
    fn effect(&self) -> &DesktopNamespaceEffect;
    fn plan_sha256(&self) -> &str;
    fn workspaces(&self) -> &[DesktopNamespaceWorkspace];
    fn guarded_workspace_ids(&self) -> &[WorkspaceId];
}

impl RecoveryPlanView for DesktopNamespacePlan {
    fn effect(&self) -> &DesktopNamespaceEffect {
        DesktopNamespacePlan::effect(self)
    }
    fn plan_sha256(&self) -> &str {
        DesktopNamespacePlan::plan_sha256(self)
    }
    fn workspaces(&self) -> &[DesktopNamespaceWorkspace] {
        DesktopNamespacePlan::workspaces(self)
    }
    fn guarded_workspace_ids(&self) -> &[WorkspaceId] {
        DesktopNamespacePlan::guarded_workspace_ids(self)
    }
}

impl RecoveryPlanView for RemoteDesktopNamespacePlan {
    fn effect(&self) -> &DesktopNamespaceEffect {
        RemoteDesktopNamespacePlan::effect(self)
    }
    fn plan_sha256(&self) -> &str {
        RemoteDesktopNamespacePlan::plan_sha256(self)
    }
    fn workspaces(&self) -> &[DesktopNamespaceWorkspace] {
        RemoteDesktopNamespacePlan::workspaces(self)
    }
    fn guarded_workspace_ids(&self) -> &[WorkspaceId] {
        RemoteDesktopNamespacePlan::guarded_workspace_ids(self)
    }
}

struct PreparedRecordRef<'a> {
    plan: &'a dyn RecoveryPlanView,
    host_runtime_id: RuntimeId,
    proof_json: &'a str,
    proof_sha256: &'a str,
    source_pin_sha256: &'a str,
    source_parent_pin_sha256: &'a str,
    destination_parent_pin_sha256: Option<&'a str>,
    operation_id: Option<NativeIntentId>,
    fence_id: Option<NativeIntentId>,
    namespace_id: Option<&'a str>,
}

/// Reconstruct recovery evidence from the exact persisted Host pins and
/// positive current filesystem identities. This does not establish the owner
/// lock or worker retirement; the trusted caller supplies their receipts.
pub(super) fn recover_native_namespace(
    record: &DesktopNamespaceIntentRecord,
    current_runtime: RuntimeId,
    owner_lock_receipt_sha256: &str,
    worker_retirement_receipt_sha256: &str,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopNamespaceRecoveryEvidence, DesktopFileErrorCode> {
    if record.state != DesktopNamespaceIntentState::Prepared
        || record.host_runtime_id == current_runtime
        || !is_sha256(owner_lock_receipt_sha256)
        || !is_sha256(worker_retirement_receipt_sha256)
    {
        return Err(DesktopFileErrorCode::Invalid);
    }

    let prepared = parse_prepared(record)?;
    let source_path = effect_paths(record.plan.effect()).0;
    let source_parent_path = source_path.parent().ok_or(DesktopFileErrorCode::Invalid)?;
    let source_witness = &prepared.source.root;
    let source_parent_witness = &prepared.source_parent;

    let mut observed = "retiredRequestedRecovery";
    let mut source_absent = None;
    let mut destination_absent = None;
    let mut destination_path = None;
    let mut destination_parent_path = None;
    let mut destination_identity_sha256 = None;
    let mut destination_parent_identity_sha256 = None;

    match record.plan.effect() {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            if old_path != source_path {
                return Err(DesktopFileErrorCode::Invalid);
            }
            let destination_parent = new_path.parent().ok_or(DesktopFileErrorCode::Invalid)?;
            let destination_witness = prepared
                .destination_parent
                .as_ref()
                .ok_or(DesktopFileErrorCode::Invalid)?;
            let observation = observe_move(
                source_path,
                new_path,
                source_parent_path,
                destination_parent,
                source_parent_witness,
                destination_witness,
                source_witness,
                check,
            )?;
            let disposition = match observation {
                MoveObservation::Applied => {
                    observed = "applied";
                    source_absent = Some(true);
                    destination_absent = Some(false);
                    destination_identity_sha256 = Some(record.source_pin_sha256().to_owned());
                    MoveRootDisposition::Moved
                }
                MoveObservation::NoChange => {
                    observed = "noChange";
                    source_absent = Some(false);
                    destination_absent = Some(true);
                    MoveRootDisposition::Original
                }
            };
            verify_root_manifest(&record.plan, &prepared.source, disposition, check)?;
            let confirmed = observe_move(
                source_path,
                new_path,
                source_parent_path,
                destination_parent,
                source_parent_witness,
                destination_witness,
                source_witness,
                check,
            )?;
            if !matches!(
                (&observation, &confirmed),
                (MoveObservation::Applied, MoveObservation::Applied)
                    | (MoveObservation::NoChange, MoveObservation::NoChange)
            ) {
                return Err(DesktopFileErrorCode::Changed);
            }
            destination_path = Some(path_text(new_path)?);
            destination_parent_path = Some(path_text(destination_parent)?);
            destination_parent_identity_sha256 = record
                .destination_parent_pin_sha256()
                .map(ToOwned::to_owned);
        }
        DesktopNamespaceEffect::Remove { old_path } => {
            if old_path != source_path {
                return Err(DesktopFileErrorCode::Invalid);
            }
            let parent = open_matching_directory(source_parent_path, source_parent_witness, check)?;
            parent.verify_named()?;
            verify_unaffected_guarded_roots(&record.plan, &prepared.source, source_path, check)?;
            parent.verify_named()?;
            check()?;
        }
    }

    let wire = RecoveryProofWire {
        version: 1,
        operation_id: Some(record.operation_id),
        fence_id: Some(record.fence_id),
        namespace_id: Some(record.plan.namespace_id()),
        old_runtime_id: record.host_runtime_id,
        current_runtime_id: current_runtime,
        plan_sha256: record.plan.plan_sha256().to_owned(),
        prepared_proof_sha256: record.prepared_proof_sha256.clone(),
        observed,
        source_path: path_text(source_path)?,
        source_parent_path: path_text(source_parent_path)?,
        destination_path,
        destination_parent_path,
        source_identity_sha256: record.source_pin_sha256().to_owned(),
        source_parent_identity_sha256: record.source_parent_pin_sha256().to_owned(),
        destination_identity_sha256,
        destination_parent_identity_sha256,
        source_absent,
        destination_absent,
        effect_receipt_sha256: None,
        owner_lock_receipt_sha256: owner_lock_receipt_sha256.to_owned(),
        worker_retirement_receipt_sha256: worker_retirement_receipt_sha256.to_owned(),
    };
    let proof_json = serde_json::to_string(&wire).map_err(|_| DesktopFileErrorCode::Invalid)?;
    if proof_json.len() > MAX_RECOVERY_PROOF_BYTES {
        return Err(DesktopFileErrorCode::Limit);
    }

    match record.plan.effect() {
        DesktopNamespaceEffect::Move { .. } => {
            DesktopNamespaceRecoveryEvidence::from_host_verified_owner_lock_and_retirement(
                record,
                current_runtime,
                &proof_json,
            )
            .map_err(|_| DesktopFileErrorCode::Invalid)
        }
        DesktopNamespaceEffect::Remove { .. } => DesktopNamespaceRecoveryEvidence::
            from_host_verified_retire_requested_registrations_after_uncertain_remove(
                record,
                current_runtime,
                &proof_json,
            )
            .map_err(|_| DesktopFileErrorCode::Invalid),
    }
}

/// Recover a remote namespace intent only when its persisted source/destination
/// manifest proves either the exact directory move or the exact no-change
/// prestate. A missing Remove source is intentionally inconclusive: remote
/// removal has no native tombstone protocol or synthetic effect receipt.
pub(super) fn recover_remote_namespace(
    record: &RemoteDesktopNamespaceIntentRecord,
    current_runtime: RuntimeId,
    owner_lock_receipt_sha256: &str,
    operation_retirement_receipt_sha256: &str,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<RemoteDesktopNamespaceRecoveryEvidence, DesktopFileErrorCode> {
    if record.state != DesktopNamespaceIntentState::Prepared
        || record.host_runtime_id == current_runtime
        || !is_sha256(owner_lock_receipt_sha256)
        || !is_sha256(operation_retirement_receipt_sha256)
    {
        return Err(DesktopFileErrorCode::Invalid);
    }

    let prepared = parse_prepared_remote(record)?;
    let source_path = effect_paths(record.plan.effect()).0;
    let source_parent_path = source_path.parent().ok_or(DesktopFileErrorCode::Invalid)?;
    let source_witness = &prepared.source.root;
    let source_parent_witness = &prepared.source_parent;
    let mut observed = "noChange";
    let mut source_absent = false;
    let mut destination_absent = None;
    let mut destination_path = None;
    let mut destination_parent_path = None;
    let mut destination_identity_sha256 = None;
    let mut destination_parent_identity_sha256 = None;

    match record.plan.effect() {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            if old_path != source_path {
                return Err(DesktopFileErrorCode::Invalid);
            }
            let destination_parent = new_path.parent().ok_or(DesktopFileErrorCode::Invalid)?;
            let destination_witness = prepared
                .destination_parent
                .as_ref()
                .ok_or(DesktopFileErrorCode::Invalid)?;
            let observation = observe_move(
                source_path,
                new_path,
                source_parent_path,
                destination_parent,
                source_parent_witness,
                destination_witness,
                source_witness,
                check,
            )?;
            let disposition = match observation {
                MoveObservation::Applied => {
                    observed = "applied";
                    source_absent = true;
                    destination_absent = Some(false);
                    destination_identity_sha256 = Some(record.source_pin_sha256().to_owned());
                    MoveRootDisposition::Moved
                }
                MoveObservation::NoChange => {
                    destination_absent = Some(true);
                    MoveRootDisposition::Original
                }
            };
            verify_root_manifest(&record.plan, &prepared.source, disposition, check)?;
            let confirmed = observe_move(
                source_path,
                new_path,
                source_parent_path,
                destination_parent,
                source_parent_witness,
                destination_witness,
                source_witness,
                check,
            )?;
            if !matches!(
                (&observation, &confirmed),
                (MoveObservation::Applied, MoveObservation::Applied)
                    | (MoveObservation::NoChange, MoveObservation::NoChange)
            ) {
                return Err(DesktopFileErrorCode::Changed);
            }
            destination_path = Some(path_text(new_path)?);
            destination_parent_path = Some(path_text(destination_parent)?);
            destination_parent_identity_sha256 = record
                .destination_parent_pin_sha256()
                .map(ToOwned::to_owned);
        }
        DesktopNamespaceEffect::Remove { old_path } => {
            if old_path != source_path {
                return Err(DesktopFileErrorCode::Invalid);
            }
            observe_remove_no_change(
                &record.plan,
                &prepared.source,
                source_path,
                source_parent_path,
                source_parent_witness,
                source_witness,
                check,
            )?;
            // Repeat the complete source/root census before minting NoChange.
            observe_remove_no_change(
                &record.plan,
                &prepared.source,
                source_path,
                source_parent_path,
                source_parent_witness,
                source_witness,
                check,
            )?;
        }
    }

    let wire = RemoteRecoveryProofWire {
        version: 1,
        namespace_id: record.namespace_id.clone(),
        actor: record.actor,
        workspace_id: record.workspace_id,
        operation_id: record.operation_id,
        method: record.method,
        old_runtime_id: record.host_runtime_id,
        current_runtime_id: current_runtime,
        plan_sha256: record.plan.plan_sha256().to_owned(),
        prepared_proof_sha256: record.prepared_proof_sha256.clone(),
        observed,
        source_path: path_text(source_path)?,
        source_parent_path: path_text(source_parent_path)?,
        destination_path,
        destination_parent_path,
        source_identity_sha256: record.source_pin_sha256().to_owned(),
        source_parent_identity_sha256: record.source_parent_pin_sha256().to_owned(),
        destination_identity_sha256,
        destination_parent_identity_sha256,
        source_absent,
        destination_absent,
        effect_receipt_sha256: None,
        owner_lock_receipt_sha256: owner_lock_receipt_sha256.to_owned(),
        operation_retirement_receipt_sha256: operation_retirement_receipt_sha256.to_owned(),
    };
    let proof_json = serde_json::to_string(&wire).map_err(|_| DesktopFileErrorCode::Invalid)?;
    if proof_json.len() > MAX_RECOVERY_PROOF_BYTES {
        return Err(DesktopFileErrorCode::Limit);
    }
    RemoteDesktopNamespaceRecoveryEvidence::from_host_verified_owner_lock_and_retirement(
        record,
        current_runtime,
        &proof_json,
    )
    .map_err(|_| DesktopFileErrorCode::Invalid)
}

struct PreparedPins {
    source: SourcePinWire,
    source_parent: DesktopDirectoryWitness,
    destination_parent: Option<DesktopDirectoryWitness>,
}

/// Obtain the process witness from the same bounded, rehashed manifest used
/// for filesystem recovery. A legacy manifest without it cannot prove that a
/// lost no-exec worker stopped and must retain quarantine.
pub(super) fn prepared_host_process(
    record: &DesktopNamespaceIntentRecord,
) -> Result<lomi_platform::noexec_process::NoExecHostProcessWitness, DesktopFileErrorCode> {
    if record.state != DesktopNamespaceIntentState::Prepared {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let witness = parse_prepared(record)?
        .source
        .host_process
        .ok_or(DesktopFileErrorCode::Unsupported)?;
    witness
        .canonical_json()
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    Ok(witness)
}

pub(super) fn prepared_remote_host_process(
    record: &RemoteDesktopNamespaceIntentRecord,
) -> Result<lomi_platform::noexec_process::NoExecHostProcessWitness, DesktopFileErrorCode> {
    if record.state != DesktopNamespaceIntentState::Prepared {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let witness = parse_prepared_remote(record)?
        .source
        .host_process
        .ok_or(DesktopFileErrorCode::Unsupported)?;
    witness
        .canonical_json()
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    Ok(witness)
}

fn parse_prepared(
    record: &DesktopNamespaceIntentRecord,
) -> Result<PreparedPins, DesktopFileErrorCode> {
    let namespace_id = record.plan.namespace_id();
    parse_prepared_record(PreparedRecordRef {
        plan: &record.plan,
        host_runtime_id: record.host_runtime_id,
        proof_json: &record.prepared_proof_json,
        proof_sha256: &record.prepared_proof_sha256,
        source_pin_sha256: record.source_pin_sha256(),
        source_parent_pin_sha256: record.source_parent_pin_sha256(),
        destination_parent_pin_sha256: record.destination_parent_pin_sha256(),
        operation_id: Some(record.operation_id),
        fence_id: Some(record.fence_id),
        namespace_id: Some(&namespace_id),
    })
}

fn parse_prepared_remote(
    record: &RemoteDesktopNamespaceIntentRecord,
) -> Result<PreparedPins, DesktopFileErrorCode> {
    parse_prepared_record(PreparedRecordRef {
        plan: &record.plan,
        host_runtime_id: record.host_runtime_id,
        proof_json: &record.prepared_proof_json,
        proof_sha256: &record.prepared_proof_sha256,
        source_pin_sha256: record.source_pin_sha256(),
        source_parent_pin_sha256: record.source_parent_pin_sha256(),
        destination_parent_pin_sha256: record.destination_parent_pin_sha256(),
        operation_id: None,
        fence_id: None,
        namespace_id: Some(&record.namespace_id),
    })
}

fn parse_prepared_record(
    record: PreparedRecordRef<'_>,
) -> Result<PreparedPins, DesktopFileErrorCode> {
    if record.proof_json.is_empty()
        || record.proof_json.len() > MAX_PREPARED_PROOF_BYTES
        || sha256(record.proof_json.as_bytes()) != record.proof_sha256
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let proof: NamespacePhysicalProofWire =
        serde_json::from_str(record.proof_json).map_err(|_| DesktopFileErrorCode::Invalid)?;
    let (source_path, destination_path) = effect_paths(record.plan.effect());
    let source_parent_path = source_path.parent().ok_or(DesktopFileErrorCode::Invalid)?;
    let destination_parent = destination_path
        .map(|path| path.parent().ok_or(DesktopFileErrorCode::Invalid))
        .transpose()?;
    if proof.version != 1
        || proof.operation_id != record.operation_id
        || proof.fence_id != record.fence_id
        || proof.namespace_id.as_deref() != record.namespace_id
        || proof.host_runtime_id != record.host_runtime_id
        || proof.plan_sha256 != record.plan.plan_sha256()
        || proof.source_path != path_text(source_path)?
        || proof.source_parent_path != path_text(source_parent_path)?
        || proof.destination_path.as_deref()
            != destination_path.map(path_text).transpose()?.as_deref()
        || proof.destination_parent_path.as_deref()
            != destination_parent.map(path_text).transpose()?.as_deref()
        || proof.source_identity_pin.len() > MAX_PIN_BYTES
        || proof.source_parent_identity_pin.len() > MAX_PIN_BYTES
        || proof
            .destination_parent_identity_pin
            .as_ref()
            .is_some_and(|pin| pin.len() > MAX_PIN_BYTES)
        || sha256(proof.source_identity_pin.as_bytes()) != record.source_pin_sha256
        || sha256(proof.source_parent_identity_pin.as_bytes()) != record.source_parent_pin_sha256
        || proof
            .destination_parent_identity_pin
            .as_deref()
            .map(|pin| sha256(pin.as_bytes()))
            != record.destination_parent_pin_sha256.map(ToOwned::to_owned)
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    match record.plan.effect() {
        DesktopNamespaceEffect::Move { .. }
            if proof.destination_absent != Some(true)
                || proof.destination_parent_identity_pin.is_none() =>
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        DesktopNamespaceEffect::Remove { .. }
            if proof.destination_absent.is_some()
                || proof.destination_parent_identity_pin.is_some() =>
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        _ => {}
    }

    let source: SourcePinWire = serde_json::from_str(&proof.source_identity_pin)
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    validate_source_manifest(record.plan, &source, source_path)?;
    let source_parent: DesktopDirectoryWitness =
        serde_json::from_str(&proof.source_parent_identity_pin)
            .map_err(|_| DesktopFileErrorCode::Invalid)?;
    require_recovery_witness(&source_parent)?;
    let destination_parent_witness = proof
        .destination_parent_identity_pin
        .as_deref()
        .map(serde_json::from_str::<DesktopDirectoryWitness>)
        .transpose()
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    if let Some(witness) = destination_parent_witness.as_ref() {
        require_recovery_witness(witness)?;
    }
    if destination_parent.is_some() != destination_parent_witness.is_some() {
        return Err(DesktopFileErrorCode::Invalid);
    }
    Ok(PreparedPins {
        source,
        source_parent,
        destination_parent: destination_parent_witness,
    })
}

fn validate_source_manifest(
    plan: &dyn RecoveryPlanView,
    source: &SourcePinWire,
    source_path: &Path,
) -> Result<(), DesktopFileErrorCode> {
    if source.version != 1
        || source.workspace_roots.len() != plan.workspaces().len()
        || source.guarded_roots.len() != plan.guarded_workspace_ids().len()
        || source.guarded_roots.len() > MAX_WORKSPACES
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    require_recovery_witness(&source.root)?;

    let mut guarded = BTreeMap::new();
    let mut previous_id = None;
    for root in &source.guarded_roots {
        require_recovery_witness(&root.witness)?;
        let path = PathBuf::from(&root.old_path);
        validate_absolute_path(&path)?;
        if previous_id.is_some_and(|previous| previous >= root.workspace_id)
            || guarded
                .insert(root.workspace_id, (path, &root.witness))
                .is_some()
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
        previous_id = Some(root.workspace_id);
    }
    if guarded.keys().copied().collect::<BTreeSet<_>>()
        != plan.guarded_workspace_ids().iter().copied().collect()
    {
        return Err(DesktopFileErrorCode::Invalid);
    }

    for (wire, workspace) in source.workspace_roots.iter().zip(plan.workspaces()) {
        let Some((old_path, witness)) = guarded.get(&workspace.workspace_id) else {
            return Err(DesktopFileErrorCode::Invalid);
        };
        let expected_relative = relative_path(&workspace.old_path, source_path)?;
        let expected_new = match plan.effect() {
            DesktopNamespaceEffect::Move { new_path, .. } => {
                Some(new_path.join(Path::new(&expected_relative)))
            }
            DesktopNamespaceEffect::Remove { .. } => None,
        };
        if wire.workspace_id != workspace.workspace_id
            || wire.relative_path != expected_relative
            || &wire.witness != *witness
            || old_path != &workspace.old_path
            || !is_under_or_equal(&workspace.old_path, source_path)
            || (expected_relative.is_empty() && &wire.witness != &source.root)
            || workspace.new_path != expected_new
        {
            return Err(DesktopFileErrorCode::Invalid);
        }
    }
    Ok(())
}

enum MoveRootDisposition {
    Original,
    Moved,
}

fn observe_move(
    source_path: &Path,
    destination_path: &Path,
    source_parent_path: &Path,
    destination_parent_path: &Path,
    source_parent_witness: &DesktopDirectoryWitness,
    destination_parent_witness: &DesktopDirectoryWitness,
    source_witness: &DesktopDirectoryWitness,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<MoveObservation, DesktopFileErrorCode> {
    if !source_witness.identity.is_valid() {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let source_parent = open_matching_directory(source_parent_path, source_parent_witness, check)?;
    let destination_parent =
        open_matching_directory(destination_parent_path, destination_parent_witness, check)?;
    let source_entry = census_child(&source_parent, source_path, check)?;
    let destination_entry = census_child(&destination_parent, destination_path, check)?;

    let result = match (source_entry, destination_entry) {
        (Some(source), None)
            if source.kind == DesktopFileKind::Directory
                && source.identity == source_witness.identity =>
        {
            let current = open_matching_directory(source_path, source_witness, check)?;
            current.verify_named()?;
            MoveObservation::NoChange
        }
        (None, Some(destination))
            if destination.kind == DesktopFileKind::Directory
                && destination.identity == source_witness.identity =>
        {
            let current = open_matching_directory(destination_path, source_witness, check)?;
            current.verify_named()?;
            MoveObservation::Applied
        }
        _ => return Err(DesktopFileErrorCode::Changed),
    };

    source_parent.verify_named()?;
    destination_parent.verify_named()?;
    let source_after = census_child(&source_parent, source_path, check)?;
    let destination_after = census_child(&destination_parent, destination_path, check)?;
    match (&result, source_after, destination_after) {
        (MoveObservation::NoChange, Some(source), None)
            if source.kind == DesktopFileKind::Directory
                && source.identity == source_witness.identity => {}
        (MoveObservation::Applied, None, Some(destination))
            if destination.kind == DesktopFileKind::Directory
                && destination.identity == source_witness.identity => {}
        _ => return Err(DesktopFileErrorCode::Changed),
    }
    source_parent.verify_named()?;
    destination_parent.verify_named()?;
    check()?;
    Ok(result)
}

fn verify_root_manifest(
    plan: &impl RecoveryPlanView,
    source: &SourcePinWire,
    disposition: MoveRootDisposition,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    let workspace_roots: BTreeMap<_, _> = source
        .workspace_roots
        .iter()
        .map(|workspace| (workspace.workspace_id, workspace))
        .collect();
    for root in &source.guarded_roots {
        check()?;
        let old_path = PathBuf::from(&root.old_path);
        let target = match workspace_roots.get(&root.workspace_id) {
            Some(workspace) => match disposition {
                MoveRootDisposition::Original => old_path,
                MoveRootDisposition::Moved => {
                    let DesktopNamespaceEffect::Move { new_path, .. } = plan.effect() else {
                        return Err(DesktopFileErrorCode::Invalid);
                    };
                    new_path.join(Path::new(&workspace.relative_path))
                }
            },
            None => old_path,
        };
        open_matching_directory(&target, &root.witness, check)?;
    }
    Ok(())
}

fn verify_unaffected_guarded_roots(
    plan: &impl RecoveryPlanView,
    source: &SourcePinWire,
    removed_path: &Path,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    let affected: BTreeSet<_> = plan
        .workspaces()
        .iter()
        .map(|workspace| workspace.workspace_id)
        .collect();
    for root in &source.guarded_roots {
        check()?;
        let path = PathBuf::from(&root.old_path);
        if affected.contains(&root.workspace_id) && is_under_or_equal(&path, removed_path) {
            continue;
        }
        open_matching_directory(&path, &root.witness, check)?;
    }
    Ok(())
}

fn observe_remove_no_change(
    plan: &impl RecoveryPlanView,
    source: &SourcePinWire,
    source_path: &Path,
    source_parent_path: &Path,
    source_parent_witness: &DesktopDirectoryWitness,
    source_witness: &DesktopDirectoryWitness,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<(), DesktopFileErrorCode> {
    if !matches!(plan.effect(), DesktopNamespaceEffect::Remove { .. }) {
        return Err(DesktopFileErrorCode::Invalid);
    }
    let parent = open_matching_directory(source_parent_path, source_parent_witness, check)?;
    let source_entry = census_child(&parent, source_path, check)?;
    if !source_entry.as_ref().is_some_and(|entry| {
        entry.kind == DesktopFileKind::Directory && entry.identity == source_witness.identity
    }) {
        return Err(DesktopFileErrorCode::Changed);
    }
    let root = open_matching_directory(source_path, source_witness, check)?;
    root.verify_named()?;
    verify_root_manifest(plan, source, MoveRootDisposition::Original, check)?;
    parent.verify_named()?;
    let confirmed = census_child(&parent, source_path, check)?;
    if !confirmed.as_ref().is_some_and(|entry| {
        entry.kind == DesktopFileKind::Directory && entry.identity == source_witness.identity
    }) {
        return Err(DesktopFileErrorCode::Changed);
    }
    root.verify_named()?;
    parent.verify_named()?;
    check()?;
    Ok(())
}

fn open_matching_directory(
    path: &Path,
    expected: &DesktopDirectoryWitness,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<DesktopDirectoryPin, DesktopFileErrorCode> {
    require_recovery_witness(expected)?;
    validate_absolute_path(path)?;
    check()?;
    let pin = DesktopDirectoryPin::open(path)?;
    if pin.witness() != expected {
        return Err(DesktopFileErrorCode::Changed);
    }
    pin.verify_named()?;
    check()?;
    Ok(pin)
}

fn census_child(
    parent: &DesktopDirectoryPin,
    target: &Path,
    check: &mut impl FnMut() -> Result<(), DesktopFileErrorCode>,
) -> Result<Option<lomi_files::desktop::DesktopSourcePrecondition>, DesktopFileErrorCode> {
    let leaf = target.file_name().ok_or(DesktopFileErrorCode::Invalid)?;
    check()?;
    parent.verify_named()?;
    let found = parent.exact_child(leaf, check)?;
    parent.verify_named()?;
    check()?;
    Ok(found)
}

fn effect_paths(effect: &DesktopNamespaceEffect) -> (&Path, Option<&Path>) {
    match effect {
        DesktopNamespaceEffect::Move { old_path, new_path } => {
            (old_path.as_path(), Some(new_path.as_path()))
        }
        DesktopNamespaceEffect::Remove { old_path } => (old_path.as_path(), None),
    }
}

fn relative_path(path: &Path, root: &Path) -> Result<String, DesktopFileErrorCode> {
    let relative = path
        .strip_prefix(root)
        .map_err(|_| DesktopFileErrorCode::Invalid)?;
    if relative
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        && relative != Path::new("")
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    relative
        .to_str()
        .map(ToOwned::to_owned)
        .ok_or(DesktopFileErrorCode::Invalid)
}

fn validate_absolute_path(path: &Path) -> Result<(), DesktopFileErrorCode> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || path.to_str().is_none()
    {
        return Err(DesktopFileErrorCode::Invalid);
    }
    Ok(())
}

fn is_under_or_equal(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

fn require_recovery_witness(witness: &DesktopDirectoryWitness) -> Result<(), DesktopFileErrorCode> {
    if !witness.is_valid() || witness.created_unix_ns.is_none() {
        return Err(DesktopFileErrorCode::Unsupported);
    }
    Ok(())
}

fn path_text(path: &Path) -> Result<String, DesktopFileErrorCode> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or(DesktopFileErrorCode::Invalid)
}

fn sha256(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
