//! Actual Store journal prerequisites for a future typed remote rename executor.
//! Synthetic remote identity/context only: this file does not mint remote
//! authority or claim to exercise a worker, current peer, transport or writer cap.
use lomi_host_store::{
    HostStore, Limits, OperationBinding, ProjectRecord, StoreError, parameter_hash,
};
use lomi_remote_protocol::{rpc::*, *};

fn actor() -> ConsumerAuthorizationId {
    ConsumerAuthorizationId::from_bytes([71; 16]).unwrap()
}
fn required() -> CapabilitySet {
    vec![
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalManage,
    ]
    .try_into()
    .unwrap()
}
fn binding(call: &RpcCall, consumer: ConsumerAuthorizationId) -> OperationBinding {
    let edit = super::RemoteTerminalEdit::from_call(call).unwrap();
    let mutation = edit.mutation();
    OperationBinding {
        rights: StoredOperationRights::new(
            mutation.operation_id,
            consumer,
            mutation.context.workspace_id,
            edit.method(),
            required(),
            false,
        )
        .unwrap(),
        // Preserve original remote wire tuple; no hash of translated local DTO.
        parameter_hash: parameter_hash(call).unwrap(),
    }
}
fn fixture() -> (tempfile::TempDir, HostStore, ProjectRecord) {
    fixture_layout(false)
}
fn fixture_layout(move_layout: bool) -> (tempfile::TempDir, HostStore, ProjectRecord) {
    let root = tempfile::tempdir().unwrap();
    let mut store = HostStore::open(&root.path().join("host.sqlite"), Limits::default()).unwrap();
    let project = store
        .add_project(root.path(), "rename fixture".to_owned().try_into().unwrap())
        .unwrap();
    store
        .share(project.state.context.workspace_id, project.fence)
        .unwrap();
    let project = store.workspace(project.state.context.workspace_id).unwrap();
    let create = OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([72; 16]).unwrap(),
            actor(),
            project.state.context.workspace_id,
            Method::TerminalCreate,
            required(),
            false,
        )
        .unwrap(),
        parameter_hash: parameter_hash(&"source-only fixture setup; no PTY process").unwrap(),
    };
    store
        .admit_external(&create, project.state.domain_revision)
        .unwrap();
    let permit = store.start_external(&create).unwrap();
    let mut next = project.state.clone();
    next.domain_revision.0 += 1;
    let pane_id = PaneId::from_bytes([73; 16]).unwrap();
    let session_id = TerminalSessionId::from_bytes([74; 16]).unwrap();
    let session_epoch = SessionEpoch::from_bytes([75; 16]).unwrap();
    next.tabs = BoundedList(vec![TerminalTab {
        tab_id: TabId::from_bytes([76; 16]).unwrap(),
        name: "before".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                state: PaneState::Running,
                session: Some(TerminalContext {
                    workspace: next.context.clone(),
                    pane_id,
                    session_id,
                    session_epoch,
                    profile: TerminalProfile::ExperimentalRustGridV1,
                }),
            },
        },
    }]);
    if move_layout {
        next.tabs.0.push(TerminalTab {
            tab_id: TabId::from_bytes([79; 16]).unwrap(),
            name: "move-target".to_owned().try_into().unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: PaneId::from_bytes([80; 16]).unwrap(),
                    state: PaneState::Stopped,
                    session: None,
                },
            },
        });
    }
    store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: next.domain_revision,
                pane_id,
                session_id,
                session_epoch,
            }),
            Some(next),
        )
        .unwrap();
    for publication in store.pending_publications().unwrap() {
        assert!(store.acknowledge_publication(&publication).unwrap());
    }
    let current = store.workspace(project.state.context.workspace_id).unwrap();
    (root, store, current)
}
fn call(project: &ProjectRecord, operation: u8, name: &str) -> RpcCall {
    // Owner runtime generation is local. The grant tuple uses independent
    // server generation/access/grant revision. Workspace ID/epoch stay exact.
    let mut wire = project.state.context.clone();
    wire.runtime_generation = DecimalU64(wire.runtime_generation.0 + 11);
    wire.host_access_epoch = DecimalU64(wire.host_access_epoch.0 + 12);
    wire.grant_revision = DecimalU64(wire.grant_revision.0 + 13);
    RpcCall::TerminalRename(TerminalRenameParams {
        mutation: MutationContext {
            operation_id: OperationId::from_bytes([operation; 16]).unwrap(),
            context: wire,
            expected_revision: project.state.domain_revision,
        },
        tab_id: project.state.tabs.0[0].tab_id,
        name: name.to_owned().try_into().unwrap(),
    })
}
fn rename(
    store: &mut HostStore,
    call: &RpcCall,
    consumer: ConsumerAuthorizationId,
) -> lomi_host_store::Admission {
    let RpcCall::TerminalRename(params) = call else {
        panic!("rename fixture");
    };
    store
        .rename_tab(
            &binding(call, consumer),
            params.mutation.expected_revision,
            params.tab_id,
            params.name.clone(),
        )
        .unwrap()
}
#[test]
fn rename_uses_original_remote_hash_consumer_rights_and_atomic_exact_delta() {
    let (_root, mut store, before) = fixture();
    assert!(store.pending_publications().unwrap().is_empty());
    let request = call(&before, 77, "after");
    let original = binding(&request, actor());
    let mut translated = request.clone();
    let RpcCall::TerminalRename(params) = &mut translated else {
        unreachable!();
    };
    params.mutation.context = before.state.context.clone();
    assert_ne!(
        original.parameter_hash,
        parameter_hash(&translated).unwrap()
    );
    assert_ne!(actor().to_bytes(), store.identity().host_id.to_bytes());
    let result = rename(&mut store, &request, actor());
    assert!(result.newly_admitted);
    assert_eq!(result.receipt.state(), OperationState::Succeeded);
    assert_eq!(result.receipt.effect(), Effect::Committed);
    assert_eq!(result.receipt.stored_rights().actor(), actor());
    assert_eq!(result.receipt.stored_rights().actual_rights(), &required());
    let after = store.workspace(before.state.context.workspace_id).unwrap();
    let mut expected = before.state.clone();
    expected.domain_revision.0 += 1;
    expected.tabs.0[0].name = "after".to_owned().try_into().unwrap();
    assert_eq!(after.state, expected);
    assert_eq!(after.local_root, before.local_root);
    assert_eq!(after.consent, before.consent);
    assert_eq!(after.fence, before.fence);
    let publication = store.pending_publications().unwrap().remove(0);
    assert_eq!(publication.workspace_id, before.state.context.workspace_id);
    assert_eq!(publication.domain_revision, after.state.domain_revision);
    assert_eq!(publication.fence, before.fence);
    assert!(publication.enabled);
}
#[test]
fn exact_duplicate_precedes_cas_and_does_not_replace_own_publication() {
    let (_root, mut store, before) = fixture();
    let request = call(&before, 78, "once");
    let first = rename(&mut store, &request, actor());
    let publication = store.pending_publications().unwrap();
    let duplicate = rename(&mut store, &request, actor());
    assert!(!duplicate.newly_admitted);
    assert_eq!(first.receipt, duplicate.receipt);
    assert_eq!(store.pending_publications().unwrap(), publication);
    assert_eq!(
        store
            .workspace(before.state.context.workspace_id)
            .unwrap()
            .state
            .domain_revision
            .0,
        before.state.domain_revision.0 + 1
    );
    // This proves only atomic journal deduplication. A future remote executor
    // MUST still deny ordinary current reads while that publication is pending.
}
#[test]
fn changed_wire_parameters_conflict_and_foreign_or_insufficient_disclosure_denies() {
    let (_root, mut store, before) = fixture();
    let request = call(&before, 79, "once");
    let original = binding(&request, actor());
    rename(&mut store, &request, actor());
    let changed = call(&before, 79, "changed");
    let RpcCall::TerminalRename(params) = &changed else {
        unreachable!();
    };
    assert!(matches!(
        store.rename_tab(
            &binding(&changed, actor()),
            params.mutation.expected_revision,
            params.tab_id,
            params.name.clone()
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(
        store
            .lookup(&binding(&changed, actor()), &required())
            .unwrap()
            .is_none()
    );
    let read: CapabilitySet = vec![Capability::WorkspaceRead].try_into().unwrap();
    assert!(store.lookup(&original, &read).unwrap().is_none());
    let foreign = ConsumerAuthorizationId::from_bytes([80; 16]).unwrap();
    assert!(
        store
            .lookup(&binding(&request, foreign), &required())
            .unwrap()
            .is_none()
    );
    let current = store.workspace(before.state.context.workspace_id).unwrap();
    assert_eq!(
        current.state.tabs.0[0].name,
        DisplayText::try_from("once".to_owned()).unwrap()
    );
    let stale = call(&before, 81, "stale CAS");
    let RpcCall::TerminalRename(params) = &stale else {
        unreachable!();
    };
    assert!(matches!(
        store.rename_tab(
            &binding(&stale, actor()),
            params.mutation.expected_revision,
            params.tab_id,
            params.name.clone()
        ),
        Err(StoreError::RevisionConflict)
    ));
}

#[test]
fn durable_receipt_survives_unshare_and_is_not_current_remote_authority() {
    let (_root, mut store, before) = fixture();
    let request = call(&before, 82, "committed before revoke");
    let result = rename(&mut store, &request, actor());
    let own_publication = store.pending_publications().unwrap().remove(0);
    store.unshare(before.state.context.workspace_id).unwrap();
    let revoked = store.workspace(before.state.context.workspace_id).unwrap();
    assert!(!revoked.consent);
    assert_ne!(revoked.fence, before.fence);
    assert_ne!(
        revoked.state.context.workspace_epoch,
        before.state.context.workspace_epoch
    );
    let replacement = store.pending_publications().unwrap().remove(0);
    assert!(!replacement.enabled);
    assert_ne!(replacement.token, own_publication.token);
    assert!(!store.acknowledge_publication(&own_publication).unwrap());
    // Caller-supplied synthetic caps can still read the durable audit receipt.
    // Therefore receipt presence/Store.lookup alone MUST NEVER bypass actual
    // owner consent/epoch/fence/revoke/source checks in a future remote adapter.
    assert_eq!(
        store
            .lookup(&binding(&request, actor()), &required())
            .unwrap(),
        Some(result.receipt)
    );
}

fn move_request(project: &ProjectRecord, operation: u8) -> RpcCall {
    let RpcCall::TerminalRename(params) = call(project, operation, "unused") else {
        unreachable!()
    };
    RpcCall::TerminalMove(TerminalMoveParams {
        mutation: params.mutation,
        pane_id: PaneId::from_bytes([73; 16]).unwrap(),
        source_tab_id: project.state.tabs.0[0].tab_id,
        target_tab_id: project.state.tabs.0[1].tab_id,
        target_pane_id: PaneId::from_bytes([80; 16]).unwrap(),
        placement: MovePlacement::Before,
    })
}
fn move_pane(
    store: &mut HostStore,
    request: &RpcCall,
) -> Result<lomi_host_store::Admission, StoreError> {
    let RpcCall::TerminalMove(params) = request else {
        unreachable!()
    };
    store.move_pane(
        &binding(request, actor()),
        params.mutation.expected_revision,
        &lomi_host_store::TerminalMoveLayout::from(params),
    )
}
#[test]
fn move_original_wire_binding_duplicate_before_missing_source_and_cas_retains_exact_receipt() {
    let (_root, mut store, project) = fixture_layout(true);
    let request = move_request(&project, 115);
    let RpcCall::TerminalMove(params) = &request else {
        unreachable!()
    };
    let original = binding(&request, actor());
    let mut translated = request.clone();
    let RpcCall::TerminalMove(local) = &mut translated else {
        unreachable!()
    };
    local.mutation.context = project.state.context.clone();
    assert_ne!(
        original.parameter_hash,
        parameter_hash(&translated).unwrap()
    );
    let events = store.events_after(0).unwrap().events.len();
    let admission = move_pane(&mut store, &request).unwrap();
    let after = store.workspace(project.state.context.workspace_id).unwrap();
    assert!(
        !after
            .state
            .tabs
            .0
            .iter()
            .any(|t| t.tab_id == params.source_tab_id)
    );
    assert_eq!(
        after.state,
        super::RemoteTerminalEdit::from_call(&request)
            .unwrap()
            .expected_state(&project.state)
            .unwrap()
    );
    let outbox = store.pending_publications().unwrap();
    let duplicate = move_pane(&mut store, &request).unwrap();
    assert!(!duplicate.newly_admitted);
    assert_eq!(duplicate.receipt, admission.receipt);
    assert_eq!(store.pending_publications().unwrap(), outbox);
    assert_eq!(store.events_after(0).unwrap().events.len(), events + 1);
    assert_eq!(
        store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .state,
        after.state
    );
    let mut changed = request.clone();
    let RpcCall::TerminalMove(changed_params) = &mut changed else {
        unreachable!()
    };
    changed_params.placement = MovePlacement::After;
    assert!(matches!(
        move_pane(&mut store, &changed),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(
        store
            .lookup(&binding(&changed, actor()), &required())
            .unwrap(),
        None
    );
    assert_eq!(
        store.lookup(&original, &required()).unwrap(),
        Some(admission.receipt.clone())
    );
    let observe: CapabilitySet = vec![Capability::WorkspaceRead, Capability::TerminalObserve]
        .try_into()
        .unwrap();
    assert_eq!(store.lookup(&original, &observe).unwrap(), None);
    assert_eq!(
        store
            .lookup(
                &binding(
                    &request,
                    ConsumerAuthorizationId::from_bytes([117; 16]).unwrap()
                ),
                &required()
            )
            .unwrap(),
        None
    );
    assert!(
        StoredOperationRights::new(
            params.mutation.operation_id,
            actor(),
            params.mutation.context.workspace_id,
            Method::TerminalMove,
            observe,
            false
        )
        .is_err()
    );
    assert_eq!(store.pending_publications().unwrap(), outbox);
}
