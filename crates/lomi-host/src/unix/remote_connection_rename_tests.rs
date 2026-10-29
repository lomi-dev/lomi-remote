//! Signed synthetic gate fixtures. No new receipt proof or current authority is
//! fabricated here; generic gates must continue rejecting pending publication.
use super::*;
fn rename(f: &Fixture) -> RpcCall {
    let RpcCall::TerminalSnapshot(target) = f.snapshot(0) else {
        unreachable!();
    };
    RpcCall::TerminalRename(TerminalRenameParams {
        mutation: MutationContext {
            operation_id: OperationId::from_bytes([91; 16]).unwrap(),
            context: target.terminal.workspace,
            expected_revision: DecimalU64(7),
        },
        tab_id: TabId::from_bytes([92; 16]).unwrap(),
        name: "rename fixture".to_owned().try_into().unwrap(),
    })
}
#[test]
fn rename_requires_actual_signed_manage_and_workspace_channel() {
    let f = Fixture::new(manage(), false);
    let mut core = f.core();
    assert!(
        core.evaluate(&rename(&f), &f.facts(), &mut || f.now(1))
            .is_ok()
    );
    let f = Fixture::new(observe(), false);
    let mut core = f.core();
    assert_eq!(
        core.evaluate(&rename(&f), &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
    let f = Fixture::new(manage(), true);
    let mut core = f.core();
    assert_eq!(
        core.evaluate(&rename(&f), &f.facts(), &mut || f.now(1)),
        Err(GateError::Denied)
    );
}
#[test]
fn ordinary_rename_and_read_never_get_pending_publication_exception() {
    for rename_call in [false, true] {
        let f = Fixture::new(manage(), false);
        let mut core = f.core();
        let mut facts = f.facts();
        facts.pending_publication = true;
        let call = if rename_call {
            rename(&f)
        } else {
            let RpcCall::TerminalSnapshot(target) = f.snapshot(0) else {
                unreachable!();
            };
            RpcCall::WorkspaceGet(WorkspaceReadParams {
                context: target.terminal.workspace,
            })
        };
        assert_eq!(
            core.evaluate(&call, &facts, &mut || f.now(1)),
            Err(GateError::Disposed)
        );
    }
}
#[test]
fn rename_queue_retains_exact_original_wire_call_and_original_deadline() {
    let f = Fixture::new(manage(), false);
    let mut core = f.core();
    let request = f.request(rename(&f), 120000);
    let cancelled = AtomicBool::new(false);
    let operation = Operation::new(Instant::now() + Duration::from_secs(60), &cancelled);
    let queued = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(1))
        .unwrap();
    assert_eq!(queued.deadline, operation.deadline());
    assert_eq!(
        core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(2))
            .unwrap(),
        request
    );
}

fn movement(f: &Fixture) -> RpcCall {
    let RpcCall::TerminalRename(params) = rename(f) else {
        unreachable!()
    };
    RpcCall::TerminalMove(TerminalMoveParams {
        mutation: params.mutation,
        pane_id: PaneId::from_bytes([93; 16]).unwrap(),
        source_tab_id: params.tab_id,
        target_tab_id: TabId::from_bytes([94; 16]).unwrap(),
        target_pane_id: PaneId::from_bytes([95; 16]).unwrap(),
        placement: MovePlacement::After,
    })
}
#[test]
fn move_requires_all_signed_static_rights_and_workspace_channel() {
    // Incomplete dependency closures cannot form even a synthetic signed grant.
    assert!(
        CapabilitySet::try_from(vec![
            Capability::TerminalObserve,
            Capability::TerminalManage
        ])
        .is_err()
    );
    assert!(
        CapabilitySet::try_from(vec![Capability::WorkspaceRead, Capability::TerminalManage])
            .is_err()
    );
    for (rights, terminal_channel, allowed) in [
        (manage(), false, true),
        (observe(), false, false),
        (control(), false, false),
        (manage(), true, false),
    ] {
        let f = Fixture::new(rights, terminal_channel);
        assert_eq!(
            f.core()
                .evaluate(&movement(&f), &f.facts(), &mut || f.now(1))
                .is_ok(),
            allowed
        );
    }
}
#[test]
fn queued_move_retains_wire_hash_operation_identity_and_deadline() {
    let f = Fixture::new(manage(), false);
    let mut core = f.core();
    let request = f.request(movement(&f), 120000);
    let cancelled = AtomicBool::new(false);
    let operation = Operation::new(Instant::now() + Duration::from_secs(60), &cancelled);
    let queued = core
        .queue(&request, &operation, &f.facts(), &mut || f.now(1))
        .unwrap();
    assert_eq!(queued.deadline, operation.deadline());
    let other = Operation::new(operation.deadline(), &cancelled);
    assert!(
        core.after_wait(&queued, &other, &f.facts(), &mut || f.now(2))
            .is_err()
    );
    let original = core
        .after_wait(&queued, &operation, &f.facts(), &mut || f.now(2))
        .unwrap();
    assert_eq!(original, request);
    assert_eq!(
        lomi_host_store::parameter_hash(&original.call).unwrap(),
        lomi_host_store::parameter_hash(&request.call).unwrap()
    );
}
#[test]
fn move_owner_config_generation_grant_changes_and_pending_publication_close_gate() {
    for scenario in 0..8 {
        let mut f = Fixture::new(manage(), false);
        let mut core = f.core();
        let request = movement(&f);
        match scenario {
            0 => f.host.host_authorization_id = HostAuthorizationId::from_bytes([97; 16]).unwrap(),
            1 => f.scope.owner_generation += 1,
            2 => f.scope.authorization_generation += 1,
            3 => f.scope.remote_api_origin = "https://changed.example".into(),
            4 => f.runtime.runtime_generation.0 += 1,
            5 => f.host.access_epoch += 1,
            6 => f.authority.grant_revision += 1,
            _ => {}
        }
        let result = if scenario == 6 {
            core.refresh(f.read(1, &f.heartbeat), &f.facts(), &mut || f.now(2))
        } else {
            let mut facts = f.facts();
            facts.pending_publication = scenario == 7;
            core.evaluate(&request, &facts, &mut || f.now(1))
        };
        assert_eq!(result, Err(GateError::Disposed));
        assert!(core.disposed);
    }
}
#[test]
fn queued_move_cancellation_and_expiry_never_refresh_admission() {
    for expire in [false, true] {
        let f = Fixture::new(manage(), false);
        let mut core = f.core();
        let request = f.request(movement(&f), 120000);
        let cancelled = AtomicBool::new(false);
        let operation = Operation::new(Instant::now() + Duration::from_secs(60), &cancelled);
        let queued = core
            .queue(&request, &operation, &f.facts(), &mut || f.now(1))
            .unwrap();
        if expire {
            operation.expire_for_test();
        } else {
            cancelled.store(true, Ordering::Release);
        }
        assert!(
            core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(2))
                .is_err()
        );
        cancelled.store(false, Ordering::Release);
        assert!(
            core.after_wait(&queued, &operation, &f.facts(), &mut || f.now(3))
                .is_err()
        );
    }
}
