use super::*;
use lomi_host_store::{HostStore, Limits};
use std::{
    sync::atomic::AtomicBool,
    thread,
    time::{Duration, Instant},
};

struct Fixture {
    temp: tempfile::TempDir,
    coordinator: Arc<Coordinator>,
    connection: ConnectionState,
    workspace: WorkspaceId,
}
fn fixture() -> Fixture {
    fixture_with_shell(None)
}
fn fixture_with_shell(shell: Option<DefaultShellProfile>) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let mut store = HostStore::open(&temp.path().join("host.sqlite"), Limits::default()).unwrap();
    let workspace = store
        .add_project(temp.path(), "Synthetic".to_owned().try_into().unwrap())
        .unwrap()
        .state
        .context
        .workspace_id;
    if let Some(shell) = shell {
        store.initialize_default_shell(shell).unwrap();
    }
    let coordinator = Arc::new(Coordinator::new(store, Arc::new(AtomicBool::new(false))));
    let mut connection = new_connection(coordinator.clone()).unwrap();
    connection.profile_override = Some(SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec![],
        cwd: temp.path().into(),
        environment: vec![
            ("HOME".into(), temp.path().to_str().unwrap().into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("TERM".into(), "xterm-256color".into()),
        ],
        shell_integration: None,
        rows: 8,
        cols: 40,
        history: 16,
    });
    Fixture {
        temp,
        coordinator,
        connection,
        workspace,
    }
}
static TEST_OBSERVATION_CANCELLED: AtomicBool = AtomicBool::new(false);
fn test_operation() -> Operation<'static> {
    Operation::new(
        Instant::now() + Duration::from_secs(10),
        &TEST_OBSERVATION_CANCELLED,
    )
}
fn new_connection(coordinator: Arc<Coordinator>) -> Result<ConnectionState, LocalError> {
    let operation = Operation::new(
        Instant::now() + Duration::from_secs(10),
        &coordinator.stopping,
    );
    ConnectionState::new(coordinator.clone(), &operation)
}
fn admitted_dispatch(
    coordinator: &Coordinator,
    connection: &mut ConnectionState,
    request: RpcRequest,
) -> RpcResponse {
    let admission = super::super::ipc_admission::IpcAdmission::capture(
        Duration::from_secs(10),
        &coordinator.stopping,
    )
    .unwrap();
    let operation = admission
        .into_operation(Duration::from_millis(request.timeout_ms.get()))
        .unwrap();
    super::dispatch(coordinator, connection, request, &operation)
}
fn workspace_record(coordinator: &Coordinator, id: WorkspaceId) -> ProjectRecord {
    let operation = test_operation();
    owner_call(&operation, || coordinator.owner.workspace(&operation, id)).unwrap()
}
fn add_workspace(coordinator: &Coordinator, root: &std::path::Path, name: &str) -> ProjectRecord {
    let operation = test_operation();
    let name: DisplayText = name.to_owned().try_into().unwrap();
    let mut turn = owner_call(&operation, || {
        coordinator
            .owner
            .begin_add_project(&operation, root, name.clone())
    })
    .unwrap();
    owner_call(&operation, || turn.try_commit()).unwrap()
}
fn lookup(
    coordinator: &Coordinator,
    actor: ConsumerAuthorizationId,
    workspace: WorkspaceId,
    id: OperationId,
) -> Option<OperationReceipt> {
    let operation = test_operation();
    owner_call(&operation, || {
        coordinator
            .owner
            .lookup_operation(&operation, actor, workspace, id, &local_rights())
    })
    .unwrap()
}
fn hold_store(
    coordinator: Arc<Coordinator>,
) -> (std::sync::mpsc::Sender<()>, thread::JoinHandle<()>) {
    let (locked_tx, locked_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let worker = thread::spawn(move || {
        let operation = test_operation();
        coordinator
            .owner
            .hold_store_for_test(&operation, locked_tx, release_rx)
            .unwrap();
    });
    locked_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    (release_tx, worker)
}
fn state(f: &Fixture) -> WorkspaceState {
    workspace_record(&f.coordinator, f.workspace).state
}
fn mutation_context(f: &Fixture) -> MutationContext {
    let state = state(f);
    MutationContext {
        context: state.context,
        operation_id: fresh(),
        expected_revision: state.domain_revision,
    }
}
fn request(call: RpcCall) -> RpcRequest {
    RpcRequest {
        v: ApplicationMajor,
        r#type: RequestKind::Request,
        request_id: Uuid::new_v4().to_string().try_into().unwrap(),
        timeout_ms: TimeoutMs::new(10000).unwrap(),
        call,
    }
}
fn invoke(f: &mut Fixture, call: RpcCall) -> RpcResponse {
    let request = request(call);
    let response = admitted_dispatch(&f.coordinator, &mut f.connection, request.clone());
    response.validate_for(&request).unwrap();
    response
}
fn good(f: &mut Fixture, call: RpcCall) -> RpcResult {
    match invoke(f, call) {
        RpcResponse::Result { result, .. } => result,
        RpcResponse::Error { error, .. } => panic!("synthetic RPC failed: {:?}", error.code()),
    }
}
fn create_call(f: &Fixture, name: &str) -> RpcCall {
    RpcCall::TerminalCreate(TerminalCreateParams {
        mutation: mutation_context(f),
        tab_name: name.to_owned().try_into().unwrap(),
        profile_id: "default".to_owned().try_into().unwrap(),
    })
}
fn terminal_context(f: &Fixture) -> TerminalContext {
    state(f)
        .tabs
        .0
        .iter()
        .find_map(|tab| first_pane(&tab.layout).session.clone())
        .unwrap()
}
fn first_pane(layout: &TerminalLayout) -> &TerminalPane {
    match layout {
        TerminalLayout::Pane { pane } => pane,
        TerminalLayout::Split { first, .. } => first_pane(first),
    }
}
fn snapshot(f: &mut Fixture, context: &TerminalContext) -> TerminalSnapshotMetadata {
    let RpcResult::TerminalAttach(metadata) = good(
        f,
        RpcCall::TerminalAttach(TerminalReadParams {
            terminal: context.clone(),
        }),
    ) else {
        panic!()
    };
    let mut bytes = Vec::new();
    loop {
        let event = f
            .connection
            .next_event(&test_operation())
            .expect("snapshot should emit chunks and completion");
        let LocalStreamEvent::Terminal(frame) = event else {
            panic!()
        };
        lomi_remote_protocol::decode_terminal_frame(&serde_json::to_vec(&frame).unwrap()).unwrap();
        match frame {
            TerminalStreamFrame::SnapshotChunk(chunk) => {
                assert!(chunk.bytes.0.len() <= 16384);
                bytes.extend(chunk.bytes.0);
            }
            TerminalStreamFrame::SnapshotComplete(complete) => {
                assert_eq!(complete.subscription_id, metadata.subscription_id);
                break;
            }
            _ => panic!("metadata response must precede only its snapshot chunks"),
        }
    }
    assert_eq!(bytes.len(), metadata.total_bytes.0 as usize);
    let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(value["sessionEpoch"], String::from(context.session_epoch));
    metadata
}
fn claim(
    f: &mut Fixture,
    context: &TerminalContext,
    metadata: &TerminalSnapshotMetadata,
) -> TerminalLeaseResult {
    let RpcResult::TerminalClaim(lease) = good(
        f,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: context.clone(),
            subscription_id: metadata.subscription_id.clone(),
            rendered_through_seq: metadata.through_seq,
        }),
    ) else {
        panic!()
    };
    lease
}
#[test]
fn durable_create_duplicate_and_second_view_never_spawn_again() {
    let mut f = fixture();
    let call = create_call(&f, "First");
    let RpcResult::TerminalCreate(first) = good(&mut f, call.clone()) else {
        panic!()
    };
    assert_eq!(first.state(), OperationState::Succeeded);
    let context = terminal_context(&f);
    let original = state(&f);
    let RpcResult::TerminalCreate(repeated) = good(&mut f, call) else {
        panic!()
    };
    assert_eq!(first, repeated);
    assert_eq!(state(&f), original);
    let metadata = snapshot(&mut f, &context);
    assert!(metadata.total_bytes.0 > 16384);
    let mut second = new_connection(f.coordinator.clone()).unwrap();
    let req = request(RpcCall::TerminalAttach(TerminalReadParams {
        terminal: context.clone(),
    }));
    assert!(matches!(
        admitted_dispatch(&f.coordinator, &mut second, req),
        RpcResponse::Result {
            result: RpcResult::TerminalAttach(_),
            ..
        }
    ));
    drop(second);
    assert!(
        f.coordinator
            .terminals
            .snapshot(context.session_id, context.session_epoch)
            .is_ok()
    );
    assert_eq!(state(&f), original);
    f.coordinator.terminals.shutdown().unwrap();
}
#[test]
fn canonical_input_lease_binding_duplicates_and_disconnect_do_not_replay() {
    let mut f = fixture();
    let call = create_call(&f, "Input");
    good(&mut f, call);
    let context = terminal_context(&f);
    let metadata = snapshot(&mut f, &context);
    let lease = claim(&mut f, &context, &metadata);
    let input = RpcCall::TerminalInput(TerminalInputParams {
        terminal: context.clone(),
        lease: lease.lease.clone(),
        input_id: lease.next_input_id,
        input_seq: lease.next_input_seq,
        bytes: BoundedList(b"printf 'RPC_SYNTHETIC\\n'\n".to_vec()),
    });
    let RpcResult::TerminalInput(first) = good(&mut f, input.clone()) else {
        panic!()
    };
    let RpcResult::TerminalInput(duplicate) = good(&mut f, input) else {
        panic!()
    };
    assert_eq!(first, duplicate);
    let end = Instant::now() + Duration::from_secs(3);
    loop {
        let snapshot = f
            .coordinator
            .terminals
            .snapshot(context.session_id, context.session_epoch)
            .unwrap();
        let text: String = snapshot
            .normal
            .lines
            .iter()
            .flat_map(|l| l.cells.iter().map(|c| c.text.as_str()))
            .collect();
        if text.contains("RPC_SYNTHETIC") {
            break;
        }
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(5));
    }
    let mut second = new_connection(f.coordinator.clone()).unwrap();
    let req = request(RpcCall::TerminalInput(TerminalInputParams {
        terminal: context.clone(),
        lease: lease.lease.clone(),
        input_id: DecimalU64(2),
        input_seq: InputSeq(DecimalU64(2)),
        bytes: BoundedList(vec![65]),
    }));
    assert!(
        matches!(admitted_dispatch(&f.coordinator,&mut second,req),RpcResponse::Error {error,..} if error.code()==ErrorCode::ControlRequired)
    );
    drop(second);
    let replacement = new_connection(f.coordinator.clone()).unwrap();
    let old = std::mem::replace(&mut f.connection, replacement);
    drop(old);
    assert!(
        f.coordinator
            .terminals
            .snapshot(context.session_id, context.session_epoch)
            .is_ok()
    );
    let metadata = snapshot(&mut f, &context);
    let fresh = claim(&mut f, &context, &metadata);
    assert_eq!(fresh.next_input_seq.0.0, 2);
    assert_eq!(fresh.next_input_id.0, 2);
    assert_ne!(fresh.lease.token, lease.lease.token);
    f.coordinator.terminals.shutdown().unwrap();
}
#[test]
fn split_move_rename_close_are_checked_durable_domain_operations() {
    let mut f = fixture();
    let call = create_call(&f, "First");
    good(&mut f, call);
    let call = create_call(&f, "Second");
    good(&mut f, call);
    let before = state(&f);
    let first_tab = before.tabs.0[0].tab_id;
    let second_tab = before.tabs.0[1].tab_id;
    let original = first_pane(&before.tabs.0[0].layout).pane_id;
    let target = first_pane(&before.tabs.0[1].layout).pane_id;
    let call = RpcCall::TerminalSplit(TerminalSplitParams {
        mutation: mutation_context(&f),
        tab_id: first_tab,
        pane_id: original,
        axis: SplitAxis::Vertical,
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    good(&mut f, call);
    let split = state(&f);
    let TerminalLayout::Split { second, .. } = &split.tabs.0[0].layout else {
        panic!()
    };
    let added = first_pane(second).clone();
    let call = RpcCall::TerminalRename(TerminalRenameParams {
        mutation: mutation_context(&f),
        tab_id: first_tab,
        name: "Renamed".to_owned().try_into().unwrap(),
    });
    good(&mut f, call);
    let call = RpcCall::TerminalMove(TerminalMoveParams {
        mutation: mutation_context(&f),
        pane_id: added.pane_id,
        source_tab_id: first_tab,
        target_tab_id: second_tab,
        target_pane_id: target,
        placement: MovePlacement::After,
    });
    good(&mut f, call);
    assert!(pane(&state(&f).tabs.0[1].layout, added.pane_id).is_some());
    let call = RpcCall::TerminalClose(TerminalCloseParams {
        mutation: mutation_context(&f),
        pane_id: added.pane_id,
        expected_session: added.session.clone(),
    });
    good(&mut f, call);
    assert!(find_pane(&state(&f), added.pane_id).is_none());
    assert_eq!(state(&f).domain_revision.0, 6);
    assert!(
        f.coordinator
            .terminals
            .snapshot(
                added.session.as_ref().unwrap().session_id,
                context_epoch(&added)
            )
            .is_err()
    );
    f.coordinator.terminals.shutdown().unwrap();
}
fn context_epoch(pane: &TerminalPane) -> SessionEpoch {
    pane.session.as_ref().unwrap().session_epoch
}
#[test]
fn concurrent_cas_creates_have_one_effect_and_one_revision_conflict() {
    let mut f = fixture();
    let first = create_call(&f, "One");
    let second = create_call(&f, "Two");
    let owner = f.coordinator.clone();
    let mut connection = new_connection(owner.clone()).unwrap();
    connection.profile_override = f.connection.profile_override.clone();
    let worker = thread::spawn(move || admitted_dispatch(&owner, &mut connection, request(second)));
    let response = invoke(&mut f, first);
    let other = worker.join().unwrap();
    let responses = [response, other];
    assert_eq!(
        responses
            .iter()
            .filter(|r| matches!(r, RpcResponse::Result { .. }))
            .count(),
        1
    );
    assert_eq!(responses.iter().filter(|r|matches!(r,RpcResponse::Error {error,..} if error.code()==ErrorCode::RevisionConflict)).count(),1);
    assert_eq!(state(&f).tabs.0.len(), 1);
    assert_eq!(state(&f).domain_revision.0, 1);
    f.coordinator.terminals.shutdown().unwrap();
}
#[test]
fn crash_lost_descriptor_can_restart_with_expected_none_without_adoption() {
    let mut f = fixture();
    let call = create_call(&f, "Recover");
    good(&mut f, call);
    let old = terminal_context(&f);
    let pane_id = old.pane_id;
    let db = f.temp.path().join("host.sqlite");
    let workspace = f.workspace;
    let temp = f.temp;
    f.coordinator.terminals.shutdown().unwrap();
    drop(f.connection);
    drop(f.coordinator);
    let store = HostStore::open(&db, Limits::default()).unwrap();
    let coordinator = Arc::new(Coordinator::new(store, Arc::new(AtomicBool::new(false))));
    let mut connection = new_connection(coordinator.clone()).unwrap();
    connection.profile_override = Some(SpawnProfile {
        executable: "/bin/sh".into(),
        args: vec![],
        cwd: temp.path().into(),
        environment: vec![
            ("HOME".into(), temp.path().to_str().unwrap().into()),
            ("PATH".into(), "/usr/bin:/bin".into()),
        ],
        shell_integration: None,
        rows: 8,
        cols: 40,
        history: 0,
    });
    let mut f = Fixture {
        temp,
        coordinator,
        connection,
        workspace,
    };
    let lost = state(&f);
    let descriptor = find_pane(&lost, pane_id).unwrap();
    assert_eq!(descriptor.state, PaneState::Lost);
    assert!(descriptor.session.is_none());
    assert!(matches!(
        invoke(
            &mut f,
            RpcCall::TerminalAttach(TerminalReadParams {
                terminal: old.clone()
            })
        ),
        RpcResponse::Error { .. }
    ));
    let call = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id,
        expected_session: None,
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    good(&mut f, call);
    let new = terminal_context(&f);
    assert_ne!(old.session_epoch, new.session_epoch);
    assert_ne!(old.session_id, new.session_id);
    assert!(
        f.coordinator
            .terminals
            .snapshot(new.session_id, new.session_epoch)
            .is_ok()
    );
    f.coordinator.terminals.shutdown().unwrap();
}
#[test]
fn operation_status_cancel_use_immutable_admission_binding() {
    let mut f = fixture();
    let call = create_call(&f, "Inspect");
    let operation_id = mutation(&call).operation_id;
    let RpcResult::TerminalCreate(receipt) = good(&mut f, call) else {
        panic!()
    };
    let params = OperationStatusParams {
        context: state(&f).context,
        operation_id,
    };
    let RpcResult::OperationStatus(status) = good(&mut f, RpcCall::OperationStatus(params.clone()))
    else {
        panic!()
    };
    assert_eq!(status, receipt);
    let RpcResult::OperationCancel(cancel) = good(
        &mut f,
        RpcCall::OperationCancel(OperationCancelParams {
            context: params.context,
            operation_id: params.operation_id,
        }),
    ) else {
        panic!()
    };
    assert_eq!(cancel.state(), OperationState::Succeeded);
    assert!(
        f.coordinator
            .terminals
            .snapshot(
                terminal_context(&f).session_id,
                terminal_context(&f).session_epoch
            )
            .is_ok()
    );
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn completed_snapshot_allows_claim_during_next_delta_and_rejects_unsent_ack() {
    let mut f = fixture();
    let call = create_call(&f, "Active");
    good(&mut f, call);
    let context = terminal_context(&f);
    let metadata = snapshot(&mut f, &context);
    // A second authenticated observer/writer makes real output while this
    // connection still has only its completed snapshot applied.
    let mut other = new_connection(f.coordinator.clone()).unwrap();
    let req = request(RpcCall::TerminalAttach(TerminalReadParams {
        terminal: context.clone(),
    }));
    let RpcResponse::Result {
        result: RpcResult::TerminalAttach(other_metadata),
        ..
    } = admitted_dispatch(&f.coordinator, &mut other, req)
    else {
        panic!()
    };
    while let Some(event) = other.next_event(&test_operation()) {
        if matches!(
            event,
            LocalStreamEvent::Terminal(TerminalStreamFrame::SnapshotComplete(_))
        ) {
            break;
        }
    }
    let req = request(RpcCall::TerminalClaim(TerminalClaimParams {
        terminal: context.clone(),
        subscription_id: other_metadata.subscription_id,
        rendered_through_seq: other_metadata.through_seq,
    }));
    let RpcResponse::Result {
        result: RpcResult::TerminalClaim(lease),
        ..
    } = admitted_dispatch(&f.coordinator, &mut other, req)
    else {
        panic!()
    };
    let req = request(RpcCall::TerminalInput(TerminalInputParams {
        terminal: context.clone(),
        lease: lease.lease,
        input_id: lease.next_input_id,
        input_seq: lease.next_input_seq,
        bytes: BoundedList(b"printf 'ACTIVE_OUTPUT\\n'\n".to_vec()),
    }));
    assert!(matches!(
        admitted_dispatch(&f.coordinator, &mut other, req),
        RpcResponse::Result { .. }
    ));
    drop(other);
    let end = Instant::now() + Duration::from_secs(2);
    loop {
        if let Some(LocalStreamEvent::Terminal(TerminalStreamFrame::DeltaMetadata(_))) =
            f.connection.next_event(&test_operation())
        {
            break;
        }
        assert!(Instant::now() < end);
        thread::sleep(Duration::from_millis(2));
    }
    let sub = f
        .connection
        .subscriptions
        .get(&String::from(metadata.subscription_id.clone()))
        .unwrap();
    assert!(sub.stream.as_ref().is_some_and(|s| s.previous.is_some()));
    let sent = sub.sent_through.unwrap();
    let actual = f
        .coordinator
        .terminals
        .snapshot(context.session_id, context.session_epoch)
        .unwrap()
        .sequence
        .0;
    if actual > sent {
        let response = invoke(
            &mut f,
            RpcCall::TerminalAck(TerminalAckParams {
                terminal: context.clone(),
                subscription_id: metadata.subscription_id.clone(),
                through_seq: TerminalSeq(DecimalU64(actual)),
            }),
        );
        assert!(
            matches!(response,RpcResponse::Error {error,..} if error.code()==ErrorCode::ResyncRequired)
        );
    }
    let RpcResult::TerminalClaim(_) = good(
        &mut f,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: context,
            subscription_id: metadata.subscription_id,
            rendered_through_seq: TerminalSeq(DecimalU64(sent)),
        }),
    ) else {
        panic!()
    };
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn actor_wait_deadline_never_admits_or_spawns() {
    let mut f = fixture();
    let owner = f.coordinator.workspace_lock(f.workspace).unwrap();
    let guard = owner.lock().unwrap();
    let mut req = request(create_call(&f, "Expired"));
    req.timeout_ms = TimeoutMs::new(1).unwrap();
    let original = state(&f);
    let start = Instant::now();
    let reply = admitted_dispatch(&f.coordinator, &mut f.connection, req.clone());
    assert!(start.elapsed() < Duration::from_millis(200));
    reply.validate_for(&req).unwrap();
    assert!(
        matches!(reply, RpcResponse::Error { error, .. } if error.code() == ErrorCode::DeadlineExceeded && error.effect() == Effect::None)
    );
    drop(guard);
    assert_eq!(state(&f), original);
    let RpcCall::TerminalCreate(params) = req.call else {
        panic!()
    };
    assert!(
        lookup(
            &f.coordinator,
            f.connection.connection.actor(),
            f.workspace,
            params.mutation.operation_id
        )
        .is_none()
    );
}

#[test]
fn post_spawn_failure_is_durable_unknown_and_never_replayed() {
    let mut f = fixture();
    let marker = f.temp.path().join("startup-marker");
    f.connection.profile_override.as_mut().unwrap().args = vec![
        "-c".into(),
        "printf %s $$ > startup-pid; printf x >> startup-marker; exec /bin/sleep 30".into(),
    ];
    let observe = marker.clone();
    f.connection.startup_check = Some(Arc::new(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        while !observe.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(2));
        }
        assert!(
            observe.exists(),
            "actual child startup must precede rejection"
        );
        Err(lomi_terminal::Error::StateFailed)
    }));
    let call = create_call(&f, "Unknown");
    let RpcResult::TerminalCreate(first) = good(&mut f, call.clone()) else {
        panic!()
    };
    assert_eq!(first.state(), OperationState::OutcomeUnknown);
    assert_eq!(first.effect(), Effect::Unknown);
    assert!(state(&f).tabs.0.is_empty());
    f.connection.startup_check = None;
    let RpcResult::TerminalCreate(repeated) = good(&mut f, call) else {
        panic!()
    };
    assert_eq!(first, repeated);
    assert_eq!(std::fs::read(marker).unwrap(), b"x");
    let pid: i32 = std::fs::read_to_string(f.temp.path().join("startup-pid"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        -1,
        "post-exec rejection must reap its owned child"
    );
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn failed_replacement_records_old_stop_and_can_restart_again() {
    let mut f = fixture();
    let create = create_call(&f, "Initial");
    good(&mut f, create);
    let old = terminal_context(&f);
    f.connection.profile_override.as_mut().unwrap().executable =
        "/lomi-synthetic-missing-executable".into();
    let restart = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id: old.pane_id,
        expected_session: Some(old.clone()),
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    let RpcResult::TerminalRestart(receipt) = good(&mut f, restart.clone()) else {
        panic!()
    };
    assert_eq!(receipt.state(), OperationState::OutcomeUnknown);
    let stopped = state(&f);
    let pane = first_pane(&stopped.tabs.0[0].layout);
    assert_eq!(pane.state, PaneState::Stopped);
    assert!(pane.session.is_none());
    assert_eq!(good(&mut f, restart), RpcResult::TerminalRestart(receipt));
    f.connection.profile_override.as_mut().unwrap().executable = "/bin/sh".into();
    let restart = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id: old.pane_id,
        expected_session: None,
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    let RpcResult::TerminalRestart(receipt) = good(&mut f, restart) else {
        panic!()
    };
    assert_eq!(receipt.state(), OperationState::Succeeded);
    let new = terminal_context(&f);
    assert_ne!(old.session_epoch, new.session_epoch);
    let close = RpcCall::TerminalClose(TerminalCloseParams {
        mutation: mutation_context(&f),
        pane_id: new.pane_id,
        expected_session: Some(new),
    });
    good(&mut f, close);
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn connection_retires_more_than_capacity_sequential_terminal_lifecycles() {
    let mut f = fixture();
    for _ in 0..35 {
        let call = create_call(&f, "Lifecycle");
        good(&mut f, call);
        let context = terminal_context(&f);
        let metadata = snapshot(&mut f, &context);
        claim(&mut f, &context, &metadata);
        let call = RpcCall::TerminalClose(TerminalCloseParams {
            mutation: mutation_context(&f),
            pane_id: context.pane_id,
            expected_session: Some(context.clone()),
        });
        good(&mut f, call);
        let until = Instant::now() + Duration::from_secs(2);
        let mut exited = false;
        while Instant::now() < until {
            if let Some(LocalStreamEvent::Terminal(TerminalStreamFrame::Delta(delta))) =
                f.connection.next_event(&test_operation())
                && matches!(delta.change, TerminalChange::Exit(_))
            {
                exited = true;
                break;
            }
            thread::sleep(Duration::from_millis(1));
        }
        assert!(exited, "ordered final exit must be delivered");
        assert!(f.connection.subscriptions.is_empty());
        assert!(f.connection.schedule.is_empty());
        assert!(f.connection.leases.is_empty());
    }
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn two_continuously_noisy_ptys_receive_fair_ordered_frames() {
    let mut f = fixture();
    f.connection.profile_override.as_mut().unwrap().args = vec![
        "-c".into(),
        "while :; do printf noise; /bin/sleep 0.03; done".into(),
    ];
    let call = create_call(&f, "One");
    good(&mut f, call);
    let one = terminal_context(&f);
    let call = create_call(&f, "Two");
    good(&mut f, call);
    let two = state(&f)
        .tabs
        .0
        .iter()
        .map(|t| first_pane(&t.layout).session.clone().unwrap())
        .find(|c| c != &one)
        .unwrap();
    let first = snapshot(&mut f, &one);
    let second = snapshot(&mut f, &two);
    let mut counts = HashMap::<String, usize>::new();
    let mut pending = HashMap::<String, (u64, u32)>::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    while Instant::now() < deadline {
        if let Some(LocalStreamEvent::Terminal(frame)) = f.connection.next_event(&test_operation())
        {
            match frame {
                TerminalStreamFrame::DeltaMetadata(m) => {
                    assert!(
                        pending
                            .insert(
                                m.subscription_id.as_str().to_owned(),
                                (m.through_seq.0.0, 0)
                            )
                            .is_none()
                    );
                }
                TerminalStreamFrame::DeltaChunk(c) => {
                    let p = pending.get_mut(c.subscription_id.as_str()).unwrap();
                    assert_eq!(p.1, c.index.0);
                    p.1 += 1;
                }
                TerminalStreamFrame::DeltaComplete(c) => {
                    let p = pending.remove(c.subscription_id.as_str()).unwrap();
                    assert_eq!(p.0, c.through_seq.0.0);
                    *counts
                        .entry(c.subscription_id.as_str().to_owned())
                        .or_default() += 1;
                }
                TerminalStreamFrame::ResyncRequired(_) => {
                    panic!("fair consumption must prevent starvation overflow")
                }
                _ => {}
            }
        } else {
            thread::sleep(Duration::from_millis(1));
        }
        if counts
            .get(first.subscription_id.as_str())
            .copied()
            .unwrap_or(0)
            >= 5
            && counts
                .get(second.subscription_id.as_str())
                .copied()
                .unwrap_or(0)
                >= 5
        {
            break;
        }
    }
    assert!(
        counts
            .get(first.subscription_id.as_str())
            .copied()
            .unwrap_or(0)
            >= 5
    );
    assert!(
        counts
            .get(second.subscription_id.as_str())
            .copied()
            .unwrap_or(0)
            >= 5
    );
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn uncertain_resize_error_keeps_unknown_effect_without_durable_operation() {
    let mut f = fixture();
    let call = create_call(&f, "Resize");
    good(&mut f, call);
    let terminal_context = terminal_context(&f);
    let metadata = snapshot(&mut f, &terminal_context);
    let lease = claim(&mut f, &terminal_context, &metadata);
    let req = request(RpcCall::TerminalResize(TerminalResizeParams {
        terminal: terminal_context,
        lease: lease.lease,
        resize_seq: lease.next_resize_seq,
        columns: TerminalDimension(80),
        rows: TerminalDimension(24),
    }));
    let error = terminal(lomi_terminal::Error::OutcomeUnknown);
    assert_eq!(error.code(), ErrorCode::OutcomeUnknown);
    assert_eq!(error.effect(), Effect::Unknown);
    let response = RpcResponse::Error {
        v: ApplicationMajor,
        request_id: req.request_id.clone(),
        operation_id: None,
        error,
    };
    response.validate_for(&req).unwrap();
    let bytes = serde_json::to_vec(&response).unwrap();
    lomi_remote_protocol::decode_response_for(&bytes, &req).unwrap();
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn unobserved_natural_exit_is_persisted_once_and_final_model_stays_readonly() {
    let mut f = fixture();
    f.connection.profile_override.as_mut().unwrap().args =
        vec!["-c".into(), "printf FINAL_RETAINED; exit 0".into()];
    let call = create_call(&f, "Short lived");
    good(&mut f, call);
    let context = terminal_context(&f);
    let owner = f.coordinator.workspace_lock(f.workspace).unwrap();
    let guard = owner.lock().unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    while f
        .coordinator
        .terminals
        .exited_sessions()
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
    // The observer never waits behind a mutator or publishes its old planning
    // snapshot over an in-flight workspace operation.
    reconcile_terminal_lifecycle(&f.coordinator, &test_operation()).unwrap();
    assert_eq!(
        first_pane(&state(&f).tabs.0[0].layout).state,
        PaneState::Running
    );
    drop(guard);
    // No attachment exists. The owner lifecycle poll, rather than a view or
    // request handler, observes the service's final model and commits the exit.
    let coordinator = f.coordinator.clone();
    let workspace = f.workspace;
    thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            reconcile_terminal_lifecycle(&coordinator, &test_operation()).unwrap();
            let p = workspace_record(&coordinator, workspace);
            if first_pane(&p.state.tabs.0[0].layout).state == PaneState::Exited {
                break;
            }
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
    })
    .join()
    .unwrap();
    let exited = state(&f);
    assert_eq!(exited.domain_revision, DecimalU64(2));
    assert_eq!(
        first_pane(&exited.tabs.0[0].layout).session.as_ref(),
        Some(&context)
    );
    reconcile_terminal_lifecycle(&f.coordinator, &test_operation()).unwrap();
    assert_eq!(state(&f), exited);
    let final_screen = f
        .coordinator
        .terminals
        .snapshot(context.session_id, context.session_epoch)
        .unwrap();
    let text: String = final_screen
        .normal
        .lines
        .iter()
        .flat_map(|line| line.cells.iter().map(|cell| cell.text.as_str()))
        .collect();
    assert!(text.contains("FINAL_RETAINED"));
    let metadata = snapshot(&mut f, &context);
    let denied = invoke(
        &mut f,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: context.clone(),
            subscription_id: metadata.subscription_id,
            rendered_through_seq: metadata.through_seq,
        }),
    );
    assert!(
        matches!(denied, RpcResponse::Error { error, .. } if error.code() == ErrorCode::SessionExited)
    );
    let denied = invoke(
        &mut f,
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: context.clone(),
            lease: LeaseBinding {
                token: Uuid::new_v4().to_string().try_into().unwrap(),
                version: DecimalU64(0),
            },
            input_id: DecimalU64(1),
            input_seq: InputSeq(DecimalU64(1)),
            bytes: BoundedList(vec![b'x']),
        }),
    );
    assert!(
        matches!(denied, RpcResponse::Error { error, .. } if error.code() == ErrorCode::ControlRequired)
    );
    let call = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id: context.pane_id,
        expected_session: Some(context.clone()),
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    f.connection.profile_override.as_mut().unwrap().args.clear();
    good(&mut f, call);
    let fresh = terminal_context(&f);
    assert_ne!(fresh.session_epoch, context.session_epoch);
    assert!(matches!(
        f.coordinator
            .terminals
            .snapshot(context.session_id, context.session_epoch),
        Err(lomi_terminal::Error::SessionMissing)
    ));
    let operation = test_operation();
    let mut exit = owner_call(&operation, || {
        f.coordinator
            .owner
            .begin_terminal_exit(&operation, &context)
    })
    .unwrap();
    assert!(!owner_call(&operation, || exit.try_commit()).unwrap());
    assert_eq!(
        first_pane(&state(&f).tabs.0[0].layout).state,
        PaneState::Running
    );
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn capacity_pressure_retires_oldest_unattached_exit_but_preserves_unacked_view() {
    let mut f = fixture();
    f.connection.profile_override.as_mut().unwrap().args =
        vec!["-c".into(), "printf retained; exit 0".into()];
    let mut contexts = Vec::new();
    for index in 0..32 {
        let call = create_call(&f, "Retained");
        let RpcResult::TerminalCreate(receipt) = good(&mut f, call) else {
            unreachable!()
        };
        assert_eq!(
            receipt.state(),
            OperationState::Succeeded,
            "create receipt: {receipt:?}"
        );
        let current = state(&f)
            .tabs
            .0
            .iter()
            .filter_map(|tab| first_pane(&tab.layout).session.clone())
            .find(|context| {
                !contexts
                    .iter()
                    .any(|old: &TerminalContext| old.session_id == context.session_id)
            })
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        while !f
            .coordinator
            .terminals
            .exited_sessions()
            .unwrap()
            .iter()
            .any(|exit| exit.session_id == current.session_id)
        {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(2));
        }
        let operation = test_operation();
        reconcile_terminal_lifecycle(&f.coordinator, &operation).unwrap();
        if index == 0 {
            // Leave the initial snapshot unacknowledged and pending. Even an
            // exited session with this live view is ineligible for eviction.
            f.connection.attach(current.clone(), &operation).unwrap();
        }
        contexts.push(current);
    }
    let retained = state(&f);
    let oldest = find_pane(&retained, contexts[0].pane_id).unwrap();
    assert_eq!(oldest.state, PaneState::Exited);
    assert_eq!(oldest.session.as_ref(), Some(&contexts[0]));
    let retired = find_pane(&retained, contexts[1].pane_id).unwrap();
    assert_eq!(retired.state, PaneState::Stopped);
    assert!(retired.session.is_none());
    assert!(
        f.coordinator
            .terminals
            .snapshot(contexts[0].session_id, contexts[0].session_epoch)
            .is_ok()
    );
    assert!(matches!(
        f.coordinator
            .terminals
            .snapshot(contexts[1].session_id, contexts[1].session_epoch),
        Err(lomi_terminal::Error::SessionMissing)
    ));
    assert!(!f.coordinator.terminals.at_capacity().unwrap());
    let additional_root = f.temp.path().join("another-workspace");
    std::fs::create_dir(&additional_root).unwrap();
    f.workspace = add_workspace(&f.coordinator, &additional_root, "Another")
        .state
        .context
        .workspace_id;
    f.connection.profile_override.as_mut().unwrap().cwd = additional_root;
    let call = create_call(&f, "Capacity reused");
    let RpcResult::TerminalCreate(receipt) = good(&mut f, call) else {
        panic!()
    };
    assert_eq!(receipt.state(), OperationState::Succeeded);
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn late_exited_attach_retires_after_contiguous_exit_across_35_lifecycles() {
    let mut f = fixture();
    f.connection.profile_override.as_mut().unwrap().args =
        vec!["-c".into(), "printf FINAL_SCREEN; exit 0".into()];
    for _ in 0..35 {
        let call = create_call(&f, "Late view");
        good(&mut f, call);
        let context = terminal_context(&f);
        let until = Instant::now() + Duration::from_secs(3);
        while !f
            .coordinator
            .terminals
            .exited_sessions()
            .unwrap()
            .iter()
            .any(|exit| exit.session_id == context.session_id)
        {
            assert!(Instant::now() < until);
            thread::sleep(Duration::from_millis(2));
        }
        reconcile_terminal_lifecycle(&f.coordinator, &test_operation()).unwrap();
        let revision = state(&f).domain_revision;
        let metadata = snapshot(&mut f, &context);
        let Some(LocalStreamEvent::Terminal(TerminalStreamFrame::Delta(exit))) =
            f.connection.next_event(&test_operation())
        else {
            panic!("late snapshot must end with its exit")
        };
        assert_eq!(exit.subscription_id, metadata.subscription_id);
        assert_eq!(exit.seq.0.0, metadata.through_seq.0.0 + 1);
        assert!(matches!(exit.change, TerminalChange::Exit(_)));
        lomi_remote_protocol::decode_terminal_frame(
            &serde_json::to_vec(&TerminalStreamFrame::Delta(exit)).unwrap(),
        )
        .unwrap();
        assert!(f.connection.subscriptions.is_empty());
        assert!(f.connection.schedule.is_empty());
        assert!(f.connection.leases.is_empty());
        reconcile_terminal_lifecycle(&f.coordinator, &test_operation()).unwrap();
        assert_eq!(
            state(&f).domain_revision,
            revision,
            "late view closure must not invent a domain exit"
        );
        let close = RpcCall::TerminalClose(TerminalCloseParams {
            mutation: mutation_context(&f),
            pane_id: context.pane_id,
            expected_session: Some(context),
        });
        good(&mut f, close);
    }
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn two_late_views_have_ordered_snapshots_and_their_own_contiguous_exit() {
    let mut f = fixture();
    f.connection.profile_override.as_mut().unwrap().args =
        vec!["-c".into(), "printf FINAL_SCREEN; exit 0".into()];
    let call = create_call(&f, "Two late views");
    good(&mut f, call);
    let context = terminal_context(&f);
    let until = Instant::now() + Duration::from_secs(3);
    while f
        .coordinator
        .terminals
        .exited_sessions()
        .unwrap()
        .is_empty()
    {
        assert!(Instant::now() < until);
        thread::sleep(Duration::from_millis(2));
    }
    reconcile_terminal_lifecycle(&f.coordinator, &test_operation()).unwrap();
    let revision = state(&f).domain_revision;
    let mut views = HashMap::new();
    for _ in 0..2 {
        let RpcResult::TerminalAttach(metadata) = good(
            &mut f,
            RpcCall::TerminalAttach(TerminalReadParams {
                terminal: context.clone(),
            }),
        ) else {
            panic!()
        };
        views.insert(
            metadata.subscription_id.as_str().to_owned(),
            (metadata, Vec::new(), false, false),
        );
    }
    while views.values().any(|(_, _, _, exited)| !exited) {
        let Some(LocalStreamEvent::Terminal(frame)) = f.connection.next_event(&test_operation())
        else {
            panic!("late view lost completion")
        };
        lomi_remote_protocol::decode_terminal_frame(&serde_json::to_vec(&frame).unwrap()).unwrap();
        match frame {
            TerminalStreamFrame::SnapshotChunk(chunk) => {
                let (_, bytes, complete, exited) =
                    views.get_mut(chunk.subscription_id.as_str()).unwrap();
                assert!(!*complete && !*exited);
                assert_eq!(chunk.index.0 as usize, bytes.len().div_ceil(16384));
                bytes.extend(chunk.bytes.0);
            }
            TerminalStreamFrame::SnapshotComplete(complete) => {
                let (metadata, bytes, completed, exited) =
                    views.get_mut(complete.subscription_id.as_str()).unwrap();
                assert!(!*completed && !*exited);
                assert_eq!(complete.through_seq, metadata.through_seq);
                assert_eq!(bytes.len() as u64, metadata.total_bytes.0);
                let snapshot: serde_json::Value = serde_json::from_slice(bytes).unwrap();
                assert_eq!(
                    snapshot["sequence"],
                    serde_json::to_value(complete.through_seq.0).unwrap()
                );
                *completed = true;
            }
            TerminalStreamFrame::Delta(delta) => {
                let (metadata, _, complete, exited) =
                    views.get_mut(delta.subscription_id.as_str()).unwrap();
                assert!(*complete && !*exited);
                assert!(matches!(delta.change, TerminalChange::Exit(_)));
                assert_eq!(delta.seq.0.0, metadata.through_seq.0.0 + 1);
                *exited = true;
            }
            _ => panic!("late readonly view must contain only snapshot and exit"),
        }
    }
    assert!(f.connection.subscriptions.is_empty());
    assert!(f.connection.next_event(&test_operation()).is_none());
    assert_eq!(state(&f).domain_revision, revision);
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn failed_repeat_claim_preserves_original_renew_input_and_release() {
    let mut f = fixture();
    let call = create_call(&f, "Retain lease");
    good(&mut f, call);
    let context = terminal_context(&f);
    let metadata = snapshot(&mut f, &context);
    let lease = claim(&mut f, &context, &metadata);
    let original = lease.lease.clone();
    let denied = invoke(
        &mut f,
        RpcCall::TerminalClaim(TerminalClaimParams {
            terminal: context.clone(),
            subscription_id: metadata.subscription_id,
            rendered_through_seq: metadata.through_seq,
        }),
    );
    assert!(
        matches!(denied, RpcResponse::Error { error, .. } if error.code() == ErrorCode::ControlRequired)
    );
    let RpcResult::TerminalRenew(renewed) = good(
        &mut f,
        RpcCall::TerminalRenew(TerminalLeaseParams {
            terminal: context.clone(),
            lease: original.clone(),
        }),
    ) else {
        panic!()
    };
    assert_eq!(renewed.lease, original);
    let RpcResult::TerminalInput(receipt) = good(
        &mut f,
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: context.clone(),
            lease: original.clone(),
            input_id: renewed.next_input_id,
            input_seq: renewed.next_input_seq,
            bytes: BoundedList(b"printf CLAIM_SURVIVED\n".to_vec()),
        }),
    ) else {
        panic!()
    };
    assert!(receipt.accepted_bytes().get() > 0);
    let RpcResult::TerminalRelease(released) = good(
        &mut f,
        RpcCall::TerminalRelease(TerminalLeaseParams {
            terminal: context,
            lease: original,
        }),
    ) else {
        panic!()
    };
    assert!(released.released);
    f.coordinator.terminals.shutdown().unwrap();
}

#[test]
fn contended_other_workspace_startup_cannot_stop_after_close_or_restart_deadline() {
    use std::sync::Barrier;
    for restart in [false, true] {
        let mut f = fixture();
        let create = create_call(&f, "Must remain running");
        good(&mut f, create);
        let context = terminal_context(&f);
        let original = state(&f);
        let other_root = f.temp.path().join("contended-workspace");
        std::fs::create_dir(&other_root).unwrap();
        let other = add_workspace(&f.coordinator, &other_root, "Other");
        let mut other_connection = new_connection(f.coordinator.clone()).unwrap();
        other_connection.profile_override = f.connection.profile_override.clone();
        other_connection.profile_override.as_mut().unwrap().cwd = other_root;
        let begin = Arc::new(Barrier::new(2));
        let acquired = Arc::new(Barrier::new(2));
        let gate = acquired.clone();
        other_connection.startup_check = Some(Arc::new(move || {
            // An actual second child has started. This bounded trusted startup
            // integrity check holds session-map exclusion past the first call's
            // deadline, reproducing contention at the destructive boundary.
            gate.wait();
            thread::sleep(Duration::from_millis(150));
            Ok(())
        }));
        let worker_start = begin.clone();
        let coordinator = f.coordinator.clone();
        let other_create = request(RpcCall::TerminalCreate(TerminalCreateParams {
            mutation: MutationContext {
                context: other.state.context,
                operation_id: fresh(),
                expected_revision: other.state.domain_revision,
            },
            tab_name: "Contending startup".to_owned().try_into().unwrap(),
            profile_id: "default".to_owned().try_into().unwrap(),
        }));
        let worker = thread::spawn(move || {
            worker_start.wait();
            let response =
                admitted_dispatch(&coordinator, &mut other_connection, other_create.clone());
            response.validate_for(&other_create).unwrap();
            assert!(matches!(response, RpcResponse::Result { .. }));
        });
        f.connection.before_terminal_stop = Some(Arc::new(move || {
            begin.wait();
            acquired.wait();
            // Startup of another workspace no longer holds the sessions map, so
            // contention alone does not reliably cross this 100 ms deadline (it
            // then depended on child-exec latency). Cross it deterministically at
            // the destructive boundary, which is the property under test.
            thread::sleep(Duration::from_millis(150));
        }));
        let mutation = mutation_context(&f);
        let operation_id = mutation.operation_id;
        let call = if restart {
            RpcCall::TerminalRestart(TerminalRestartParams {
                mutation,
                pane_id: context.pane_id,
                expected_session: Some(context.clone()),
                profile_id: "default".to_owned().try_into().unwrap(),
            })
        } else {
            RpcCall::TerminalClose(TerminalCloseParams {
                mutation,
                pane_id: context.pane_id,
                expected_session: Some(context.clone()),
            })
        };
        let mut req = request(call);
        req.timeout_ms = TimeoutMs::new(100).unwrap();
        let response = admitted_dispatch(&f.coordinator, &mut f.connection, req.clone());
        response.validate_for(&req).unwrap();
        assert!(
            matches!(response, RpcResponse::Error { error, .. } if error.code() == ErrorCode::DeadlineExceeded && error.effect() == Effect::None)
        );
        worker.join().unwrap();
        assert_eq!(state(&f), original);
        assert!(
            f.coordinator
                .terminals
                .snapshot(context.session_id, context.session_epoch)
                .is_ok()
        );
        // The request's expired Operation cannot be renewed to finalize. Model
        // the separately admitted owner-loop persistence-only maintenance pass.
        reconcile_deferred_completions(&f.coordinator, &test_operation()).unwrap();
        let receipt = lookup(
            &f.coordinator,
            f.connection.connection.actor(),
            f.workspace,
            operation_id,
        )
        .unwrap();
        assert_eq!(receipt.state(), OperationState::Failed);
        assert_eq!(receipt.effect(), Effect::None);
        f.coordinator.terminals.shutdown().unwrap();
    }
}

#[test]
fn persisted_shell_process_probe() {
    #[cfg(feature = "owned-host-fixture")]
    lomi_terminal::owned_host_fixture_probe_running_barrier().unwrap();
    let Some(database) = std::env::var_os("LOMI_TEST_SHELL_DATABASE") else {
        return;
    };
    let mut store = HostStore::open(std::path::Path::new(&database), Limits::default()).unwrap();
    initialize_default_shell(&mut store).unwrap();
    let expected = PathBuf::from(std::env::var_os("LOMI_TEST_EXPECTED_SHELL").unwrap());
    assert_eq!(store.default_shell().unwrap().unwrap().executable, expected);
    let project = match store.list_projects().unwrap().into_iter().next() {
        Some(project) => project,
        None => store
            .add_project(
                std::path::Path::new(&database).parent().unwrap(),
                "Shell probe".to_owned().try_into().unwrap(),
            )
            .unwrap(),
    };
    let coordinator = Arc::new(Coordinator::new(store, Arc::new(AtomicBool::new(false))));
    let connection = new_connection(coordinator.clone()).unwrap();
    let resolved = profile(&coordinator, &project, &connection, &test_operation()).unwrap();
    assert_eq!(resolved.executable, expected);
    assert!(resolved.args.is_empty());
    assert_eq!(resolved.cwd, project.local_root);
}

#[test]
fn sqlite_shell_selection_survives_restart_and_changed_service_environment() {
    let temp = tempfile::tempdir().unwrap();
    let database = temp.path().join("host.sqlite");
    let selected = temp.path().join("selected-shell");
    let changed = temp.path().join("changed-shell");
    std::os::unix::fs::symlink("/bin/sh", &selected).unwrap();
    std::os::unix::fs::symlink("/bin/sh", &changed).unwrap();
    for shell in [&selected, &changed] {
        #[cfg(feature = "owned-host-fixture")]
        let output =
            lomi_terminal::owned_host_fixture_shell_probe(&database, &selected, shell).unwrap();
        #[cfg(not(feature = "owned-host-fixture"))]
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "unix::rpc::tests::persisted_shell_process_probe",
                "--nocapture",
            ])
            .env("LOMI_TEST_SHELL_DATABASE", &database)
            .env("LOMI_TEST_EXPECTED_SHELL", &selected)
            .env("SHELL", shell)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn unknown_profile_rejects_create_split_and_restart_before_process_effect() {
    let mut f = fixture();
    let mut call = create_call(&f, "Rejected");
    let RpcCall::TerminalCreate(params) = &mut call else {
        unreachable!()
    };
    params.profile_id = "unknown".to_owned().try_into().unwrap();
    assert!(
        matches!(invoke(&mut f, call), RpcResponse::Error { error, .. }
        if error.code() == ErrorCode::InvalidArgument && error.effect() == Effect::None)
    );
    assert!(state(&f).tabs.0.is_empty());
    let call = create_call(&f, "Live");
    good(&mut f, call);
    let original = state(&f);
    let target = terminal_context(&f);
    let tab_id = original.tabs.0[0].tab_id;
    let split = RpcCall::TerminalSplit(TerminalSplitParams {
        mutation: mutation_context(&f),
        tab_id,
        pane_id: target.pane_id,
        axis: SplitAxis::Horizontal,
        profile_id: "unknown".to_owned().try_into().unwrap(),
    });
    assert!(
        matches!(invoke(&mut f, split), RpcResponse::Error { error, .. }
        if error.code() == ErrorCode::InvalidArgument && error.effect() == Effect::None)
    );
    let restart = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id: target.pane_id,
        expected_session: Some(target.clone()),
        profile_id: "unknown".to_owned().try_into().unwrap(),
    });
    assert!(
        matches!(invoke(&mut f, restart), RpcResponse::Error { error, .. }
        if error.code() == ErrorCode::InvalidArgument && error.effect() == Effect::None)
    );
    assert_eq!(state(&f), original);
    // Still attachable with the original session: restart never stopped it.
    snapshot(&mut f, &target);
}

#[test]
fn unavailable_persisted_shell_fails_restart_before_stopping_existing_session() {
    let shell_root = tempfile::tempdir().unwrap();
    let unavailable = shell_root.path().join("removed-shell");
    let mut f = fixture_with_shell(Some(DefaultShellProfile {
        executable: unavailable.clone(),
        args: vec![],
    }));
    let call = create_call(&f, "Live");
    good(&mut f, call);
    let original = state(&f);
    let target = terminal_context(&f);
    f.connection.profile_override = None;
    let restart = RpcCall::TerminalRestart(TerminalRestartParams {
        mutation: mutation_context(&f),
        pane_id: target.pane_id,
        expected_session: Some(target.clone()),
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    assert!(
        matches!(invoke(&mut f, restart), RpcResponse::Error { error, .. }
        if error.code() == ErrorCode::InvalidArgument && error.effect() == Effect::None)
    );
    assert_eq!(state(&f), original);
    snapshot(&mut f, &target);
    // A regular file without execute permission is also rejected on Unix.
    std::fs::write(&unavailable, "not executable").unwrap();
    let operation = test_operation();
    let stored = owner_call(&operation, || f.coordinator.owner.default_shell(&operation))
        .unwrap()
        .unwrap();
    assert!(validate_shell(&stored).is_err());
    f.coordinator.terminals.shutdown().unwrap();
}

fn effect_calls(context: &TerminalContext, lease: &TerminalLeaseResult) -> [RpcCall; 2] {
    [
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: context.clone(),
            lease: lease.lease.clone(),
            input_id: lease.next_input_id,
            input_seq: lease.next_input_seq,
            bytes: BoundedList(b"printf LOCK_ORDER\n".to_vec()),
        }),
        RpcCall::TerminalResize(TerminalResizeParams {
            terminal: context.clone(),
            lease: lease.lease.clone(),
            resize_seq: lease.next_resize_seq,
            columns: TerminalDimension(60),
            rows: TerminalDimension(12),
        }),
    ]
}

#[test]
fn input_and_resize_wait_for_actor_before_store_and_expire_without_effect() {
    for resize in [false, true] {
        let mut f = fixture();
        let create = create_call(&f, "Actor deadline");
        good(&mut f, create);
        let context = terminal_context(&f);
        let metadata = snapshot(&mut f, &context);
        let lease = claim(&mut f, &context, &metadata);
        let call = effect_calls(&context, &lease)[usize::from(resize)].clone();
        let owner = f.coordinator.workspace_lock(f.workspace).unwrap();
        let actor = owner.lock().unwrap();
        let (release_store, store_holder) = hold_store(f.coordinator.clone());
        let coordinator = f.coordinator.clone();
        let mut connection = f.connection;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            let mut req = request(call);
            req.timeout_ms = TimeoutMs::new(5).unwrap();
            let response = admitted_dispatch(&coordinator, &mut connection, req.clone());
            response.validate_for(&req).unwrap();
            tx.send(response).unwrap();
        });
        // Both locks stay held: a Store-first implementation cannot finish.
        let response = rx.recv_timeout(Duration::from_millis(300));
        release_store.send(()).unwrap();
        store_holder.join().unwrap();
        drop(actor);
        worker.join().unwrap();
        assert!(matches!(response.unwrap(), RpcResponse::Error { error, .. }
            if error.code() == ErrorCode::DeadlineExceeded && error.effect() == Effect::None));
        assert_eq!(
            f.coordinator
                .terminals
                .snapshot(context.session_id, context.session_epoch)
                .unwrap()
                .rows,
            8
        );
        f.coordinator.terminals.shutdown().unwrap();
    }
}

#[test]
fn input_and_resize_recheck_context_after_actor_wait() {
    for resize in [false, true] {
        let mut f = fixture();
        let create = create_call(&f, "Actor stale context");
        good(&mut f, create);
        let context = terminal_context(&f);
        let metadata = snapshot(&mut f, &context);
        let lease = claim(&mut f, &context, &metadata);
        let call = effect_calls(&context, &lease)[usize::from(resize)].clone();
        let owner = f.coordinator.workspace_lock(f.workspace).unwrap();
        let actor = owner.lock().unwrap();
        let coordinator = f.coordinator.clone();
        let mut connection = f.connection;
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = thread::spawn(move || {
            tx.send(admitted_dispatch(
                &coordinator,
                &mut connection,
                request(call),
            ))
            .unwrap();
        });
        let early = rx.recv_timeout(Duration::from_millis(30));
        // Model a normal epoch writer while owning the same workspace actor.
        let operation = test_operation();
        let mut turn = owner_call(&operation, || {
            f.coordinator.owner.begin_unshare(&operation, f.workspace)
        })
        .unwrap();
        owner_call(&operation, || turn.try_commit()).unwrap();
        drop(actor);
        let response = if let Ok(response) = early {
            response
        } else {
            rx.recv_timeout(Duration::from_secs(2)).unwrap()
        };
        worker.join().unwrap();
        assert!(matches!(response, RpcResponse::Error { error, .. }
            if error.code() == ErrorCode::StaleEpoch && error.effect() == Effect::None));
        assert_eq!(
            f.coordinator
                .terminals
                .snapshot(context.session_id, context.session_epoch)
                .unwrap()
                .rows,
            8
        );
        f.coordinator.terminals.shutdown().unwrap();
    }
}

#[test]
fn core_effect_gate_uses_only_atomic_stop_and_deadline_even_with_store_locked() {
    let f = fixture();
    let (release_store, store_holder) = hold_store(f.coordinator.clone());
    let stopping = AtomicBool::new(false);
    let current = Operation::new(Instant::now() + Duration::from_secs(1), &stopping);
    assert!(terminal_effect_current(&current));
    let expired = Operation::new(Instant::now(), &stopping);
    assert!(!terminal_effect_current(&expired));
    stopping.store(true, Ordering::Release);
    assert!(!terminal_effect_current(&current));
    release_store.send(()).unwrap();
    store_holder.join().unwrap();
}
