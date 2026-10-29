//! Two live remote clients share one host-owned PTY over real TLS/WebSocket/
//! Noise connections; scenarios cover the shared workspace view and leases.
use super::*;
use crate::unix::{
    Coordinator,
    auth::remote_ingress::{Registry, actor_wait_duration},
    rpc,
};
use std::sync::{
    Arc, Condvar, Mutex,
    atomic::{AtomicU8, Ordering as AtomicOrdering},
};

const MARKER: &str = "remote-terminal-marker";

/// What a client thread reports to the host thread driving the connections.
#[cfg_attr(not(feature = "cloud-fixture"), allow(dead_code))]
enum Signal {
    Connected,
    IdleWorkspaceReady,
    SnapshotComplete,
    Parked(ClientRole),
    FirstRename,
    SecondRename,
    RevokeClosed(ClientRole),
    Done,
}
/// Ordered rendezvous between the two client threads and the host thread.
struct Stage(Mutex<u32>, Condvar);
impl Stage {
    fn lock(&self) -> std::sync::MutexGuard<'_, u32> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
    fn reach(&self, stage: u32) {
        let mut current = self.lock();
        *current = (*current).max(stage);
        self.1.notify_all();
    }
    fn current(&self) -> u32 {
        *self.lock()
    }
    fn wait(&self, stage: u32) {
        let deadline = Instant::now() + Duration::from_secs(30);
        let mut current = self.lock();
        while *current < stage {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                drop(current);
                panic!("stage {stage} was never reached");
            }
            current = self
                .1
                .wait_timeout(current, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .0;
        }
    }
}
#[derive(Clone, Copy, PartialEq)]
enum ClientRole {
    A,
    B,
}

fn workspace_state(client: &mut NativeClient, workspace: &WorkspaceContext) -> WorkspaceState {
    match client.call(RpcCall::WorkspaceGet(WorkspaceReadParams {
        context: workspace.clone(),
    })) {
        RpcResult::WorkspaceGet(state) => state,
        other => panic!("workspace.get returned {other:?}"),
    }
}
fn ingress_turns(registry: &Registry<'_>, channel_id: ChannelId) -> u64 {
    registry
        .failure_observation_for_test(channel_id)
        .map(|observation| observation.2)
        .unwrap_or_default()
}
#[allow(clippy::too_many_arguments)]
fn client(
    role: ClientRole,
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    initiator: Handshake,
    channel: [u8; 16],
    terminal: TerminalContext,
    root_path: std::path::PathBuf,
    signal: mpsc::SyncSender<Signal>,
    stage: Arc<Stage>,
    maintenance_rollover: bool,
    rollover_stage: Arc<Stage>,
    progress: Arc<[AtomicU8; 2]>,
    terminal_purpose: bool,
    stress_snapshot: bool,
    idle_sibling_snapshot: bool,
    shared_lease: Arc<Mutex<Option<TerminalLeaseResult>>>,
) {
    let mut client = accept_native_client(listener, tls, initiator, channel);
    let progress_index = match role {
        ClientRole::A => 0,
        ClientRole::B => 1,
    };
    progress[progress_index].store(1, AtomicOrdering::Release);
    signal.send(Signal::Connected).unwrap();
    let workspace = terminal.workspace.clone();
    if idle_sibling_snapshot && role == ClientRole::A {
        let _ = workspace_state(&mut client, &workspace);
        progress[progress_index].store(2, AtomicOrdering::Release);
        signal.send(Signal::IdleWorkspaceReady).unwrap();
        stage.wait(1);
        drop(client);
        signal.send(Signal::Done).unwrap();
        return;
    }
    let snapshot_started = Instant::now();
    let RpcResult::TerminalAttach(attached) =
        client.call(RpcCall::TerminalAttach(TerminalReadParams {
            terminal: terminal.clone(),
        }))
    else {
        panic!("attach")
    };
    progress[progress_index].store(2, AtomicOrdering::Release);
    client.snapshot(&attached);
    if stress_snapshot {
        assert!(
            snapshot_started.elapsed() < Duration::from_secs(30),
            "80x24 attach-to-SnapshotComplete exceeded its 30 s bound"
        );
        if role == ClientRole::A {
            assert!(
                progress[1].load(AtomicOrdering::Acquire) >= 2,
                "channel B must attach before channel A completes its 80x24 snapshot"
            );
        }
    }
    progress[progress_index].store(3, AtomicOrdering::Release);
    if idle_sibling_snapshot {
        signal.send(Signal::SnapshotComplete).unwrap();
        stage.reach(1);
        drop(client);
        signal.send(Signal::Done).unwrap();
        return;
    }
    assert!(matches!(
        client.call(RpcCall::TerminalAck(TerminalAckParams {
            terminal: terminal.clone(),
            subscription_id: attached.subscription_id.clone(),
            through_seq: attached.through_seq
        })),
        RpcResult::TerminalAck(_)
    ));
    progress[progress_index].store(4, AtomicOrdering::Release);
    // Keep both attached TLS/Noise clients read-only and parked until the
    // actual manager revoke has completed and the shared CloudWorker sees it.
    if !terminal_purpose && std::env::var_os("LOMI_E2_SHARED_CLOUD_REVOKE_DIR").is_some() {
        progress[progress_index].store(5, AtomicOrdering::Release);
        signal.send(Signal::Parked(role)).unwrap();
        stage.wait(1);
        assert!(matches!(
            client.try_call(RpcCall::WorkspaceGet(WorkspaceReadParams {
                context: workspace,
            })),
            Delivery::Closed
        ));
        println!(
            "LOMI_SHARED_CLOUD_REVOKE_CLIENT_CLOSED={}",
            match role {
                ClientRole::A => "A",
                ClientRole::B => "B",
            }
        );
        signal.send(Signal::RevokeClosed(role)).unwrap();
        return;
    }
    if maintenance_rollover {
        progress[progress_index].store(5, AtomicOrdering::Release);
        signal.send(Signal::Parked(role)).unwrap();
        rollover_stage.wait(1);
    }
    if terminal_purpose {
        match role {
            ClientRole::A => {
                let RpcResult::TerminalClaim(claim) =
                    client.call(RpcCall::TerminalClaim(TerminalClaimParams {
                        terminal: terminal.clone(),
                        subscription_id: attached.subscription_id.clone(),
                        rendered_through_seq: attached.through_seq,
                    }))
                else {
                    panic!("terminal claim")
                };
                let RpcResult::TerminalRenew(lease) =
                    client.call(RpcCall::TerminalRenew(TerminalLeaseParams {
                        terminal: terminal.clone(),
                        lease: claim.lease,
                    }))
                else {
                    panic!("terminal renew")
                };
                *shared_lease
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(lease.clone());
                stage.reach(1);
                stage.wait(2);

                let command = crate::testsupport::marker_command("TERMINAL_OWNER_ONLY");
                let RpcResult::TerminalInput(receipt) =
                    client.call(RpcCall::TerminalInput(TerminalInputParams {
                        terminal: terminal.clone(),
                        lease: lease.lease.clone(),
                        input_id: lease.next_input_id,
                        input_seq: lease.next_input_seq,
                        bytes: BoundedList(command.clone()),
                    }))
                else {
                    panic!("terminal owner input")
                };
                assert_eq!(receipt.accepted_bytes().get(), command.len() as u64);
                let executed = Instant::now() + Duration::from_secs(10);
                while std::fs::read(root_path.join(MARKER)).ok().as_deref() != Some(b"x".as_slice())
                {
                    assert!(Instant::now() < executed, "A's input did not execute once");
                    thread::sleep(Duration::from_millis(5));
                }
                assert!(matches!(
                    client.call(RpcCall::TerminalRelease(TerminalLeaseParams {
                        terminal: terminal.clone(),
                        lease: lease.lease,
                    })),
                    RpcResult::TerminalRelease(_)
                ));
                stage.reach(3);
                stage.wait(4);
            }
            ClientRole::B => {
                stage.wait(1);
                let lease = shared_lease
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone()
                    .expect("A published its terminal lease");
                let command = crate::testsupport::marker_command("UNAUTHORIZED_TERMINAL_INPUT");
                match client.try_call(RpcCall::TerminalInput(TerminalInputParams {
                    terminal: terminal.clone(),
                    lease: lease.lease.clone(),
                    input_id: lease.next_input_id,
                    input_seq: lease.next_input_seq,
                    bytes: BoundedList(command),
                })) {
                    Delivery::Rejected(code) => assert_eq!(code, ErrorCode::ControlRequired),
                    Delivery::Result(result) => {
                        panic!("B used A's terminal lease for input: {result:?}")
                    }
                    Delivery::Closed => panic!("B's terminal input probe closed its connection"),
                }
                for (method, call) in [
                    (
                        "renew",
                        RpcCall::TerminalRenew(TerminalLeaseParams {
                            terminal: terminal.clone(),
                            lease: lease.lease.clone(),
                        }),
                    ),
                    (
                        "release",
                        RpcCall::TerminalRelease(TerminalLeaseParams {
                            terminal: terminal.clone(),
                            lease: lease.lease.clone(),
                        }),
                    ),
                ] {
                    match client.try_call(call) {
                        Delivery::Rejected(code) => {
                            assert_eq!(code, ErrorCode::ControlRequired, "terminal.{method}")
                        }
                        Delivery::Result(result) => {
                            panic!("B used A's terminal lease for {method}: {result:?}")
                        }
                        Delivery::Closed => {
                            panic!("B's terminal.{method} probe closed its connection")
                        }
                    }
                }

                let before_offset = attached.output_offset.0;
                // Do not hold A's five-second control lease while this client
                // drains a streamed snapshot. A uses the lease as soon as the
                // denied control probes finish; this read then proves that B's
                // connection remains usable after those rejections.
                stage.reach(2);
                stage.wait(3);

                let RpcResult::TerminalSnapshot(snapshot) =
                    client.call(RpcCall::TerminalSnapshot(TerminalReadParams {
                        terminal: terminal.clone(),
                    }))
                else {
                    panic!("B terminal snapshot after rejected lease probes")
                };
                client.snapshot(&snapshot);
                assert!(matches!(
                    client.call(RpcCall::TerminalAck(TerminalAckParams {
                        terminal: terminal.clone(),
                        subscription_id: snapshot.subscription_id.clone(),
                        through_seq: snapshot.through_seq,
                    })),
                    RpcResult::TerminalAck(_)
                ));
                assert!(
                    snapshot.output_offset.0 > before_offset,
                    "B did not observe A's output: {} <= {before_offset}",
                    snapshot.output_offset.0
                );
                assert!(matches!(
                    client.call(RpcCall::TerminalAck(TerminalAckParams {
                        terminal,
                        subscription_id: snapshot.subscription_id.clone(),
                        through_seq: snapshot.through_seq,
                    })),
                    RpcResult::TerminalAck(_)
                ));
                stage.reach(4);
            }
        }
        drop(client);
        signal.send(Signal::Done).unwrap();
        return;
    }
    match role {
        ClientRole::A => {
            let RpcResult::TerminalClaim(claim) =
                client.call(RpcCall::TerminalClaim(TerminalClaimParams {
                    terminal: terminal.clone(),
                    subscription_id: attached.subscription_id.clone(),
                    rendered_through_seq: attached.through_seq,
                }))
            else {
                panic!("claim")
            };
            let RpcResult::TerminalRenew(lease) =
                client.call(RpcCall::TerminalRenew(TerminalLeaseParams {
                    terminal: terminal.clone(),
                    lease: claim.lease,
                }))
            else {
                panic!("renew")
            };
            // B attaches to the same PTY before A types.
            stage.wait(1);
            let command = crate::testsupport::marker_command("SHARED_ONCE");
            let command = command.as_slice();
            let RpcResult::TerminalInput(receipt) =
                client.call(RpcCall::TerminalInput(TerminalInputParams {
                    terminal: terminal.clone(),
                    lease: lease.lease.clone(),
                    input_id: lease.next_input_id,
                    input_seq: lease.next_input_seq,
                    bytes: BoundedList(command.to_vec()),
                }))
            else {
                panic!("input")
            };
            assert_eq!(receipt.accepted_bytes().get(), command.len() as u64);
            let executed = Instant::now() + Duration::from_secs(10);
            while std::fs::read(root_path.join(MARKER)).ok().as_deref() != Some(b"x".as_slice()) {
                assert!(Instant::now() < executed, "A's input did not execute once");
                thread::sleep(Duration::from_millis(5));
            }
            stage.reach(2);
            // B has fully read the shared PTY, and the host has finished B's
            // post-response maintenance, before the workspace changes.
            stage.wait(4);
            // A renames the tab; the host publishes it.
            let state = workspace_state(&mut client, &workspace);
            let RpcResult::TerminalRename(receipt) =
                client.call(RpcCall::TerminalRename(TerminalRenameParams {
                    mutation: MutationContext {
                        operation_id: OperationId::from_bytes([200; 16]).unwrap(),
                        context: workspace.clone(),
                        expected_revision: state.domain_revision,
                    },
                    tab_id: state.tabs.0[0].tab_id,
                    name: "renamed-by-a".to_owned().try_into().unwrap(),
                }))
            else {
                panic!("rename")
            };
            assert_eq!(receipt.state(), OperationState::Succeeded);
            signal.send(Signal::FirstRename).unwrap();
            // B observes the first rename and exercises its ordinary stale
            // revision conflict before A makes the revoke-triggering change.
            stage.wait(7);
            let state = workspace_state(&mut client, &workspace);
            let RpcResult::TerminalRename(receipt) =
                client.call(RpcCall::TerminalRename(TerminalRenameParams {
                    mutation: MutationContext {
                        operation_id: OperationId::from_bytes([202; 16]).unwrap(),
                        context: workspace.clone(),
                        expected_revision: state.domain_revision,
                    },
                    tab_id: state.tabs.0[0].tab_id,
                    name: "second-rename-by-a".to_owned().try_into().unwrap(),
                }))
            else {
                panic!("second rename")
            };
            assert_eq!(receipt.state(), OperationState::Succeeded);
            signal.send(Signal::SecondRename).unwrap();
            // Wait until B observes the pending-publication revoke and the
            // fixture acknowledges this second publication.
            stage.wait(10);
        }
        ClientRole::B => {
            let _baseline = workspace_state(&mut client, &workspace);
            let before_offset = attached.output_offset.0;
            stage.reach(1);
            stage.wait(2);
            // B sees A's output on the very same PTY.
            let RpcResult::TerminalSnapshot(snapshot) =
                client.call(RpcCall::TerminalSnapshot(TerminalReadParams {
                    terminal: terminal.clone(),
                }))
            else {
                panic!("snapshot")
            };
            client.snapshot(&snapshot);
            assert!(
                snapshot.output_offset.0 > before_offset,
                "B did not observe A's output: {} <= {before_offset}",
                snapshot.output_offset.0
            );
            // The host finishes the snapshot stream before it answers another
            // call, so A's rename cannot overlap B's stream proofs.
            let _ = workspace_state(&mut client, &workspace);
            stage.reach(3);
            stage.wait(5);
            // A's first rename has been acknowledged; B sees the shared newer
            // view and its stale edit remains an ordinary revision conflict.
            let after = workspace_state(&mut client, &workspace);
            assert_eq!(after.domain_revision.0, _baseline.domain_revision.0 + 1);
            let renamed: DisplayText = "renamed-by-a".to_owned().try_into().unwrap();
            assert_eq!(after.tabs.0[0].name, renamed);
            assert_ne!(_baseline.tabs.0[0].name, renamed);
            assert_eq!(after.tabs.0[0].layout, _baseline.tabs.0[0].layout);
            match client.try_call(RpcCall::TerminalRename(TerminalRenameParams {
                mutation: MutationContext {
                    operation_id: OperationId::from_bytes([201; 16]).unwrap(),
                    context: workspace.clone(),
                    expected_revision: _baseline.domain_revision,
                },
                tab_id: _baseline.tabs.0[0].tab_id,
                name: "stale-by-b".to_owned().try_into().unwrap(),
            })) {
                Delivery::Rejected(code) => assert_eq!(code, ErrorCode::RevisionConflict),
                Delivery::Result(_) => panic!("a stale edit was applied"),
                Delivery::Closed => panic!("a stale edit closed the connection"),
            }
            assert_eq!(
                workspace_state(&mut client, &workspace).tabs.0[0].name,
                renamed
            );
            stage.reach(6);
            stage.wait(8);
            // A's second mutation is committed but its publication is still
            // unacknowledged. B's next workspace read must close the stream.
            assert!(matches!(
                client.try_call(RpcCall::WorkspaceGet(WorkspaceReadParams {
                    context: workspace.clone(),
                })),
                Delivery::Closed
            ));
            stage.reach(9);
        }
    }
    drop(client);
    signal.send(Signal::Done).unwrap();
}

fn acknowledge_pending_publication(
    store: &crate::unix::shared_owner::PeerStoreForTest,
    eligibility: &mut crate::unix::auth::cloud::PeerEligibility,
) {
    let mut store = store.lock().unwrap();
    if store.pending_publications().unwrap().is_empty() {
        return;
    }
    let publication = store
        .prepare_host_publication(&eligibility.binding)
        .unwrap();
    eligibility.binding = store
        .acknowledge_host_publication(
            &publication,
            &PublicationResult {
                runtime: publication.params.runtime.clone(),
                publication_seq: publication.params.publication_seq,
            },
        )
        .unwrap();
    eligibility.publication = store
        .acknowledged_host_publication(&eligibility.binding)
        .unwrap()
        .unwrap();
}

#[cfg(feature = "cloud-fixture")]
fn cloud_worker_step(
    worker: &mut crate::unix::auth::cloud::Worker,
    fixture: &peer::tests::Fixture<'_>,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn crate::unix::auth::cloud::DataApi,
) -> crate::unix::auth::cloud::StepOutcome {
    let generation = fixture.eligibility.binding.scope.authorization_generation;
    worker
        .step_using(
            auth,
            transport,
            &fixture.config,
            fixture.runtime(),
            generation,
        )
        .unwrap_or_else(|_| panic!("LOMI_SHARED_CLOUD_FAILURE=worker_step"))
}

#[cfg(feature = "cloud-fixture")]
fn cloud_worker_publish_pending(
    worker: &mut crate::unix::auth::cloud::Worker,
    fixture: &mut peer::tests::Fixture<'_>,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn crate::unix::auth::cloud::DataApi,
) {
    let pending = fixture
        .store
        .lock()
        .unwrap()
        .pending_publications()
        .unwrap();
    if pending.is_empty() {
        return;
    }
    let mut saw_publication = false;
    for _ in 0..6 {
        match cloud_worker_step(worker, fixture, auth, transport) {
            crate::unix::auth::cloud::StepOutcome::Network => {
                if fixture
                    .store
                    .lock()
                    .unwrap()
                    .pending_publications()
                    .unwrap()
                    .is_empty()
                {
                    saw_publication = true;
                    break;
                }
            }
            crate::unix::auth::cloud::StepOutcome::PeerEligible(eligibility) => {
                fixture.eligibility = *eligibility;
                break;
            }
            crate::unix::auth::cloud::StepOutcome::Deferred => {
                panic!("LOMI_SHARED_CLOUD_FAILURE=worker_deferred")
            }
        }
    }
    assert!(
        saw_publication
            || fixture
                .store
                .lock()
                .unwrap()
                .pending_publications()
                .unwrap()
                .is_empty(),
        "LOMI_SHARED_CLOUD_FAILURE=publication_not_acknowledged"
    );
    for _ in 0..3 {
        if let crate::unix::auth::cloud::StepOutcome::PeerEligible(eligibility) =
            cloud_worker_step(worker, fixture, auth, transport)
        {
            fixture.eligibility = *eligibility;
            return;
        }
    }
    panic!("LOMI_SHARED_CLOUD_FAILURE=eligibility_not_refreshed");
}

#[cfg(feature = "cloud-fixture")]
fn cloud_worker_reconcile_initial(
    worker: &mut crate::unix::auth::cloud::Worker,
    fixture: &mut peer::tests::Fixture<'_>,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn crate::unix::auth::cloud::DataApi,
) {
    for index in 0..3 {
        match cloud_worker_step(worker, fixture, auth, transport) {
            crate::unix::auth::cloud::StepOutcome::Network if index < 2 => {}
            crate::unix::auth::cloud::StepOutcome::PeerEligible(eligibility) if index == 2 => {
                fixture.eligibility = *eligibility;
                return;
            }
            _ => panic!("LOMI_SHARED_CLOUD_FAILURE=initial_reconciliation"),
        }
    }
}

#[cfg(feature = "cloud-fixture")]
fn cloud_worker_refresh_eligibility(
    worker: &mut crate::unix::auth::cloud::Worker,
    fixture: &mut peer::tests::Fixture<'_>,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn crate::unix::auth::cloud::DataApi,
) {
    for _ in 0..4 {
        match cloud_worker_step(worker, fixture, auth, transport) {
            crate::unix::auth::cloud::StepOutcome::Network => {}
            crate::unix::auth::cloud::StepOutcome::PeerEligible(eligibility) => {
                fixture.eligibility = *eligibility;
                return;
            }
            crate::unix::auth::cloud::StepOutcome::Deferred => {
                panic!("LOMI_SHARED_CLOUD_FAILURE=heartbeat_refresh_deferred")
            }
        }
    }
    panic!("LOMI_SHARED_CLOUD_FAILURE=heartbeat_refresh_incomplete");
}

#[test]
fn real_tls_noise_two_clients_share_one_pty_and_one_workspace_view() {
    exercise_two_clients(false);
}

#[test]
fn real_tls_noise_two_terminal_purpose_clients_isolate_control_leases() {
    exercise_two_clients(true);
}

#[test]
fn real_tls_noise_80x24_snapshots_use_queued_output_scheduling() {
    exercise_two_clients_with_grid(false, 24, 80);
}

#[test]
fn real_tls_noise_idle_sibling_does_not_delay_80x24_snapshot() {
    exercise_two_clients_with_idle_sibling_snapshot();
}

fn exercise_two_clients(terminal_purpose: bool) {
    exercise_two_clients_with_grid(terminal_purpose, 12, 40);
}

fn exercise_two_clients_with_grid(terminal_purpose: bool, rows: u16, cols: u16) {
    exercise_two_clients_with_options(terminal_purpose, rows, cols, false);
}

fn exercise_two_clients_with_idle_sibling_snapshot() {
    exercise_two_clients_with_options(false, 24, 80, true);
}

fn exercise_two_clients_with_options(
    terminal_purpose: bool,
    rows: u16,
    cols: u16,
    idle_sibling_snapshot: bool,
) {
    let stress_snapshot = rows == 24 && cols == 80;
    peer::current_pairing_script::clear();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint: lomi_remote_protocol::ipc::LocalRelayEndpoint = format!(
        "wss://127.0.0.1:{}/v2/relay",
        listener.local_addr().unwrap().port()
    )
    .try_into()
    .unwrap();
    let (root, tls) = certificate();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    #[cfg(feature = "cloud-fixture")]
    let cloud_fixture = if std::env::var_os("LOMI_E2_SHARED_CLOUD_FIXTURE").is_some() {
        Some(peer::tests::CloudFixtureOptions {
            host_id: std::env::var("LOMI_E2_CLOUD_FIXTURE_HOST_ID")
                .expect("fixture host id")
                .try_into()
                .expect("fixture host id"),
            runtime_id: std::env::var("LOMI_E2_CLOUD_FIXTURE_RUNTIME_ID")
                .expect("fixture runtime id")
                .try_into()
                .expect("fixture runtime id"),
            generation: std::env::var("LOMI_E2_CLOUD_FIXTURE_GENERATION")
                .expect("fixture generation")
                .parse()
                .expect("fixture generation"),
            epoch: std::env::var("LOMI_E2_CLOUD_FIXTURE_EPOCH")
                .expect("fixture epoch")
                .parse()
                .expect("fixture epoch"),
            publication_seq: std::env::var("LOMI_E2_CLOUD_FIXTURE_PUBLICATION_SEQ")
                .expect("fixture publication sequence")
                .parse()
                .expect("fixture publication sequence"),
            access: std::env::var("LOMI_E2_CLOUD_FIXTURE_ACCESS")
                .expect("fixture access credential")
                .try_into()
                .expect("fixture access credential"),
            origin: std::env::var("LOMI_E2_CLOUD_FIXTURE_ORIGIN").expect("fixture origin"),
        })
    } else {
        None
    };
    #[cfg(feature = "cloud-fixture")]
    let cloud_transport_inputs = cloud_fixture.as_ref().map(|fixture| {
        (
            fixture.origin.clone(),
            std::fs::read(
                std::env::var("LOMI_E2_CLOUD_FIXTURE_ROOT_DER").expect("fixture TLS root"),
            )
            .expect("fixture TLS root file"),
        )
    });
    let run_fixture = |f: &mut peer::tests::Fixture<'_>,
                       auth: &mut HostAuth<'_, dyn SecretStorage + '_>| {
        #[cfg(feature = "cloud-fixture")]
        let central_revoke_dir =
            std::env::var_os("LOMI_E2_SHARED_CLOUD_REVOKE_DIR").map(std::path::PathBuf::from);
        #[cfg(feature = "cloud-fixture")]
        let maintenance_rollover = !terminal_purpose && central_revoke_dir.is_none();
        #[cfg(not(feature = "cloud-fixture"))]
        let maintenance_rollover = !terminal_purpose;
        #[cfg(feature = "cloud-fixture")]
        let mut cloud_worker = cloud_transport_inputs
            .as_ref()
            .map(|_| crate::unix::auth::cloud::Worker::default());
        #[cfg(feature = "cloud-fixture")]
        let cloud_transport = cloud_transport_inputs.as_ref().map(|(origin, root)| {
            lomi_host_http::DataTransport::with_test_root(
                lomi_host_http::RemoteApiOrigin::new(&f.config, origin.clone())
                    .expect("pinned fixture origin"),
                root.clone(),
            )
            .expect("fixture TLS transport")
        });
        #[cfg(feature = "cloud-fixture")]
        if let (Some(worker), Some(transport)) = (&mut cloud_worker, &cloud_transport) {
            cloud_worker_reconcile_initial(worker, f, auth, transport);
            println!("LOMI_SHARED_CLOUD_STAGE=initial_state_reconciled");
        }
        let coordinator = Coordinator::with_existing_owner_for_test(
            f.owner.clone(),
            Arc::new(AtomicBool::new(false)),
        );
        let _cleanup = ServiceCleanup(coordinator.clone());
        let root_path = {
            let mut store = f.store.lock().unwrap();
            store
                .initialize_default_shell(lomi_host_store::DefaultShellProfile {
                    executable: crate::testsupport::shell_executable(),
                    args: vec![],
                })
                .unwrap();
            store.workspace(f.workspace).unwrap().local_root
        };
        let mut local =
            rpc::ConnectionState::new(coordinator.clone(), f.runtime().operation).unwrap();
        // Existing lifecycle scenarios stay at 12x40 to keep them ~4x cheaper
        // than the default 80x24. The queued-output regression passes the
        // default dimensions to exercise the larger multi-fragment snapshot.
        local.set_profile_override_for_test(lomi_terminal::SpawnProfile {
            executable: crate::testsupport::shell_executable(),
            args: vec![],
            cwd: root_path.clone(),
            environment: crate::testsupport::shell_environment(&root_path),
            shell_integration: None,
            rows,
            cols,
            history: 64,
        });
        let before = f
            .store
            .lock()
            .unwrap()
            .workspace(f.workspace)
            .unwrap()
            .state;
        let local_request = RpcRequest {
            v: lomi_remote_protocol::ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: "local_terminal_create".to_owned().try_into().unwrap(),
            timeout_ms: 4000u64.try_into().unwrap(),
            call: RpcCall::TerminalCreate(TerminalCreateParams {
                mutation: lomi_remote_protocol::MutationContext {
                    operation_id: OperationId::from_bytes([71; 16]).unwrap(),
                    context: before.context,
                    expected_revision: before.domain_revision,
                },
                tab_name: "Synthetic PTY".to_owned().try_into().unwrap(),
                profile_id: "default".to_owned().try_into().unwrap(),
            }),
        };
        assert!(matches!(
            rpc::dispatch(
                &coordinator,
                &mut local,
                local_request,
                f.runtime().operation
            ),
            RpcResponse::Result {
                result: RpcResult::TerminalCreate(_),
                ..
            }
        ));
        let local_target = running_target(
            &f.store
                .lock()
                .unwrap()
                .workspace(f.workspace)
                .unwrap()
                .state,
        );
        // Publish only after host-local lifecycle created and committed the PTY.
        #[cfg(feature = "cloud-fixture")]
        if let (Some(worker), Some(transport)) = (&mut cloud_worker, &cloud_transport) {
            cloud_worker_publish_pending(worker, f, auth, transport);
        } else {
            acknowledge_pending_publication(&f.store, &mut f.eligibility);
        }
        #[cfg(not(feature = "cloud-fixture"))]
        acknowledge_pending_publication(&f.store, &mut f.eligibility);
        let host_identity = auth.public_host_identity(f.now()).unwrap();
        let consumer = Identity::generate(
            host_identity.account_id.to_bytes(),
            [22; 16],
            Role::Device,
            1,
        )
        .unwrap();
        let mut first_input = input_with_consumer(f, auth, &consumer);
        let signed = SignedGrantV3::from_wire(&first_input.grant).unwrap();
        let workspace = WorkspaceContext {
            workspace_id: f.workspace,
            workspace_epoch: WorkspaceEpoch::from_bytes(signed.grant.workspace_epoch).unwrap(),
            runtime_id: RuntimeId::from_bytes(signed.grant.runtime_id).unwrap(),
            runtime_generation: DecimalU64(signed.grant.runtime_generation),
            host_access_epoch: DecimalU64(signed.grant.access_epoch),
            grant_revision: DecimalU64(signed.grant.grant_revision),
        };
        let terminal = TerminalContext {
            workspace,
            ..local_target.clone()
        };
        if terminal_purpose {
            let mut context = ChannelContextV3::from_canonical(
                &hex_bytes(first_input.expected_context.expose_wire())
                    .unwrap_or_else(|_| panic!("workspace context bytes")),
            )
            .unwrap();
            context.purpose = lomi_remote_crypto::ChannelPurposeV3::Terminal;
            context.terminal = Some(lomi_remote_crypto::TerminalTargetV3 {
                pane_id: terminal.pane_id.to_bytes(),
                session_id: terminal.session_id.to_bytes(),
                session_epoch: terminal.session_epoch.to_bytes(),
                terminal_profile: "lomi-rust-grid-v1-experimental".into(),
            });
            first_input.expected_context = hex(&context.canonical().unwrap()).try_into().unwrap();
            first_input.expected_context_json = serde_json::to_value(&context)
                .unwrap()
                .as_object()
                .unwrap()
                .clone();
            first_input.authority.terminal_membership =
                Some(lomi_remote_protocol::http::ChannelTerminalMembership {
                    pane_id: terminal.pane_id,
                    session_id: terminal.session_id,
                    session_epoch: terminal.session_epoch,
                    terminal_profile: terminal.profile.clone(),
                });
        }
        let source = f
            .store
            .lock()
            .unwrap()
            .acknowledged_workspace_grants()
            .unwrap()
            .remove(0);
        if terminal_purpose {
            let PairingResult::Approved { authority, .. } = &source.response else {
                panic!("persisted pairing response")
            };
            assert!(
                authority.terminal_membership.is_none(),
                "fresh pairing GET fixture must not supply terminal membership"
            );
        }
        // Each 16 KiB snapshot fragment performs its own current-peer read. An
        // exhausted script yields Invalid by design (the default 80x24 grid
        // needed ~195 reads per connection, which the former 64 never covered),
        // so keep a bounded margin well above the measured need.
        for _ in 0..8192 {
            peer::current_pairing_script::enqueue(
                source.intent.preparation.pairing_id,
                source.response.clone(),
            );
        }
        let stage = Arc::new(Stage(Mutex::new(0), Condvar::new()));
        let rollover_stage = Arc::new(Stage(Mutex::new(0), Condvar::new()));
        let shared_lease = Arc::new(Mutex::new(None));
        let client_progress = Arc::new([AtomicU8::new(0), AtomicU8::new(0)]);
        let stopping = f.stopping.clone();
        let mut ingress = Registry::with_coordinator(&stopping, Arc::downgrade(&coordinator));
        let mut links: Vec<(ChannelId, thread::JoinHandle<()>, mpsc::Receiver<Signal>)> =
            Vec::new();
        let mut connected = [false; 2];
        let mut idle_workspace_ready = false;
        let until = Instant::now() + Duration::from_secs(60);
        let mut heartbeat = Instant::now();
        #[cfg(feature = "cloud-fixture")]
        let mut cloud_refresh = Instant::now();
        // Complete A's initial relay handshake before starting B. Both native
        // clients then remain live in one registry sharing the same owner.
        for (channel_byte, role) in [(60u8, ClientRole::A), (61u8, ClientRole::B)] {
            let mut input = first_input.clone();
            let mut context = ChannelContextV3::from_canonical(
                &hex_bytes(input.expected_context.expose_wire())
                    .unwrap_or_else(|_| panic!("context bytes")),
            )
            .unwrap();
            context.channel_id = [channel_byte; 16];
            context.issued_at = f.now();
            context.expires_at = f.now() + 30;
            input.expected_context = hex(&context.canonical().unwrap()).try_into().unwrap();
            let channel_id = ChannelId::from_bytes(context.channel_id).unwrap();
            let api = Api {
                replies: RefCell::new(VecDeque::from([Reply::Poll(ChannelPendingResult {
                    channels: vec![PendingChannel {
                        channel_id,
                        inputs: input.clone(),
                    }]
                    .try_into()
                    .unwrap(),
                })])),
                requests: RefCell::new(vec![]),
                params: RefCell::new(vec![]),
                hook: RefCell::new(None),
            };
            let (mut channel_worker, intent) = prepared(f, auth, &api);
            api.replies
                .borrow_mut()
                .push_back(Reply::state(admitted(&intent)));
            assert!(step(f, auth, &mut channel_worker, &api).is_ok());
            let admission =
                SignedChannelAdmissionV3::from_wire(&intent.preparation.params.admission).unwrap();
            let host = SignedBundle::from_wire(&host_identity.identity).unwrap();
            let validated = admission
                .verify(
                    &signed,
                    &context,
                    &host,
                    &host_identity.fingerprint,
                    &consumer.public_bundle(),
                    &context.grant.consumer_fingerprint,
                    &authority(&input.authority),
                    f.now(),
                )
                .unwrap();
            let initiator = Handshake::new_v3(
                true,
                &consumer,
                validated,
                &host,
                &host_identity.fingerprint,
                f.now(),
            )
            .unwrap();
            let (signal_tx, signal_rx) = mpsc::sync_channel(8);
            let server_listener = listener.try_clone().unwrap();
            let server_tls = tls.clone();
            let server_terminal = terminal.clone();
            let marker_root = root_path.clone();
            let server_stage = stage.clone();
            let server_rollover_stage = rollover_stage.clone();
            let server_progress = client_progress.clone();
            let server_shared_lease = shared_lease.clone();
            let server_maintenance_rollover = maintenance_rollover;
            let server_terminal_purpose = terminal_purpose;
            let server_idle_sibling_snapshot = idle_sibling_snapshot;
            let join = thread::spawn(move || {
                client(
                    role,
                    server_listener,
                    server_tls,
                    initiator,
                    context.channel_id,
                    server_terminal,
                    marker_root,
                    signal_tx,
                    server_stage,
                    server_maintenance_rollover,
                    server_rollover_stage,
                    server_progress,
                    server_terminal_purpose,
                    stress_snapshot,
                    server_idle_sibling_snapshot,
                    server_shared_lease,
                )
            });
            ingress
                .script_ticket_for_channel_test(
                    channel_id,
                    Ok(ticket_response(&intent)),
                    None,
                    Duration::ZERO,
                )
                .expect("bounded per-channel ticket script");
            ingress
                .script_relay_for_channel_test(
                    channel_id,
                    lomi_host_http::RelayTransport::with_test_root(endpoint.clone(), root.clone())
                        .unwrap(),
                )
                .expect("bounded per-channel relay script");
            ingress.after_channel_step(&mut channel_worker, auth, f.runtime(), &f.eligibility);
            // Ticket, connect, and frame work all use the same registry
            // round-robin advance, including while a sibling socket is live.
            let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
            if immediate {
                assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
            }
            let next_wait = actor_wait_duration(immediate);
            thread::sleep(next_wait);
            links.push((channel_id, join, signal_rx));
            if role == ClientRole::A {
                while !connected[0]
                    || (idle_sibling_snapshot
                        && (!idle_workspace_ready
                            || ingress.has_immediate_output(f.runtime(), Some(&f.eligibility))))
                {
                    ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                    let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                    if immediate {
                        assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                    }
                    let next_wait = actor_wait_duration(immediate);
                    while let Ok(signal) = links[0].2.try_recv() {
                        match signal {
                            Signal::Connected => connected[0] = true,
                            Signal::IdleWorkspaceReady => idle_workspace_ready = true,
                            _ => panic!("unexpected signal during channel A startup"),
                        }
                    }
                    assert!(
                        Instant::now() < until,
                        "first native client did not connect"
                    );
                    thread::sleep(next_wait);
                }
                if idle_sibling_snapshot {
                    assert!(idle_workspace_ready);
                    assert!(
                        !ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)),
                        "channel A must be idle before channel B starts its snapshot"
                    );
                }
            }
        }
        while connected.contains(&false) {
            #[cfg(feature = "cloud-fixture")]
            if central_revoke_dir.is_some() && cloud_refresh.elapsed() >= Duration::from_millis(500)
            {
                cloud_worker_refresh_eligibility(
                    cloud_worker.as_mut().expect("CloudWorker"),
                    f,
                    auth,
                    cloud_transport.as_ref().expect("Cloud transport"),
                );
                cloud_refresh = Instant::now();
            }
            #[cfg(feature = "cloud-fixture")]
            if central_revoke_dir.is_none() && heartbeat.elapsed() > Duration::from_secs(1) {
                f.eligibility.heartbeat.request_started = Instant::now();
                f.eligibility.heartbeat.wall_at_request_start = f.now();
                heartbeat = Instant::now();
            }
            #[cfg(not(feature = "cloud-fixture"))]
            if heartbeat.elapsed() > Duration::from_secs(1) {
                f.eligibility.heartbeat.request_started = Instant::now();
                f.eligibility.heartbeat.wall_at_request_start = f.now();
                heartbeat = Instant::now();
            }
            ingress.poll(auth, f.runtime(), Some(&f.eligibility));
            let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
            if immediate {
                assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
            }
            let next_wait = actor_wait_duration(immediate);
            for (index, (_, _, signals)) in links.iter_mut().enumerate() {
                if !connected[index] && matches!(signals.try_recv(), Ok(Signal::Connected)) {
                    connected[index] = true;
                }
            }
            assert!(
                Instant::now() < until,
                "both native clients did not connect"
            );
            thread::sleep(next_wait);
        }
        if idle_sibling_snapshot {
            assert!(idle_workspace_ready);
            let idle_channel = links[0].0;
            let snapshot_channel = links[1].0;
            let deadline = Instant::now() + Duration::from_secs(30);
            let mut snapshot_complete = false;
            let mut saw_pending_stream = false;
            let mut shortened_refresh_cutoffs = false;
            let mut idle_refresh_won_priority = false;
            let mut done = 0;
            let mut idle_fast_turns = 0;
            while done < 2 {
                #[cfg(feature = "cloud-fixture")]
                if central_revoke_dir.is_some()
                    && cloud_refresh.elapsed() >= Duration::from_millis(500)
                {
                    cloud_worker_refresh_eligibility(
                        cloud_worker.as_mut().expect("CloudWorker"),
                        f,
                        auth,
                        cloud_transport.as_ref().expect("Cloud transport"),
                    );
                    cloud_refresh = Instant::now();
                }
                #[cfg(feature = "cloud-fixture")]
                if central_revoke_dir.is_none() && heartbeat.elapsed() > Duration::from_secs(1) {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    heartbeat = Instant::now();
                }
                #[cfg(not(feature = "cloud-fixture"))]
                if heartbeat.elapsed() > Duration::from_secs(1) {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    heartbeat = Instant::now();
                }

                if !shortened_refresh_cutoffs && ingress.stream_pending_for_test(snapshot_channel) {
                    let now = Instant::now();
                    ingress.shorten_peer_cutoff_for_test(
                        idle_channel,
                        now + Duration::from_millis(300),
                    );
                    ingress.shorten_peer_cutoff_for_test(
                        snapshot_channel,
                        now + Duration::from_millis(600),
                    );
                    shortened_refresh_cutoffs = true;
                    assert!(
                        ingress.has_retained_operation(),
                        "pre-expiry proof refresh must retain its current worker unit"
                    );
                }
                let pending_before =
                    ingress.has_immediate_output(f.runtime(), Some(&f.eligibility));
                let idle_turns_before = ingress_turns(&ingress, idle_channel);
                let snapshot_turns_before = ingress_turns(&ingress, snapshot_channel);
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                if ingress.stream_pending_for_test(snapshot_channel) {
                    saw_pending_stream = true;
                    assert!(
                        ingress.has_retained_operation(),
                        "an unfinished terminal stream must retain its original worker operation"
                    );
                }
                let next_wait = actor_wait_duration(immediate);
                let pending_after = ingress.has_immediate_output(f.runtime(), Some(&f.eligibility));
                if pending_after {
                    assert!(
                        immediate,
                        "queued eligible output must keep the next pass fast"
                    );
                    assert_eq!(next_wait, Duration::ZERO);
                    assert!(!ingress.has_immediate_output(f.runtime(), None));
                    let mut stale_eligibility = f.eligibility.clone();
                    stale_eligibility.heartbeat.request_started = Instant::now()
                        .checked_sub(Duration::from_secs(10))
                        .expect("past monotonic time");
                    assert!(
                        !ingress.has_immediate_output(f.runtime(), Some(&stale_eligibility)),
                        "stale peer eligibility cannot request an immediate pass"
                    );
                } else {
                    assert!(!immediate);
                    assert_eq!(next_wait, Duration::from_millis(250));
                }
                let idle_turns_after = ingress_turns(&ingress, idle_channel);
                let snapshot_turns_after = ingress_turns(&ingress, snapshot_channel);
                if shortened_refresh_cutoffs && !idle_refresh_won_priority {
                    assert_eq!(
                        idle_turns_after,
                        idle_turns_before + 1,
                        "the earliest peer cutoff refreshes before the busy sibling"
                    );
                    assert_eq!(
                        snapshot_turns_after, snapshot_turns_before,
                        "refresh priority still advances only one connection per pass"
                    );
                    idle_refresh_won_priority = true;
                }
                if pending_before
                    && pending_after
                    && idle_turns_after > idle_turns_before
                    && snapshot_turns_after == snapshot_turns_before
                {
                    idle_fast_turns += 1;
                }

                for (_, _, signals) in &links {
                    while let Ok(signal) = signals.try_recv() {
                        match signal {
                            Signal::Connected | Signal::IdleWorkspaceReady => (),
                            Signal::SnapshotComplete => snapshot_complete = true,
                            Signal::Done => done += 1,
                            Signal::Parked(_)
                            | Signal::FirstRename
                            | Signal::SecondRename
                            | Signal::RevokeClosed(_) => {
                                panic!("unexpected signal in idle-sibling snapshot scenario")
                            }
                        }
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "idle sibling delayed the 80x24 SnapshotComplete"
                );
                thread::sleep(next_wait);
            }
            assert!(snapshot_complete, "the 80x24 snapshot must complete");
            assert!(
                saw_pending_stream,
                "the multi-fragment snapshot must exercise retained stream state"
            );
            assert!(
                idle_fast_turns > 0,
                "at least one idle workspace turn must occur while B has queued snapshot output"
            );
            assert!(
                shortened_refresh_cutoffs && idle_refresh_won_priority,
                "idle peer refresh must win the earlier cutoff while the sibling streams"
            );
            while links
                .iter()
                .any(|(channel_id, ..)| ingress.connected_for_test(*channel_id))
            {
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                let pending = ingress.has_immediate_output(f.runtime(), Some(&f.eligibility));
                let next_wait = actor_wait_duration(immediate);
                assert_eq!(immediate, pending);
                assert_eq!(next_wait, actor_wait_duration(pending));
                assert!(
                    Instant::now() < deadline,
                    "idle sibling sockets did not close"
                );
                thread::sleep(next_wait);
            }
            for (_, join, _) in links {
                join.join().unwrap();
            }
            ingress.discard();
            assert!(!ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
            return;
        }
        if maintenance_rollover {
            let mut parked = [false; 2];
            while parked.contains(&false) {
                #[cfg(feature = "cloud-fixture")]
                if central_revoke_dir.is_none() && heartbeat.elapsed() > Duration::from_secs(1) {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    heartbeat = Instant::now();
                }
                #[cfg(not(feature = "cloud-fixture"))]
                if heartbeat.elapsed() > Duration::from_secs(1) {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    heartbeat = Instant::now();
                }
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                if immediate {
                    assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                }
                let next_wait = actor_wait_duration(immediate);
                for (_, _, signals) in links.iter_mut() {
                    while let Ok(signal) = signals.try_recv() {
                        if let Signal::Parked(role) = signal {
                            parked[match role {
                                ClientRole::A => 0,
                                ClientRole::B => 1,
                            }] = true;
                        }
                    }
                }
                assert!(
                    Instant::now() < until,
                    "both native clients did not park for maintenance rollover"
                );
                thread::sleep(next_wait);
            }
            // Receiving an ACK result can precede retiring its final encoder
            // state. Settle that finite output before asserting idle behavior.
            while ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)) {
                assert!(Instant::now() < until, "parked client output did not drain");
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                thread::sleep(actor_wait_duration(immediate));
            }
            let channel_ids: Vec<_> = links.iter().map(|(channel_id, ..)| *channel_id).collect();
            let refresh_deadline = Instant::now() + Duration::from_secs(5);
            while ingress.has_retained_operation() {
                assert!(
                    Instant::now() < refresh_deadline,
                    "pre-expiry maintenance did not return the idle worker unit"
                );
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                thread::sleep(actor_wait_duration(immediate));
            }
            assert!(
                !ingress.has_retained_operation(),
                "idle connections settle the worker unit after pre-expiry peer refresh"
            );
            for channel_id in &channel_ids {
                ingress.settle_maintenance_for_test(*channel_id);
            }
            assert!(
                !ingress.has_retained_operation(),
                "expired maintenance operations should not be retained"
            );
            assert!(
                !ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)),
                "live but idle connections do not request an immediate actor pass"
            );
            assert!(
                !ingress.has_immediate_output(f.runtime(), None),
                "missing peer eligibility cannot request an immediate actor pass"
            );
            assert_eq!(
                actor_wait_duration(false),
                Duration::from_millis(250),
                "idle ingress preserves the production actor wait"
            );
            // Polling prunes only truly empty drivers. These connections have
            // no queued RPCs while parked, so their expired maintenance state
            // must not make the registry drop either live socket.
            ingress.poll(auth, f.runtime(), Some(&f.eligibility));
            assert_eq!(
                ingress.registered_channels_for_test().len(),
                channel_ids.len(),
                "live idle connections must survive maintenance rollover"
            );
            for channel_id in &channel_ids {
                assert!(ingress.connected_for_test(*channel_id));
            }

            // Repeated new admissions must not take priority over the two
            // already-live sockets. Each failed ticket attempt below is
            // counted alongside incumbent frame turns, proving no aggregate
            // advance performs two ingress stages.
            let initial_turns: Vec<_> = channel_ids
                .iter()
                .map(|channel_id| ingress_turns(&ingress, *channel_id))
                .collect();
            for offset in 0..6u8 {
                let newcomer = ChannelId::from_bytes([120 + offset; 16]).unwrap();
                let calls = add_registry_candidate(f, auth, &mut ingress, &first_input, newcomer);
                assert_eq!(calls.get(), 0, "queued admission must not send ticket HTTP");
                let mut selected = false;
                for _ in 0..3 {
                    let before_calls = calls.get();
                    let before_turns: u64 = channel_ids
                        .iter()
                        .map(|channel_id| ingress_turns(&ingress, *channel_id))
                        .sum();
                    ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                    let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                    if immediate {
                        assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                    }
                    let next_wait = actor_wait_duration(immediate);
                    let after_calls = calls.get();
                    let after_turns: u64 = channel_ids
                        .iter()
                        .map(|channel_id| ingress_turns(&ingress, *channel_id))
                        .sum();
                    assert!(
                        (after_calls.saturating_sub(before_calls) as u64)
                            + after_turns.saturating_sub(before_turns)
                            <= 1,
                        "one aggregate registry stage per advance"
                    );
                    if after_calls == 1 {
                        selected = true;
                        thread::sleep(next_wait);
                        break;
                    }
                    assert_eq!(after_calls, 0, "failed ticket must not be replayed");
                    for channel_id in &channel_ids {
                        assert!(ingress.connected_for_test(*channel_id));
                    }
                    thread::sleep(next_wait);
                }
                assert!(
                    selected,
                    "new ticket gets a round-robin turn within three passes"
                );
                assert_eq!(calls.get(), 1, "failed ticket is consumed exactly once");
                assert!(
                    !ingress.registered_channels_for_test().contains(&newcomer),
                    "failed newcomer is pruned without evicting live peers"
                );
            }
            for (index, channel_id) in channel_ids.iter().enumerate() {
                assert!(ingress_turns(&ingress, *channel_id) > initial_turns[index]);
                assert!(ingress.connected_for_test(*channel_id));
            }
            rollover_stage.reach(1);
        }
        #[cfg(feature = "cloud-fixture")]
        if !terminal_purpose && central_revoke_dir.is_some() {
            let requested_directory = central_revoke_dir
                .as_ref()
                .expect("shared Cloud revoke directory");
            let requested = requested_directory.to_str().expect("UTF-8 rendezvous path");
            let components: Vec<_> = requested.split('/').collect();
            assert_eq!(components.len(), 4, "bounded rendezvous path required");
            assert_eq!(components[0], "");
            assert_eq!(components[1], "tmp");
            assert_eq!(components[3], "cloud-central-revoke-rendezvous");
            let fixture_name = components[2];
            let uuid = fixture_name
                .strip_prefix("lomi-e2-")
                .expect("fixture directory");
            assert_eq!(uuid.len(), 36, "fixture UUID length");
            for (index, byte) in uuid.bytes().enumerate() {
                if [8, 13, 18, 23].contains(&index) {
                    assert_eq!(byte, b'-', "fixture UUID format");
                } else {
                    assert!(
                        byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
                        "fixture UUID format"
                    );
                }
            }
            let directory = std::fs::canonicalize(requested_directory)
                .expect("canonical private rendezvous directory");
            let base = directory.parent().expect("fixture base directory");
            let temp_root = base.parent().expect("private temp root");
            assert!(
                temp_root == std::path::Path::new("/tmp")
                    || temp_root == std::path::Path::new("/private/tmp")
            );
            assert_eq!(
                base.file_name().and_then(|value| value.to_str()),
                Some(fixture_name)
            );
            assert_eq!(
                directory.file_name().and_then(|value| value.to_str()),
                Some("cloud-central-revoke-rendezvous")
            );
            for path in [base, directory.as_path()] {
                let metadata =
                    std::fs::symlink_metadata(path).expect("rendezvous directory metadata");
                assert!(
                    metadata.is_dir() && !metadata.file_type().is_symlink(),
                    "rendezvous directories must be real directories"
                );
            }
            let mut parked_a = false;
            let mut parked_b = false;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !parked_a || !parked_b {
                if cloud_refresh.elapsed() >= Duration::from_millis(500) {
                    cloud_worker_refresh_eligibility(
                        cloud_worker.as_mut().expect("CloudWorker"),
                        f,
                        auth,
                        cloud_transport.as_ref().expect("Cloud transport"),
                    );
                    cloud_refresh = Instant::now();
                }
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                if immediate {
                    assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                }
                let next_wait = actor_wait_duration(immediate);
                for (_, _, signals) in links.iter_mut() {
                    while let Ok(signal) = signals.try_recv() {
                        if let Signal::Parked(role) = signal {
                            match role {
                                ClientRole::A => parked_a = true,
                                ClientRole::B => parked_b = true,
                            }
                        }
                    }
                }
                if Instant::now() >= deadline {
                    let client_state =
                        |index: usize| match client_progress[index].load(AtomicOrdering::Acquire) {
                            0 => "starting",
                            1 => "noise-connected",
                            2 => "attached",
                            3 => "snapshot-complete",
                            4 => "acknowledged",
                            5 => "parked",
                            _ => "unknown",
                        };
                    let driver_state: Vec<_> = links
                        .iter()
                        .map(|(channel_id, ..)| {
                            (
                                channel_id,
                                ingress.failure_observation_for_test(*channel_id),
                                ingress.channel_step_observation_for_test(*channel_id),
                            )
                        })
                        .collect();
                    panic!(
                        "both clients did not park after attach: clients=[A:{}, B:{}], drivers={driver_state:?}",
                        client_state(0),
                        client_state(1)
                    );
                }
                thread::sleep(next_wait);
            }
            let (worker, transport) = (
                cloud_worker.as_mut().expect("CloudWorker"),
                cloud_transport.as_ref().expect("Cloud transport"),
            );
            use std::io::Write as _;
            let mut ready = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(directory.join("clients-ready"))
                .expect("create live-client rendezvous");
            ready
                .write_all(b"ready")
                .expect("write live-client rendezvous");
            let deadline = Instant::now() + Duration::from_secs(60);
            let release_path = directory.join("manager-revoked");
            let mut released = false;
            while !released {
                assert!(
                    Instant::now() < deadline,
                    "manager revoke rendezvous timed out"
                );
                match std::fs::symlink_metadata(&release_path) {
                    Ok(metadata) => {
                        assert!(metadata.is_file() && !metadata.file_type().is_symlink());
                        assert!(
                            metadata.len() <= 16,
                            "bounded revoke release marker required"
                        );
                        assert_eq!(
                            std::fs::read(&release_path).expect("read revoke marker"),
                            b"revoked"
                        );
                        released = true;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => panic!("invalid revoke rendezvous marker"),
                }
            }
            assert!(!worker.has_retained_operation());
            assert!(
                f.store
                    .lock()
                    .unwrap()
                    .pending_publications()
                    .unwrap()
                    .is_empty()
            );
            // Run the production supervisor so a real DataFailure::AuthRequired
            // commits begin_authority_rejection through this same HostAuth and
            // SharedOwner. Its private stop flag leaves the live ingress
            // Drivers untouched until both read-only probes observe closure.
            let owner = f.owner.clone();
            let supervisor_stop = AtomicBool::new(false);
            let observer_cancel = AtomicBool::new(false);
            let mut supervisor_runtime = f.runtime();
            supervisor_runtime.stopping = &supervisor_stop;
            let identity_transport =
                lomi_host_http::Transport::new(&f.config).expect("fixture identity transport");
            let saw_shared_fence = thread::scope(|threads| {
                let observer_owner = owner.clone();
                let stop_supervisor = &supervisor_stop;
                let observer = threads.spawn(move || {
                    let operation = crate::unix::auth::OwnerOperation::new(
                        Instant::now() + Duration::from_secs(20),
                        &observer_cancel,
                    );
                    for _ in 0..2000 {
                        if observer_owner
                            .authorization_state(&operation)
                            .is_ok_and(|authorization| authorization.locked)
                        {
                            stop_supervisor.store(true, Ordering::Release);
                            return true;
                        }
                        thread::sleep(Duration::from_millis(10));
                    }
                    stop_supervisor.store(true, Ordering::Release);
                    false
                });
                crate::unix::auth::run_with_data(
                    auth,
                    &identity_transport,
                    &f.config,
                    supervisor_runtime,
                    Some(transport),
                );
                observer.join().expect("shared-owner fence observer")
            });
            assert!(
                saw_shared_fence,
                "production supervisor did not fence shared owner"
            );
            assert!(supervisor_stop.load(Ordering::Acquire));
            assert!(!f.stopping.load(Ordering::Acquire));
            assert!(
                owner
                    .authorization_state(f.runtime().operation)
                    .expect("shared owner authorization state")
                    .locked,
                "shared owner must fence after actual Cloud revoke"
            );
            println!("LOMI_SHARED_CLOUD_REVOKE_STAGE=actual_revoke_rejected");
            println!("LOMI_SHARED_CLOUD_REVOKE_STAGE=shared_owner_fenced");
            // This stage releases only read-only probes. Each probe must see
            // the same shared HostAuth fence as the CloudWorker rejection.
            stage.reach(1);
            let mut closed_a = false;
            let mut closed_b = false;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !closed_a || !closed_b {
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                if immediate {
                    assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                }
                let next_wait = actor_wait_duration(immediate);
                for (_, _, signals) in links.iter_mut() {
                    while let Ok(signal) = signals.try_recv() {
                        if let Signal::RevokeClosed(role) = signal {
                            match role {
                                ClientRole::A => closed_a = true,
                                ClientRole::B => closed_b = true,
                            }
                        }
                    }
                }
                assert!(
                    Instant::now() < deadline,
                    "both revoked clients did not close"
                );
                thread::sleep(next_wait);
            }
            while links
                .iter()
                .any(|(channel_id, ..)| ingress.connected_for_test(*channel_id))
            {
                ingress.poll(auth, f.runtime(), Some(&f.eligibility));
                let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
                if immediate {
                    assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
                }
                assert!(
                    Instant::now() < deadline,
                    "revoked client drivers stayed connected"
                );
                thread::sleep(actor_wait_duration(immediate));
            }
            for (_, join, _) in links {
                join.join().unwrap();
            }
            ingress.discard();
            assert!(closed_a && closed_b);
            println!("LOMI_SHARED_CLOUD_REVOKE_STAGE=both_live_clients_closed");
            return;
        }
        let mut done = 0;
        let mut settling: Option<(u32, Instant)> = None;
        while done < 2 {
            // Drain B's host-side refresh after its stream proofs before each
            // workspace mutation by A.
            let current_stage = stage.current();
            if !terminal_purpose && matches!(current_stage, 3 | 6) {
                let since = match settling {
                    Some((target, since)) if target == current_stage => since,
                    _ => {
                        let since = Instant::now();
                        settling = Some((current_stage, since));
                        since
                    }
                };
                let ready_after = if current_stage == 3 { 4 } else { 7 };
                if since.elapsed() > Duration::from_millis(300) {
                    stage.reach(ready_after);
                }
            }
            // The production heartbeat worker refreshes cloud freshness; this
            // fixture has none, so emulate it.
            if heartbeat.elapsed() > Duration::from_secs(1) {
                f.eligibility.heartbeat.request_started = Instant::now();
                f.eligibility.heartbeat.wall_at_request_start = f.now();
                heartbeat = Instant::now();
            }
            if terminal_purpose {
                // Terminal input is ephemeral, but keep the same fixture-side
                // publication refresh as each client request is serviced.
                #[cfg(feature = "cloud-fixture")]
                if let (Some(worker), Some(transport)) = (&mut cloud_worker, &cloud_transport) {
                    cloud_worker_publish_pending(worker, f, auth, transport);
                } else {
                    acknowledge_pending_publication(&f.store, &mut f.eligibility);
                }
                #[cfg(not(feature = "cloud-fixture"))]
                acknowledge_pending_publication(&f.store, &mut f.eligibility);
            } else {
                // Reads and input before A's first rename may journal a
                // publication; acknowledge them before the next current-peer read.
                for _ in &links {
                    if stage.current() < 3 || stage.current() == 4 {
                        #[cfg(feature = "cloud-fixture")]
                        if let (Some(worker), Some(transport)) =
                            (&mut cloud_worker, &cloud_transport)
                        {
                            cloud_worker_publish_pending(worker, f, auth, transport);
                        } else {
                            acknowledge_pending_publication(&f.store, &mut f.eligibility);
                        }
                        #[cfg(not(feature = "cloud-fixture"))]
                        acknowledge_pending_publication(&f.store, &mut f.eligibility);
                    }
                    if stage.current() == 9 {
                        // B has observed the closed delivery. Assert the second
                        // mutation is still in the outbox, then acknowledge it.
                        assert_eq!(
                            f.store
                                .lock()
                                .unwrap()
                                .pending_publications()
                                .unwrap()
                                .len(),
                            1,
                            "expected exactly one unacknowledged publication"
                        );
                        #[cfg(feature = "cloud-fixture")]
                        if let (Some(worker), Some(transport)) =
                            (&mut cloud_worker, &cloud_transport)
                        {
                            cloud_worker_publish_pending(worker, f, auth, transport);
                            println!("LOMI_SHARED_CLOUD_STAGE=post_close_publication_acknowledged");
                        } else {
                            acknowledge_pending_publication(&f.store, &mut f.eligibility);
                        }
                        #[cfg(not(feature = "cloud-fixture"))]
                        acknowledge_pending_publication(&f.store, &mut f.eligibility);
                        stage.reach(10);
                    }
                }
            }
            ingress.poll(auth, f.runtime(), Some(&f.eligibility));
            let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
            if immediate {
                assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
            }
            let next_wait = actor_wait_duration(immediate);
            for link in &links {
                while let Ok(signal) = link.2.try_recv() {
                    match signal {
                        Signal::Connected => (),
                        Signal::Done => done += 1,
                        Signal::FirstRename => {
                            // A's first rename is fully published so B can
                            // verify shared state and stale-revision behavior.
                            #[cfg(feature = "cloud-fixture")]
                            if let (Some(worker), Some(transport)) =
                                (&mut cloud_worker, &cloud_transport)
                            {
                                cloud_worker_publish_pending(worker, f, auth, transport);
                            } else {
                                acknowledge_pending_publication(&f.store, &mut f.eligibility);
                            }
                            #[cfg(not(feature = "cloud-fixture"))]
                            acknowledge_pending_publication(&f.store, &mut f.eligibility);
                            stage.reach(5);
                        }
                        Signal::SecondRename => {
                            assert_eq!(
                                f.store
                                    .lock()
                                    .unwrap()
                                    .pending_publications()
                                    .unwrap()
                                    .len(),
                                1,
                                "expected exactly one pending second publication"
                            );
                            stage.reach(8);
                        }
                        Signal::Parked(_) | Signal::RevokeClosed(_) => {
                            panic!("revoke-only client signal in regular multi-client flow")
                        }
                        Signal::IdleWorkspaceReady | Signal::SnapshotComplete => {
                            panic!("idle-sibling signal in regular multi-client flow")
                        }
                    }
                }
            }
            assert!(
                Instant::now() < until,
                "two-client scenario did not settle: {:?}",
                links
                    .iter()
                    .map(|(channel_id, ..)| (
                        channel_id,
                        ingress.failure_observation_for_test(*channel_id),
                        ingress.channel_step_observation_for_test(*channel_id),
                    ))
                    .collect::<Vec<_>>()
            );
            thread::sleep(next_wait);
        }
        while links
            .iter()
            .any(|(channel_id, ..)| ingress.connected_for_test(*channel_id))
        {
            assert!(Instant::now() < until, "sockets did not disconnect");
            ingress.poll(auth, f.runtime(), Some(&f.eligibility));
            let immediate = ingress.advance(auth, f.runtime(), Some(&f.eligibility));
            if immediate {
                assert!(ingress.has_immediate_output(f.runtime(), Some(&f.eligibility)));
            }
            thread::sleep(actor_wait_duration(immediate));
        }
        for (_, join, _) in links {
            join.join().unwrap();
        }
        ingress.discard();
        // One PTY served both clients: the input ran exactly once.
        assert_eq!(std::fs::read(root_path.join(MARKER)).unwrap(), b"x");
        assert!(
            coordinator
                .terminals
                .snapshot(local_target.session_id, local_target.session_epoch)
                .unwrap()
                .output_offset
                .0
                > 0
        );
    };
    #[cfg(feature = "cloud-fixture")]
    if let Some(cloud) = cloud_fixture {
        peer::tests::fixture_at_wall_with_cloud(now, Some(endpoint.clone()), cloud, run_fixture);
    } else {
        peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), run_fixture);
    }
    #[cfg(not(feature = "cloud-fixture"))]
    peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), run_fixture);
    peer::current_pairing_script::clear();
}
