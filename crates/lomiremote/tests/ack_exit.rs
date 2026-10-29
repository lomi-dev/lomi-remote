#![cfg(unix)]
use lomi_platform::unix::{Error, LocalClient, LocalDiscovery, OwnerEndpoint, OwnerLock};
use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use lomi_terminal_state::TerminalState;
use lomiremote::{
    attach::{View, acknowledge_rendered, draw},
    terminal_commands,
};
use ratatui::{Terminal, backend::TestBackend};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
const ID: &str = "11111111-1111-4111-8111-111111111111";
fn context() -> TerminalContext {
    serde_json::from_value(serde_json::json!({"workspace":{"workspaceId":ID,"workspaceEpoch":ID,"runtimeId":ID,"runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"},"paneId":ID,"sessionId":ID,"sessionEpoch":ID,"profile":"lomi-rust-grid-v1-experimental"})).unwrap()
}
fn subscription() -> SubscriptionId {
    "ack-exit-fixture".to_owned().try_into().unwrap()
}
struct Profile(PathBuf);
impl Drop for Profile {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[derive(Clone, Copy)]
enum Scenario {
    Exit,
    NoExit,
    WrongTerminal,
    WrongSubscription,
    OtherError,
}
fn exercise(scenario: Scenario) {
    let profile = Profile(
        fs::canonicalize("/tmp")
            .unwrap()
            .join(format!("la-{}", Uuid::new_v4().simple())),
    );
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&profile.0)
        .unwrap();
    let discovery = LocalDiscovery {
        version: LocalIpcVersion::CURRENT,
        profile_id: IpcProfileId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap(),
        host_id: ID.to_owned().try_into().unwrap(),
        runtime_id: ID.to_owned().try_into().unwrap(),
        build_id: "ack-exit-fixture".into(),
    };
    let endpoint = OwnerEndpoint::bind(OwnerLock::acquire(&profile.0).unwrap(), discovery).unwrap();
    let mut engine = TerminalState::new_with_epoch(2, 4, 0, context().session_epoch).unwrap();
    engine.feed(b"done").unwrap();
    let model = engine.snapshot().unwrap();
    let bytes = serde_json::to_vec(&model).unwrap();
    assert!(bytes.len() >= 15);
    let metadata = TerminalSnapshotMetadata {
        terminal: context(),
        subscription_id: subscription(),
        through_seq: TerminalSeq(model.sequence),
        output_offset: model.output_offset,
        columns: TerminalDimension(4),
        rows: TerminalDimension(2),
        chunk_count: ChunkCount(15),
        total_bytes: DecimalU64(bytes.len() as u64),
    };
    let server_metadata = metadata.clone();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = loop {
            if let Some(socket) = endpoint.accept().unwrap() {
                break socket;
            }
            assert!(Instant::now() < deadline, "accept deadline");
            thread::sleep(Duration::from_millis(2));
        };
        let mut connection = endpoint.handshake(socket).unwrap();
        connection.set_deadline(deadline);
        let request = connection.read_request().unwrap();
        let LocalCall::Rpc(rpc) = request.call else {
            panic!("typed RPC attach")
        };
        assert!(matches!(rpc.call, RpcCall::TerminalAttach(_)));
        connection
            .write(&LocalResponse {
                version: request.version,
                request_id: request.request_id,
                result: Ok(LocalResult::Rpc(Box::new(RpcResponse::Result {
                    v: ApplicationMajor,
                    request_id: rpc.request_id,
                    result: RpcResult::TerminalAttach(server_metadata.clone()),
                }))),
            })
            .unwrap();
        // Exactly sixteen queued events: fifteen bounded chunks, then complete.
        for index in 0..15 {
            connection
                .write(&LocalStreamEvent::Terminal(
                    TerminalStreamFrame::SnapshotChunk(TerminalSnapshotChunk {
                        terminal: context(),
                        subscription_id: subscription(),
                        index: ChunkIndex(index as u32),
                        bytes: BoundedList(
                            bytes[bytes.len() * index / 15..bytes.len() * (index + 1) / 15]
                                .to_vec(),
                        ),
                    }),
                ))
                .unwrap();
        }
        connection
            .write(&LocalStreamEvent::Terminal(
                TerminalStreamFrame::SnapshotComplete(TerminalSnapshotComplete {
                    terminal: context(),
                    subscription_id: subscription(),
                    through_seq: server_metadata.through_seq,
                    output_offset: server_metadata.output_offset,
                }),
            ))
            .unwrap();
        if !matches!(scenario, Scenario::NoExit) {
            let mut target = context();
            if matches!(scenario, Scenario::WrongTerminal) {
                target.session_epoch =
                    SessionEpoch::from_bytes(*Uuid::new_v4().as_bytes()).unwrap();
            }
            let sub = if matches!(scenario, Scenario::WrongSubscription) {
                "other-view".to_owned().try_into().unwrap()
            } else {
                subscription()
            };
            connection
                .write(&LocalStreamEvent::Terminal(TerminalStreamFrame::Delta(
                    TerminalDelta {
                        terminal: target,
                        subscription_id: sub,
                        seq: TerminalSeq(DecimalU64(server_metadata.through_seq.0.0 + 1)),
                        change: TerminalChange::Exit(TerminalExit { exit_code: Some(0) }),
                    },
                )))
                .unwrap();
        }
        // The terminal has already exited and retired its subscription before
        // this rendered ACK arrives. Return the canonical bound RPC error.
        let request = connection.read_request().unwrap();
        let LocalCall::Rpc(rpc) = request.call else {
            panic!("typed RPC ACK")
        };
        let RpcCall::TerminalAck(ack) = rpc.call else {
            panic!("single ACK only")
        };
        assert_eq!(ack.through_seq, server_metadata.through_seq);
        assert_eq!(ack.subscription_id, subscription());
        let code = if matches!(scenario, Scenario::OtherError) {
            ErrorCode::ServiceUnavailable
        } else {
            ErrorCode::ResyncRequired
        };
        let response = LocalResponse {
            version: request.version,
            request_id: request.request_id,
            result: Ok(LocalResult::Rpc(Box::new(RpcResponse::Error {
                v: ApplicationMajor,
                request_id: rpc.request_id,
                operation_id: None,
                error: RemoteError::new(code, false, Effect::None, ErrorDetails::empty(), None)
                    .unwrap(),
            }))),
        };
        // A rejected stream binding poisons/shuts down the client's socket, so
        // the server's already prepared reply may become unwritable.
        let written = connection.write(&response);
        if !matches!(
            scenario,
            Scenario::WrongTerminal | Scenario::WrongSubscription
        ) {
            written.unwrap();
        }
    });
    let mut client = LocalClient::connect(&profile.0).unwrap();
    let result = terminal_commands::result(
        client
            .request(LocalCall::Rpc(Box::new(terminal_commands::request(
                RpcCall::TerminalAttach(TerminalReadParams {
                    terminal: context(),
                }),
            ))))
            .unwrap(),
        None,
    )
    .unwrap();
    let RpcResult::TerminalAttach(meta) = result else {
        panic!("attach result")
    };
    assert_eq!(meta, metadata);
    let mut view = View::new(context());
    view.begin(meta).unwrap();
    for _ in 0..16 {
        view.apply(
            client
                .next_event(Duration::from_secs(2))
                .unwrap()
                .expect("sixteen frames"),
        )
        .unwrap();
    }
    assert!(!view.exited);
    assert_eq!(view.model.as_ref(), Some(&model));
    let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
    terminal.draw(|f| draw(f, &view, "Observer")).unwrap();
    view.changed = false;
    let ack = acknowledge_rendered(&mut client, &mut view, metadata.through_seq);
    match scenario {
        Scenario::Exit => {
            assert!(
                !ack.unwrap(),
                "obsolete ACK is not an acknowledged sequence"
            );
            assert!(view.exited);
            assert!(view.changed, "Exit callback must schedule final redraw");
            assert_eq!(view.model.as_ref().unwrap().normal, model.normal);
            assert_eq!(view.through.unwrap().0.0, model.sequence.0 + 1);
            terminal
                .draw(|f| draw(f, &view, "Observer: session exited"))
                .unwrap();
            assert_eq!(terminal.backend().buffer()[(0, 1)].symbol(), "d");
            assert!(
                terminal
                    .backend()
                    .buffer()
                    .content()
                    .iter()
                    .take(80)
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .contains("session exited")
            );
        }
        Scenario::NoExit => {
            assert_eq!(ack.unwrap_err().code, "RESYNC_REQUIRED");
            assert!(!view.exited);
        }
        Scenario::OtherError => {
            assert_eq!(ack.unwrap_err().code, "SERVICE_UNAVAILABLE");
            assert!(view.exited);
        }
        Scenario::WrongTerminal | Scenario::WrongSubscription => {
            let _failure = ack.expect_err("a wrongly bound Exit must fail closed");
            assert!(!view.exited);
            assert!(
                matches!(
                    client.request(LocalCall::Status {}),
                    Err(Error::InvalidFrame)
                ),
                "bad Exit must poison transport"
            );
        }
    }
    server.join().unwrap();
}
#[test]
fn ordered_exit_while_ack_waits_keeps_final_readonly_view() {
    exercise(Scenario::Exit);
}
#[test]
fn resync_without_exit_remains_an_error() {
    exercise(Scenario::NoExit);
}
#[test]
fn wrong_terminal_exit_poisons_transport() {
    exercise(Scenario::WrongTerminal);
}
#[test]
fn wrong_subscription_exit_poisons_transport() {
    exercise(Scenario::WrongSubscription);
}
#[test]
fn another_remote_error_after_exit_remains_an_error() {
    exercise(Scenario::OtherError);
}
