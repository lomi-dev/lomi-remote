// Included below the existing joined synthetic TLS fixtures in the lib suite.
// Authored only: real network execution waits for Root's serialized admission.
use super::*;
use crate::{RelayConnection, RelayTransport};
use lomi_remote_protocol::{
    admission::WssAdmissionFrame, ipc::LocalRelayEndpoint, message_framing::MAX_TRANSPORT_FRAME_LEN,
};
use std::net::Shutdown;
use tungstenite::Message;

fn endpoint(port: u16) -> LocalRelayEndpoint {
    format!("wss://127.0.0.1:{port}/v2/relay")
        .try_into()
        .unwrap()
}
fn admission() -> WssAdmissionFrame {
    WssAdmissionFrame {
        channel_id: ChannelId::from_bytes([4; 16]).unwrap(),
        ticket: "A".repeat(43).try_into().unwrap(),
    }
}
fn transport(port: u16, root: &[u8]) -> RelayTransport {
    RelayTransport::with_test_root(endpoint(port), root.to_vec()).unwrap()
}
fn connect(transport: &RelayTransport) -> Result<RelayConnection> {
    let started = Instant::now();
    transport.connect(
        &admission(),
        started,
        5000,
        started + Duration::from_secs(2),
        &|| Ok(()),
    )
}
#[derive(Clone)]
enum RelayAction {
    Echo,
    PingEcho,
    StallReady,
    StallBinary,
    Malformed(String),
    EarlyReady,
    EarlyBinary,
    Binary(Vec<u8>),
    Text,
}
struct RelayServer {
    port: u16,
    stop: Arc<AtomicBool>,
    join: Option<JoinHandle<()>>,
    active: Arc<Mutex<Option<TcpStream>>>,
    connections: Arc<AtomicUsize>,
    admissions: Arc<Mutex<Vec<WssAdmissionFrame>>>,
    binaries: Arc<AtomicUsize>,
    pongs: Arc<AtomicUsize>,
}
impl RelayServer {
    fn new(cert: &Certificate, action: RelayAction) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(AtomicBool::new(false));
        let active = Arc::new(Mutex::new(None));
        let connections = Arc::new(AtomicUsize::new(0));
        let admissions = Arc::new(Mutex::new(Vec::new()));
        let binaries = Arc::new(AtomicUsize::new(0));
        let pongs = Arc::new(AtomicUsize::new(0));
        let (done, live, count, captured, frames, controls, tls) = (
            stop.clone(),
            active.clone(),
            connections.clone(),
            admissions.clone(),
            binaries.clone(),
            pongs.clone(),
            cert.config.clone(),
        );
        let join = std::thread::spawn(move || {
            let tcp = loop {
                if done.load(Ordering::Acquire) {
                    return;
                }
                match listener.accept() {
                    Ok((tcp, _)) => break tcp,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(2))
                    }
                    Err(_) => return,
                }
            };
            *live.lock().unwrap() = Some(tcp.try_clone().unwrap());
            count.fetch_add(1, Ordering::SeqCst);
            // Darwin inherits O_NONBLOCK from the accept-loop listener. This
            // joined fixture uses tungstenite's blocking accept/read API; socket
            // timeouts below bound it, and Drop can interrupt through live.
            tcp.set_nonblocking(false).unwrap();
            tcp.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
            tcp.set_write_timeout(Some(Duration::from_millis(200)))
                .unwrap();
            let connection = rustls::ServerConnection::new(tls).unwrap();
            let stream = rustls::StreamOwned::new(connection, tcp);
            let Ok(mut socket) = tungstenite::accept(stream) else {
                return;
            };
            let Ok(Message::Text(first)) = socket.read() else {
                return;
            };
            let Ok(frame) = serde_json::from_str::<WssAdmissionFrame>(first.as_str()) else {
                return;
            };
            captured.lock().unwrap().push(frame);
            if matches!(action, RelayAction::EarlyReady) {
                let _ = socket.send(Message::Text(r#"{"type":"ready"}"#.into()));
                wait_stop(&done);
                return;
            }
            if matches!(action, RelayAction::EarlyBinary) {
                let _ = socket.send(Message::Binary(vec![1].into()));
                wait_stop(&done);
                return;
            }
            if matches!(action, RelayAction::PingEcho) {
                if socket.send(Message::Ping(vec![7].into())).is_err() {
                    return;
                }
                match socket.read() {
                    Ok(Message::Pong(bytes)) if bytes.as_ref() == [7] => {
                        controls.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => return,
                }
            }
            if socket
                .send(Message::Text(
                    r#"{"type":"authenticated","expiresAt":2000000000000}"#.into(),
                ))
                .is_err()
            {
                return;
            }
            if matches!(action, RelayAction::StallReady) {
                wait_stop(&done);
                return;
            }
            let ready = match &action {
                RelayAction::Malformed(text) => text.as_str(),
                _ => r#"{"type":"ready"}"#,
            };
            if socket.send(Message::Text(ready.into())).is_err() {
                return;
            }
            match &action {
                RelayAction::StallBinary | RelayAction::Malformed(_) => {
                    wait_stop(&done);
                    return;
                }
                RelayAction::Binary(bytes) => {
                    let _ = socket.send(Message::Binary(bytes.clone().into()));
                    wait_stop(&done);
                    return;
                }
                RelayAction::Text => {
                    let _ = socket.send(Message::Text("unexpected application text".into()));
                    wait_stop(&done);
                    return;
                }
                RelayAction::PingEcho if socket.send(Message::Ping(vec![8].into())).is_err() => {
                    return;
                }
                _ => {}
            }
            while !done.load(Ordering::Acquire) {
                match socket.read() {
                    Ok(Message::Binary(bytes)) => {
                        frames.fetch_add(1, Ordering::SeqCst);
                        if socket.send(Message::Binary(bytes)).is_err() {
                            return;
                        }
                    }
                    Ok(Message::Pong(_)) => {
                        controls.fetch_add(1, Ordering::SeqCst);
                    }
                    _ => return,
                }
            }
        });
        Self {
            port,
            stop,
            join: Some(join),
            active,
            connections,
            admissions,
            binaries,
            pongs,
        }
    }
}
impl Drop for RelayServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(socket) = self.active.lock().unwrap().as_ref() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        if let Some(join) = self.join.take()
            && let Err(panic) = join.join()
            && !std::thread::panicking()
        {
            std::panic::resume_unwind(panic);
        }
    }
}

#[test]
fn relay_verified_tls_admission_ready_and_max_binary_roundtrip() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::Echo);
    let transport = transport(server.port, &cert.root);
    assert_eq!(format!("{transport:?}"), "RelayTransport");
    let mut connection = connect(&transport).unwrap();
    assert_eq!(format!("{connection:?}"), "RelayConnection");
    assert_eq!(*server.admissions.lock().unwrap(), [admission()]);
    let bytes = vec![23; MAX_TRANSPORT_FRAME_LEN];
    connection
        .send_binary(&bytes, Instant::now() + Duration::from_secs(1), &|| Ok(()))
        .unwrap();
    assert_eq!(
        connection
            .read_binary(Instant::now() + Duration::from_secs(1), &|| Ok(()))
            .unwrap(),
        bytes
    );
    assert_eq!(server.binaries.load(Ordering::SeqCst), 1);
    connection.close();
    assert!(connection.is_closed());
    assert_eq!(
        connection.send_binary(&[1], Instant::now() + Duration::from_secs(1), &|| Ok(())),
        Err(Error::RelayClosed)
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
#[test]
fn relay_ping_pong_before_ready_and_between_binary_frames() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::PingEcho);
    let mut connection = connect(&transport(server.port, &cert.root)).unwrap();
    connection
        .send_binary(&[1, 2, 3], Instant::now() + Duration::from_secs(1), &|| {
            Ok(())
        })
        .unwrap();
    assert_eq!(
        connection
            .read_binary(Instant::now() + Duration::from_secs(1), &|| Ok(()))
            .unwrap(),
        [1, 2, 3]
    );
    assert!(server.pongs.load(Ordering::SeqCst) >= 1);
    assert_eq!(server.binaries.load(Ordering::SeqCst), 1);
}
#[test]
fn relay_certificate_chain_hostname_and_expiry_fail_before_admission() {
    let _network = network_guard();
    for fault in 0..3 {
        let cert = certificate(
            if fault == 1 {
                "wrong.example"
            } else {
                "127.0.0.1"
            },
            fault == 2,
        );
        let server = RelayServer::new(&cert, RelayAction::Echo);
        let transport = if fault == 0 {
            RelayTransport::new(endpoint(server.port)).unwrap()
        } else {
            transport(server.port, &cert.root)
        };
        assert!(connect(&transport).is_err());
        assert!(server.admissions.lock().unwrap().is_empty());
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn relay_redirect_is_refused_without_following_or_ticket_frame() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = Server::new(&cert, Action::Reply(b"HTTP/1.1 302 Found\r\nLocation: wss://other.example/v2/relay\r\nContent-Length: 0\r\n\r\n".to_vec()));
    let result = connect(&transport(server.port, &cert.root));
    assert!(matches!(result, Err(Error::Redirect)));
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    let requests = server.captured();
    assert_eq!(requests.len(), 1);
    assert!(
        !requests[0]
            .windows(43)
            .any(|window| window == "A".repeat(43).as_bytes())
    );
}
#[test]
fn relay_malformed_duplicate_and_out_of_order_statuses_fail_closed() {
    let _network = network_guard();
    for action in [
        RelayAction::Malformed("not json".into()),
        RelayAction::Malformed(r#"{"type":"ready","extra":true}"#.into()),
        RelayAction::Malformed(r#"{"type":"ready","type":"ready"}"#.into()),
        RelayAction::Malformed(r#"{"type":"authenticated","expiresAt":2000000000000}"#.into()),
        RelayAction::EarlyReady,
        RelayAction::EarlyBinary,
    ] {
        let cert = certificate("127.0.0.1", false);
        let server = RelayServer::new(&cert, action);
        assert!(matches!(
            connect(&transport(server.port, &cert.root)),
            Err(Error::InvalidResponse)
        ));
        assert_eq!(server.admissions.lock().unwrap().len(), 1);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn relay_inbound_text_and_oversize_binary_close_socket() {
    let _network = network_guard();
    for (action, expected) in [
        (RelayAction::Text, Error::InvalidResponse),
        (
            RelayAction::Binary(vec![1; MAX_TRANSPORT_FRAME_LEN + 1]),
            Error::ResponseTooLarge,
        ),
    ] {
        let cert = certificate("127.0.0.1", false);
        let server = RelayServer::new(&cert, action);
        let mut connection = connect(&transport(server.port, &cert.root)).unwrap();
        assert_eq!(
            connection.read_binary(Instant::now() + Duration::from_secs(1), &|| Ok(())),
            Err(expected)
        );
        assert!(connection.is_closed());
        assert_eq!(
            connection.read_binary(Instant::now() + Duration::from_secs(1), &|| Ok(())),
            Err(Error::RelayClosed)
        );
    }
}
#[test]
fn relay_outbound_oversize_is_rejected_without_application_send() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::Echo);
    let mut connection = connect(&transport(server.port, &cert.root)).unwrap();
    assert_eq!(
        connection.send_binary(
            &vec![0; MAX_TRANSPORT_FRAME_LEN + 1],
            Instant::now() + Duration::from_secs(1),
            &|| Ok(())
        ),
        Err(Error::Request)
    );
    assert!(connection.is_closed());
    assert_eq!(server.binaries.load(Ordering::SeqCst), 0);
}
#[test]
fn relay_ticket_deadline_uses_request_start_and_pre_cancel_creates_no_socket() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::Echo);
    let transport = transport(server.port, &cert.root);
    let now = Instant::now();
    let stale = now.checked_sub(Duration::from_millis(250)).unwrap();
    assert!(matches!(
        transport.connect(
            &admission(),
            stale,
            100,
            now + Duration::from_secs(1),
            &|| Ok(())
        ),
        Err(Error::Timeout)
    ));
    assert!(matches!(
        transport.connect(
            &admission(),
            now,
            5000,
            now + Duration::from_secs(1),
            &|| Err(BudgetStop::Cancelled)
        ),
        Err(Error::Cancelled)
    ));
    assert!(matches!(
        transport.connect(
            &admission(),
            now,
            5001,
            now + Duration::from_secs(1),
            &|| Ok(())
        ),
        Err(Error::Request)
    ));
    assert_eq!(server.connections.load(Ordering::SeqCst), 0);
}
#[test]
fn relay_tls_upgrade_and_ready_stalls_share_original_budget_and_cancel() {
    let _network = network_guard();
    for action in [Action::StallTls, Action::StallHeaders] {
        for cancelled in [false, true] {
            let cert = certificate("127.0.0.1", false);
            let server = Server::new(&cert, action.clone());
            let transport = transport(server.port, &cert.root);
            let stop = AtomicBool::new(false);
            let started = Instant::now();
            let result = std::thread::scope(|scope| {
                if cancelled {
                    scope.spawn(|| {
                        std::thread::sleep(Duration::from_millis(50));
                        stop.store(true, Ordering::SeqCst);
                    });
                }
                transport.connect(
                    &admission(),
                    started,
                    5000,
                    started + Duration::from_millis(180),
                    &|| {
                        if stop.load(Ordering::SeqCst) {
                            Err(BudgetStop::Cancelled)
                        } else {
                            Ok(())
                        }
                    },
                )
            });
            assert!(
                matches!(result, Err(error) if error == if cancelled { Error::Cancelled } else { Error::Timeout })
            );
            assert!(started.elapsed() < Duration::from_secs(1));
            assert_eq!(server.connections.load(Ordering::SeqCst), 1);
        }
    }
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::StallReady);
    let started = Instant::now();
    assert!(matches!(
        transport(server.port, &cert.root).connect(
            &admission(),
            started,
            180,
            started + Duration::from_secs(2),
            &|| Ok(())
        ),
        Err(Error::Timeout)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(server.admissions.lock().unwrap().len(), 1);
}
#[test]
fn relay_binary_read_deadline_and_cancel_close_without_replaying_admission() {
    let _network = network_guard();
    for cancelled in [false, true] {
        let cert = certificate("127.0.0.1", false);
        let server = RelayServer::new(&cert, RelayAction::StallBinary);
        let mut connection = connect(&transport(server.port, &cert.root)).unwrap();
        let started = Instant::now();
        let check = || {
            if cancelled {
                Err(BudgetStop::Cancelled)
            } else {
                Ok(())
            }
        };
        assert_eq!(
            connection.read_binary(started + Duration::from_millis(100), &check),
            Err(if cancelled {
                Error::Cancelled
            } else {
                Error::Timeout
            })
        );
        assert!(connection.is_closed());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(server.admissions.lock().unwrap().len(), 1);
        assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    }
}
#[test]
fn relay_later_binary_operation_keeps_no_expired_admission_budget() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::Echo);
    let started = Instant::now();
    let mut connection = transport(server.port, &cert.root)
        .connect(
            &admission(),
            started,
            200,
            started + Duration::from_millis(200),
            &|| Ok(()),
        )
        .unwrap();
    std::thread::sleep(Duration::from_millis(250));
    connection
        .send_binary(&[9], Instant::now() + Duration::from_secs(1), &|| Ok(()))
        .unwrap();
    assert_eq!(
        connection
            .read_binary(Instant::now() + Duration::from_secs(1), &|| Ok(()))
            .unwrap(),
        [9]
    );
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
}
#[test]
fn relay_partial_ciphertext_write_error_closes_without_resend_or_reconnect() {
    let _network = network_guard();
    let cert = certificate("127.0.0.1", false);
    let server = RelayServer::new(&cert, RelayAction::Echo);
    let mut connection = connect(&transport(server.port, &cert.root)).unwrap();
    let written = Arc::new(AtomicUsize::new(0));
    connection.fail_write_after_prefix(17, written.clone());
    assert_eq!(
        connection.send_binary(&[5; 1024], Instant::now() + Duration::from_secs(1), &|| Ok(
            ()
        )),
        Err(Error::Network)
    );
    assert_eq!(written.load(Ordering::SeqCst), 17);
    assert!(connection.is_closed());
    assert_eq!(
        connection.send_binary(&[5; 1024], Instant::now() + Duration::from_secs(1), &|| Ok(
            ()
        )),
        Err(Error::RelayClosed)
    );
    assert_eq!(written.load(Ordering::SeqCst), 17);
    assert_eq!(server.admissions.lock().unwrap().len(), 1);
    assert_eq!(server.connections.load(Ordering::SeqCst), 1);
    assert_eq!(server.binaries.load(Ordering::SeqCst), 0);
}
#[test]
fn relay_dependency_logs_are_statically_disabled_and_closed_errors_are_redacted() {
    assert_eq!(log::STATIC_MAX_LEVEL, log::LevelFilter::Off);
    assert_eq!(Error::RelayClosed.to_string(), "HOST_RELAY_CLOSED");
    assert_eq!(format!("{:?}", Error::RelayClosed), "RelayClosed");
    assert_eq!(format!("{:?}", Error::InvalidResponse), "InvalidResponse");
}
