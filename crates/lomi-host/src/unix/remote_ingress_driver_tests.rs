//! Authored source-only integration fixture. Real TLS, WebSocket, native Noise,
//! private Store journals, actual HostAuth and the production ingress Driver.
use super::*;
use lomi_remote_crypto::{GrantV3, Handshake, Identity, SignedBundle};
use lomi_remote_protocol::message_framing::{MessageAssembler, MessageEncoder, MessageKind};
use lomi_remote_protocol::{Capability, CapabilitySet};
#[cfg(feature = "cloud-fixture")]
use std::io::{Read, Write};
use std::{
    net::{TcpListener, TcpStream},
    sync::{Arc, mpsc},
    thread,
    time::{SystemTime, UNIX_EPOCH},
};
use tungstenite::{
    Message,
    protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    },
};

type ServerSocket =
    tungstenite::WebSocket<rustls::StreamOwned<rustls::ServerConnection, TcpStream>>;
fn certificate() -> (Vec<u8>, Arc<rustls::ServerConfig>) {
    use rcgen::{
        BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
        KeyUsagePurpose,
    };
    let mut ca = CertificateParams::new(Vec::<String>::new()).unwrap();
    ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign];
    let key = KeyPair::generate().unwrap();
    let root = ca.self_signed(&key).unwrap();
    let issuer = Issuer::new(ca, key);
    let mut leaf = CertificateParams::new(vec!["127.0.0.1".into()]).unwrap();
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let key = KeyPair::generate().unwrap();
    let leaf = leaf.signed_by(&key, &issuer).unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![leaf.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .unwrap();
    (root.der().to_vec(), Arc::new(config))
}
fn binary(socket: &mut ServerSocket) -> Vec<u8> {
    loop {
        match socket.read().unwrap() {
            Message::Binary(bytes) => return bytes.to_vec(),
            Message::Ping(_) => socket.flush().unwrap(),
            Message::Pong(_) => (),
            _ => panic!("unexpected synthetic relay frame"),
        }
    }
}
fn input_with_consumer(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    consumer: &Identity,
) -> ChannelAdmissionInputs {
    input_with_consumer_for_channel(f, auth, consumer, [44; 16])
}
fn input_with_consumer_for_channel(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    consumer: &Identity,
    channel_id: [u8; 16],
) -> ChannelAdmissionInputs {
    input_with_consumer_for_channel_and_capabilities(f, auth, consumer, channel_id, None)
}
fn input_with_consumer_for_channel_and_capabilities(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    consumer: &Identity,
    channel_id: [u8; 16],
    capabilities: Option<CapabilitySet>,
) -> ChannelAdmissionInputs {
    let mut proposal = f.proposal(auth);
    let bytes: Vec<u8> = proposal
        .maximum_grant
        .expose_wire()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect();
    let mut maximum = GrantV3::from_canonical(&bytes).unwrap();
    maximum.consumer_fingerprint = consumer.public_bundle().bundle.fingerprint().unwrap();
    if let Some(capabilities) = capabilities {
        maximum.capabilities = capabilities;
    }
    proposal.maximum_grant = hex(&maximum.canonical().unwrap()).try_into().unwrap();
    proposal.identities.consumer = consumer.public_bundle().to_wire().unwrap();
    proposal.identities.consumer_fingerprint =
        hex(&maximum.consumer_fingerprint).try_into().unwrap();
    let api = PairApi {
        proposal,
        pending_calls: std::cell::Cell::new(0),
        decide_calls: std::cell::Cell::new(0),
        get_calls: std::cell::Cell::new(0),
    };
    let mut pairing = peer::Worker::default();
    for _ in 0..3 {
        assert!(
            pairing
                .step(auth, &f.config, f.runtime(), &f.eligibility, Some(&api))
                .is_ok()
        );
    }
    let source = f
        .store
        .lock()
        .unwrap()
        .acknowledged_workspace_grants()
        .unwrap()
        .remove(0);
    let PairingResult::Approved {
        grant,
        identities,
        authority,
        ..
    } = source.response
    else {
        panic!("approved grant")
    };
    let context = ChannelContextV3 {
        version: 3,
        grant: SignedGrantV3::from_wire(&grant).unwrap().grant,
        channel_id,
        initiator_role: Role::Device,
        responder_role: Role::Host,
        purpose: ChannelPurposeV3::Workspace,
        terminal: None,
        issued_at: f.now(),
        expires_at: f.now() + 30,
    };
    ChannelAdmissionInputs {
        expected_context: hex(&context.canonical().unwrap()).try_into().unwrap(),
        expected_context_json: serde_json::to_value(&context)
            .unwrap()
            .as_object()
            .unwrap()
            .clone(),
        grant,
        identities,
        authority,
    }
}
fn input_with_reissued_channel(
    mut input: ChannelAdmissionInputs,
    channel_id: lomi_remote_protocol::ChannelId,
) -> ChannelAdmissionInputs {
    let canonical = hex_bytes(input.expected_context.expose_wire())
        .unwrap_or_else(|_| panic!("admitted context"));
    let mut context = lomi_remote_crypto::ChannelContextV3::from_canonical(&canonical).unwrap();
    context.channel_id = channel_id.to_bytes();
    let canonical = context.canonical().unwrap();
    input.expected_context = hex(&canonical).try_into().unwrap();
    input.expected_context_json = serde_json::to_value(&context)
        .unwrap()
        .as_object()
        .unwrap()
        .clone();
    input
}
fn channel_api_for(
    channel_id: lomi_remote_protocol::ChannelId,
    inputs: ChannelAdmissionInputs,
) -> Api<'static> {
    Api {
        replies: RefCell::new(VecDeque::from([Reply::Poll(ChannelPendingResult {
            channels: vec![PendingChannel { channel_id, inputs }]
                .try_into()
                .unwrap(),
        })])),
        requests: RefCell::new(vec![]),
        params: RefCell::new(vec![]),
        hook: RefCell::new(None),
    }
}
fn admitted_channel_worker(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    inputs: ChannelAdmissionInputs,
    channel_id: lomi_remote_protocol::ChannelId,
) -> (Worker, ChannelAdmissionIntent) {
    let api = channel_api_for(channel_id, input_with_reissued_channel(inputs, channel_id));
    let (mut worker, intent) = prepared(f, auth, &api);
    api.replies
        .borrow_mut()
        .push_back(Reply::state(admitted(&intent)));
    assert!(step(f, auth, &mut worker, &api).is_ok());
    assert!(worker.has_retained_operation());
    (worker, intent)
}
fn add_registry_candidate(
    f: &mut Fixture,
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    registry: &mut super::super::super::remote_ingress::Registry<'_>,
    base_inputs: &ChannelAdmissionInputs,
    channel_id: lomi_remote_protocol::ChannelId,
) -> std::rc::Rc<std::cell::Cell<usize>> {
    f.eligibility.heartbeat.request_started = Instant::now();
    let (mut worker, _intent) = admitted_channel_worker(f, auth, base_inputs.clone(), channel_id);
    let calls = registry
        .script_ticket_for_channel_test(
            channel_id,
            Err(lomi_host_http::Error::Network),
            None,
            Duration::ZERO,
        )
        .expect("test ticket script for an admissible channel");
    registry.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
    assert!(
        !worker.has_retained_operation(),
        "registry consumes handoff once"
    );
    calls
}
#[expect(
    clippy::too_many_arguments,
    reason = "explicit joined synthetic relay synchronization and real native initiator ownership"
)]
fn server(
    listener: TcpListener,
    progress: mpsc::Sender<&'static str>,
    tls: Arc<rustls::ServerConfig>,
    mut initiator: Handshake,
    context: ChannelContextV3,
    fragment: mpsc::SyncSender<()>,
    release_fragment: mpsc::Receiver<()>,
    first_response: mpsc::SyncSender<()>,
    release_second: mpsc::Receiver<()>,
    done: mpsc::SyncSender<Vec<(u64, RpcResult)>>,
    revoked: bool,
    capabilities_on_second: bool,
) {
    listener.set_nonblocking(true).unwrap();
    let accept_deadline = Instant::now() + Duration::from_secs(5);
    let (tcp, _) = loop {
        match listener.accept() {
            Ok(connection) => break connection,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    Instant::now() < accept_deadline,
                    "fixture WSS client did not connect"
                );
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => panic!("fixture WSS accept failed: {error}"),
        }
    };
    let _ = progress.send("tcp-accepted");
    tcp.set_nonblocking(false).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
    let stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), tcp);
    let mut socket = tungstenite::accept(stream).unwrap();
    let _ = progress.send("websocket-upgraded");
    let Message::Text(admission) = socket.read().unwrap() else {
        panic!("ticket admission")
    };
    let admission: lomi_remote_protocol::admission::WssAdmissionFrame =
        serde_json::from_str(admission.as_str()).unwrap();
    assert_eq!(admission.channel_id.to_bytes(), context.channel_id);
    assert_eq!(admission.ticket.expose_wire(), "A".repeat(43).as_str());
    let _ = progress.send("admission-validated");
    socket
        .send(Message::Text(
            r#"{"type":"authenticated","expiresAt":2000000000000}"#.into(),
        ))
        .unwrap();
    socket
        .send(Message::Text(r#"{"type":"ready"}"#.into()))
        .unwrap();
    let first = initiator.write().unwrap();
    let middle = first.len() / 2;
    socket
        .send(Message::Frame(Frame::message(
            first[..middle].to_vec(),
            OpCode::Data(Data::Binary),
            false,
        )))
        .unwrap();
    fragment.send(()).unwrap();
    release_fragment
        .recv_timeout(Duration::from_secs(2))
        .unwrap();
    socket
        .send(Message::Frame(Frame::message(
            first[middle..].to_vec(),
            OpCode::Data(Data::Continue),
            true,
        )))
        .unwrap();
    initiator.read(&binary(&mut socket)).unwrap();
    socket
        .send(Message::Binary(initiator.write().unwrap().into()))
        .unwrap();
    let mut crypto = initiator.finish().unwrap();
    let workspace = WorkspaceContext {
        workspace_id: WorkspaceId::from_bytes(context.grant.workspace_id).unwrap(),
        workspace_epoch: WorkspaceEpoch::from_bytes(context.grant.workspace_epoch).unwrap(),
        runtime_id: RuntimeId::from_bytes(context.grant.runtime_id).unwrap(),
        runtime_generation: DecimalU64(context.grant.runtime_generation),
        host_access_epoch: DecimalU64(context.grant.access_epoch),
        grant_revision: DecimalU64(context.grant.grant_revision),
    };
    let start = Instant::now();
    let mut encoder = MessageEncoder::new();
    let mut decoder = MessageAssembler::new();
    let mut responses = Vec::new();
    for ordinal in 1..=2u8 {
        let call = if ordinal == 2 && capabilities_on_second {
            RpcCall::WorkspaceCapabilities(WorkspaceReadParams {
                context: workspace.clone(),
            })
        } else {
            RpcCall::WorkspaceGet(WorkspaceReadParams {
                context: workspace.clone(),
            })
        };
        let request = RpcRequest {
            v: lomi_remote_protocol::ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: RequestId::try_from(format!("request-{ordinal}")).unwrap(),
            timeout_ms: 2000u64.try_into().unwrap(),
            call,
        };
        encoder
            .begin(
                MessageKind::RpcRequest,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
        while let Some(frame) = encoder.next_frame().unwrap() {
            socket
                .send(Message::Binary(
                    crypto
                        .seal_binary(context.channel_id, &frame)
                        .unwrap()
                        .into(),
                ))
                .unwrap();
        }
        if revoked && ordinal == 2 {
            assert!(
                socket.read().is_err(),
                "revoked owner emitted an application response"
            );
            done.send(responses).unwrap();
            return;
        }
        loop {
            let plaintext = crypto
                .open_binary(context.channel_id, &binary(&mut socket))
                .unwrap();
            if let Some(message) = decoder
                .push(&plaintext, start.elapsed().as_millis() as u64)
                .unwrap()
            {
                assert_eq!(message.kind, MessageKind::RpcResponse);
                assert_eq!(
                    message.id,
                    u64::from(ordinal),
                    "connection encoder restarted response IDs"
                );
                let response: RpcResponse = serde_json::from_slice(&message.bytes).unwrap();
                let RpcResponse::Result {
                    request_id, result, ..
                } = response
                else {
                    panic!("workspace request result")
                };
                assert_eq!(request_id, request.request_id);
                match (&request.call, &result) {
                    (RpcCall::WorkspaceGet(_), RpcResult::WorkspaceGet(state)) => {
                        assert_eq!(state.context, workspace);
                    }
                    (RpcCall::WorkspaceCapabilities(_), RpcResult::WorkspaceCapabilities(_)) => {}
                    _ => panic!("request/result kind mismatch"),
                }
                responses.push((message.id, result));
                break;
            }
        }
        if ordinal == 1 {
            first_response.send(()).unwrap();
            release_second.recv_timeout(Duration::from_secs(2)).unwrap();
        }
    }
    done.send(responses).unwrap();
}
#[cfg(feature = "cloud-fixture")]
fn ticket_http_server(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    expected: Arc<std::sync::Mutex<Option<String>>>,
    observed: Arc<std::sync::atomic::AtomicBool>,
    stage: Arc<std::sync::atomic::AtomicU8>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let accept_deadline = Instant::now() + Duration::from_secs(5);
        let (tcp, _) = loop {
            match listener.accept() {
                Ok(connection) => break connection,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= accept_deadline {
                        return;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        };
        stage.store(1, std::sync::atomic::Ordering::Release);
        tcp.set_nonblocking(false).unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        tcp.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut stream = rustls::StreamOwned::new(rustls::ServerConnection::new(tls).unwrap(), tcp);
        let mut header = Vec::new();
        loop {
            let mut byte = [0u8; 1];
            if stream.read_exact(&mut byte).is_err() {
                return;
            }
            stage.store(2, std::sync::atomic::Ordering::Release);
            header.push(byte[0]);
            assert!(
                header.len() <= 16 * 1024,
                "ticket request header exceeded bound"
            );
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        stage.store(3, std::sync::atomic::Ordering::Release);
        let header_text = std::str::from_utf8(&header).unwrap();
        let mut lines = header_text.split("\r\n");
        let request_line = lines.next().unwrap();
        let mut request_parts = request_line.split_ascii_whitespace();
        assert_eq!(request_parts.next(), Some("POST"));
        let path = request_parts.next().unwrap();
        assert_eq!(request_parts.next(), Some("HTTP/1.1"));
        let mut content_length = None;
        let mut bearer_present = false;
        for line in lines {
            if let Some((name, value)) = line.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    content_length = Some(value.trim().parse::<usize>().unwrap());
                }
                if name.eq_ignore_ascii_case("authorization") {
                    bearer_present = value.trim().starts_with("Bearer ");
                }
            }
        }
        let body_length = content_length.expect("bounded content length");
        assert!(body_length <= 16 * 1024);
        let mut body = vec![0; body_length];
        stream.read_exact(&mut body).unwrap();
        stage.store(4, std::sync::atomic::Ordering::Release);
        let params: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected_path = expected
            .lock()
            .unwrap()
            .clone()
            .expect("expected channel set before ticket request");
        assert_eq!(path, expected_path);
        assert!(params.get("runtime").is_some());
        assert!(bearer_present, "actual ticket request omitted HostAccess");

        let channel_text = path
            .strip_prefix("/v2/remote/channels/")
            .and_then(|value| value.strip_suffix("/tickets"))
            .expect("canonical channel-ticket path");
        let channel_id: lomi_remote_protocol::ChannelId =
            channel_text.to_owned().try_into().unwrap();
        let result = lomi_remote_protocol::http::ChannelTicketResult {
            channel_id,
            ticket: "A".repeat(43).try_into().unwrap(),
            expires_in_ms: lomi_remote_protocol::DecimalU64(5000),
        };
        let response = serde_json::to_vec(&result).unwrap();
        write!(
            stream,
            "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncache-control: no-store\r\nconnection: close\r\ncontent-length: {}\r\n\r\n",
            response.len()
        )
        .unwrap();
        stream.write_all(&response).unwrap();
        stream.flush().unwrap();
        stage.store(5, std::sync::atomic::Ordering::Release);
        observed.store(true, std::sync::atomic::Ordering::Release);
    })
}
fn exercise(populated: bool, revoked: bool) {
    exercise_with_transport(populated, revoked, false);
}
fn exercise_with_transport(populated: bool, revoked: bool, actual_cloud_transport: bool) {
    exercise_with_options(
        populated,
        revoked,
        actual_cloud_transport,
        false,
        false,
        None,
    );
}
fn exercise_with_options(
    populated: bool,
    revoked: bool,
    actual_cloud_transport: bool,
    capabilities_on_second: bool,
    revoke_after_second_queued: bool,
    grant_capabilities: Option<CapabilitySet>,
) {
    peer::current_pairing_script::clear();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let endpoint: lomi_remote_protocol::ipc::LocalRelayEndpoint = format!(
        "wss://127.0.0.1:{}/v2/relay",
        listener.local_addr().unwrap().port()
    )
    .try_into()
    .unwrap();
    let (root, tls) = certificate();
    #[cfg(feature = "cloud-fixture")]
    let (api_origin, api_expected, api_observed, api_stage, api_thread) = if actual_cloud_transport
    {
        let api_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!(
            "https://127.0.0.1:{}",
            api_listener.local_addr().unwrap().port()
        );
        let expected = Arc::new(std::sync::Mutex::new(None));
        let observed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stage = Arc::new(std::sync::atomic::AtomicU8::new(0));
        let join = ticket_http_server(
            api_listener,
            tls.clone(),
            expected.clone(),
            observed.clone(),
            stage.clone(),
        );
        (
            Some(origin),
            Some(expected),
            Some(observed),
            Some(stage),
            Some(join),
        )
    } else {
        (None, None, None, None, None)
    };
    #[cfg(not(feature = "cloud-fixture"))]
    assert!(
        !actual_cloud_transport,
        "real fixture transport requires cloud-fixture"
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let run_fixture = |f: &mut Fixture<'_>, auth: &mut HostAuth<'_, dyn SecretStorage + '_>| {
        let terminal = populated.then(|| terminal(f));
        let host = auth.public_host_identity(f.now()).unwrap();
        let consumer =
            Identity::generate(host.account_id.to_bytes(), [22; 16], Role::Device, 1).unwrap();
        let input = input_with_consumer_for_channel_and_capabilities(
            f,
            auth,
            &consumer,
            [44; 16],
            grant_capabilities.clone(),
        );
        let api = Api::poll(input);
        let (mut worker, intent) = prepared(f, auth, &api);
        api.replies
            .borrow_mut()
            .push_back(Reply::state(admitted(&intent)));
        assert!(step(f, auth, &mut worker, &api).is_ok());
        let handoff = worker.take_admitted().unwrap();
        let admission =
            SignedChannelAdmissionV3::from_wire(&intent.preparation.params.admission).unwrap();
        let context = admission.context.clone();
        let signed = SignedGrantV3::from_wire(&intent.preparation.inputs.grant).unwrap();
        let host = SignedBundle::from_wire(&host.identity).unwrap();
        let peer_pin = context.grant.host_fingerprint;
        let validated = admission
            .verify(
                &signed,
                &context,
                &host,
                &peer_pin,
                &consumer.public_bundle(),
                &context.grant.consumer_fingerprint,
                &authority(&intent.preparation.inputs.authority),
                f.now(),
            )
            .unwrap();
        let initiator =
            Handshake::new_v3(true, &consumer, validated, &host, &peer_pin, f.now()).unwrap();
        let source = handoff.source().clone();
        for _ in 0..16 {
            peer::current_pairing_script::enqueue(
                source.intent.preparation.pairing_id,
                source.response.clone(),
            );
        }
        let (fragment_tx, fragment_rx) = mpsc::sync_channel(1);
        let (continue_tx, continue_rx) = mpsc::sync_channel(1);
        let (first_tx, first_rx) = mpsc::sync_channel(1);
        let (second_tx, second_rx) = mpsc::sync_channel(1);
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let (server_progress_tx, server_progress_rx) = mpsc::channel();
        let join = thread::spawn(move || {
            server(
                listener,
                server_progress_tx,
                tls,
                initiator,
                context,
                fragment_tx,
                continue_rx,
                first_tx,
                second_rx,
                done_tx,
                revoked,
                capabilities_on_second,
            )
        });
        let mut driver = super::super::super::remote_ingress::Driver::new(&f.stopping);
        #[cfg(feature = "cloud-fixture")]
        if actual_cloud_transport {
            let expected = api_expected
                .as_ref()
                .expect("real ticket API fixture")
                .clone();
            *expected.lock().unwrap() = Some(format!(
                "/v2/remote/channels/{}/tickets",
                String::from(intent.preparation.channel_id)
            ));
            driver
                .use_cloud_fixture_transport_for_test(root.clone(), root.clone())
                .unwrap();
        } else {
            driver.script_ticket_for_test(Ok(ticket_response(&intent)), None, Duration::ZERO);
            driver.script_relay_for_test(
                lomi_host_http::RelayTransport::with_test_root(endpoint.clone(), root.clone())
                    .unwrap(),
            );
        }
        #[cfg(not(feature = "cloud-fixture"))]
        {
            driver.script_ticket_for_test(Ok(ticket_response(&intent)), None, Duration::ZERO);
            driver.script_relay_for_test(
                lomi_host_http::RelayTransport::with_test_root(endpoint.clone(), root.clone())
                    .unwrap(),
            );
        }
        assert!(driver.accept(handoff, auth, f.runtime(), &f.eligibility));
        #[cfg(feature = "cloud-fixture")]
        if actual_cloud_transport {
            let configured_api_origin = api_origin.as_deref().expect("real ticket API origin");
            assert_eq!(
                f.eligibility.binding.scope.remote_api_origin, configured_api_origin,
                "Cloud fixture scope and trusted API origin must target the same fixture"
            );
        }
        driver.after_channel_step(&mut worker, auth, f.runtime(), &f.eligibility);
        #[cfg(feature = "cloud-fixture")]
        if actual_cloud_transport {
            assert_eq!(
                driver.channel_step_observation_for_test(),
                ("ticket-retained", None),
                "actual ticket POST did not produce a retained ticket; API response complete={}; HTTP fixture stage={}; transport_error={:?}",
                api_observed
                    .as_ref()
                    .expect("real ticket API observation")
                    .load(std::sync::atomic::Ordering::Acquire),
                api_stage
                    .as_ref()
                    .expect("real ticket API stage")
                    .load(std::sync::atomic::Ordering::Acquire),
                driver.cloud_fixture_ticket_error_for_test()
            );
        }
        driver.advance(auth, f.runtime(), Some(&f.eligibility)); // ticket stage settles
        driver.advance(auth, f.runtime(), Some(&f.eligibility)); // actual TLS/WSS admission
        let fragment_result = fragment_rx.recv_timeout(Duration::from_secs(2));
        assert!(
            fragment_result.is_ok(),
            "configured WSS did not deliver the initial Noise fragment; connected={}; connect_failure={:?}; server_progress={:?}",
            driver.connected_for_test(),
            driver.failure_observation_for_test(),
            server_progress_rx.try_iter().collect::<Vec<_>>()
        );
        let poll_started = Instant::now();
        driver.advance(auth, f.runtime(), Some(&f.eligibility));
        assert!(
            poll_started.elapsed() < Duration::from_millis(250),
            "fragmented poll blocked instead of yielding Pending"
        );
        assert!(
            driver.connected_for_test(),
            "partial Noise WebSocket closed on WouldBlock"
        );
        continue_tx.send(()).unwrap();
        let until = Instant::now() + Duration::from_secs(3);
        while first_rx.try_recv().is_err() {
            assert!(
                Instant::now() < until,
                "first encrypted response did not arrive"
            );
            driver.advance(auth, f.runtime(), Some(&f.eligibility));
            thread::yield_now();
        }
        // Actual worker-unit admission transition: Cloud settlement deliberately
        // loses cached eligibility. No socket IO may run during that gap.
        driver.advance(auth, f.runtime(), Some(&f.eligibility)); // settle completed response
        driver.settle_maintenance_for_test();
        assert!(!driver.has_retained_operation());
        assert!(!driver.poll(auth, f.runtime(), None));
        driver.advance(auth, f.runtime(), None);
        assert!(driver.connected_for_test());
        let outer = f.runtime();
        let mut units =
            super::super::super::WorkerOperationUnits::new(outer.operation, outer.aborted);
        units.admit_after_settlement(&f.stopping);
        let resumed = Runtime {
            operation: units.operation(),
            aborted: units.aborted(),
            ..outer
        };
        if revoked && !revoke_after_second_queued {
            let cancelled = AtomicBool::new(false);
            let operation = owner_domain::Operation::new(until, &cancelled);
            f.owner
                .begin_unshare(&operation, f.workspace)
                .unwrap()
                .try_commit()
                .unwrap();
        }
        second_tx.send(()).unwrap();
        if revoke_after_second_queued {
            loop {
                if driver.diagnostic_request_for_test() == (2, "workspace.capabilities")
                    && driver.diagnostic_response_pending_for_test()
                {
                    assert!(
                        driver.has_retained_operation(),
                        "a pending RPC response must retain its original worker operation"
                    );
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "second capabilities request was not processed"
                );
                driver.advance(auth, resumed, Some(&f.eligibility));
                thread::yield_now();
            }
            let cancelled = AtomicBool::new(false);
            let operation = owner_domain::Operation::new(until, &cancelled);
            f.owner
                .begin_unshare(&operation, f.workspace)
                .unwrap()
                .try_commit()
                .unwrap();
        }
        let responses = loop {
            if let Ok(responses) = done_rx.try_recv() {
                break responses;
            }
            assert!(
                Instant::now() < until,
                "second response/revocation did not settle"
            );
            driver.advance(auth, resumed, Some(&f.eligibility));
            thread::yield_now();
        };
        assert_eq!(responses.len(), if revoked { 1 } else { 2 });
        for (ordinal, result) in responses {
            if ordinal == 2 && capabilities_on_second {
                let RpcResult::WorkspaceCapabilities(capabilities) = result else {
                    panic!("workspace capabilities result")
                };
                assert_eq!(
                    Vec::<Capability>::from(capabilities.capabilities),
                    vec![
                        Capability::WorkspaceRead,
                        Capability::TerminalObserve,
                        Capability::TerminalManage,
                        Capability::FilesRead,
                        Capability::GitRead,
                    ],
                    "implemented Git reads must still be limited by the signed grant"
                );
                assert_eq!(capabilities.profiles.0.len(), 1);
                assert_eq!(capabilities.profiles.0[0].profile_id.as_str(), "default");
                assert_eq!(capabilities.profiles.0[0].name.as_str(), "Default shell");
                continue;
            }
            let RpcResult::WorkspaceGet(state) = result else {
                panic!("workspace get result")
            };
            assert_eq!(state.tabs.0.len(), usize::from(populated));
            if let Some(target) = &terminal {
                let TerminalLayout::Pane { pane } = &state.tabs.0[0].layout else {
                    panic!("pane projection")
                };
                let session = pane.session.as_ref().unwrap();
                assert_eq!(session.pane_id, target.pane_id);
                assert_eq!(session.session_id, target.session_id);
                assert_eq!(session.session_epoch, target.session_epoch);
                assert_eq!(session.workspace, state.context);
            }
        }
        if revoked {
            assert!(!driver.connected_for_test());
        }
        driver.discard();
        join.join().unwrap();
    };
    #[cfg(feature = "cloud-fixture")]
    if actual_cloud_transport {
        let cloud = peer::tests::CloudFixtureOptions {
            host_id: lomi_remote_protocol::HostId::from_bytes([42; 16]).unwrap(),
            runtime_id: lomi_remote_protocol::RuntimeId::from_bytes([43; 16]).unwrap(),
            generation: 18,
            epoch: 12,
            publication_seq: 1,
            access: "synthetic_current_access".to_owned().try_into().unwrap(),
            origin: api_origin.clone().expect("real ticket API origin"),
        };
        peer::tests::fixture_at_wall_with_cloud(now, Some(endpoint.clone()), cloud, run_fixture);
    } else {
        peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), run_fixture);
    }
    #[cfg(not(feature = "cloud-fixture"))]
    peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), run_fixture);
    #[cfg(feature = "cloud-fixture")]
    if actual_cloud_transport {
        api_thread.expect("real ticket API thread").join().unwrap();
        assert!(
            api_observed
                .expect("real ticket API observation")
                .load(std::sync::atomic::Ordering::Acquire),
            "Driver did not request its ticket from the pinned HTTPS fixture"
        );
    }
    peer::current_pairing_script::clear();
}

#[test]
fn registry_rejects_actual_duplicate_and_ninth_handoffs_before_driver_creation_or_ticket() {
    peer::current_pairing_script::clear();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    peer::tests::fixture_at_wall(now, |f, auth| {
        let host = auth.public_host_identity(f.now()).unwrap();
        let consumer =
            Identity::generate(host.account_id.to_bytes(), [22; 16], Role::Device, 1).unwrap();
        let base_inputs = input_with_consumer(f, auth, &consumer);
        let cancelled = f.stopping.clone();
        let mut registry = super::super::super::remote_ingress::Registry::with_coordinator(
            &cancelled,
            std::sync::Weak::new(),
        );
        let incumbent = lomi_remote_protocol::ChannelId::from_bytes([44; 16]).unwrap();
        let incumbent_calls =
            add_registry_candidate(f, auth, &mut registry, &base_inputs, incumbent);
        assert_eq!(registry.driver_factory_calls_for_test(), 1);
        assert_eq!(
            incumbent_calls.get(),
            0,
            "admission must not issue ticket HTTP"
        );

        // The protected Store will not mint a second same-ID handoff after
        // its first acknowledgement. Seed the occupied key in the registry
        // test seam, then submit a genuine same-ID handoff through the real
        // channel Worker and verify rejection precedes factory/ticket work.
        let duplicate_id = lomi_remote_protocol::ChannelId::from_bytes([45; 16]).unwrap();
        registry.reserve_test_key_for_duplicate(duplicate_id);
        let (mut duplicate, _) =
            admitted_channel_worker(f, auth, base_inputs.clone(), duplicate_id);
        registry.after_channel_step(&mut duplicate, auth, f.runtime(), &f.eligibility);
        assert!(!duplicate.has_retained_operation());
        assert_eq!(
            registry.registered_channels_for_test(),
            [incumbent, duplicate_id]
        );
        assert_eq!(registry.driver_factory_calls_for_test(), 1);
        assert_eq!(
            incumbent_calls.get(),
            0,
            "duplicate must not issue ticket HTTP"
        );
        assert!(
            registry.has_retained_operation(),
            "duplicate cannot replace incumbent"
        );

        let mut incumbent_calls_all = vec![(incumbent, incumbent_calls)];
        for byte in 60..66 {
            let channel_id = lomi_remote_protocol::ChannelId::from_bytes([byte; 16]).unwrap();
            let calls = add_registry_candidate(f, auth, &mut registry, &base_inputs, channel_id);
            assert_eq!(calls.get(), 0, "enqueue must not issue ticket HTTP");
            incumbent_calls_all.push((channel_id, calls));
        }
        assert_eq!(registry.registered_channels_for_test().len(), 8);
        let admitted_ids = registry.registered_channels_for_test();
        let factory_calls = registry.driver_factory_calls_for_test();
        let ninth_id = lomi_remote_protocol::ChannelId::from_bytes([90; 16]).unwrap();
        let (mut ninth, _) = admitted_channel_worker(f, auth, base_inputs, ninth_id);
        registry.after_channel_step(&mut ninth, auth, f.runtime(), &f.eligibility);
        assert!(!ninth.has_retained_operation());
        assert_eq!(registry.registered_channels_for_test(), admitted_ids);
        assert_eq!(registry.driver_factory_calls_for_test(), factory_calls);
        assert!(
            incumbent_calls_all
                .iter()
                .all(|(_, calls)| calls.get() == 0),
            "full registry must reject before any ticket request"
        );
        assert!(
            registry.has_retained_operation(),
            "ninth must not evict incumbents"
        );
        registry.discard();
    });
    peer::current_pairing_script::clear();
}

#[test]
fn real_tls_noise_empty_workspace_two_requests_survive_fragment_and_unit_rollover() {
    exercise(false, false);
}
#[test]
fn real_tls_noise_populated_workspace_projects_all_contexts() {
    exercise(true, false);
}
#[test]
fn real_tls_noise_unshare_rejects_next_response_after_unit_wait() {
    exercise(true, true);
}
#[test]
fn real_tls_noise_workspace_capabilities_are_grant_limited_and_list_only_supported_profile() {
    let capabilities = CapabilitySet::try_from(vec![
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalManage,
        Capability::FilesRead,
        Capability::GitRead,
    ])
    .unwrap();
    exercise_with_options(true, false, false, true, false, Some(capabilities));
}
#[test]
fn real_tls_noise_workspace_capabilities_recheck_revocation_before_queued_response() {
    let capabilities = CapabilitySet::try_from(vec![
        Capability::WorkspaceRead,
        Capability::TerminalObserve,
        Capability::TerminalManage,
        Capability::FilesRead,
        Capability::GitRead,
    ])
    .unwrap();
    exercise_with_options(true, true, false, true, true, Some(capabilities));
}
#[cfg(feature = "cloud-fixture")]
#[test]
fn cloud_fixture_transport_selection_is_bounded_and_exclusive() {
    let cancelled = std::sync::atomic::AtomicBool::new(false);
    let mut driver = super::super::super::remote_ingress::Driver::new(&cancelled);
    assert!(
        driver
            .use_cloud_fixture_transport_for_test(Vec::new(), vec![1])
            .is_err()
    );
    assert!(
        driver
            .use_cloud_fixture_transport_for_test(vec![1], vec![0; 16 * 1024 + 1])
            .is_err()
    );
    driver
        .use_cloud_fixture_transport_for_test(vec![1], vec![1])
        .unwrap();
    assert!(
        driver
            .use_cloud_fixture_transport_for_test(vec![1], vec![1])
            .is_err()
    );

    let mut scripted = super::super::super::remote_ingress::Driver::new(&cancelled);
    scripted.script_ticket_for_test(Err(lomi_host_http::Error::Network), None, Duration::ZERO);
    assert!(
        scripted
            .use_cloud_fixture_transport_for_test(vec![1], vec![1])
            .is_err()
    );
}
#[cfg(feature = "cloud-fixture")]
#[test]
fn cloud_fixture_transport_uses_pinned_https_ticket_and_configured_wss() {
    exercise_with_transport(true, false, true);
}

#[path = "remote_terminal_ingress_tests.rs"]
mod terminal_ingress_tests;
