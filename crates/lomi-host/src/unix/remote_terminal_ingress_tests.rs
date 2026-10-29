//! SOURCE-ONLY authored real host-local PTY lifecycle + TLS/Noise ingress test.
//! One authentic owner and one normal TerminalService survive both connections.
use super::*;
use crate::unix::{Coordinator, auth::remote_ingress::Driver, rpc};
use lomi_remote_protocol::streams::{TerminalSnapshotMetadata, TerminalStreamFrame};
use std::collections::VecDeque;

struct ServiceCleanup(Arc<Coordinator>);
impl Drop for ServiceCleanup {
    fn drop(&mut self) {
        let result = self.0.terminals.shutdown();
        if !thread::panicking() {
            result.expect("synthetic PTY cleanup");
        }
    }
}
/// What the host did with one request on a connection that may be revoked.
enum Delivery {
    Result(Box<RpcResult>),
    Rejected(ErrorCode),
    Closed,
}
/// The authority change that races a live terminal connection (REQ-13).
#[derive(Clone, Copy, PartialEq, Debug)]
enum Revocation {
    Unshare,
    Logout,
}
/// Where in the terminal conversation the revocation lands.
#[derive(Clone, Copy, PartialEq, Debug)]
enum RevokeAt {
    /// After the first snapshot chunk, before the snapshot completes.
    Snapshot,
    /// After the lease was claimed, before the first `terminal.input`.
    Input,
    /// While a `files.watch` subscription is established: a change made after
    /// the revocation must never produce an invalidation frame.
    Watch,
}
/// Client-side hooks into the host thread that performs the revocation.
struct RevokeHandshake {
    at: RevokeAt,
    /// Tells the host thread the client reached the revocation point.
    reached: mpsc::SyncSender<()>,
    /// The host thread reports the revocation has committed.
    committed: mpsc::Receiver<()>,
}
struct NativeClient {
    socket: ServerSocket,
    crypto: lomi_remote_crypto::Channel,
    channel: [u8; 16],
    encoder: MessageEncoder,
    decoder: MessageAssembler,
    streams: VecDeque<TerminalStreamFrame>,
    request: u8,
    started: Instant,
}
impl NativeClient {
    fn message(&mut self) -> lomi_remote_protocol::message_framing::CompletedMessage {
        loop {
            let ciphertext = binary(&mut self.socket);
            let plain = self.crypto.open_binary(self.channel, &ciphertext).unwrap();
            if let Some(message) = self
                .decoder
                .push(&plain, self.started.elapsed().as_millis() as u64)
                .unwrap()
            {
                return message;
            }
        }
    }
    /// Like `message`, but a closed or failed socket is `None` instead of a panic.
    fn try_message(&mut self) -> Option<lomi_remote_protocol::message_framing::CompletedMessage> {
        loop {
            let ciphertext = loop {
                match self.socket.read() {
                    Ok(Message::Binary(bytes)) => break bytes.to_vec(),
                    Ok(Message::Ping(_)) => {
                        let _ = self.socket.flush();
                    }
                    Ok(Message::Pong(_)) => (),
                    _ => return None,
                }
            };
            let plain = self.crypto.open_binary(self.channel, &ciphertext).ok()?;
            if let Some(message) = self
                .decoder
                .push(&plain, self.started.elapsed().as_millis() as u64)
                .ok()?
            {
                return Some(message);
            }
        }
    }
    /// Sends one request and reports what the host did with it, tolerating a
    /// host that revokes the connection instead of answering.
    fn try_call(&mut self, call: RpcCall) -> Delivery {
        self.request += 1;
        let request = RpcRequest {
            v: lomi_remote_protocol::ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: format!("terminal_request_{}", self.request)
                .try_into()
                .unwrap(),
            timeout_ms: 4000u64.try_into().unwrap(),
            call,
        };
        self.encoder
            .begin(
                MessageKind::RpcRequest,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
        while let Some(frame) = self.encoder.next_frame().unwrap() {
            let sealed = self.crypto.seal_binary(self.channel, &frame).unwrap();
            if self.socket.send(Message::Binary(sealed.into())).is_err() {
                return Delivery::Closed;
            }
        }
        loop {
            let Some(message) = self.try_message() else {
                return Delivery::Closed;
            };
            match message.kind {
                MessageKind::TerminalFrame => {
                    if let Ok(frame) = lomi_remote_protocol::decode_terminal_frame(&message.bytes) {
                        self.streams.push_back(frame);
                    }
                }
                MessageKind::RpcResponse => {
                    return match lomi_remote_protocol::decode_response_for(&message.bytes, &request)
                    {
                        Ok(RpcResponse::Result { result, .. }) => {
                            Delivery::Result(Box::new(result))
                        }
                        Ok(RpcResponse::Error { error, .. }) => Delivery::Rejected(error.code()),
                        Err(_) => Delivery::Closed,
                    };
                }
                _ => return Delivery::Closed,
            }
        }
    }
    fn call(&mut self, call: RpcCall) -> RpcResult {
        self.request += 1;
        let request = RpcRequest {
            v: lomi_remote_protocol::ApplicationMajor,
            r#type: RequestKind::Request,
            request_id: format!("terminal_request_{}", self.request)
                .try_into()
                .unwrap(),
            timeout_ms: 4000u64.try_into().unwrap(),
            call,
        };
        self.encoder
            .begin(
                MessageKind::RpcRequest,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
        while let Some(frame) = self.encoder.next_frame().unwrap() {
            self.socket
                .send(Message::Binary(
                    self.crypto
                        .seal_binary(self.channel, &frame)
                        .unwrap()
                        .into(),
                ))
                .unwrap();
        }
        loop {
            let message = self.message();
            match message.kind {
                MessageKind::TerminalFrame => self.streams.push_back(
                    lomi_remote_protocol::decode_terminal_frame(&message.bytes).unwrap(),
                ),
                MessageKind::RpcResponse => {
                    let response =
                        lomi_remote_protocol::decode_response_for(&message.bytes, &request)
                            .unwrap();
                    let RpcResponse::Result { result, .. } = response else {
                        panic!("terminal RPC rejected: {response:?}")
                    };
                    return result;
                }
                _ => panic!("unexpected terminal fixture message"),
            }
        }
    }
    fn stream(&mut self) -> TerminalStreamFrame {
        if let Some(frame) = self.streams.pop_front() {
            return frame;
        }
        let message = self.message();
        assert_eq!(message.kind, MessageKind::TerminalFrame);
        lomi_remote_protocol::decode_terminal_frame(&message.bytes).unwrap()
    }
    fn snapshot(&mut self, metadata: &TerminalSnapshotMetadata) {
        let mut bytes = Vec::new();
        loop {
            match self.stream() {
                TerminalStreamFrame::SnapshotChunk(chunk)
                    if chunk.subscription_id == metadata.subscription_id =>
                {
                    assert_eq!(chunk.terminal, metadata.terminal);
                    bytes.extend_from_slice(&chunk.bytes.0);
                }
                TerminalStreamFrame::SnapshotComplete(end)
                    if end.subscription_id == metadata.subscription_id =>
                {
                    assert_eq!(end.through_seq, metadata.through_seq);
                    assert_eq!(end.terminal, metadata.terminal);
                    assert_eq!(bytes.len() as u64, metadata.total_bytes.0);
                    assert!(serde_json::from_slice::<serde_json::Value>(&bytes).is_ok());
                    return;
                }
                _ => (),
            }
        }
    }
}
// Reuse the existing actual TLS/WebSocket/native Noise handshake for the
// terminal lifecycle and fixed rename fixtures; no synthetic transport adapter.
fn accept_native_client(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    mut initiator: Handshake,
    channel: [u8; 16],
) -> NativeClient {
    let (tcp, _) = listener.accept().unwrap();
    tcp.set_nonblocking(false).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    tcp.set_write_timeout(Some(Duration::from_secs(5))).unwrap();
    let mut socket = tungstenite::accept(rustls::StreamOwned::new(
        rustls::ServerConnection::new(tls).unwrap(),
        tcp,
    ))
    .unwrap();
    let Message::Text(admission) = socket.read().unwrap() else {
        panic!("ticket")
    };
    let admission: lomi_remote_protocol::admission::WssAdmissionFrame =
        serde_json::from_str(admission.as_str()).unwrap();
    assert_eq!(admission.channel_id.to_bytes(), channel);
    socket
        .send(Message::Text(
            r#"{"type":"authenticated","expiresAt":2000000000000}"#.into(),
        ))
        .unwrap();
    socket
        .send(Message::Text(r#"{"type":"ready"}"#.into()))
        .unwrap();
    socket
        .send(Message::Binary(initiator.write().unwrap().into()))
        .unwrap();
    initiator.read(&binary(&mut socket)).unwrap();
    socket
        .send(Message::Binary(initiator.write().unwrap().into()))
        .unwrap();
    NativeClient {
        socket,
        crypto: initiator.finish().unwrap(),
        channel,
        encoder: MessageEncoder::new(),
        decoder: MessageAssembler::new(),
        streams: VecDeque::new(),
        request: 0,
        started: Instant::now(),
    }
}
#[allow(clippy::too_many_arguments)]
fn terminal_client(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    initiator: Handshake,
    channel: [u8; 16],
    terminal: TerminalContext,
    reconnect: bool,
    done: mpsc::SyncSender<()>,
    revoke: Option<RevokeHandshake>,
    root_path: std::path::PathBuf,
) {
    let mut client = accept_native_client(listener, tls, initiator, channel);
    let RpcResult::TerminalAttach(attached) =
        client.call(RpcCall::TerminalAttach(TerminalReadParams {
            terminal: terminal.clone(),
        }))
    else {
        panic!("attach")
    };
    if let Some(revoke) = revoke
        .as_ref()
        .filter(|revoke| revoke.at == RevokeAt::Watch)
    {
        use lomi_remote_protocol::rpc::{FilesListParams, FilesWatchParams, PageLimit};
        let watched = root_path.join("watched");
        std::fs::create_dir(&watched).unwrap();
        let root = EntryId::from_bytes(terminal.workspace.workspace_id.to_bytes()).unwrap();
        let RpcResult::FilesList(listing) = client.call(RpcCall::FilesList(FilesListParams {
            context: terminal.workspace.clone(),
            parent_entry_id: root,
            cursor: None,
            limit: PageLimit::try_from(200).unwrap(),
        })) else {
            panic!("files.list")
        };
        let directory = listing
            .entries
            .0
            .iter()
            .find(|entry| entry.display_name.as_str() == "watched")
            .expect("the watched directory")
            .entry_id;
        let RpcResult::FilesWatch(_) = client.call(RpcCall::FilesWatch(FilesWatchParams {
            context: terminal.workspace.clone(),
            entry_id: directory,
            cursor: None,
        })) else {
            panic!("files.watch")
        };
        revoke.reached.send(()).unwrap();
        revoke
            .committed
            .recv_timeout(Duration::from_secs(10))
            .expect("host committed the revocation");
        // A change after the revocation: the host polls once a second, so wait
        // past two polls for the connection to end without any watch frame.
        std::fs::write(watched.join("after-revoke"), b"x").unwrap();
        while let Some(message) = client.try_message() {
            assert_ne!(
                message.kind,
                MessageKind::FileWatchFrame,
                "an invalidation was delivered after the workspace was revoked"
            );
        }
        drop(client);
        done.send(()).unwrap();
        return;
    }
    if let Some(revoke) = revoke
        .as_ref()
        .filter(|revoke| revoke.at == RevokeAt::Snapshot)
    {
        // Take exactly one chunk, then let the host revoke mid-snapshot.
        loop {
            if matches!(client.stream(), TerminalStreamFrame::SnapshotChunk(chunk)
                if chunk.subscription_id == attached.subscription_id)
            {
                break;
            }
        }
        revoke.reached.send(()).unwrap();
        revoke
            .committed
            .recv_timeout(Duration::from_secs(10))
            .expect("host committed the revocation");
        // Whatever was already in flight may arrive, but the snapshot must
        // never be completed for a revoked connection.
        while let Some(message) = client.try_message() {
            if message.kind == MessageKind::TerminalFrame
                && let Ok(TerminalStreamFrame::SnapshotComplete(_)) =
                    lomi_remote_protocol::decode_terminal_frame(&message.bytes)
            {
                panic!("snapshot completed after the workspace was revoked");
            }
        }
        drop(client);
        done.send(()).unwrap();
        return;
    }
    client.snapshot(&attached);
    let RpcResult::TerminalSnapshot(snapshot) =
        client.call(RpcCall::TerminalSnapshot(TerminalReadParams {
            terminal: terminal.clone(),
        }))
    else {
        panic!("snapshot")
    };
    client.snapshot(&snapshot);
    assert!(matches!(
        client.call(RpcCall::TerminalAck(TerminalAckParams {
            terminal: terminal.clone(),
            subscription_id: snapshot.subscription_id.clone(),
            through_seq: snapshot.through_seq
        })),
        RpcResult::TerminalAck(_)
    ));
    if !reconnect {
        let RpcResult::TerminalClaim(claim) =
            client.call(RpcCall::TerminalClaim(TerminalClaimParams {
                terminal: terminal.clone(),
                subscription_id: snapshot.subscription_id,
                rendered_through_seq: snapshot.through_seq,
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
        let command = crate::testsupport::marker_command("REMOTE_TERMINAL_ONCE");
        let command = command.as_slice();
        if let Some(revoke) = revoke
            .as_ref()
            .filter(|revoke| revoke.at == RevokeAt::Input)
        {
            revoke.reached.send(()).unwrap();
            revoke
                .committed
                .recv_timeout(Duration::from_secs(10))
                .expect("host committed the revocation");
            match client.try_call(RpcCall::TerminalInput(TerminalInputParams {
                terminal: terminal.clone(),
                lease: lease.lease.clone(),
                input_id: lease.next_input_id,
                input_seq: lease.next_input_seq,
                bytes: BoundedList(command.to_vec()),
            })) {
                Delivery::Result(result) => {
                    panic!("terminal.input was accepted after revocation: {result:?}")
                }
                Delivery::Rejected(_) | Delivery::Closed => (),
            }
            drop(client);
            done.send(()).unwrap();
            return;
        }
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
        assert!(matches!(
            client.call(RpcCall::TerminalResize(TerminalResizeParams {
                terminal: terminal.clone(),
                lease: lease.lease.clone(),
                resize_seq: lease.next_resize_seq,
                columns: TerminalDimension(97),
                rows: TerminalDimension(31)
            })),
            RpcResult::TerminalResize(_)
        ));
        loop {
            if matches!(client.stream(), TerminalStreamFrame::DeltaComplete(delta) if delta.through_seq.0.0 > snapshot.through_seq.0.0)
            {
                break;
            }
        }
        assert!(matches!(
            client.call(RpcCall::TerminalRelease(TerminalLeaseParams {
                terminal,
                lease: lease.lease
            })),
            RpcResult::TerminalRelease(_)
        ));
    }
    // Drop the authenticated socket; never replay terminal.input on reconnect.
    drop(client);
    done.send(()).unwrap();
}

fn running_target(state: &WorkspaceState) -> TerminalContext {
    let TerminalLayout::Pane { pane } = &state.tabs.0[0].layout else {
        panic!("local pane")
    };
    pane.session
        .clone()
        .expect("local host-created running PTY")
}
#[test]
fn real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay() {
    exercise_terminal(None);
}
#[test]
fn real_tls_noise_terminal_purpose_attach_uses_fresh_pairing_membership_projection() {
    exercise_terminal_with_purpose(None, true);
}
#[test]
fn real_tls_noise_terminal_purpose_unshare_before_input_never_reaches_the_pty() {
    exercise_terminal_with_purpose(Some((Revocation::Unshare, RevokeAt::Input)), true);
}
#[test]
fn real_tls_noise_terminal_purpose_logout_before_input_never_reaches_the_pty() {
    exercise_terminal_with_purpose(Some((Revocation::Logout, RevokeAt::Input)), true);
}
#[test]
fn real_tls_noise_terminal_purpose_unshare_during_snapshot_never_completes_the_snapshot() {
    exercise_terminal_with_purpose(Some((Revocation::Unshare, RevokeAt::Snapshot)), true);
}
#[test]
fn real_tls_noise_terminal_purpose_logout_during_snapshot_never_completes_the_snapshot() {
    exercise_terminal_with_purpose(Some((Revocation::Logout, RevokeAt::Snapshot)), true);
}
#[test]
fn real_tls_noise_unshare_before_input_never_reaches_the_pty() {
    exercise_terminal(Some((Revocation::Unshare, RevokeAt::Input)));
}
#[test]
fn real_tls_noise_logout_before_input_never_reaches_the_pty() {
    exercise_terminal(Some((Revocation::Logout, RevokeAt::Input)));
}
#[test]
fn real_tls_noise_unshare_while_watching_never_delivers_an_invalidation() {
    exercise_terminal(Some((Revocation::Unshare, RevokeAt::Watch)));
}
#[test]
fn real_tls_noise_logout_while_watching_never_delivers_an_invalidation() {
    exercise_terminal(Some((Revocation::Logout, RevokeAt::Watch)));
}
#[test]
fn real_tls_noise_unshare_during_snapshot_never_completes_the_snapshot() {
    exercise_terminal(Some((Revocation::Unshare, RevokeAt::Snapshot)));
}
#[test]
fn real_tls_noise_logout_during_snapshot_never_completes_the_snapshot() {
    exercise_terminal(Some((Revocation::Logout, RevokeAt::Snapshot)));
}
fn exercise_terminal(revoke: Option<(Revocation, RevokeAt)>) {
    exercise_terminal_with_purpose(revoke, false);
}
fn exercise_terminal_with_purpose(revoke: Option<(Revocation, RevokeAt)>, terminal_purpose: bool) {
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
    peer::tests::fixture_at_wall_with_relay(now, Some(endpoint.clone()), |f, auth| {
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
        // A 12x40 grid keeps the snapshot multi-fragment (several 16 KiB chunks)
        // but ~4x cheaper than the default 80x24, so the scenario fits the real
        // 5 s freshness window even when the whole suite runs in parallel.
        local.set_profile_override_for_test(lomi_terminal::SpawnProfile {
            executable: crate::testsupport::shell_executable(),
            args: vec![],
            cwd: root_path.clone(),
            environment: crate::testsupport::shell_environment(&root_path),
            shell_integration: None,
            rows: 12,
            cols: 40,
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
        {
            let mut store = f.store.lock().unwrap();
            let intent = store
                .prepare_host_publication(&f.eligibility.binding)
                .unwrap();
            f.eligibility.binding = store
                .acknowledge_host_publication(
                    &intent,
                    &PublicationResult {
                        runtime: intent.params.runtime.clone(),
                        publication_seq: intent.params.publication_seq,
                    },
                )
                .unwrap();
            f.eligibility.publication = store
                .acknowledged_host_publication(&f.eligibility.binding)
                .unwrap()
                .unwrap();
        }
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
        // A revoked scenario has exactly one connection; the reconnect round
        // belongs to the replay scenario.
        let rounds: &[bool] = if revoke.is_some() {
            &[false]
        } else {
            &[false, true]
        };
        for &reconnect in rounds {
            let mut input = first_input.clone();
            let mut context = ChannelContextV3::from_canonical(
                &hex_bytes(input.expected_context.expose_wire())
                    .unwrap_or_else(|_| panic!("context bytes")),
            )
            .unwrap();
            context.channel_id = if reconnect { [45; 16] } else { [44; 16] };
            context.issued_at = f.now();
            context.expires_at = f.now() + 30;
            input.expected_context = hex(&context.canonical().unwrap()).try_into().unwrap();
            let api = Api {
                replies: RefCell::new(VecDeque::from([Reply::Poll(ChannelPendingResult {
                    channels: vec![PendingChannel {
                        channel_id: ChannelId::from_bytes(context.channel_id).unwrap(),
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
            let handoff = channel_worker.take_admitted().unwrap();
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
            let (done_tx, done_rx) = mpsc::sync_channel(1);
            let (reached_tx, reached_rx) = mpsc::sync_channel(1);
            let (committed_tx, committed_rx) = mpsc::sync_channel(1);
            let handshake = revoke.map(|(_, at)| RevokeHandshake {
                at,
                reached: reached_tx,
                committed: committed_rx,
            });
            let server_listener = listener.try_clone().unwrap();
            let server_tls = tls.clone();
            let server_terminal = terminal.clone();
            let client_root = root_path.clone();
            let join = thread::spawn(move || {
                terminal_client(
                    server_listener,
                    server_tls,
                    initiator,
                    context.channel_id,
                    server_terminal,
                    reconnect,
                    done_tx,
                    handshake,
                    client_root,
                )
            });
            let mut driver = Driver::with_coordinator(&f.stopping, Arc::downgrade(&coordinator));
            driver.script_ticket_for_test(Ok(ticket_response(&intent)), None, Duration::ZERO);
            driver.script_relay_for_test(
                lomi_host_http::RelayTransport::with_test_root(endpoint.clone(), root.clone())
                    .unwrap(),
            );
            assert!(driver.accept(handoff, auth, f.runtime(), &f.eligibility));
            driver.after_channel_step(&mut channel_worker, auth, f.runtime(), &f.eligibility);
            let until = Instant::now() + Duration::from_secs(20);
            // The production heartbeat worker re-observes the Cloud runtime well
            // inside the 5 s freshness window; this fixture has no such worker,
            // so emulate it. Without it the scenario is bound to 5 s of total
            // wall time, which a slower core does not meet.
            let mut heartbeat = Instant::now();
            loop {
                if heartbeat.elapsed() > Duration::from_secs(1) {
                    f.eligibility.heartbeat.request_started = Instant::now();
                    f.eligibility.heartbeat.wall_at_request_start = f.now();
                    heartbeat = Instant::now();
                }
                driver.advance(auth, f.runtime(), Some(&f.eligibility));
                if let Some((kind, _)) = revoke
                    && reached_rx.try_recv().is_ok()
                {
                    // The client is parked at the revocation point: commit the
                    // authority change through the real Shared owner.
                    let cancelled = AtomicBool::new(false);
                    let operation = crate::unix::owner_domain::Operation::new(
                        Instant::now() + Duration::from_secs(5),
                        &cancelled,
                    );
                    match kind {
                        Revocation::Unshare => f
                            .owner
                            .begin_unshare(&operation, f.workspace)
                            .unwrap()
                            .try_commit()
                            .map(|_| ())
                            .unwrap(),
                        Revocation::Logout => f
                            .owner
                            .begin_local_logout(&operation)
                            .unwrap()
                            .try_commit()
                            .map(|_| ())
                            .unwrap(),
                    }
                    committed_tx.send(()).unwrap();
                }
                if done_rx.try_recv().is_ok() {
                    break;
                }
                assert!(
                    Instant::now() < until,
                    "real terminal ingress did not settle: driver={:?} channel={:?}",
                    driver.failure_observation_for_test(),
                    driver.channel_step_observation_for_test()
                );
                thread::yield_now();
            }
            while driver.connected_for_test() {
                assert!(
                    Instant::now() < until,
                    "socket close did not disconnect remote principal: driver={:?} channel={:?}",
                    driver.failure_observation_for_test(),
                    driver.channel_step_observation_for_test()
                );
                driver.advance(auth, f.runtime(), Some(&f.eligibility));
            }
            join.join().unwrap();
            if let Some((_, at)) = revoke {
                // Revoked: the host dropped the connection and the PTY never
                // saw the input that was sent after the revocation.
                let settle = Instant::now() + Duration::from_millis(600);
                while Instant::now() < settle {
                    assert!(
                        !root_path.join("remote-terminal-marker").exists(),
                        "input reached the PTY after {at:?} revocation"
                    );
                    thread::sleep(Duration::from_millis(20));
                }
                continue;
            }
            while std::fs::read(root_path.join("remote-terminal-marker"))
                .ok()
                .as_deref()
                != Some(b"x".as_slice())
            {
                assert!(
                    Instant::now() < until,
                    "accepted marker input did not execute once"
                );
                thread::yield_now();
            }
            let retained = coordinator
                .terminals
                .snapshot(local_target.session_id, local_target.session_epoch)
                .unwrap();
            assert_eq!((retained.cols, retained.rows), (97, 31));
            assert!(retained.output_offset.0 > 0);
            assert_eq!(
                std::fs::read(root_path.join("remote-terminal-marker")).unwrap(),
                b"x",
                "input replayed across remote reconnect"
            );
        }
    });
    peer::current_pairing_script::clear();
}

#[path = "remote_terminal_multi_client_tests.rs"]
mod multi_client_tests;
#[path = "remote_terminal_rename_ingress_tests.rs"]
mod rename_ingress_tests;
