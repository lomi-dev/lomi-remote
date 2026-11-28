//! The tunnel service against a real coordinator (store, terminal service, files, chat) and the
//! real device core. The test plays the uplink thread: it feeds the engine, applies what the
//! service workers pushed through the `Handle`, and relays bytes to the device core.
use super::*;
use lomi_host_http::uplink::tunnels::{
    DeviceEntry, DeviceEvent, Engine, Out, Policy, testing::Scripted,
};
use lomi_host_store::{DeviceGrant, HostStore, Limits, OperationBinding, ProjectRecord};
use lomi_remote_core::{
    bridge,
    frame::{Direction, Frame, MAX_FRAME_BYTES, decode_frame, encode_frame},
    tunnel::{hex, unhex},
};
use lomi_remote_crypto::{Identity, Permissions, Role};
use lomi_remote_protocol::{
    ipc::{ChatLevel, LocalAuthConfiguration, LocalAuthProvider, LocalFileAcknowledgement},
    rpc::{PaneState, TerminalLayout, TerminalPane, TerminalTab},
    tunnel::DirectoryMessage,
};
use serde_json::{Value, json};
use std::{collections::VecDeque, fs, os::unix::fs::PermissionsExt, path::PathBuf};

const VECTORS: &str = include_str!("../../../lomi-remote-core/test-vectors/relay-frames.v1.json");
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WALL0: u64 = 1_794_999_000_000;
const ACCOUNT: [u8; 16] = [0xa1; 16];
const HOST_ID: [u8; 16] = [0xb2; 16];
const WAIT: Duration = Duration::from_secs(20);

struct TestDirectory(PathBuf);
impl TestDirectory {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        #[cfg(target_os = "macos")]
        let temp_root = PathBuf::from("/private/tmp");
        #[cfg(not(target_os = "macos"))]
        let temp_root = std::env::temp_dir().canonicalize().unwrap();
        let path = temp_root.join(format!(
            "lomi-tunnel-svc-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
}
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---- device side: the in-memory relay between the device core and the engine -----------------

#[derive(Debug, Clone)]
enum Rec {
    Send(Vec<u8>),
    Ev(Value),
    Msg(u32, Vec<u8>),
}
fn call(h: u32, op: &str, args: Value, payload: &[u8]) -> Vec<u8> {
    let out = bridge::call(h, op, &serde_json::to_vec(&args).unwrap(), payload);
    assert_eq!(out[0], 0, "{op}: {}", String::from_utf8_lossy(&out[1..]));
    out[1..].to_vec()
}
fn recs(mut b: &[u8]) -> Vec<Rec> {
    let mut out = Vec::new();
    while !b.is_empty() {
        let n = u32::from_be_bytes(b[1..5].try_into().unwrap()) as usize;
        let body = b[5..5 + n].to_vec();
        match b[0] {
            2 => out.push(Rec::Send(body)),
            4 => out.push(Rec::Ev(serde_json::from_slice(&body).unwrap())),
            5 => out.push(Rec::Msg(
                u32::from_be_bytes(body[..4].try_into().unwrap()),
                body[4..].to_vec(),
            )),
            _ => {}
        }
        b = &b[5 + n..];
    }
    out
}
fn dashed(id: &[u8; 16]) -> String {
    let h = hex(id);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}
fn vector(name: &str) -> Vec<u8> {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let h = d["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap()["hex"]
        .as_str()
        .unwrap();
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap())
        .collect()
}

/// One device with its own tunnel and engine; engines share the coordinator.
struct Rig {
    link: u32,
    tunnel: u32,
    device: Identity,
    device_id: [u8; 16],
    engine: Engine,
    log: Vec<Rec>,
}
impl Drop for Rig {
    fn drop(&mut self) {
        bridge::free(self.tunnel);
        bridge::free(self.link);
    }
}
fn handle_of(b: &[u8]) -> u32 {
    serde_json::from_slice::<Value>(b).unwrap()["handle"]
        .as_u64()
        .unwrap() as u32
}
fn at(mut v: Value) -> Value {
    v["monoMs"] = json!(0);
    v["wallMs"] = json!(WALL0);
    v
}
impl Rig {
    fn new(fx: &Fx, device: Identity, device_id: [u8; 16]) -> Self {
        Self::with_consent(fx, device, device_id, None)
    }
    /// With a consent, it is the engine's policy and the service's source of control prompts.
    fn with_consent(
        fx: &Fx,
        device: Identity,
        device_id: [u8; 16],
        consent: Option<DeviceConsent>,
    ) -> Self {
        let host = Identity::import_secret_seed_blob(
            &fx.host.export_secret_seed_blob().unwrap(),
            &fx.host.public_bundle(),
        )
        .unwrap();
        let link = handle_of(&call(
            0,
            "link.new",
            json!({"contractHash": HASH, "seed": 1, "silenceMs": 0}),
            &[],
        ));
        call(
            link,
            "link.start",
            at(json!({"token": "T".repeat(24), "expiresAt": WALL0 + 1_000_000})),
            &[],
        );
        call(link, "link.onOpen", at(json!({})), &[]);
        call(
            link,
            "link.onMessage",
            at(json!({})),
            &vector("ready-device"),
        );
        let inbox = Handle::new(|| {});
        let policy: Box<dyn Policy> = match &consent {
            Some(c) => {
                c.set_handle(inbox.clone());
                c.policy()
            }
            None => Box::new(Scripted::default()),
        };
        let engine = Engine::new(
            Config {
                identity: host,
                host_id: HOST_ID,
                contract_hash: unhex(HASH).unwrap(),
            },
            policy,
            service_for_test(Arc::downgrade(&fx.coordinator), inbox.clone(), consent),
            inbox,
        )
        .unwrap();
        let args = json!({
            "link": link,
            "deviceBundle": serde_json::to_value(device.public_bundle()).unwrap(),
            "hostBundle": serde_json::to_value(fx.host.public_bundle()).unwrap(),
            "hostFingerprint": hex(&fx.host.public_bundle().bundle.fingerprint().unwrap()),
            "contractHash": HASH,
            "accountId": hex(&ACCOUNT),
            "hostId": hex(&HOST_ID),
            "hello": {
                "deviceName": "Phone", "deviceKind": "mobile", "authEpoch": 1,
                "hostAccessEpoch": 2, "runtimeGeneration": 3, "resume": [], "sendDirectory": true,
            },
        });
        let tunnel = handle_of(&call(
            0,
            "tunnel.new",
            args,
            &device.export_secret_seed_blob().unwrap(),
        ));
        Self {
            link,
            tunnel,
            device,
            device_id,
            engine,
            log: Vec::new(),
        }
    }

    fn to_device(&self, bytes: &[u8]) -> Vec<Rec> {
        recs(&call(self.link, "link.onMessage", at(json!({})), bytes))
    }
    fn deliver(&mut self, o: Out) -> Vec<Rec> {
        match o {
            Out::Data { circuit, bytes } => {
                self.to_device(&[&[DATA_BYTE][..], &circuit, &bytes].concat())
            }
            Out::Close { circuit } => {
                let mut data = serde_json::Map::new();
                data.insert("circuitId".into(), hex(&circuit).into());
                data.insert("reason".into(), "peer_closed".into());
                let frame = encode_frame(
                    &Frame::Event {
                        name: "circuit.closed".into(),
                        data,
                    },
                    MAX_FRAME_BYTES,
                )
                .unwrap();
                self.to_device(&frame)
            }
        }
    }
    /// Runs both sides until neither has anything left to say right now.
    fn settle(&mut self, first: Vec<Rec>) {
        let mut work = VecDeque::from([first]);
        while let Some(batch) = work.pop_front() {
            for r in &batch {
                let Rec::Send(b) = r else { continue };
                if b[0] == DATA_BYTE {
                    let circuit: [u8; 16] = b[1..17].try_into().unwrap();
                    self.engine.on_data(&[&circuit[..], &b[17..]].concat(), 0);
                    continue;
                }
                let Frame::Call {
                    call_id,
                    name,
                    args,
                } = decode_frame(b, Direction::Client, MAX_FRAME_BYTES).unwrap()
                else {
                    panic!("unexpected frame");
                };
                assert_eq!(name, "circuit.open");
                let ev = json!({
                    "circuitId": args["circuitId"], "nonce": args["nonce"],
                    "device": {
                        "accountId": dashed(&ACCOUNT), "deviceId": dashed(&self.device_id),
                        "clientClass": "native",
                        "attestation": {
                            "fingerprint": hex(&self.device.public_bundle().bundle.fingerprint().unwrap()),
                            "authEpoch": "1", "expiresAt": now() + 3_600_000,
                        },
                    },
                });
                let Value::Object(ev) = ev else {
                    unreachable!()
                };
                self.engine.on_circuit_open(&ev, 0);
                let reply = encode_frame(
                    &Frame::ReplyOk {
                        call_id,
                        data: Default::default(),
                    },
                    MAX_FRAME_BYTES,
                )
                .unwrap();
                work.push_back(self.to_device(&reply));
            }
            self.log.extend(batch);
            self.engine.drain_commands();
            for o in self.engine.take_out() {
                let r = self.deliver(o);
                work.push_back(r);
            }
        }
    }
    fn op(&mut self, op: &str, args: Value, payload: &[u8]) -> Vec<Rec> {
        let r = recs(&call(self.tunnel, op, at(args), payload));
        let copy = r.clone();
        self.settle(r);
        copy
    }
    fn start(&mut self) {
        self.op("tunnel.start", json!({"random": hex(&[1; 32])}), &[]);
    }
    fn open(&mut self, kind: &str, params: Value) -> u32 {
        let r = self.op(
            "tunnel.openStream",
            json!({"kind": kind, "params": params}),
            &[],
        );
        self.events("streamStarted")
            .last()
            .and_then(|e| e["stream"].as_u64())
            .unwrap_or_else(|| panic!("no stream started: {r:?}")) as u32
    }
    fn send(&mut self, stream: u32, bytes: &[u8]) {
        self.op("tunnel.send", json!({"stream": stream}), bytes);
    }
    fn events(&self, ty: &str) -> Vec<Value> {
        self.log
            .iter()
            .filter_map(|r| match r {
                Rec::Ev(v) if v["type"] == ty => Some(v.clone()),
                _ => None,
            })
            .collect()
    }
    fn messages(&self, stream: u32) -> Vec<Vec<u8>> {
        self.log
            .iter()
            .filter_map(|r| match r {
                Rec::Msg(s, d) if *s == stream => Some(d.clone()),
                _ => None,
            })
            .collect()
    }
    /// JSON messages on `stream` whose `type` is `ty`.
    fn json_of(&self, stream: u32, ty: &str) -> Vec<Value> {
        self.messages(stream)
            .iter()
            .filter_map(|m| serde_json::from_slice::<Value>(m).ok())
            .filter(|v| v["type"] == ty)
            .collect()
    }
    fn reset_code(&self, stream: u32) -> Option<u64> {
        self.events("streamReset")
            .iter()
            .find(|e| e["stream"].as_u64() == Some(stream as u64))
            .and_then(|e| e["code"].as_u64())
    }
    /// Plays the uplink until `done` holds.
    fn wait(&mut self, what: &str, done: impl Fn(&Rig) -> bool) {
        let start = Instant::now();
        while !done(self) {
            assert!(
                start.elapsed() < WAIT,
                "timed out waiting for {what}: {:#?}",
                self.log
                    .iter()
                    .map(|r| match r {
                        Rec::Msg(s, d) => format!("msg {s}: {}", String::from_utf8_lossy(d)),
                        Rec::Ev(v) => format!("ev {v}"),
                        Rec::Send(_) => String::new(),
                    })
                    .filter(|l| !l.is_empty())
                    .collect::<Vec<_>>()
            );
            self.settle(Vec::new());
            std::thread::sleep(Duration::from_millis(4));
        }
    }
    /// Sends one rpc envelope on `stream` and waits for the response with its request id.
    fn request(
        &mut self,
        stream: u32,
        id: &str,
        workspace: Option<&WorkspaceId>,
        call: Value,
    ) -> Value {
        let mut body = json!({"requestId": id, "timeoutMs": 20000, "call": call});
        if let Some(w) = workspace {
            body["workspaceId"] = json!(String::from(*w));
        }
        self.send(stream, body.to_string().as_bytes());
        let find = |rig: &Rig| -> Option<Value> {
            rig.messages(stream)
                .iter()
                .filter_map(|m| serde_json::from_slice::<Value>(m).ok())
                .find(|v| v["requestId"] == id)
        };
        self.wait(&format!("response {id}"), |r| find(r).is_some());
        find(self).unwrap()
    }
}
const DATA_BYTE: u8 = 0x10;

// ---- Host side fixture ----------------------------------------------------------------------

struct Fx {
    _dir: TestDirectory,
    coordinator: Arc<Coordinator>,
    host: Identity,
    /// `[observe-only, control]`
    devices: [Option<Identity>; 2],
    a: ProjectRecord,
    b: ProjectRecord,
    terminal: Option<TerminalContext>,
    root: PathBuf,
}

fn now() -> u64 {
    now_ms()
}

fn seed_terminal(
    store: &mut HostStore,
    project: &ProjectRecord,
    service: &lomi_terminal::TerminalService,
) -> TerminalContext {
    let pane_id = PaneId::from_bytes([0x93; 16]).unwrap();
    let session_id = TerminalSessionId::from_bytes([0x91; 16]).unwrap();
    let session_epoch = SessionEpoch::from_bytes([0x92; 16]).unwrap();
    let operation_id = OperationId::from_bytes([0x94; 16]).unwrap();
    let mut next = project.state.clone();
    next.domain_revision = DecimalU64(next.domain_revision.0 + 1);
    let terminal = TerminalContext {
        workspace: next.context.clone(),
        pane_id,
        session_id,
        session_epoch,
        profile: TerminalProfile::ExperimentalRustGridV1,
    };
    next.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([0x95; 16]).unwrap(),
        name: "main".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                session: Some(terminal.clone()),
                state: PaneState::Running,
            },
        },
    });
    let rights = StoredOperationRights::new(
        operation_id,
        ConsumerAuthorizationId::from_bytes([5; 16]).unwrap(),
        project.state.context.workspace_id,
        Method::TerminalCreate,
        CapabilitySet::try_from(vec![
            Capability::WorkspaceRead,
            Capability::TerminalObserve,
            Capability::TerminalManage,
        ])
        .unwrap(),
        false,
    )
    .unwrap();
    let call = RpcCall::TerminalCreate(TerminalCreateParams {
        mutation: MutationContext {
            operation_id,
            context: project.state.context.clone(),
            expected_revision: project.state.domain_revision,
        },
        tab_name: "main".to_owned().try_into().unwrap(),
        profile_id: "default".to_owned().try_into().unwrap(),
    });
    let binding = OperationBinding {
        rights,
        parameter_hash: lomi_host_store::parameter_hash(&call).unwrap(),
    };
    let (_, permit) = store
        .admit_start_external(&binding, project.state.domain_revision)
        .unwrap();
    let permit = permit.expect("new terminal effect has its permit");
    service
        .spawn(
            session_id,
            session_epoch,
            &lomi_terminal::SpawnProfile {
                executable: PathBuf::from("/bin/sh"),
                args: vec!["-c".into(), "exec /bin/cat".into()],
                cwd: project.local_root.clone(),
                environment: Vec::new(),
                shell_integration: None,
                rows: 24,
                cols: 80,
                history: 0,
            },
        )
        .unwrap();
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
    terminal
}

fn grant(device: &Identity, device_id: [u8; 16], ceiling: Permissions) -> DeviceGrant {
    DeviceGrant {
        device_key: device.public_bundle().bundle.fingerprint().unwrap(),
        account_id: ACCOUNT,
        device_id,
        device_name: "Phone".into(),
        device_kind: "mobile".into(),
        ceiling,
        granted_at: now(),
        authorization_expires_at: now() + 3_600_000,
        authorization_epoch: 1,
        server_confirmed_at: now(),
        control_confirmed_at: (ceiling == Permissions::Control).then(now),
    }
}

impl Fx {
    /// `pty`: also run a terminal session (needs the native PTY, so Linux only).
    fn new(pty: bool) -> Self {
        let dir = TestDirectory::new();
        let mut store = HostStore::open(&dir.0.join("host.sqlite3"), Limits::default()).unwrap();
        store
            .configure_auth(&LocalAuthConfiguration {
                version: 1,
                origin: "https://identity.example".to_owned().try_into().unwrap(),
                remote_api_origin: Some("https://remote.example".to_owned().try_into().unwrap()),
                relay_endpoint: None,
                client_id: "host".to_owned().try_into().unwrap(),
                provider: LocalAuthProvider::ProtectedFile,
                keychain_path: None,
                protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
            })
            .unwrap();
        store.enable_authorization(0).unwrap();
        let root = dir.0.join("app");
        fs::create_dir(&root).unwrap();
        fs::write(root.join("hello.txt"), b"hello from the host").unwrap();
        let other_root = dir.0.join("secret");
        fs::create_dir(&other_root).unwrap();
        let service = lomi_terminal::TerminalService::new();
        let a = store
            .add_project(&root, "app".to_owned().try_into().unwrap())
            .unwrap();
        let terminal = pty.then(|| seed_terminal(&mut store, &a, &service));
        let a = store.workspace(a.state.context.workspace_id).unwrap();
        store.share(a.state.context.workspace_id, a.fence).unwrap();
        store
            .set_chat_level(a.state.context.workspace_id, ChatLevel::Edit)
            .unwrap();
        let b = store
            .add_project(&other_root, "secret".to_owned().try_into().unwrap())
            .unwrap();
        let observe = Identity::generate(ACCOUNT, [0xc3; 16], Role::Device, 1).unwrap();
        let control = Identity::generate(ACCOUNT, [0xc4; 16], Role::Device, 1).unwrap();
        store
            .upsert_grant(&grant(&observe, [0xc3; 16], Permissions::Observe))
            .unwrap();
        store
            .upsert_grant(&grant(&control, [0xc4; 16], Permissions::Control))
            .unwrap();
        let a = store.workspace(a.state.context.workspace_id).unwrap();

        let bin = dir.0.join("bin");
        fs::create_dir(&bin).unwrap();
        let claude = bin.join("claude");
        fs::write(
            &claude,
            "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"type\":\"stream_event\",\"event\":{\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}}' '{\"type\":\"result\",\"result\":\"hello\"}'\n",
        )
        .unwrap();
        fs::set_permissions(&claude, fs::Permissions::from_mode(0o755)).unwrap();
        let mut coordinator =
            Coordinator::with_terminals(store, Arc::new(AtomicBool::new(false)), service).unwrap();
        coordinator.chat = remote_chat::Chat::with_resolver(dir.0.join("chat"), move |cli| {
            (cli == "claude").then(|| claude.clone())
        });
        Self {
            _dir: dir,
            coordinator: Arc::new(coordinator),
            host: Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap(),
            devices: [Some(observe), Some(control)],
            a,
            b,
            terminal,
            root,
        }
    }
    fn observer(&mut self) -> Rig {
        let device = self.devices[0].take().unwrap();
        let mut rig = Rig::new(self, device, [0xc3; 16]);
        rig.start();
        rig
    }
    fn controller(&mut self) -> Rig {
        let device = self.devices[1].take().unwrap();
        let mut rig = Rig::new(self, device, [0xc4; 16]);
        rig.start();
        rig
    }
    fn ws(&self) -> WorkspaceId {
        self.a.state.context.workspace_id
    }
    fn terminal(&self) -> &TerminalContext {
        self.terminal.as_ref().expect("fixture without a terminal")
    }
    fn terminal_open(&self) -> Value {
        json!({
            "workspaceId": String::from(self.ws()),
            "paneId": String::from(self.terminal().pane_id),
            "sessionEpoch": String::from(self.terminal().session_epoch),
            "cols": 80, "rows": 24,
        })
    }
    fn store<R>(&self, f: impl FnOnce(&mut HostStore) -> R) -> R {
        self.coordinator.owner.with_store_for_test(f)
    }
}

fn kinds(rig: &Rig, stream: u32) -> Vec<String> {
    rig.messages(stream)
        .iter()
        .filter_map(|m| serde_json::from_slice::<Value>(m).ok())
        .filter_map(|v| v["type"].as_str().map(str::to_owned))
        .collect()
}
fn error_code(v: &Value) -> String {
    assert_eq!(v["type"], "error", "{v}");
    v["error"]["code"].as_str().unwrap_or_default().to_owned()
}

// ---- tests ----------------------------------------------------------------------------------

#[test]
fn directory_is_the_first_message_lists_only_shared_workspaces_and_follows_changes() {
    let pty = cfg!(target_os = "linux");
    let mut fx = Fx::new(pty);
    let mut rig = fx.observer();
    // the Host-opened directory stream is stream 2 and its first message is the snapshot
    let first = rig.messages(2).into_iter().next().expect("directory first");
    let DirectoryMessage::Snapshot(snapshot) = DirectoryMessage::decode(&first).unwrap() else {
        panic!("first directory message is not a snapshot");
    };
    assert_eq!(snapshot.seq, 0);
    assert_eq!(snapshot.host.platform.as_str(), std::env::consts::OS);
    assert_eq!(
        snapshot.workspaces.len(),
        1,
        "the unshared workspace is not listed"
    );
    let ws = &snapshot.workspaces[0];
    assert_eq!(ws.id, fx.ws());
    assert_eq!(ws.name.as_str(), "app");
    // an observe-only device does not get the control capabilities
    assert!(ws.capabilities.contains(Capability::TerminalObserve));
    assert!(!ws.capabilities.contains(Capability::TerminalControl));
    assert_eq!(ws.terminals.len(), usize::from(pty));
    assert_eq!(ws.tabs.len(), usize::from(pty));
    if pty {
        assert_eq!(ws.terminals[0].state, PaneState::Running);
        assert_eq!(
            ws.terminals[0].session_epoch,
            Some(fx.terminal().session_epoch)
        );
    }

    // sharing the second workspace shows up as a change; unsharing the first removes it
    let b = fx.b.state.context.workspace_id;
    fx.store(|s| {
        let fence = s.workspace(b).unwrap().fence;
        s.share(b, fence).unwrap();
        s.unshare(fx.ws()).unwrap();
    });
    rig.wait("directory changes", |r| r.messages(2).len() >= 3);
    let changes: Vec<_> = rig
        .messages(2)
        .iter()
        .skip(1)
        .map(|m| match DirectoryMessage::decode(m).unwrap() {
            DirectoryMessage::Change(c) => c,
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(changes.iter().map(|c| c.seq).collect::<Vec<_>>(), [1, 2]);
    assert!(
        changes
            .iter()
            .any(|c| matches!(&c.change, DirectoryChange::Workspace(w) if w.id == b))
    );
    assert!(
        changes
            .iter()
            .any(|c| c.change == DirectoryChange::Removed(fx.ws()))
    );
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY")]
fn terminal_stream_snapshot_input_echo_resize_and_claim_levels() {
    let mut fx = Fx::new(true);
    let open = fx.terminal_open();
    let terminal = serde_json::to_value(fx.terminal()).unwrap();
    let ws = fx.ws();

    // Read level: attach works, the claim is refused with SCOPE_DENIED
    let mut reader = fx.observer();
    let s = reader.open("terminal", open.clone());
    reader.wait("snapshot", |r| {
        kinds(r, s).contains(&"snapshotComplete".to_owned())
    });
    let claim = json!({"method": "terminal.claim", "params": {
        "terminal": terminal, "subscriptionId": "x", "renderedThroughSeq": "0"}});
    let refused = reader.request(s, "claim-read", None, claim.clone());
    assert_eq!(error_code(&refused), "SCOPE_DENIED", "{refused}");

    // Control level: OPEN and claim in one go (the claim does not wait for the snapshot)
    let mut ctl = fx.controller();
    let s = ctl.open("terminal", open);
    let granted = ctl.request(s, "claim-control", None, claim);
    assert_eq!(granted["type"], "result", "{granted}");
    let lease = granted["result"]["params"]["lease"].clone();
    assert!(lease["token"].is_string(), "{granted}");
    let kinds_so_far = kinds(&ctl, s);
    assert_eq!(
        kinds_so_far[0], "snapshotMetadata",
        "snapshot comes first: {kinds_so_far:?}"
    );
    assert!(kinds_so_far.contains(&"snapshotComplete".to_owned()));

    // input is echoed by the PTY and arrives as a delta
    let input = json!({"method": "terminal.input", "params": {
        "terminal": serde_json::to_value(fx.terminal()).unwrap(), "lease": lease,
        "inputId": "1", "inputSeq": "1", "bytes": [104, 105, 10]}});
    let receipt = ctl.request(s, "input-1", None, input);
    assert_eq!(receipt["type"], "result", "{receipt}");
    ctl.wait("echo delta", |r| {
        kinds(r, s).contains(&"deltaComplete".to_owned())
    });

    // resize
    let resize = json!({"method": "terminal.resize", "params": {
        "terminal": serde_json::to_value(fx.terminal()).unwrap(), "lease": lease,
        "resizeSeq": "1", "columns": 100, "rows": 30}});
    let resized = ctl.request(s, "resize-1", None, resize);
    assert_eq!(resized["type"], "result", "{resized}");
    assert_eq!(resized["result"]["params"]["columns"], 100);

    // a terminal stream for another workspace is refused
    let b = fx.b.state.context.workspace_id;
    let mut other = fx.terminal_open();
    other["workspaceId"] = json!(String::from(b));
    let refused = ctl.open("terminal", other);
    ctl.wait("reset", |r| r.reset_code(refused).is_some());
    assert_eq!(ctl.reset_code(refused), Some(u64::from(RESET_UNSHARED)));
    let _ = ws;
}

#[test]
#[cfg_attr(not(target_os = "linux"), ignore = "requires Linux native PTY")]
fn unsharing_a_workspace_resets_its_live_terminal_stream() {
    let mut fx = Fx::new(true);
    let mut ctl = fx.controller();
    let s = ctl.open("terminal", fx.terminal_open());
    ctl.wait("snapshot", |r| {
        kinds(r, s).contains(&"snapshotComplete".to_owned())
    });
    assert_eq!(ctl.reset_code(s), None);
    fx.store(|st| st.unshare(fx.ws()).unwrap());
    ctl.wait("reset after unshare", |r| r.reset_code(s).is_some());
    assert_eq!(ctl.reset_code(s), Some(u64::from(RESET_UNSHARED)));
}

#[test]
fn rpc_files_read_ok_and_unshared_workspace_refused() {
    let mut fx = Fx::new(false);
    let mut ctl = fx.controller();
    let context = serde_json::to_value(&fx.a.state.context).unwrap();
    let root = String::from(EntryId::from_bytes(fx.ws().to_bytes()).unwrap());
    let list = ctl.request(
        0,
        "list",
        None,
        json!({"method": "files.list", "params": {
            "context": context, "parentEntryId": root, "cursor": null, "limit": 50}}),
    );
    assert_eq!(list["type"], "result", "{list}");
    let entry = list["result"]["params"]["entries"][0]["entryId"].clone();
    let read = ctl.request(
        0,
        "read",
        None,
        json!({"method": "files.read", "params": {
            "context": context, "entryId": entry, "fileRevision": null,
            "offset": "0", "maxBytes": 1024}}),
    );
    assert_eq!(read["type"], "result", "{read}");
    let bytes: Vec<u8> = read["result"]["params"]["bytes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b.as_u64().unwrap() as u8)
        .collect();
    assert_eq!(bytes, b"hello from the host");

    // the other workspace is not shared
    let other = serde_json::to_value(&fx.b.state.context).unwrap();
    let refused = ctl.request(
        0,
        "unshared",
        None,
        json!({"method": "files.list", "params": {
            "context": other, "parentEntryId": root, "cursor": null, "limit": 50}}),
    );
    assert_eq!(error_code(&refused), "WORKSPACE_UNSHARED", "{refused}");
    // a call may not name a workspace other than its envelope's
    let mismatch = ctl.request(
        0,
        "mismatch",
        Some(&fx.ws()),
        json!({"method": "files.list", "params": {
            "context": other, "parentEntryId": root, "cursor": null, "limit": 50}}),
    );
    assert_eq!(error_code(&mismatch), "WORKSPACE_UNSHARED", "{mismatch}");
}

#[test]
fn control_is_refused_at_read_until_the_owner_approves_the_code() {
    let mut fx = Fx::new(false);
    let device = fx.devices[1].take().unwrap();
    let key = device.public_bundle().bundle.fingerprint().unwrap();
    // A device the Host has not seen: D5 variant 2 stores it at Read, control unconfirmed.
    fx.store(|s| s.revoke(&key).unwrap());
    let store = fx.coordinator.owner.store_handle();
    let consent = DeviceConsent::new(store, ACCOUNT, Mode::Auto);
    consent.roster().apply(&DeviceEvent::Ready {
        host_access_epoch: 2,
        runtime_generation: 3,
        devices: Some(vec![DeviceEntry {
            device_id: [0xc4; 16],
            fingerprint: key,
            client_class: None,
            auth_epoch: 1,
            expires_at: now() + 3_600_000,
        }]),
    });
    let mut rig = Rig::with_consent(&fx, device, [0xc4; 16], Some(consent.clone()));
    rig.start();
    let ws = fx.ws();
    let create = |id: &str| {
        json!({"method": "chat.thread.create", "params": {
            "operationId": uuid::Uuid::new_v4().to_string(), "providerId": "claude", "model": "m",
            "effort": null, "permissions": "read-only", "workspaceMode": "project", "title": id}})
    };
    // Read already works.
    let providers = rig.request(
        0,
        "providers",
        Some(&ws),
        json!({"method": "chat.providers", "params": {}}),
    );
    assert_eq!(providers["type"], "result", "{providers}");
    // A mutation is refused and puts the code in front of the owner.
    let refused = rig.request(0, "before", Some(&ws), create("a"));
    assert_eq!(error_code(&refused), "SCOPE_DENIED", "{refused}");
    let pending = consent.pending();
    assert_eq!(pending.len(), 1, "{pending:?}");
    assert!(consent.approve(pending[0].circuit));
    rig.settle(Vec::new());
    // The grant now records the confirmation, and the live tunnel is at Control.
    assert!(fx.store(|s| {
        s.get_grant(&key)
            .unwrap()
            .unwrap()
            .control_confirmed_at
            .is_some()
    }));
    let allowed = rig.request(0, "after", Some(&ws), create("b"));
    assert_eq!(allowed["type"], "result", "{allowed}");
}

#[test]
fn files_watch_stream_reports_an_invalidation() {
    let mut fx = Fx::new(false);
    let mut ctl = fx.controller();
    let root = String::from(EntryId::from_bytes(fx.ws().to_bytes()).unwrap());
    let s = ctl.open(
        "files.watch",
        json!({"workspaceId": String::from(fx.ws()), "path": root}),
    );
    // give the Host a moment to start the watch, then change the directory
    std::thread::sleep(Duration::from_millis(300));
    fs::write(fx.root.join("new.txt"), b"x").unwrap();
    ctl.wait("invalidation", |r| !r.json_of(s, "invalidated").is_empty());
    assert_eq!(ctl.reset_code(s), None);

    // unsharing the workspace resets the live stream (same recheck as for terminals)
    fx.store(|st| st.unshare(fx.ws()).unwrap());
    ctl.wait("reset after unshare", |r| r.reset_code(s).is_some());
    assert_eq!(ctl.reset_code(s), Some(u64::from(RESET_UNSHARED)));
}

#[test]
fn chat_stream_delivers_frames_for_a_thread() {
    let mut fx = Fx::new(false);
    let mut ctl = fx.controller();
    let ws = fx.ws();
    let created = ctl.request(
        0,
        "create",
        Some(&ws),
        json!({"method": "chat.thread.create", "params": {
            "operationId": uuid::Uuid::new_v4().to_string(), "providerId": "claude", "model": "m",
            "effort": null, "permissions": "read-only", "workspaceMode": "project", "title": null}}),
    );
    assert_eq!(created["type"], "result", "{created}");
    let thread = created["result"]["params"]["thread"].clone();
    let thread_id = thread["threadId"].clone();
    let s = ctl.open(
        "chat",
        json!({"workspaceId": String::from(ws), "threadId": thread_id, "after": null}),
    );
    std::thread::sleep(Duration::from_millis(200));
    let sent = ctl.request(
        0,
        "send",
        Some(&ws),
        json!({"method": "chat.send", "params": {
            "operationId": uuid::Uuid::new_v4().to_string(), "threadId": thread_id,
            "expectedRevision": thread["revision"], "text": "hi"}}),
    );
    assert_eq!(sent["type"], "result", "{sent}");
    ctl.wait("chat frames", |r| !r.json_of(s, "message").is_empty());
    // the generation streamed its text before the final message
    assert!(!ctl.json_of(s, "delta").is_empty() || !ctl.json_of(s, "snapshot").is_empty());
    assert_eq!(ctl.reset_code(s), None);
}

#[test]
fn a_stream_for_an_unshared_workspace_is_refused_for_every_kind() {
    let mut fx = Fx::new(false);
    let mut ctl = fx.controller();
    let b = String::from(fx.b.state.context.workspace_id);
    let id = String::from(EntryId::from_bytes(fx.b.state.context.workspace_id.to_bytes()).unwrap());
    let watch = ctl.open("files.watch", json!({"workspaceId": b, "path": id}));
    let chat = ctl.open(
        "chat",
        json!({"workspaceId": b, "threadId": "0".repeat(32), "after": null}),
    );
    ctl.wait("resets", |r| {
        r.reset_code(watch).is_some() && r.reset_code(chat).is_some()
    });
    assert_eq!(ctl.reset_code(watch), Some(u64::from(RESET_UNSHARED)));
    assert_eq!(ctl.reset_code(chat), Some(u64::from(RESET_UNSHARED)));
}
