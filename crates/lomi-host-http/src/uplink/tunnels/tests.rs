use super::{testing::*, *};
use lomi_remote_core::tunnel::{hex, open_params};
use lomi_remote_crypto::Role;
use serde_json::json;

const HASH: [u8; 32] = [7; 32];
const ACCOUNT: Id = [0xa1; 16];
const HOST_ID: Id = [0xb2; 16];
const U: &str = "11111111-1111-4111-8111-111111111111";

fn dashed(id: &Id) -> String {
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
fn terminal() -> OpenParams {
    open_params(
        "terminal",
        json!({"workspaceId": U, "paneId": U, "sessionEpoch": U, "cols": 80, "rows": 24}),
    )
    .unwrap()
}
fn transfer() -> OpenParams {
    open_params("transfer", json!({"requestId": "t1"})).unwrap()
}

struct World {
    e: Engine,
    host: SignedBundle,
    policy: Scripted,
    log: Arc<Mutex<Vec<String>>>,
    handle: Handle,
}
fn world() -> World {
    let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
    let bundle = host.public_bundle();
    let (policy, echo) = (Scripted::default(), Echo::default());
    let log = echo.log.clone();
    let handle = Handle::new(|| {});
    let e = Engine::new(
        Config {
            identity: host,
            host_id: HOST_ID,
            contract_hash: HASH,
        },
        Box::new(policy.clone()),
        Box::new(echo),
        handle.clone(),
    )
    .unwrap();
    World {
        e,
        host: bundle,
        policy,
        log,
        handle,
    }
}
fn device(n: u8) -> Identity {
    Identity::generate(ACCOUNT, [n; 16], Role::Device, 1).unwrap()
}
fn event(circuit: CircuitId, device: &Identity, auth_epoch: u64) -> Object {
    event_as(circuit, device, auth_epoch, None)
}
/// `attested_id`: the device id the relay claims, when it is not the bundle's own.
fn event_as(
    circuit: CircuitId,
    device: &Identity,
    auth_epoch: u64,
    attested_id: Option<Id>,
) -> Object {
    let b = &device.public_bundle().bundle;
    let device_id = attested_id.unwrap_or(b.subject_id);
    let Value::Object(o) = json!({
        "circuitId": hex(&circuit), "nonce": hex(&circuit),
        "device": {
            "accountId": dashed(&ACCOUNT), "deviceId": dashed(&device_id), "clientClass": "web",
            "attestation": {"fingerprint": hex(&b.fingerprint().unwrap()), "authEpoch": auth_epoch.to_string(), "expiresAt": 9},
        },
    }) else {
        unreachable!()
    };
    o
}

struct Dev {
    circuit: CircuitId,
    noise: Noise,
    table: StreamTable,
    code: String,
}
impl Dev {
    fn send(&mut self, w: &mut World, frames: &[TunnelFrame], now: u64) {
        let mut plain = Vec::new();
        frames
            .iter()
            .for_each(|f| f.encode_into(&mut plain).unwrap());
        let ct = self.noise.encrypt(&plain).unwrap();
        w.e.on_data(&[&self.circuit[..], &ct].concat(), now);
    }
    /// One entry per Noise message for this circuit; every frame also goes through the table.
    fn recv(&mut self, outs: &[Out]) -> Vec<Vec<TunnelFrame>> {
        outs.iter()
            .filter_map(|o| match o {
                Out::Data { circuit, bytes } if *circuit == self.circuit => Some(bytes),
                _ => None,
            })
            .map(|b| {
                let frames = decode_frames(&self.noise.decrypt(b).unwrap()).unwrap();
                frames
                    .iter()
                    .filter(|f| f.kind != FrameType::Control)
                    .for_each(|f| {
                        self.table.on_frame(f).unwrap();
                    });
                frames
            })
            .collect()
    }
}
fn greeting(dev: &mut Dev, outs: &[Out]) -> HostGreeting {
    let Some(Out::Data { bytes, .. }) = outs.first() else {
        panic!("no greeting: {outs:?}")
    };
    HostGreeting::decode(&dev.noise.decrypt(bytes).unwrap()).unwrap()
}
/// Opens a circuit and runs the device side up to the Host's answer to message 3.
fn handshake(
    w: &mut World,
    id: &Identity,
    c: u8,
    epoch: u64,
    send_directory: bool,
    now: u64,
) -> (Dev, Vec<Out>) {
    handshake_as(w, id, c, epoch, send_directory, now, None)
}
fn handshake_as(
    w: &mut World,
    id: &Identity,
    c: u8,
    epoch: u64,
    send_directory: bool,
    now: u64,
    attested_id: Option<Id>,
) -> (Dev, Vec<Out>) {
    let circuit = [c; 16];
    w.e.on_circuit_open(&event_as(circuit, id, epoch, attested_id), now);
    let prologue = TunnelPrologue {
        contract_hash: HASH,
        path: TunnelPath::Relay,
        circuit_id: circuit,
        nonce: circuit,
        host_id: HOST_ID,
        host_fingerprint: w.host.bundle.fingerprint().unwrap(),
        device_fingerprint: id.public_bundle().bundle.fingerprint().unwrap(),
        account_id: ACCOUNT,
    };
    let host_fp = w.host.bundle.fingerprint().unwrap();
    let mut hs = TunnelHandshake::device(id, &prologue, &w.host, &host_fp).unwrap();
    w.e.on_data(
        &[&circuit[..], &hs.write_message(&[]).unwrap()].concat(),
        now,
    );
    let Some(Out::Data { bytes, .. }) = w.e.take_out().into_iter().next() else {
        panic!("message 2 expected")
    };
    hs.read_message(&bytes).unwrap();
    let hello: Hello = serde_json::from_value(json!({
        "deviceName": "T", "deviceKind": "web", "authEpoch": 1, "hostAccessEpoch": 2,
        "runtimeGeneration": 3, "resume": [], "sendDirectory": send_directory,
        "deviceBundle": serde_json::to_vec(&id.public_bundle()).unwrap(),
    }))
    .unwrap();
    let m3 = hs.write_message(&hello.encode().unwrap()).unwrap();
    let code = hs.confirmation_code().unwrap();
    let noise = hs.into_transport().unwrap();
    w.e.on_data(&[&circuit[..], &m3].concat(), now);
    let dev = Dev {
        circuit,
        noise,
        table: StreamTable::new(Side::Device),
        code,
    };
    (dev, w.e.take_out())
}
fn welcome() -> HostGreeting {
    HostGreeting::Welcome(Welcome { directory: false })
}
fn open_dev(w: &mut World, n: u8) -> Dev {
    let (mut dev, outs) = handshake(w, &device(n), n, 1, false, 0);
    assert_eq!(greeting(&mut dev, &outs), welcome());
    dev
}
fn log(w: &World) -> Vec<String> {
    w.log.lock().unwrap().clone()
}

#[test]
fn control_pending_frame_carries_the_tunnel_code_to_the_device() {
    let mut w = world();
    let mut dev = open_dev(&mut w, 1);
    let code: u32 = dev.code.parse().unwrap();
    w.handle
        .push(Command::ControlPending {
            circuit: dev.circuit,
            code,
        })
        .unwrap();
    w.e.drain_commands();
    let frames = dev.recv(&w.e.take_out()).concat();
    let [f] = &frames[..] else {
        panic!("{frames:?}")
    };
    assert_eq!((f.stream_id, f.kind), (0, FrameType::Control));
    assert_eq!(f.as_control_pending().map(|p| p.code), Some(code));
    // the Host does not accept the frame from a device
    let mut table = StreamTable::new(Side::Host);
    assert!(table.on_frame(f).is_err());
}

#[test]
fn a_bundle_for_another_device_id_than_the_attested_one_is_refused() {
    let mut w = world();
    let (_, outs) = handshake_as(&mut w, &device(1), 1, 1, false, 0, Some([0xee; 16]));
    assert!(outs.contains(&Out::Close { circuit: [1; 16] }), "{outs:?}");
    assert!(w.e.is_empty());
    // the same device under its own id is welcomed
    open_dev(&mut w, 2);
}

#[test]
fn welcome_directory_and_echo() {
    let mut w = world();
    let (mut dev, outs) = handshake(&mut w, &device(1), 1, 1, true, 0);
    assert_eq!(
        greeting(&mut dev, &outs[..1]),
        HostGreeting::Welcome(Welcome { directory: true })
    );
    let frames = dev.recv(&outs[1..]).concat();
    assert_eq!(
        frames
            .iter()
            .map(|f| (f.stream_id, f.kind))
            .collect::<Vec<_>>(),
        [(2, FrameType::Open), (2, FrameType::Data)]
    );
    assert_eq!(frames[1].data, b"dir");
    let (id, open) = dev.table.open(&terminal()).unwrap();
    let data = dev.table.send_data(id, b"hello", true).unwrap();
    dev.send(&mut w, &[open, data], 5);
    let outs = w.e.take_out();
    let frames = dev.recv(&outs).concat();
    assert!(
        frames
            .iter()
            .any(|f| f.stream_id == id && f.kind == FrameType::Data && f.data == b"hello")
    );
    assert_eq!(log(&w), ["open", "stream 1"]);
}

#[test]
fn approval_pending_then_approve_deny_and_deadline() {
    let mut w = world();
    w.policy
        .0
        .lock()
        .unwrap()
        .extend([const { Admission::Pending }; 3]);
    let (mut a, outs) = handshake(&mut w, &device(1), 1, 1, false, 1_000);
    let HostGreeting::ApprovalPending(p) = greeting(&mut a, &outs) else {
        panic!()
    };
    assert_eq!(
        (p.code.to_string().len() <= 6, format!("{:06}", p.code)),
        (true, a.code.clone())
    );
    assert_eq!(p.deadline_ms, 120_000);
    assert_eq!(w.e.next_deadline(), Some(121_000));
    // anything from the device before Welcome is a violation
    let (mut b, outs) = handshake(&mut w, &device(2), 2, 1, false, 1_000);
    greeting(&mut b, &outs);
    let (mut c, outs) = handshake(&mut w, &device(3), 3, 1, false, 1_000);
    greeting(&mut c, &outs);

    w.e.approve([1; 16], Level::Control);
    assert_eq!(greeting(&mut a, &w.e.take_out()), welcome());
    w.e.deny([2; 16]);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [2; 16] }]);
    w.e.tick(120_999);
    assert!(w.e.take_out().is_empty());
    w.e.tick(121_000);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [3; 16] }]);
    assert_eq!(
        log(&w),
        ["open"],
        "the service only hears about the approved tunnel"
    );
    w.e.approve([3; 16], Level::Read); // gone: nothing happens
    assert!(w.e.take_out().is_empty());
}

#[test]
fn stale_epoch_answers_then_closes_and_a_wrong_hello_epoch_is_refused() {
    let mut w = world();
    w.policy.0.lock().unwrap().push_back(Admission::Stale {
        epochs: StaleEpoch {
            auth_epoch: 7,
            host_access_epoch: 8,
            runtime_generation: 9,
        },
    });
    let (mut dev, outs) = handshake(&mut w, &device(1), 1, 1, false, 0);
    assert!(matches!(greeting(&mut dev, &outs), HostGreeting::StaleEpoch(e) if e.auth_epoch == 7));
    assert_eq!(outs[1], Out::Close { circuit: [1; 16] });
    assert!(w.e.is_empty());
    // attested epoch 5, hello says 1, the policy would welcome: the engine does not
    let (_, outs) = handshake(&mut w, &device(2), 2, 5, false, 0);
    assert_eq!(outs, [Out::Close { circuit: [2; 16] }]);
}

#[test]
fn handshake_deadline_is_ten_seconds() {
    let mut w = world();
    w.e.on_circuit_open(&event([1; 16], &device(1), 1), 500);
    assert_eq!(w.e.next_deadline(), Some(10_500));
    w.e.tick(10_499);
    assert!(w.e.take_out().is_empty());
    w.e.tick(10_500);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [1; 16] }]);
    assert!(w.e.is_empty() && w.e.next_deadline().is_none());
}

#[test]
fn limits_per_device_devices_and_pending_handshakes() {
    let mut w = world();
    let d = device(1);
    for c in 1..=MAX_HANDSHAKES_PER_DEVICE as u8 {
        w.e.on_circuit_open(&event([c; 16], &d, 1), 0);
    }
    assert!(w.e.take_out().is_empty());
    w.e.on_circuit_open(&event([9; 16], &d, 1), 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [9; 16] }]);
    // seven more devices fill the eight slots, the ninth device is refused
    for n in 2..=8u8 {
        w.e.on_circuit_open(&event([n + 20; 16], &device(n), 1), 0);
    }
    w.e.on_circuit_open(&event([30; 16], &device(9), 1), 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [30; 16] }]);

    // handshake cap: 16 in flight over all devices, the 17th is refused
    let mut w = world();
    for n in 1..=4u8 {
        for k in 0..MAX_HANDSHAKES_PER_DEVICE as u8 {
            w.e.on_circuit_open(&event([n * 10 + k; 16], &device(n), 1), 0);
        }
    }
    assert!(w.e.take_out().is_empty());
    assert_eq!(w.e.len(), MAX_HANDSHAKES);
    w.e.on_circuit_open(&event([99; 16], &device(5), 1), 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [99; 16] }]);
}

#[test]
fn unusable_events_and_unknown_circuits() {
    let mut w = world();
    let mut bad = event([1; 16], &device(1), 1);
    bad["device"]["attestation"] = Value::Null;
    w.e.on_circuit_open(&bad, 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [1; 16] }]);
    w.e.on_data(&[[9u8; 16].as_slice(), b"junk"].concat(), 0);
    w.e.on_data(b"short", 0);
    let mut closed = Object::new();
    closed.insert("circuitId".into(), hex(&[9; 16]).into());
    w.e.on_circuit_closed(&closed);
    assert!(w.e.take_out().is_empty() && w.e.is_empty());
    // garbage as message 1 closes
    w.e.on_circuit_open(&event([2; 16], &device(1), 1), 0);
    w.e.on_data(&[[2u8; 16].as_slice(), &[0u8; 40]].concat(), 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [2; 16] }]);
}

#[test]
fn tamper_relay_close_and_link_down_close_the_service_side() {
    let mut w = world();
    let mut dev = open_dev(&mut w, 1);
    let (_, open) = dev.table.open(&terminal()).unwrap();
    let mut plain = Vec::new();
    open.encode_into(&mut plain).unwrap();
    let mut ct = dev.noise.encrypt(&plain).unwrap();
    *ct.last_mut().unwrap() ^= 1;
    w.e.on_data(&[&dev.circuit[..], &ct].concat(), 0);
    assert_eq!(
        w.e.take_out(),
        [Out::Close {
            circuit: dev.circuit
        }]
    );

    let _b = open_dev(&mut w, 2);
    let mut closed = Object::new();
    closed.insert("circuitId".into(), hex(&[2; 16]).into());
    closed.insert("reason".into(), "stale_authority".into());
    w.e.on_circuit_closed(&closed);
    assert!(w.e.take_out().is_empty(), "the relay already dropped it");
    let _c = open_dev(&mut w, 3);
    w.e.link_down();
    assert!(w.e.take_out().is_empty() && w.e.is_empty());
    assert_eq!(
        log(&w),
        [
            "open",
            "close decrypt",
            "open",
            "close stale_authority",
            "open",
            "close linkDown"
        ]
    );
}

#[test]
fn scheduler_serves_interactive_first_round_robin_and_coalesces() {
    let mut w = world();
    let mut dev = open_dev(&mut w, 1);
    let circuit = dev.circuit;
    let ids: Vec<u32> = [terminal(), terminal(), transfer()]
        .iter()
        .map(|p| {
            let (id, f) = dev.table.open(p).unwrap();
            dev.send(&mut w, &[f], 0);
            id
        })
        .collect();
    w.e.take_out();
    let (t1, t2, bulk) = (ids[0], ids[1], ids[2]);
    // queue bulk first, then two terminals: terminals still go out first, alternating
    let push = |stream, n: usize| w.handle.send(circuit, stream, vec![1; n]).unwrap();
    push(bulk, 100_000);
    push(t1, 40_000);
    push(t2, 40_000);
    w.e.drain_commands();
    let msgs = dev.recv(&w.e.take_out());
    let order: Vec<u32> = msgs
        .iter()
        .flatten()
        .filter(|f| f.kind == FrameType::Data)
        .map(|f| f.stream_id)
        .collect();
    assert_eq!(
        &order[..6],
        [t1, t2, t1, t2, t1, t2],
        "interactive streams alternate"
    );
    assert!(order[6..].iter().all(|s| *s == bulk));
    assert_eq!(
        order[6..].len(),
        4,
        "bulk stops at its 64 KiB stream window"
    );
    assert_eq!(msgs[0].len(), 3, "three 16 KiB frames fill a message");
    // credit for the rest of the bulk message
    let g = dev.table.grant(bulk, 65_536).unwrap();
    dev.send(&mut w, &[g], 0);
    let msgs = dev.recv(&w.e.take_out());
    assert_eq!(
        msgs.concat()
            .iter()
            .filter(|f| f.stream_id == bulk)
            .map(|f| f.data.len())
            .sum::<usize>(),
        100_000 - 65_536
    );
}

#[test]
fn close_follows_queued_data_and_reset_drops_it() {
    let mut w = world();
    let mut dev = open_dev(&mut w, 1);
    let (a, f) = dev.table.open(&terminal()).unwrap();
    let (b, g) = dev.table.open(&terminal()).unwrap();
    dev.send(&mut w, &[f, g], 0);
    w.e.take_out();
    let c = dev.circuit;
    let h = &w.handle;
    h.send(c, a, b"one".to_vec()).unwrap();
    h.push(Command::CloseStream {
        circuit: c,
        stream: a,
    })
    .unwrap();
    h.send(c, b, vec![0; 100_000]).unwrap();
    h.push(Command::ResetStream {
        circuit: c,
        stream: b,
        code: 5,
    })
    .unwrap();
    w.e.drain_commands();
    let frames = dev.recv(&w.e.take_out()).concat();
    let seen: Vec<(u32, FrameType)> = frames.iter().map(|f| (f.stream_id, f.kind)).collect();
    // the reset is urgent and drops the queued data; the close waited for its stream's data
    assert_eq!(
        seen,
        [
            (b, FrameType::Reset),
            (a, FrameType::Data),
            (a, FrameType::Close)
        ]
    );
}

fn fingerprint(id: &Identity) -> [u8; 32] {
    id.public_bundle().bundle.fingerprint().unwrap()
}

#[test]
fn closing_by_device_reaches_every_phase_at_once_and_only_that_device() {
    let mut w = world();
    w.policy.0.lock().unwrap().push_back(Admission::Pending);
    let (mut p, outs) = handshake(&mut w, &device(1), 1, 1, false, 0);
    greeting(&mut p, &outs);
    let mut live = open_dev(&mut w, 2);
    open_dev(&mut w, 3);
    assert_eq!(w.e.len(), 3);
    // a live tunnel: closed on receipt of the event, input afterwards goes nowhere
    w.e.close_where("deviceRevoked", |d| d.device_id == [2; 16]);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [2; 16] }]);
    assert_eq!(log(&w).last().unwrap(), "close deviceRevoked");
    let (id, open) = live.table.open(&terminal()).unwrap();
    let data = live.table.send_data(id, b"x", true).unwrap();
    live.send(&mut w, &[open, data], 1);
    assert!(w.e.take_out().is_empty());
    assert!(!log(&w).iter().any(|l| l.starts_with("stream")));
    // one still waiting for approval
    w.e.close_where("deviceRevoked", |d| d.device_id == [1; 16]);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [1; 16] }]);
    assert_eq!(w.e.len(), 1);
}

#[test]
fn a_tunnel_ends_at_its_attested_expiry_and_a_new_attestation_moves_it() {
    let mut w = world();
    let id = device(1);
    let (mut d, outs) = handshake(&mut w, &id, 1, 1, false, 0); // attests expiresAt 9
    assert_eq!(greeting(&mut d, &outs), welcome());
    assert_eq!(w.e.next_expiry(), Some(9));
    w.e.expire(8);
    assert!(w.e.take_out().is_empty());
    w.e.refresh_device(&DeviceEntry {
        device_id: [1; 16],
        fingerprint: fingerprint(&id),
        client_class: None,
        auth_epoch: 2,
        expires_at: 100,
    });
    w.e.expire(99);
    assert!(w.e.take_out().is_empty());
    w.e.expire(100);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [1; 16] }]);
    assert_eq!(log(&w).last().unwrap(), "close authorizationExpired");
    assert_eq!(w.e.next_expiry(), None);
}

#[test]
fn stale_authority_closes_everything_and_refuses_until_fresh_again() {
    let mut w = world();
    open_dev(&mut w, 1);
    open_dev(&mut w, 2);
    w.e.set_fresh(false);
    let mut outs = w.e.take_out();
    outs.sort_by_key(|o| match o {
        Out::Close { circuit } => *circuit,
        Out::Data { circuit, .. } => *circuit,
    });
    assert_eq!(
        outs,
        [
            Out::Close { circuit: [1; 16] },
            Out::Close { circuit: [2; 16] }
        ]
    );
    assert_eq!(log(&w).last().unwrap(), "close staleAuthority");
    w.e.on_circuit_open(&event([3; 16], &device(3), 1), 0);
    assert_eq!(w.e.take_out(), [Out::Close { circuit: [3; 16] }]);
    assert!(w.e.is_empty());
    w.e.set_fresh(false); // already stale: nothing more to close
    assert!(w.e.take_out().is_empty());
    w.e.set_fresh(true);
    open_dev(&mut w, 4);
    assert_eq!(w.e.len(), 1);
}

#[test]
fn set_level_command_raises_only_that_devices_live_tunnels() {
    struct Spy(Arc<Mutex<Vec<(CircuitId, Level)>>>);
    impl TunnelService for Spy {
        fn on_stream_open(
            &mut self,
            _: &mut Streams<'_>,
            _: u32,
            _: &OpenParams,
        ) -> Result<(), u16> {
            Ok(())
        }
        fn on_message(&mut self, s: &mut Streams<'_>, _: u32, _: Vec<u8>) {
            self.0.lock().unwrap().push((s.circuit(), s.level()));
        }
        fn on_tunnel_close(&mut self, _: CircuitId, _: &str) {}
    }
    let seen = Arc::new(Mutex::new(Vec::new()));
    let mut w = world();
    let handle = Handle::new(|| {});
    let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
    w.host = host.public_bundle();
    w.e = Engine::new(
        Config {
            identity: host,
            host_id: HOST_ID,
            contract_hash: HASH,
        },
        Box::new(Scripted::default()),
        Box::new(Spy(seen.clone())),
        handle.clone(),
    )
    .unwrap();
    let ids = [device(1), device(2)];
    let mut devs: Vec<Dev> = ids
        .iter()
        .zip([1, 2])
        .map(|(id, n)| {
            let (mut d, outs) = handshake(&mut w, id, n, 1, false, 0);
            assert_eq!(greeting(&mut d, &outs), welcome());
            d
        })
        .collect();
    let say = |w: &mut World, d: &mut Dev| {
        let (id, open) = d.table.open(&terminal()).unwrap();
        let data = d.table.send_data(id, b"x", true).unwrap();
        d.send(w, &[open, data], 1);
    };
    handle
        .push(Command::SetLevel {
            fingerprint: fingerprint(&ids[0]),
            level: Level::Control,
        })
        .unwrap();
    w.e.drain_commands();
    for d in &mut devs {
        say(&mut w, d);
    }
    assert_eq!(
        *seen.lock().unwrap(),
        [([1; 16], Level::Control), ([2; 16], Level::Read)]
    );
}

#[test]
fn control_commands_pass_a_full_inbox_and_a_refused_send_reports_writable() {
    let h = Handle::new(|| {});
    let big = || Command::Send {
        circuit: [1; 16],
        stream: 2,
        data: vec![0; MAX_INBOX_BYTES],
    };
    h.push(big()).unwrap();
    assert!(h.push(big()).is_err(), "data is refused when full");
    for c in [
        Command::CloseTunnel { circuit: [1; 16] },
        Command::Deny { circuit: [1; 16] },
        Command::CloseDevice {
            fingerprint: [1; 32],
        },
        Command::SetLevel {
            fingerprint: [1; 32],
            level: Level::Read,
        },
    ] {
        assert!(h.push(c).is_ok());
    }
}

#[test]
fn a_refused_send_tells_the_service_nothing_is_in_flight() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct Spy(Arc<AtomicUsize>);
    impl TunnelService for Spy {
        fn on_stream_open(
            &mut self,
            _: &mut Streams<'_>,
            _: u32,
            _: &OpenParams,
        ) -> Result<(), u16> {
            Ok(())
        }
        fn on_message(&mut self, _: &mut Streams<'_>, _: u32, _: Vec<u8>) {}
        fn on_writable(&mut self, _: &mut Streams<'_>, _: u32) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
        fn on_tunnel_close(&mut self, _: CircuitId, _: &str) {}
    }
    let writable = Arc::new(AtomicUsize::new(0));
    let mut w = world();
    let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
    w.host = host.public_bundle();
    w.e = Engine::new(
        Config {
            identity: host,
            host_id: HOST_ID,
            contract_hash: HASH,
        },
        Box::new(Scripted::default()),
        Box::new(Spy(writable.clone())),
        w.handle.clone(),
    )
    .unwrap();
    let mut dev = open_dev(&mut w, 1);
    let (id, open) = dev.table.open(&terminal()).unwrap();
    dev.send(&mut w, &[open], 1);
    // a message over 1 MiB cannot be queued: the engine refuses it
    w.handle
        .send(dev.circuit, id, vec![0; MAX_LOGICAL_MESSAGE + 1])
        .unwrap();
    w.e.drain_commands();
    assert_eq!(writable.load(Ordering::SeqCst), 1);
}

#[test]
fn one_device_cannot_fill_all_handshake_slots() {
    let mut w = world();
    let greedy = device(1);
    for c in 1..=(MAX_HANDSHAKES_PER_DEVICE as u8 + 1) {
        w.e.on_circuit_open(&event([c; 16], &greedy, 1), 0);
    }
    assert_eq!(w.e.len(), MAX_HANDSHAKES_PER_DEVICE);
    w.e.take_out();
    // another device still gets in
    w.e.on_circuit_open(&event([0x20; 16], &device(2), 1), 0);
    assert_eq!(w.e.len(), MAX_HANDSHAKES_PER_DEVICE + 1);
}
