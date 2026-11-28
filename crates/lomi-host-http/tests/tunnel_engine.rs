//! Cross-check: the real device core (`lomi-remote-core` bridge, link + tunnel ops) against the
//! real Host tunnel engine. A small in-memory relay turns the device's `circuit.open`/DATA into
//! the Host's EVENT/DATA and back. Hand-driven clock, no sockets.

use lomi_host_http::uplink::tunnels::{testing::*, *};
use lomi_remote_core::bridge;
use lomi_remote_core::frame::{Direction, Frame, MAX_FRAME_BYTES, decode_frame, encode_frame};
use lomi_remote_core::tunnel::{hex, unhex};
use lomi_remote_crypto::{Identity, Role};
use serde_json::{Value, json};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

const VECTORS: &str = include_str!("../../lomi-remote-core/test-vectors/relay-frames.v1.json");
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WALL0: u64 = 1_794_999_000_000;
const ACCOUNT: [u8; 16] = [0xa1; 16];
const HOST_ID: [u8; 16] = [0xb2; 16];
const DEVICE_ID: [u8; 16] = [0xc3; 16];
const U: &str = "11111111-1111-4111-8111-111111111111";

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
fn ev_of(r: &[Rec], ty: &str) -> Vec<Value> {
    r.iter()
        .filter_map(|x| match x {
            Rec::Ev(v) if v["type"] == ty => Some(v.clone()),
            _ => None,
        })
        .collect()
}
/// `tunnelState` values in order (`closed` as `closed:<reason>`).
fn states(r: &[Rec]) -> Vec<String> {
    ev_of(r, "tunnelState")
        .iter()
        .map(|e| match e["state"].as_str().unwrap() {
            "closed" => format!("closed:{}", e["reason"].as_str().unwrap()),
            s => s.to_owned(),
        })
        .collect()
}
fn msgs(r: &[Rec], stream: u32) -> Vec<&Vec<u8>> {
    r.iter()
        .filter_map(|x| match x {
            Rec::Msg(s, d) if *s == stream => Some(d),
            _ => None,
        })
        .collect()
}

enum Sent {
    Call {
        id: u32,
        name: String,
        args: serde_json::Map<String, Value>,
    },
    Data {
        circuit: CircuitId,
        bytes: Vec<u8>,
    },
}
fn sent(r: &[Rec]) -> Vec<Sent> {
    r.iter()
        .filter_map(|x| {
            let Rec::Send(b) = x else { return None };
            if b[0] == DATA {
                return Some(Sent::Data {
                    circuit: b[1..17].try_into().unwrap(),
                    bytes: b[17..].to_vec(),
                });
            }
            match decode_frame(b, Direction::Client, MAX_FRAME_BYTES).unwrap() {
                Frame::Call {
                    call_id,
                    name,
                    args,
                } => Some(Sent::Call {
                    id: call_id,
                    name,
                    args,
                }),
                f => panic!("unexpected {f:?}"),
            }
        })
        .collect()
}
fn relay_frame(f: &Frame) -> Vec<u8> {
    encode_frame(f, MAX_FRAME_BYTES).unwrap()
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
fn handle(b: &[u8]) -> u32 {
    serde_json::from_slice::<Value>(b).unwrap()["handle"]
        .as_u64()
        .unwrap() as u32
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
fn rpc(id: &str) -> Vec<u8> {
    format!(
        r#"{{"requestId":"{id}","timeoutMs":1000,"call":{{"method":"workspace.get","params":{{"context":{{"workspaceId":"{U}","workspaceEpoch":"{U}","runtimeId":"{U}","runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"}}}}}}}}"#
    )
    .into_bytes()
}
fn terminal_params() -> Value {
    json!({"workspaceId": U, "paneId": U, "sessionEpoch": U, "cols": 80, "rows": 24})
}

struct Rig {
    link: u32,
    tuns: Vec<u32>,
    device: Identity,
    host: Identity,
    engine: Engine,
    handle: Handle,
    log: Arc<Mutex<Vec<String>>>,
    attested_epoch: u64,
    now: u64,
    /// Circuits the Host asked the relay to close.
    host_closes: Vec<CircuitId>,
    /// Circuits the device opened, in order.
    opened: Vec<CircuitId>,
    drop_device_data: bool,
    tamper_next: bool,
}
impl Drop for Rig {
    fn drop(&mut self) {
        self.tuns.iter().for_each(|t| bridge::free(*t));
        bridge::free(self.link);
    }
}
impl Rig {
    fn new(policy: Box<dyn Policy>, attested_epoch: u64) -> Self {
        let device = Identity::generate(ACCOUNT, DEVICE_ID, Role::Device, 1).unwrap();
        let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
        let link = handle(&call(
            0,
            "link.new",
            json!({"contractHash": HASH, "seed": 1, "silenceMs": 0}),
            &[],
        ));
        let at = |v: Value| {
            let mut v = v;
            v["monoMs"] = json!(0);
            v["wallMs"] = json!(WALL0);
            v
        };
        let token = at(json!({"token": "T".repeat(24), "expiresAt": WALL0 + 1_000_000}));
        call(link, "link.start", token, &[]);
        call(link, "link.onOpen", at(json!({})), &[]);
        call(
            link,
            "link.onMessage",
            at(json!({})),
            &vector("ready-device"),
        );
        let echo = Echo::default();
        let log = echo.log.clone();
        let inbox = Handle::new(|| {});
        let engine = Engine::new(
            Config {
                identity: Identity::import_secret_seed_blob(
                    &host.export_secret_seed_blob().unwrap(),
                    &host.public_bundle(),
                )
                .unwrap(),
                host_id: HOST_ID,
                contract_hash: unhex(HASH).unwrap(),
            },
            policy,
            Box::new(echo),
            inbox.clone(),
        )
        .unwrap();
        let mut rig = Rig {
            link,
            tuns: Vec::new(),
            device,
            host,
            engine,
            handle: inbox,
            log,
            attested_epoch,
            now: 0,
            host_closes: Vec::new(),
            opened: Vec::new(),
            drop_device_data: false,
            tamper_next: false,
        };
        rig.new_tunnel();
        rig
    }
    fn new_tunnel(&mut self) -> u32 {
        let seed = self.device.export_secret_seed_blob().unwrap();
        let args = json!({
            "link": self.link,
            "deviceBundle": serde_json::to_value(self.device.public_bundle()).unwrap(),
            "hostBundle": serde_json::to_value(self.host.public_bundle()).unwrap(),
            "hostFingerprint": hex(&self.host.public_bundle().bundle.fingerprint().unwrap()),
            "contractHash": HASH,
            "accountId": hex(&ACCOUNT),
            "hostId": hex(&HOST_ID),
            "hello": {
                "deviceName": "Phone", "deviceKind": "mobile", "authEpoch": 1,
                "hostAccessEpoch": 2, "runtimeGeneration": 3, "resume": [], "sendDirectory": true,
            },
        });
        let t = handle(&call(0, "tunnel.new", args, &seed));
        self.tuns.push(t);
        t
    }
    fn at(&self, mut v: Value) -> Value {
        v["monoMs"] = json!(self.now);
        v["wallMs"] = json!(WALL0 + self.now);
        v
    }
    fn to_device(&self, bytes: &[u8]) -> Vec<Rec> {
        recs(&call(
            self.link,
            "link.onMessage",
            self.at(json!({})),
            bytes,
        ))
    }
    fn closed_event(&self, circuit: &CircuitId, reason: &str) -> Vec<u8> {
        let mut data = serde_json::Map::new();
        data.insert("circuitId".into(), hex(circuit).into());
        data.insert("reason".into(), reason.into());
        relay_frame(&Frame::Event {
            name: "circuit.closed".into(),
            data,
        })
    }
    fn deliver(&mut self, o: Out) -> Vec<Rec> {
        match o {
            Out::Data { circuit, bytes } => {
                self.to_device(&[&[DATA][..], &circuit, &bytes].concat())
            }
            Out::Close { circuit } => {
                self.host_closes.push(circuit);
                self.to_device(&self.closed_event(&circuit, "peer_closed"))
            }
        }
    }
    /// The relay between the two cores: runs both sides until nothing is left to say.
    /// Returns every device record produced on the way.
    fn settle(&mut self, first: Vec<Rec>) -> Vec<Rec> {
        let (mut all, mut work) = (Vec::new(), VecDeque::from([first]));
        while let Some(batch) = work.pop_front() {
            for s in sent(&batch) {
                match s {
                    Sent::Call { id, name, args } => {
                        match name.as_str() {
                            "circuit.open" => {
                                let circuit: CircuitId =
                                    unhex(args["circuitId"].as_str().unwrap()).unwrap();
                                self.opened.push(circuit);
                                let ev = json!({
                                    "circuitId": args["circuitId"], "nonce": args["nonce"],
                                    "device": {
                                        "accountId": dashed(&ACCOUNT), "deviceId": dashed(&DEVICE_ID),
                                        "clientClass": "native",
                                        "attestation": {
                                            "fingerprint": hex(&self.device.public_bundle().bundle.fingerprint().unwrap()),
                                            "authEpoch": self.attested_epoch.to_string(), "expiresAt": WALL0,
                                        },
                                    },
                                });
                                let Value::Object(ev) = ev else {
                                    unreachable!()
                                };
                                self.engine.on_circuit_open(&ev, self.now);
                            }
                            "circuit.close" => {
                                let mut d = serde_json::Map::new();
                                d.insert("circuitId".into(), args["circuitId"].clone());
                                d.insert("reason".into(), "peer_closed".into());
                                self.engine.on_circuit_closed(&d);
                            }
                            n => panic!("unexpected call {n}"),
                        }
                        let reply = relay_frame(&Frame::ReplyOk {
                            call_id: id,
                            data: Default::default(),
                        });
                        work.push_back(self.to_device(&reply));
                    }
                    Sent::Data { circuit, mut bytes } => {
                        if self.drop_device_data {
                            continue;
                        }
                        if std::mem::take(&mut self.tamper_next) {
                            *bytes.last_mut().unwrap() ^= 1;
                        }
                        self.engine
                            .on_data(&[&circuit[..], &bytes].concat(), self.now);
                    }
                }
            }
            all.extend(batch);
            self.engine.drain_commands();
            for o in self.engine.take_out() {
                let r = self.deliver(o);
                work.push_back(r);
            }
        }
        all
    }
    fn op_on(&mut self, tun: u32, op: &str, args: Value, payload: &[u8]) -> Vec<Rec> {
        let r = recs(&call(tun, op, self.at(args), payload));
        self.settle(r)
    }
    fn op(&mut self, op: &str, args: Value, payload: &[u8]) -> Vec<Rec> {
        self.op_on(self.tuns[0], op, args, payload)
    }
    fn start_on(&mut self, tun: u32, fill: u8) -> Vec<Rec> {
        self.op_on(
            tun,
            "tunnel.start",
            json!({"random": hex(&[fill; 32])}),
            &[],
        )
    }
    fn start(&mut self, fill: u8) -> Vec<Rec> {
        self.start_on(self.tuns[0], fill)
    }
    /// Advances the shared clock and runs both sides' deadlines.
    fn tick(&mut self, now: u64) -> Vec<Rec> {
        self.now = now;
        let r = recs(&call(self.link, "link.tick", self.at(json!({})), &[]));
        self.engine.tick(now);
        self.settle(r)
    }
    fn last_circuit(&self) -> CircuitId {
        *self.opened.last().unwrap()
    }
}
fn welcoming() -> Box<dyn Policy> {
    Box::new(Scripted::default())
}
fn pending() -> (Box<dyn Policy>, Scripted) {
    let p = Scripted::default();
    p.0.lock().unwrap().push_back(Admission::Pending);
    (Box::new(p.clone()), p)
}

#[test]
fn open_rpc_directory_and_a_terminal_message_larger_than_the_windows() {
    let mut rig = Rig::new(welcoming(), 1);
    let r = rig.start(1);
    assert_eq!(
        states(&r),
        ["opening", "handshake", "awaitingGreeting", "open"]
    );
    // Host-opened directory stream
    let opened = ev_of(&r, "streamOpened");
    assert_eq!(
        (opened[0]["stream"].as_u64(), opened[0]["kind"].as_str()),
        (Some(2), Some("directory"))
    );
    assert_eq!(msgs(&r, 2), [&b"dir".to_vec()]);
    // rpc round trip on stream 0
    let r = rig.op("tunnel.send", json!({"stream": 0}), &rpc("r1"));
    assert_eq!(msgs(&r, 0), [&rpc("r1")]);
    // terminal: 150000 bytes each way against 64 KiB stream and 256 KiB tunnel windows
    let r = rig.op(
        "tunnel.openStream",
        json!({"kind": "terminal", "params": terminal_params()}),
        &[],
    );
    assert_eq!(ev_of(&r, "streamStarted")[0]["stream"], 1);
    let payload: Vec<u8> = (0..150_000u32).map(|i| (i % 251) as u8).collect();
    let r = rig.op("tunnel.send", json!({"stream": 1}), &payload);
    assert_eq!(msgs(&r, 1), [&payload], "echoed in full");
    assert_eq!(*rig.log.lock().unwrap(), ["open", "stream 1"]);
    assert_eq!(rig.engine.len(), 1);
    // closing the stream: no error on either side
    let r = rig.op("tunnel.closeStream", json!({"stream": 1}), &[]);
    assert!(states(&r).is_empty());
}

#[test]
fn approval_pending_shows_equal_codes_then_approve_welcomes() {
    let (policy, _) = pending();
    let mut rig = Rig::new(policy, 1);
    rig.now = 1_000;
    let r = rig.start(1);
    // the device checks the Host's code against its own and closes on a mismatch
    let e = &ev_of(&r, "tunnelState").last().unwrap().clone();
    assert_eq!(
        (e["state"].as_str(), e["deadline"].as_u64()),
        (Some("approvalPending"), Some(121_000))
    );
    assert_eq!(e["code"].as_str().unwrap().len(), 6);
    assert_eq!(rig.engine.next_deadline(), Some(121_000));
    let c = rig.last_circuit();
    rig.engine.approve(c, Level::Control);
    let r = rig.settle(Vec::new());
    assert_eq!(states(&r), ["open"]);
    assert_eq!(msgs(&r, 2), [&b"dir".to_vec()]);
    assert_eq!(rig.engine.next_deadline(), None);
}

#[test]
fn approval_deadline_is_120_seconds_on_both_sides() {
    let (policy, _) = pending();
    let mut rig = Rig::new(policy, 1);
    rig.start(1);
    assert!(rig.tick(119_999).is_empty());
    let r = rig.tick(120_000);
    assert_eq!(states(&r), ["closed:approvalTimeout"]);
    assert_eq!(rig.host_closes, [rig.last_circuit()]);
    assert!(rig.engine.is_empty());
}

#[test]
fn deny_closes_the_circuit() {
    let (policy, _) = pending();
    let mut rig = Rig::new(policy, 1);
    rig.start(1);
    let c = rig.last_circuit();
    rig.engine.deny(c);
    let r = rig.settle(Vec::new());
    assert_eq!(states(&r), ["closed:peer_closed"]);
    assert!(rig.engine.is_empty() && rig.log.lock().unwrap().is_empty());
}

#[test]
fn stale_epoch_retries_once_on_a_new_circuit_and_succeeds() {
    let policy = AutoRead {
        host_access_epoch: 8,
        runtime_generation: 9,
    };
    // the relay attests auth epoch 7, the device's hello says 1
    let mut rig = Rig::new(Box::new(policy), 7);
    let r = rig.start(1);
    let stale = &ev_of(&r, "staleEpoch")[0];
    assert_eq!(
        (
            stale["authEpoch"].as_u64(),
            stale["hostAccessEpoch"].as_u64()
        ),
        (Some(7), Some(8))
    );
    assert_eq!(states(&r).last().map(String::as_str), Some("open"));
    assert_eq!(rig.opened.len(), 2);
    assert_eq!(rig.engine.len(), 1, "the first circuit is gone");
    assert_eq!(rig.host_closes, [rig.opened[0]]);
}

#[test]
fn a_tampered_data_frame_closes_the_circuit() {
    let mut rig = Rig::new(welcoming(), 1);
    rig.start(1);
    rig.tamper_next = true;
    let r = rig.op("tunnel.send", json!({"stream": 0}), &rpc("r1"));
    assert_eq!(rig.host_closes, [rig.last_circuit()]);
    assert_eq!(states(&r), ["closed:peer_closed"]);
    assert_eq!(ev_of(&r, "outcomeUnknown")[0]["requestId"], "r1");
    assert_eq!(rig.log.lock().unwrap().last().unwrap(), "close decrypt");
    assert!(rig.engine.is_empty());
}

#[test]
fn circuit_closed_from_the_relay_closes_both_sides() {
    let mut rig = Rig::new(welcoming(), 1);
    rig.start(1);
    let c = rig.last_circuit();
    let mut d = serde_json::Map::new();
    d.insert("circuitId".into(), hex(&c).into());
    d.insert("reason".into(), "stale_authority".into());
    rig.engine.on_circuit_closed(&d);
    let r = rig.to_device(&rig.closed_event(&c, "stale_authority"));
    assert_eq!(states(&r), ["closed:stale_authority"]);
    assert!(
        rig.engine.is_empty() && rig.host_closes.is_empty(),
        "the relay already dropped it"
    );
    assert_eq!(
        rig.log.lock().unwrap().last().unwrap(),
        "close stale_authority"
    );
}

#[test]
fn the_ninth_tunnel_of_one_device_is_closed() {
    let mut rig = Rig::new(welcoming(), 1);
    for _ in 0..8 {
        rig.new_tunnel();
    }
    for (i, t) in rig.tuns.clone().into_iter().enumerate() {
        let r = rig.start_on(t, i as u8 + 1);
        let last = states(&r).last().cloned();
        if i < 8 {
            assert_eq!(last.as_deref(), Some("open"), "tunnel {i}");
        } else {
            assert_eq!(last.as_deref(), Some("closed:peer_closed"));
        }
    }
    assert_eq!(rig.engine.len(), 8);
    assert_eq!(rig.host_closes, [rig.last_circuit()]);
}

#[test]
fn interactive_frames_overtake_a_queued_bulk_transfer() {
    let mut rig = Rig::new(welcoming(), 1);
    rig.start(1);
    rig.op(
        "tunnel.openStream",
        json!({"kind": "transfer", "params": {"requestId": "t1"}}),
        &[],
    );
    rig.op(
        "tunnel.openStream",
        json!({"kind": "terminal", "params": terminal_params()}),
        &[],
    );
    let (bulk, term) = (1, 3);
    let c = rig.last_circuit();
    // queue the bulk transfer first, the terminal message after it, in one batch
    rig.handle.send(c, bulk, vec![9; 50_000]).unwrap();
    rig.handle.send(c, term, vec![1; 100]).unwrap();
    rig.engine.drain_commands();
    let mut seen = Vec::new();
    for o in rig.engine.take_out() {
        seen.extend(rig.deliver(o));
    }
    let first = seen.iter().find_map(|r| match r {
        Rec::Msg(s, d) => Some((*s, d.len())),
        _ => None,
    });
    assert_eq!(
        first,
        Some((term, 100)),
        "the terminal message arrives before any bulk message completes"
    );
    // the transfer fits its window, so it is complete right behind the terminal message
    assert_eq!(msgs(&seen, bulk), [&vec![9u8; 50_000]]);
}

#[test]
fn the_handshake_deadline_is_ten_seconds_on_both_sides() {
    let mut rig = Rig::new(welcoming(), 1);
    rig.now = 500;
    rig.drop_device_data = true; // the relay never delivers the device's messages
    rig.start(1);
    assert_eq!(rig.engine.next_deadline(), Some(10_500));
    assert!(rig.tick(10_499).is_empty());
    let r = rig.tick(10_500);
    assert_eq!(states(&r), ["closed:handshakeTimeout"]);
    assert_eq!(rig.host_closes, [rig.last_circuit()]);
    assert!(rig.engine.is_empty());
}
