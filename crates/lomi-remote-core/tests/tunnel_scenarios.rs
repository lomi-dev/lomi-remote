//! Client tunnel through the bridge (link + tunnel handles) against a fake Host built from the
//! crypto and protocol crates. Bytes in, records out; no network, a hand-driven clock.

use lomi_remote_core::bridge;
use lomi_remote_core::frame::{Direction, Frame, MAX_FRAME_BYTES, decode_frame, encode_frame};
use lomi_remote_core::tunnel::{hex, unhex};
use lomi_remote_crypto::{Identity, Role, SignedBundle, Tunnel as Noise, TunnelHandshake};
use lomi_remote_crypto::{TunnelPath, TunnelPrologue};
use lomi_remote_protocol::tunnel::{
    ApprovalPending, Event as PEvent, FrameType, Hello, HostGreeting, OlderSide, OpenParams, Side,
    StaleEpoch, StreamTable, TunnelFrame, UpdateRequired, Welcome, decode_frames,
};
use serde_json::{Value, json};

const VECTORS: &str = include_str!("../test-vectors/relay-frames.v1.json");
const HASH: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const WALL0: u64 = 1_794_999_000_000;
const ACCOUNT: [u8; 16] = [0xa1; 16];
const HOST_ID: [u8; 16] = [0xb2; 16];
const DEVICE_ID: [u8; 16] = [0xc3; 16];
const U: &str = "11111111-1111-4111-8111-111111111111";

// ---- bridge helpers ----

#[derive(Debug, Clone)]
enum Rec {
    Connect,
    Send(Vec<u8>),
    Close,
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
        out.push(match b[0] {
            1 => Rec::Connect,
            2 => Rec::Send(body),
            3 => Rec::Close,
            4 => Rec::Ev(serde_json::from_slice(&body).unwrap()),
            5 => Rec::Msg(
                u32::from_be_bytes(body[..4].try_into().unwrap()),
                body[4..].to_vec(),
            ),
            t => panic!("tag {t}"),
        });
        b = &b[5 + n..];
    }
    out
}

fn evs(r: &[Rec]) -> Vec<Value> {
    r.iter()
        .filter_map(|x| {
            if let Rec::Ev(v) = x {
                Some(v.clone())
            } else {
                None
            }
        })
        .collect()
}

/// `tunnelState` values in order (`closed` as `closed:<reason>`).
fn states(r: &[Rec]) -> Vec<String> {
    evs(r)
        .iter()
        .filter(|e| e["type"] == "tunnelState")
        .map(|e| match e["state"].as_str().unwrap() {
            "closed" => format!("closed:{}", e["reason"].as_str().unwrap()),
            s => s.to_owned(),
        })
        .collect()
}

fn ev_of(r: &[Rec], ty: &str) -> Vec<Value> {
    evs(r).into_iter().filter(|e| e["type"] == ty).collect()
}

enum Sent {
    Call {
        id: u32,
        name: String,
        args: serde_json::Map<String, Value>,
    },
    Data {
        bytes: Vec<u8>,
    },
}

fn sent(r: &[Rec]) -> Vec<Sent> {
    r.iter()
        .filter_map(|x| {
            let Rec::Send(b) = x else { return None };
            if b[0] == 0x10 {
                return Some(Sent::Data {
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

fn datas(r: &[Rec]) -> Vec<Vec<u8>> {
    sent(r)
        .into_iter()
        .filter_map(|s| {
            if let Sent::Data { bytes, .. } = s {
                Some(bytes)
            } else {
                None
            }
        })
        .collect()
}

fn vector(name: &str) -> Vec<u8> {
    let d: Value = serde_json::from_str(VECTORS).unwrap();
    let v = d["valid"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["name"] == name)
        .unwrap();
    unhex_vec(v["hex"].as_str().unwrap())
}

fn unhex_vec(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn relay_frame(f: &Frame) -> Vec<u8> {
    encode_frame(f, MAX_FRAME_BYTES).unwrap()
}

fn rpc(id: &str) -> Vec<u8> {
    format!(
        r#"{{"requestId":"{id}","timeoutMs":1000,"call":{{"method":"workspace.get","params":{{"context":{{"workspaceId":"{U}","workspaceEpoch":"{U}","runtimeId":"{U}","runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"}}}}}}}}"#
    )
    .into_bytes()
}

// ---- fake Host ----

struct FakeHost {
    hs: Option<TunnelHandshake>,
    noise: Option<Noise>,
    table: StreamTable,
    circuit: [u8; 16],
    hello: Option<Hello>,
    code: String,
}

impl FakeHost {
    /// Answers `circuit.open` args and message 1; returns the host and the relay frame with message 2.
    fn accept(
        host: &Identity,
        device: &SignedBundle,
        args: &serde_json::Map<String, Value>,
        m1: &[u8],
    ) -> (Self, Vec<u8>) {
        let id = |k: &str| unhex::<16>(args[k].as_str().unwrap()).unwrap();
        let prologue = TunnelPrologue {
            contract_hash: unhex(HASH).unwrap(),
            path: TunnelPath::Relay,
            circuit_id: id("circuitId"),
            nonce: id("nonce"),
            host_id: HOST_ID,
            host_fingerprint: host.public_bundle().bundle.fingerprint().unwrap(),
            device_fingerprint: device.bundle.fingerprint().unwrap(),
            account_id: ACCOUNT,
        };
        let mut hs = TunnelHandshake::host(host, &prologue).unwrap();
        hs.read_message(m1).unwrap();
        let m2 = hs.write_message(&[]).unwrap();
        let h = Self {
            hs: Some(hs),
            noise: None,
            table: StreamTable::new(Side::Host),
            circuit: prologue.circuit_id,
            hello: None,
            code: String::new(),
        };
        let f = h.frame(&m2);
        (h, f)
    }

    fn frame(&self, ct: &[u8]) -> Vec<u8> {
        [&[0x10][..], &self.circuit, ct].concat()
    }

    fn on_m3(&mut self, m3: &[u8], device: &SignedBundle) {
        let mut hs = self.hs.take().unwrap();
        let hello = hs.read_message(m3).unwrap();
        self.hello = Some(Hello::decode(&hello).unwrap());
        hs.verify_device(device).unwrap();
        self.code = hs.confirmation_code().unwrap();
        self.noise = Some(hs.into_transport().unwrap());
    }

    fn greet(&mut self, g: HostGreeting) -> Vec<u8> {
        let ct = self
            .noise
            .as_mut()
            .unwrap()
            .encrypt(&g.encode().unwrap())
            .unwrap();
        self.frame(&ct)
    }

    /// Frames to one relay DATA frame (one Noise message).
    fn send(&mut self, frames: &[TunnelFrame]) -> Vec<u8> {
        let mut plain = Vec::new();
        frames
            .iter()
            .for_each(|f| f.encode_into(&mut plain).unwrap());
        let ct = self.noise.as_mut().unwrap().encrypt(&plain).unwrap();
        self.frame(&ct)
    }

    /// Decrypts one DATA frame from the device and runs it through the stream table.
    fn recv(&mut self, data: &[u8]) -> (Vec<TunnelFrame>, Vec<PEvent>) {
        let plain = self.noise.as_mut().unwrap().decrypt(data).unwrap();
        let frames = decode_frames(&plain).unwrap();
        let events = frames
            .iter()
            .filter_map(|f| self.table.on_frame(f).unwrap())
            .collect();
        (frames, events)
    }
}

// ---- rig ----

struct Rig {
    link: u32,
    tun: u32,
    device: Identity,
    host: Identity,
    now: u64,
    /// The link's own next deadline (token refresh), before any tunnel exists.
    base: Option<u64>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        bridge::free(self.tun);
        bridge::free(self.link);
    }
}

impl Rig {
    fn new(resume: Value) -> Self {
        let device = Identity::generate(ACCOUNT, DEVICE_ID, Role::Device, 1).unwrap();
        let host = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
        let link = handle(&call(
            0,
            "link.new",
            json!({"contractHash": HASH, "seed": 1, "silenceMs": 0}),
            &[],
        ));
        let mut rig = Rig {
            link,
            tun: 0,
            device,
            host,
            now: 0,
            base: None,
        };
        let a = rig.at(json!({"token": "T".repeat(24), "expiresAt": WALL0 + 1_000_000}));
        call(link, "link.start", a, &[]);
        call(link, "link.onOpen", rig.at(json!({})), &[]);
        call(
            link,
            "link.onMessage",
            rig.at(json!({})),
            &vector("ready-device"),
        );
        rig.base = rig.deadline();
        rig.tun = rig.new_tunnel(resume, 1, 2, 3);
        rig
    }

    fn new_tunnel(&self, resume: Value, auth: u64, access: u64, generation: u64) -> u32 {
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
                "deviceName": "Phone", "deviceKind": "mobile", "authEpoch": auth,
                "hostAccessEpoch": access, "runtimeGeneration": generation,
                "resume": resume, "sendDirectory": true,
            },
        });
        handle(&call(0, "tunnel.new", args, &seed))
    }

    fn at(&self, mut v: Value) -> Value {
        v["monoMs"] = json!(self.now);
        v["wallMs"] = json!(WALL0 + self.now);
        v
    }

    fn relay(&self, bytes: &[u8]) -> Vec<Rec> {
        recs(&call(
            self.link,
            "link.onMessage",
            self.at(json!({})),
            bytes,
        ))
    }

    fn op(&self, op: &str, args: Value, payload: &[u8]) -> Vec<Rec> {
        recs(&call(self.tun, op, self.at(args), payload))
    }

    fn deadline(&self) -> Option<u64> {
        let v: Value =
            serde_json::from_slice(&call(self.link, "link.nextDeadline", json!({}), &[])).unwrap();
        v["deadline"].as_u64()
    }

    /// Starts the tunnel: (circuit.open call id, args, message 1).
    fn start(&self, fill: u8) -> (u32, serde_json::Map<String, Value>, Vec<u8>, Vec<Rec>) {
        let r = self.op("tunnel.start", json!({"random": hex(&[fill; 32])}), &[]);
        let s = sent(&r);
        let (Sent::Call { id, name, args }, Sent::Data { bytes, .. }) = (&s[0], &s[1]) else {
            panic!("CALL then DATA expected")
        };
        assert_eq!(name, "circuit.open");
        // the relay takes the Host id as a dashed UUID (relay-frames vector `call-circuit-open`)
        assert_eq!(args["hostId"], "b2b2b2b2-b2b2-b2b2-b2b2-b2b2b2b2b2b2");
        assert_eq!(s.len(), 2);
        (*id, args.clone(), bytes.clone(), r)
    }

    /// Runs a handshake attempt up to the Host having read the hello; returns the Host.
    fn attempt(&self, fill: u8) -> FakeHost {
        let (id, args, m1, r) = self.start(fill);
        assert_eq!(states(&r), ["opening"]);
        self.attempt_from(id, &args, &m1)
    }

    fn attempt_from(&self, id: u32, args: &serde_json::Map<String, Value>, m1: &[u8]) -> FakeHost {
        let (mut host, m2) = FakeHost::accept(&self.host, &self.device.public_bundle(), args, m1);
        let r = self.relay(&relay_frame(&Frame::ReplyOk {
            call_id: id,
            data: Default::default(),
        }));
        assert_eq!(states(&r), ["handshake"]);
        let r = self.relay(&m2);
        assert_eq!(states(&r), ["awaitingGreeting"]);
        host.on_m3(&datas(&r)[0], &self.device.public_bundle());
        host
    }

    fn open(&self, fill: u8) -> FakeHost {
        let mut host = self.attempt(fill);
        let r = self.relay(&host.greet(HostGreeting::Welcome(Welcome { directory: true })));
        assert_eq!(states(&r), ["open"]);
        host
    }
}

fn handle(b: &[u8]) -> u32 {
    serde_json::from_slice::<Value>(b).unwrap()["handle"]
        .as_u64()
        .unwrap() as u32
}

fn terminal_params() -> Value {
    json!({"workspaceId": U, "paneId": U, "sessionEpoch": U, "cols": 80, "rows": 24})
}

// ---- scenarios ----

#[test]
fn open_rpc_directory_and_flow_controlled_terminal() {
    let rig = Rig::new(json!([]));
    let mut host = rig.open(1);
    assert_eq!(host.hello.as_ref().unwrap().auth_epoch, 1);
    assert!(host.hello.as_ref().unwrap().send_directory);
    assert_eq!(
        rig.deadline(),
        rig.base,
        "only the link's own deadline is left"
    );

    // rpc round trip on stream 0
    let r = rig.op("tunnel.send", json!({"stream": 0}), &rpc("r1"));
    let (_, ev) = host.recv(&datas(&r)[0]);
    assert!(matches!(&ev[..], [PEvent::Message { stream_id: 0, .. }]));
    let reply = host
        .table
        .send_data(0, br#"{"requestId":"r1","type":"result"}"#, true)
        .unwrap();
    let r = rig.relay(&host.send(&[reply]));
    assert!(matches!(&r[0], Rec::Msg(0, d) if d.starts_with(b"{\"requestId\":\"r1\"")));
    datas(&r).iter().for_each(|d| {
        host.recv(d);
    }); // the core's CREDIT frames

    // Host-opened directory stream
    let (id, open) = host.table.open(&OpenParams::Directory).unwrap();
    let data = host.table.send_data(id, b"dir-snapshot", true).unwrap();
    let r = rig.relay(&host.send(&[open, data]));
    let opened = ev_of(&r, "streamOpened");
    assert_eq!(
        (opened[0]["stream"].as_u64(), opened[0]["kind"].as_str()),
        (Some(2), Some("directory"))
    );
    assert!(
        r.iter()
            .any(|x| matches!(x, Rec::Msg(2, d) if d == b"dir-snapshot"))
    );
    // the core gives the windows back (CREDIT frames), so the Host can go on
    for d in datas(&r) {
        host.recv(&d);
    }
    assert!(host.table.send_credit(2) > 60_000);

    // terminal: 100000 bytes against a 64 KiB stream window
    let r = rig.op(
        "tunnel.openStream",
        json!({"kind": "terminal", "params": terminal_params()}),
        &[],
    );
    assert_eq!(ev_of(&r, "streamStarted")[0]["stream"], 1);
    let (_, ev) = host.recv(&datas(&r)[0]);
    assert!(matches!(&ev[..], [PEvent::Opened { stream_id: 1, .. }]));
    let payload = vec![7u8; 100_000];
    let r = rig.op("tunnel.send", json!({"stream": 1}), &payload);
    let msgs = datas(&r);
    assert_eq!(msgs.len(), 2, "four 16 KiB frames need two Noise messages");
    let (mut got, mut done) = (0, false);
    for m in &msgs {
        let (frames, ev) = host.recv(m);
        got += frames
            .iter()
            .filter(|f| f.kind == FrameType::Data)
            .map(|f| f.data.len())
            .sum::<usize>();
        done |= !ev.is_empty();
    }
    assert_eq!((got, done), (65_536, false), "blocked at the window");
    let credit = host.table.grant(1, 65_536).unwrap();
    let r = rig.relay(&host.send(&[credit]));
    let rest = datas(&r);
    assert_eq!(rest.len(), 1);
    let (_, ev) = host.recv(&rest[0]);
    assert!(matches!(&ev[..], [PEvent::Message { stream_id: 1, data }] if *data == payload));

    // cursors are kept per live stream
    call(
        rig.tun,
        "tunnel.cursors",
        json!({"stream": 1, "cursor": 42}),
        &[],
    );
    let c: Value =
        serde_json::from_slice(&call(rig.tun, "tunnel.cursors", json!({}), &[])).unwrap();
    assert_eq!(
        c,
        json!({"cursors": [{"stream": 1, "kind": "terminal", "cursor": 42}]})
    );
    // closing the stream drops its cursor
    let r = rig.op("tunnel.closeStream", json!({"stream": 1}), &[]);
    host.recv(&datas(&r)[0]);
    let c: Value =
        serde_json::from_slice(&call(rig.tun, "tunnel.cursors", json!({}), &[])).unwrap();
    assert_eq!(c, json!({"cursors": []}));
}

#[test]
fn approval_pending_shows_the_same_code_then_welcome() {
    let mut rig = Rig::new(json!([]));
    let mut host = rig.attempt(1);
    rig.now = 1_000;
    let code: u32 = host.code.parse().unwrap();
    let r = rig.relay(&host.greet(HostGreeting::ApprovalPending(ApprovalPending {
        code,
        deadline_ms: 120_000,
    })));
    let e = &ev_of(&r, "tunnelState")[0];
    assert_eq!(
        (
            e["state"].as_str(),
            e["code"].as_str(),
            e["deadline"].as_u64()
        ),
        (
            Some("approvalPending"),
            Some(host.code.as_str()),
            Some(121_000)
        )
    );
    assert_eq!(rig.deadline(), Some(121_000));
    let r = rig.relay(&host.greet(HostGreeting::Welcome(Welcome { directory: false })));
    assert_eq!(states(&r), ["open"]);
    assert_eq!(
        rig.deadline(),
        rig.base,
        "only the link's own deadline is left"
    );
}

#[test]
fn control_pending_shows_the_own_code_and_a_wrong_one_closes() {
    let mut rig = Rig::new(json!([]));
    let mut host = rig.open(1);
    rig.now = 5_000;
    let code: u32 = host.code.parse().unwrap();
    let frame = |c| TunnelFrame::control_pending(c, 120_000).unwrap();
    let r = rig.relay(&host.send(&[frame(code)]));
    let e = &ev_of(&r, "controlPending")[0];
    assert_eq!(e["code"].as_str(), Some(host.code.as_str()));
    assert_eq!(e["deadline"].as_u64(), Some(125_000));
    let r = rig.relay(&host.send(&[frame((code + 1) % 1_000_000)]));
    let closed = &ev_of(&r, "tunnelState")[0];
    assert_eq!(closed["reason"].as_str(), Some("codeMismatch"));
}

#[test]
fn approval_deadline_closes_and_releases_the_circuit() {
    let mut rig = Rig::new(json!([]));
    let mut host = rig.attempt(1);
    let code: u32 = host.code.parse().unwrap();
    rig.relay(&host.greet(HostGreeting::ApprovalPending(ApprovalPending {
        code,
        deadline_ms: 120_000,
    })));
    rig.now = 119_999;
    assert!(recs(&call(rig.link, "link.tick", rig.at(json!({})), &[])).is_empty());
    rig.now = 120_000;
    let r = recs(&call(rig.link, "link.tick", rig.at(json!({})), &[]));
    assert_eq!(states(&r), ["closed:approvalTimeout"]);
    assert!(matches!(&sent(&r)[..], [Sent::Call { name, .. }] if name == "circuit.close"));
    assert!(
        rig.deadline().is_none_or(|d| d > 120_000),
        "only the link's own deadline is left"
    );
}

#[test]
fn a_wrong_approval_code_closes() {
    let rig = Rig::new(json!([]));
    let mut host = rig.attempt(1);
    let code = (host.code.parse::<u32>().unwrap() + 1) % 1_000_000;
    let r = rig.relay(&host.greet(HostGreeting::ApprovalPending(ApprovalPending {
        code,
        deadline_ms: 1000,
    })));
    assert_eq!(states(&r), ["closed:codeMismatch"]);
}

#[test]
fn stale_epoch_retries_once_on_a_new_circuit() {
    let rig = Rig::new(json!([]));
    let (id, args, m1, _) = rig.start(1);
    let mut host = rig.attempt_from(id, &args, &m1);
    let stale = StaleEpoch {
        auth_epoch: 7,
        host_access_epoch: 8,
        runtime_generation: 9,
    };
    let r = rig.relay(&host.greet(HostGreeting::StaleEpoch(stale.clone())));
    assert_eq!(ev_of(&r, "staleEpoch")[0]["authEpoch"], 7);
    let s = sent(&r);
    let [
        Sent::Call {
            name: close,
            args: cargs,
            ..
        },
        Sent::Call {
            id: id2,
            name: open,
            args: args2,
        },
        Sent::Data { bytes: m1b, .. },
    ] = &s[..]
    else {
        panic!("close old, open new, message 1")
    };
    assert_eq!(
        (close.as_str(), open.as_str()),
        ("circuit.close", "circuit.open")
    );
    assert_eq!(cargs["circuitId"], args["circuitId"]);
    assert_ne!(args2["circuitId"], args["circuitId"]);
    assert_ne!(args2["nonce"], args["nonce"]);
    assert_eq!(states(&r), ["opening"]);
    // the second attempt carries the Host's epochs and succeeds
    let mut host2 = rig.attempt_from(*id2, args2, m1b);
    let h = host2.hello.as_ref().unwrap();
    assert_eq!(
        (h.auth_epoch, h.host_access_epoch, h.runtime_generation),
        (7, 8, 9)
    );
    let r = rig.relay(&host2.greet(HostGreeting::Welcome(Welcome { directory: true })));
    assert_eq!(states(&r), ["open"]);
    // late traffic of the first circuit is ignored
    let r = rig.relay(&host.greet(HostGreeting::Welcome(Welcome { directory: true })));
    assert!(states(&r).is_empty());
}

#[test]
fn a_second_stale_epoch_closes() {
    let rig = Rig::new(json!([]));
    let (id, args, m1, _) = rig.start(1);
    let mut host = rig.attempt_from(id, &args, &m1);
    let stale = StaleEpoch {
        auth_epoch: 7,
        host_access_epoch: 8,
        runtime_generation: 9,
    };
    let r = rig.relay(&host.greet(HostGreeting::StaleEpoch(stale.clone())));
    let s = sent(&r);
    let (
        Sent::Call {
            id: id2,
            args: args2,
            ..
        },
        Sent::Data { bytes, .. },
    ) = (&s[1], &s[2])
    else {
        panic!()
    };
    let mut host2 = rig.attempt_from(*id2, args2, bytes);
    let r = rig.relay(&host2.greet(HostGreeting::StaleEpoch(stale)));
    assert_eq!(states(&r), ["closed:staleEpoch"]);
    assert!(
        sent(&r)
            .iter()
            .all(|s| matches!(s, Sent::Call { name, .. } if name == "circuit.close"))
    );
}

#[test]
fn update_required_reports_the_older_side() {
    let rig = Rig::new(json!([]));
    let mut host = rig.attempt(1);
    let r = rig.relay(&host.greet(HostGreeting::UpdateRequired(UpdateRequired {
        older_side: OlderSide::Host,
    })));
    assert_eq!(ev_of(&r, "updateRequired")[0]["olderSide"], "host");
    assert_eq!(states(&r), ["closed:updateRequired"]);
}

#[test]
fn a_host_with_the_wrong_static_key_closes() {
    let rig = Rig::new(json!([]));
    let (id, args, m1, _) = rig.start(1);
    // Same ids, another key pair: the pinned fingerprint is in the prologue, so message 2 fails.
    let impostor = Identity::generate(ACCOUNT, HOST_ID, Role::Host, 1).unwrap();
    let (_, m2) = FakeHost::accept(&impostor, &rig.device.public_bundle(), &args, &m1);
    rig.relay(&relay_frame(&Frame::ReplyOk {
        call_id: id,
        data: Default::default(),
    }));
    let r = rig.relay(&m2);
    assert_eq!(states(&r), ["closed:handshake"]);
    assert!(
        datas(&r).is_empty(),
        "no message 3 for an unauthenticated Host"
    );
}

#[test]
fn a_tampered_frame_closes_and_inflight_rpc_is_never_resent() {
    let rig = Rig::new(json!([]));
    let mut host = rig.open(1);
    let r = rig.op("tunnel.send", json!({"stream": 0}), &rpc("r1"));
    assert_eq!(datas(&r).len(), 1);
    let reply = host
        .table
        .send_data(0, br#"{"requestId":"zzz"}"#, true)
        .unwrap();
    let mut bad = host.send(&[reply]);
    *bad.last_mut().unwrap() ^= 1;
    let r = rig.relay(&bad);
    assert_eq!(ev_of(&r, "outcomeUnknown")[0]["requestId"], "r1");
    assert_eq!(states(&r), ["closed:decrypt"]);
    assert!(datas(&r).is_empty(), "nothing is resent");
    // closed for good: the platform has to open a new tunnel
    let err = bridge::call(
        rig.tun,
        "tunnel.send",
        &serde_json::to_vec(&rig.at(json!({"stream": 0}))).unwrap(),
        &rpc("r2"),
    );
    assert_eq!(err[0], 1);
}

#[test]
fn circuit_closed_from_the_relay_closes() {
    let rig = Rig::new(json!([]));
    let host = rig.open(1);
    rig.op("tunnel.send", json!({"stream": 0}), &rpc("r1"));
    let mut data = serde_json::Map::new();
    data.insert("circuitId".into(), hex(&host.circuit).into());
    data.insert("reason".into(), "peer_closed".into());
    let r = rig.relay(&relay_frame(&Frame::Event {
        name: "circuit.closed".into(),
        data,
    }));
    assert_eq!(ev_of(&r, "outcomeUnknown")[0]["requestId"], "r1");
    assert_eq!(states(&r), ["closed:peer_closed"]);
    assert!(sent(&r).is_empty(), "the relay already dropped the circuit");
    assert!(ev_of(&r, "server").is_empty());
}

#[test]
fn handshake_deadline_is_ten_seconds() {
    let mut rig = Rig::new(json!([]));
    rig.now = 500;
    rig.start(1);
    assert_eq!(rig.deadline(), Some(10_500));
    rig.now = 10_499;
    assert!(recs(&call(rig.link, "link.tick", rig.at(json!({})), &[])).is_empty());
    rig.now = 10_500;
    let r = recs(&call(rig.link, "link.tick", rig.at(json!({})), &[]));
    assert_eq!(states(&r), ["closed:handshakeTimeout"]);
}

#[test]
fn link_loss_and_open_errors_close() {
    let rig = Rig::new(json!([]));
    rig.start(1);
    let r = recs(&call(rig.link, "link.onClose", rig.at(json!({})), &[]));
    assert_eq!(states(&r), ["closed:linkDown"]);
    assert_eq!(
        ev_of(&r, "disconnected").len(),
        1,
        "the link event still reaches the platform"
    );

    let rig = Rig::new(json!([]));
    let (id, ..) = rig.start(1);
    let r = rig.relay(&relay_frame(&Frame::ReplyErr {
        call_id: id,
        code: "UNAVAILABLE".into(),
    }));
    assert_eq!(states(&r), ["closed:unavailable"]);
    assert!(
        ev_of(&r, "callDone").is_empty(),
        "the tunnel's own call result is not shown"
    );
}

#[test]
fn resume_cursors_go_into_the_next_hello() {
    let resume = json!([{"kind": "terminal", "cursor": 42}, {"kind": "chat", "cursor": 7}]);
    let rig = Rig::new(resume);
    let host = rig.open(1);
    let h = host.hello.unwrap();
    let got: Vec<(String, u64)> = h
        .resume
        .0
        .iter()
        .map(|e| {
            (
                serde_json::to_value(e.kind)
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .to_owned(),
                e.cursor,
            )
        })
        .collect();
    assert_eq!(got, [("terminal".to_owned(), 42), ("chat".to_owned(), 7)]);
    // the device bundle travels in the hello
    assert_eq!(
        serde_json::from_slice::<SignedBundle>(&h.device_bundle.0).unwrap(),
        rig.device.public_bundle()
    );
}
