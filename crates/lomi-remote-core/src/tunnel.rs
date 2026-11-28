//! Device side of the Host tunnel (`03-protokol.md` sections 3-6), sans-I/O, running on top of a
//! relay [`link`](crate::link) that is Ready. The bridge routes the link's circuit traffic here
//! (see `bridge.rs`), so the platform never handles circuit frames itself.
//!
//! Life cycle: `Idle` -start-> `Opening` (CALL `circuit.open` + Noise message 1 sent back to back)
//! -REPLY-> `Handshake` -message 2-> `Greeting` (message 3 with `hello` sent) -> `Approval`
//! (Host shows a code; same 6 digits are computed here) -> `Open` | `Closed`. Message 4 is the
//! first transport message: a [`HostGreeting`] (not a frame batch). Deadlines: 10 s from `start`
//! to the greeting, 120 s for the approval; both end in `Closed` through [`Tunnel::tick`].
//!
//! `StaleEpoch`: the epochs in `hello` are replaced by the Host's, the old circuit is closed and
//! the handshake runs once more on a new circuit; a second `StaleEpoch` closes the tunnel. The new
//! circuit id and nonce are derived (SHA-256) from the platform's 32 random bytes, so a retry needs
//! no second round trip to the platform. (Noise ephemeral keys come from the OS RNG inside snow.)
//!
//! Any failure (decrypt error, protocol violation, `circuit.closed`, link loss, deadline) closes
//! the tunnel with a reason. Requests in flight on stream 0 are then reported as
//! [`Event::OutcomeUnknown`] and are never resent: the platform opens a new tunnel explicitly.

use crate::json::Object;
use crate::link::{CallError, LinkEvent, Output};
use lomi_remote_crypto::{
    Identity, MAX_TUNNEL_PLAINTEXT, SignedBundle, Tunnel as Noise, TunnelHandshake, TunnelPath,
    TunnelPrologue,
};
use lomi_remote_protocol::RequestId;
use lomi_remote_protocol::tunnel::{
    APPROVAL_DEADLINE_MS, FrameType, Hello, HostGreeting, MAX_FRAME_DATA, MAX_LOGICAL_MESSAGE,
    OlderSide, OpenParams, Side, StaleEpoch, StreamKind, StreamTable, TunnelFrame, decode_frames,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

/// Time from `start` until the Host's greeting.
pub const HANDSHAKE_MS: u64 = 10_000;
type Id = [u8; 16];

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Dashed lowercase UUID text of 16 bytes (the relay's `circuit.open` `hostId`).
pub fn uuid_text(b: &[u8; 16]) -> String {
    let h = hex(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// Lowercase hex of exactly `N` bytes.
pub fn unhex<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != 2 * N || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; N];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

pub struct Params {
    /// Device identity; kept until the tunnel is open or closed, then dropped (zeroized).
    pub identity: Identity,
    pub host: SignedBundle,
    pub pinned_host_fingerprint: [u8; 32],
    pub contract_hash: [u8; 32],
    pub account_id: Id,
    pub host_id: Id,
    /// Sent in message 3 (epochs known to the client, resume list, ...).
    pub hello: Hello,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// `opening`, `handshake` or `awaitingGreeting`.
    State(&'static str),
    /// `deadline` is monotonic ms. `code` is also what the Host shows.
    ApprovalPending {
        code: String,
        deadline: u64,
    },
    Open {
        directory: bool,
    },
    Closed {
        reason: String,
    },
    UpdateRequired {
        older: OlderSide,
    },
    /// The Host's current epochs; the handshake is retried (once) with them.
    StaleEpoch(StaleEpoch),
    /// A request sent on stream 0 got no answer before the tunnel closed; it may have run.
    OutcomeUnknown {
        request_id: String,
    },
    StreamOpened {
        stream: u32,
        params: OpenParams,
    },
    /// One complete logical message.
    Message {
        stream: u32,
        data: Vec<u8>,
    },
    StreamClosed {
        stream: u32,
    },
    StreamReset {
        stream: u32,
        code: u16,
    },
}

/// What the bridge has to do after a tunnel call.
#[derive(Debug, Clone, PartialEq)]
pub enum Out {
    /// A relay call (`circuit.open`, `circuit.close`); report its id with [`Tunnel::call_started`].
    Call {
        name: &'static str,
        args: Object,
    },
    /// Opaque bytes for the circuit (`Link::send_data`).
    Data {
        circuit: Id,
        bytes: Vec<u8>,
    },
    Event(Event),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Opening,
    Handshake,
    Greeting,
    Approval,
    Open,
    Closed,
}

pub struct Tunnel {
    identity: Option<Identity>,
    host: SignedBundle,
    pin: [u8; 32],
    contract_hash: [u8; 32],
    account_id: Id,
    host_id: Id,
    hello: Hello,
    phase: Phase,
    deadline: Option<(u64, &'static str)>,
    circuit: Id,
    random: [u8; 32],
    retried: bool,
    hs: Option<TunnelHandshake>,
    code: Option<String>,
    noise: Option<Noise>,
    table: StreamTable,
    /// Chunks (one frame each, `fin` on the last of a message) waiting for credit.
    queues: BTreeMap<u32, VecDeque<(Vec<u8>, bool)>>,
    rpc: Vec<String>,
    cursors: BTreeMap<u32, (StreamKind, u64)>,
    open_call: Option<u32>,
    close_calls: Vec<u32>,
}

fn code(e: impl std::fmt::Debug) -> String {
    let s = format!("{e:?}");
    s[..1].to_lowercase() + &s[1..]
}

impl Tunnel {
    pub fn new(p: Params) -> Self {
        Self {
            identity: Some(p.identity),
            host: p.host,
            pin: p.pinned_host_fingerprint,
            contract_hash: p.contract_hash,
            account_id: p.account_id,
            host_id: p.host_id,
            hello: p.hello,
            phase: Phase::Idle,
            deadline: None,
            circuit: [0; 16],
            random: [0; 32],
            retried: false,
            hs: None,
            code: None,
            noise: None,
            table: StreamTable::new(Side::Device),
            queues: BTreeMap::new(),
            rpc: Vec::new(),
            cursors: BTreeMap::new(),
            open_call: None,
            close_calls: Vec::new(),
        }
    }

    /// `random` (platform RNG) yields circuit id (first 16 bytes) and nonce (last 16).
    pub fn start(&mut self, random: [u8; 32], now: u64) -> Result<Vec<Out>, String> {
        if self.phase != Phase::Idle {
            return Err("started".into());
        }
        let mut out = Vec::new();
        self.begin(random, now, &mut out);
        Ok(out)
    }

    fn begin(&mut self, random: [u8; 32], now: u64, out: &mut Vec<Out>) {
        self.random = random;
        self.circuit.copy_from_slice(&random[..16]);
        let mut nonce = [0u8; 16];
        nonce.copy_from_slice(&random[16..]);
        let m1 = match self.handshake(nonce) {
            Ok(m) => m,
            Err(_) => return self.finish("handshake", false, out),
        };
        self.phase = Phase::Opening;
        self.deadline = Some((now + HANDSHAKE_MS, "handshakeTimeout"));
        out.push(Out::Event(Event::State("opening")));
        let mut args = Object::new();
        args.insert("hostId".into(), uuid_text(&self.host_id).into());
        args.insert("circuitId".into(), hex(&self.circuit).into());
        args.insert("nonce".into(), hex(&nonce).into());
        out.push(Out::Call {
            name: "circuit.open",
            args,
        });
        out.push(Out::Data {
            circuit: self.circuit,
            bytes: m1,
        });
    }

    /// Builds the device handshake for the current circuit and returns Noise message 1.
    fn handshake(&mut self, nonce: [u8; 16]) -> Result<Vec<u8>, String> {
        let id = self.identity.as_ref().ok_or("identity disposed")?;
        let prologue = TunnelPrologue {
            contract_hash: self.contract_hash,
            path: TunnelPath::Relay,
            circuit_id: self.circuit,
            nonce,
            host_id: self.host_id,
            host_fingerprint: self.pin,
            device_fingerprint: id.public_bundle().bundle.fingerprint()?,
            account_id: self.account_id,
        };
        let mut hs = TunnelHandshake::device(id, &prologue, &self.host, &self.pin)?;
        let m1 = hs.write_message(&[])?;
        self.hs = Some(hs);
        Ok(m1)
    }

    pub fn call_started(&mut self, name: &str, id: u32) {
        if name == "circuit.open" {
            self.open_call = Some(id);
        } else {
            self.close_calls.push(id);
        }
    }

    /// The bridge could not hand an [`Out`] to the link.
    pub fn fail(&mut self, reason: &str) -> Vec<Out> {
        let mut out = Vec::new();
        self.finish(reason, false, &mut out);
        out
    }

    pub fn close(&mut self) -> Vec<Out> {
        let mut out = Vec::new();
        self.finish("requested", true, &mut out);
        out
    }

    pub fn is_open(&self) -> bool {
        self.phase == Phase::Open
    }

    pub fn next_deadline(&self) -> Option<u64> {
        self.deadline.map(|d| d.0)
    }

    pub fn tick(&mut self, now: u64) -> Vec<Out> {
        let mut out = Vec::new();
        if let Some((_, why)) = self.deadline.filter(|d| now >= d.0) {
            self.finish(why, true, &mut out);
        }
        out
    }

    /// Feeds one link output. Returns whether the tunnel consumed it (the platform must not see it)
    /// and what to do next. Link loss closes the tunnel but is still shown to the platform.
    pub fn on_link(&mut self, o: &Output, now: u64) -> (bool, Vec<Out>) {
        let mut out = Vec::new();
        let live = !matches!(self.phase, Phase::Idle | Phase::Closed);
        let consumed = match o {
            Output::Data { circuit_id, bytes } if live && *circuit_id == self.circuit => {
                self.on_data(bytes, now, &mut out);
                true
            }
            Output::Event(LinkEvent::CallDone { call_id, result }) => {
                if self.open_call == Some(*call_id) {
                    self.open_call = None;
                    match result {
                        Err(e) if live => {
                            let why = match e {
                                CallError::Remote(c) => c.to_lowercase(),
                                CallError::Timeout => "timeout".into(),
                                _ => "linkDown".into(),
                            };
                            self.finish(&why, false, &mut out);
                        }
                        Ok(_) if self.phase == Phase::Opening => {
                            self.phase = Phase::Handshake;
                            out.push(Out::Event(Event::State("handshake")));
                        }
                        _ => {}
                    }
                    true
                } else if let Some(i) = self.close_calls.iter().position(|c| c == call_id) {
                    self.close_calls.remove(i);
                    true
                } else {
                    false
                }
            }
            Output::Event(LinkEvent::Server { name, data })
                if live
                    && name == "circuit.closed"
                    && data.get("circuitId").and_then(Value::as_str)
                        == Some(&hex(&self.circuit)) =>
            {
                let why = data
                    .get("reason")
                    .and_then(Value::as_str)
                    .unwrap_or("peer_closed");
                self.finish(why, false, &mut out);
                true
            }
            Output::Event(LinkEvent::Disconnected { .. } | LinkEvent::Stopped(_)) => {
                if live {
                    self.finish("linkDown", false, &mut out);
                }
                false
            }
            _ => false,
        };
        (consumed, out)
    }

    fn on_data(&mut self, bytes: &[u8], now: u64, out: &mut Vec<Out>) {
        if matches!(self.phase, Phase::Opening | Phase::Handshake) {
            return self.on_message2(bytes, out);
        }
        let plain = match self.noise.as_mut().map(|n| n.decrypt(bytes)) {
            Some(Ok(p)) => p,
            _ => return self.finish("decrypt", true, out), // also poisons the Noise state
        };
        match self.phase {
            Phase::Greeting | Phase::Approval => match HostGreeting::decode(&plain) {
                Ok(g) => self.on_greeting(g, now, out),
                Err(_) => self.finish("protocol", true, out),
            },
            Phase::Open => self.on_frames(&plain, out),
            _ => {}
        }
    }

    /// Noise message 2 in, message 3 (with `hello`) out; the transport starts here.
    fn on_message2(&mut self, bytes: &[u8], out: &mut Vec<Out>) {
        let Some(mut hs) = self.hs.take() else { return };
        let hello = &self.hello;
        let step = (|| -> Result<(Vec<u8>, String, Noise), String> {
            hs.read_message(bytes)?;
            let m3 = hs.write_message(&hello.encode().map_err(code)?)?;
            let c = hs.confirmation_code()?;
            Ok((m3, c, hs.into_transport()?))
        })();
        let Ok((m3, c, noise)) = step else {
            return self.finish("handshake", true, out);
        };
        (self.noise, self.code, self.phase) = (Some(noise), Some(c), Phase::Greeting);
        out.push(Out::Data {
            circuit: self.circuit,
            bytes: m3,
        });
        out.push(Out::Event(Event::State("awaitingGreeting")));
    }

    fn on_greeting(&mut self, g: HostGreeting, now: u64, out: &mut Vec<Out>) {
        match (g, self.phase) {
            (HostGreeting::Welcome(w), _) => {
                self.phase = Phase::Open;
                self.deadline = None;
                self.identity = None;
                out.push(Out::Event(Event::Open {
                    directory: w.directory,
                }));
            }
            (HostGreeting::ApprovalPending(p), Phase::Greeting) => {
                let code = self.code.clone().unwrap_or_default();
                if format!("{:06}", p.code) != code {
                    return self.finish("codeMismatch", true, out);
                }
                let deadline = now + u64::from(p.deadline_ms).min(u64::from(APPROVAL_DEADLINE_MS));
                self.phase = Phase::Approval;
                self.deadline = Some((deadline, "approvalTimeout"));
                out.push(Out::Event(Event::ApprovalPending { code, deadline }));
            }
            (HostGreeting::StaleEpoch(s), Phase::Greeting) if !self.retried => {
                self.retried = true;
                self.hello.auth_epoch = s.auth_epoch;
                self.hello.host_access_epoch = s.host_access_epoch;
                self.hello.runtime_generation = s.runtime_generation;
                out.push(Out::Event(Event::StaleEpoch(s)));
                out.push(self.close_call());
                (self.noise, self.hs, self.code) = (None, None, None);
                let d = Sha256::digest(
                    [b"lomi-remote/circuit-retry".as_slice(), &self.random].concat(),
                );
                let mut r = [0u8; 32];
                r.copy_from_slice(&d);
                self.begin(r, now, out);
            }
            (HostGreeting::StaleEpoch(_), Phase::Greeting) => self.finish("staleEpoch", true, out),
            (HostGreeting::UpdateRequired(u), Phase::Greeting) => {
                out.push(Out::Event(Event::UpdateRequired {
                    older: u.older_side,
                }));
                self.finish("updateRequired", true, out);
            }
            _ => self.finish("protocol", true, out),
        }
    }

    fn close_call(&self) -> Out {
        let mut args = Object::new();
        args.insert("circuitId".into(), hex(&self.circuit).into());
        Out::Call {
            name: "circuit.close",
            args,
        }
    }

    fn on_frames(&mut self, plain: &[u8], out: &mut Vec<Out>) {
        let Ok(frames) = decode_frames(plain) else {
            return self.finish("protocol", true, out);
        };
        let mut reply = Vec::new();
        for f in &frames {
            let Ok(ev) = self.table.on_frame(f) else {
                return self.finish("protocol", true, out);
            };
            let n = f.data.len() as u32;
            if f.kind == FrameType::Data && n > 0 {
                // Everything is handed to the platform at once, so the windows are reopened now
                // (needed anyway for messages larger than one stream window).
                reply.extend(self.table.grant(0, n).ok());
                if f.stream_id != 0 && self.table.kind_of(f.stream_id).is_some() {
                    reply.extend(self.table.grant(f.stream_id, n).ok());
                }
            }
            use lomi_remote_protocol::tunnel::Event as E;
            match ev {
                Some(E::Opened { stream_id, params }) => {
                    out.push(Out::Event(Event::StreamOpened {
                        stream: stream_id,
                        params,
                    }))
                }
                Some(E::Message { stream_id, data }) => {
                    if stream_id == 0 {
                        let id = serde_json::from_slice::<Value>(&data)
                            .ok()
                            .and_then(|v| v.get("requestId")?.as_str().map(str::to_owned));
                        self.rpc.retain(|r| Some(r) != id.as_ref());
                    }
                    out.push(Out::Event(Event::Message {
                        stream: stream_id,
                        data,
                    }));
                }
                Some(E::Closed { stream_id }) => {
                    self.forget(stream_id);
                    out.push(Out::Event(Event::StreamClosed { stream: stream_id }));
                }
                Some(E::Reset { stream_id, code }) => {
                    self.forget(stream_id);
                    out.push(Out::Event(Event::StreamReset {
                        stream: stream_id,
                        code,
                    }));
                }
                None => {}
            }
        }
        self.pack(reply, out);
        self.flush(out); // CREDIT frames may have opened a window
    }

    fn forget(&mut self, stream: u32) {
        self.queues.remove(&stream);
        self.cursors.remove(&stream);
    }

    /// `kind` as in the OPEN frame; the id comes back for the platform to address the stream.
    pub fn open_stream(&mut self, params: &OpenParams) -> Result<(u32, Vec<Out>), String> {
        self.ensure_open()?;
        let (id, frame) = self.table.open(params).map_err(code)?;
        let mut out = Vec::new();
        self.pack(vec![frame], &mut out);
        Ok((id, out))
    }

    /// Queues one logical message (any size up to 1 MiB; stream 0 takes an `RpcEnvelope` as JSON)
    /// and sends what the windows allow; the rest follows when the Host grants credit.
    pub fn send(&mut self, stream: u32, payload: &[u8]) -> Result<Vec<Out>, String> {
        self.ensure_open()?;
        if self.table.kind_of(stream).is_none() {
            return Err("unknownStream".into());
        }
        let queued: usize = self
            .queues
            .get(&stream)
            .map_or(0, |q| q.iter().map(|c| c.0.len()).sum());
        if payload.len() > MAX_LOGICAL_MESSAGE {
            return Err("tooLarge".into());
        }
        if queued + payload.len() > MAX_LOGICAL_MESSAGE {
            return Err("backpressure".into());
        }
        if stream == 0 {
            let id = rpc_request_id(payload).ok_or("badRpc")?;
            if self.rpc.contains(&id) {
                return Err("duplicateRequest".into());
            }
            self.rpc.push(id);
        }
        let chunks: Vec<&[u8]> = if payload.is_empty() {
            vec![payload]
        } else {
            payload.chunks(MAX_FRAME_DATA).collect()
        };
        let q = self.queues.entry(stream).or_default();
        for (i, c) in chunks.iter().enumerate() {
            q.push_back((c.to_vec(), i + 1 == chunks.len()));
        }
        let mut out = Vec::new();
        self.flush(&mut out);
        Ok(out)
    }

    pub fn close_stream(&mut self, stream: u32) -> Result<Vec<Out>, String> {
        self.ensure_open()?;
        let frame = self.table.close(stream).map_err(code)?;
        self.forget(stream);
        let mut out = Vec::new();
        self.pack(vec![frame], &mut out);
        Ok(out)
    }

    /// Records the resume cursor of a live stream (the platform's stream decoder knows what a
    /// cursor means; the core only keeps it). It is dropped when the stream is closed or reset.
    pub fn set_cursor(&mut self, stream: u32, cursor: u64) -> Result<(), String> {
        match self.table.kind_of(stream) {
            Some(k) if stream != 0 => {
                self.cursors.insert(stream, (k, cursor));
                Ok(())
            }
            _ => Err("unknownStream".into()),
        }
    }

    /// `(stream, kind, cursor)`: what the next tunnel's `hello.resume` can be built from.
    pub fn cursors(&self) -> Vec<(u32, StreamKind, u64)> {
        self.cursors
            .iter()
            .map(|(s, (k, c))| (*s, *k, *c))
            .collect()
    }

    fn ensure_open(&self) -> Result<(), String> {
        if self.phase == Phase::Open {
            Ok(())
        } else {
            Err("notOpen".into())
        }
    }

    /// Sends queued chunks while stream and tunnel windows allow.
    /// shortcut: streams are served in id order, no class priority (interactive > control > bulk
    /// is P3a.7 on the Host); only per-stream order is kept. Upgrade with the Host scheduler.
    fn flush(&mut self, out: &mut Vec<Out>) {
        let mut frames = Vec::new();
        for (id, q) in self.queues.iter_mut() {
            while let Some((chunk, fin)) = q.front() {
                if chunk.len() as u64 > self.table.send_credit(*id) {
                    break;
                }
                match self.table.send_data(*id, chunk, *fin) {
                    Ok(f) => {
                        frames.push(f);
                        q.pop_front();
                    }
                    Err(_) => q.clear(), // stream is gone
                }
            }
        }
        self.queues.retain(|_, q| !q.is_empty());
        self.pack(frames, out);
    }

    /// Batches frames into as few Noise messages as fit `MAX_TUNNEL_PLAINTEXT`.
    fn pack(&mut self, frames: Vec<TunnelFrame>, out: &mut Vec<Out>) {
        let mut plain = Vec::new();
        for f in &frames {
            let before = plain.len();
            if f.encode_into(&mut plain).is_err() {
                return self.finish("protocol", true, out);
            }
            if plain.len() > MAX_TUNNEL_PLAINTEXT {
                let tail = plain.split_off(before);
                self.seal(&plain, out);
                plain = tail;
            }
        }
        if !plain.is_empty() {
            self.seal(&plain, out);
        }
    }

    fn seal(&mut self, plain: &[u8], out: &mut Vec<Out>) {
        match self.noise.as_mut().map(|n| n.encrypt(plain)) {
            Some(Ok(bytes)) => out.push(Out::Data {
                circuit: self.circuit,
                bytes,
            }),
            _ => self.finish("encrypt", true, out),
        }
    }

    /// Closes once; `notify` also asks the relay to drop the circuit.
    fn finish(&mut self, reason: &str, notify: bool, out: &mut Vec<Out>) {
        if self.phase == Phase::Closed {
            return;
        }
        let started = self.phase != Phase::Idle;
        self.phase = Phase::Closed;
        (self.deadline, self.identity, self.hs, self.noise, self.code) =
            (None, None, None, None, None);
        self.queues.clear();
        for request_id in std::mem::take(&mut self.rpc) {
            out.push(Out::Event(Event::OutcomeUnknown { request_id }));
        }
        out.push(Out::Event(Event::Closed {
            reason: reason.to_owned(),
        }));
        if notify && started {
            out.push(self.close_call());
        }
    }
}

/// Stream-open parameters from JSON (`kind` plus `params`, camelCase as in the protocol DTOs).
pub fn open_params(kind: &str, params: Value) -> Result<OpenParams, String> {
    let bad = |_| "badParams".to_owned();
    Ok(match kind {
        "directory" => OpenParams::Directory,
        "terminal" => OpenParams::Terminal(serde_json::from_value(params).map_err(bad)?),
        "chat" => OpenParams::Chat(serde_json::from_value(params).map_err(bad)?),
        "files.watch" => OpenParams::FilesWatch(serde_json::from_value(params).map_err(bad)?),
        "transfer" => OpenParams::Transfer(serde_json::from_value(params).map_err(bad)?),
        _ => return Err("unknownKind".into()),
    })
}

/// Wire name of a stream kind (`terminal`, `files.watch`, ...).
pub fn kind_name(k: StreamKind) -> Value {
    json!(k)
}

/// Envelope shape and request id only. Decoding `RpcCall` here would pull its whole serde
/// decoder (~200 KB) into the web WASM; the Host validates the call itself.
fn rpc_request_id(payload: &[u8]) -> Option<String> {
    let serde_json::Value::Object(o) = serde_json::from_slice(payload).ok()? else {
        return None;
    };
    // `workspaceId` is optional: only calls without a workspace of their own (chat) need it.
    let workspace = o.get("workspaceId");
    if o.len() != 3 + usize::from(workspace.is_some())
        || workspace.is_some_and(|w| {
            !w.as_str()
                .is_some_and(|w| lomi_remote_protocol::WorkspaceId::try_from(w.to_owned()).is_ok())
        })
        || !o.get("call")?.is_object()
        || !(1..=120_000).contains(&o.get("timeoutMs")?.as_u64()?)
    {
        return None;
    }
    let id = o.get("requestId")?.as_str()?;
    RequestId::try_from(id.to_owned())
        .ok()
        .map(|r| r.as_str().to_owned())
}

#[cfg(test)]
mod envelope_tests {
    use super::rpc_request_id;

    #[test]
    fn envelope_shape() {
        let ok = br#"{"requestId":"r1","timeoutMs":5000,"call":{"method":"x"}}"#;
        assert_eq!(rpc_request_id(ok).as_deref(), Some("r1"));
        let scoped = br#"{"requestId":"r1","timeoutMs":5000,"workspaceId":"11111111-1111-4111-8111-111111111111","call":{}}"#;
        assert_eq!(rpc_request_id(scoped).as_deref(), Some("r1"));
        let bad_workspace = br#"{"requestId":"r1","timeoutMs":5000,"workspaceId":"x","call":{}}"#;
        assert!(rpc_request_id(bad_workspace).is_none());
        for bad in [
            &br#"{"requestId":"r1","timeoutMs":0,"call":{}}"#[..],
            br#"{"requestId":"r1","timeoutMs":5,"call":1}"#,
            br#"{"requestId":"r1","timeoutMs":5,"call":{},"v":2}"#,
            br#"{"requestId":"","timeoutMs":5,"call":{}}"#,
            b"[]",
        ] {
            assert!(rpc_request_id(bad).is_none());
        }
    }
}
