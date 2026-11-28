//! Host side of the device tunnels (plan-1.0 P3a.7, `03-protokol.md` sections 4 and 5), sans-I/O.
//!
//! The uplink thread feeds relay events and DATA bytes in, reads [`Out`] back and writes them to
//! the link; time comes in as `now` (monotonic ms). One circuit carries one Noise tunnel:
//! `Hs` (message 1 -> 2, then 3 with `hello`) -> `Pending` (approval, 120 s) -> `Live` (streams).
//! A tunnel that fails, times out or is closed by anyone leaves the table; `Out::Close` asks the
//! relay to drop the circuit unless the relay itself said so (`circuit.closed`) or the link is gone.
//!
//! Messages arrive in relay order (event, then DATA on the same socket) and are handled at once,
//! so no DATA is buffered for a circuit that has no state: it was closed or never admitted.
//!
//! The service runs on the uplink thread inside the callbacks below. A blocking service (terminal,
//! files) keeps its own threads and pushes output through [`Handle`], which wakes the uplink.
use lomi_remote_core::{json::Object, tunnel::unhex};
use lomi_remote_crypto::{
    Identity, MAX_TUNNEL_PLAINTEXT, SignedBundle, Tunnel as Noise, TunnelHandshake, TunnelPath,
    TunnelPrologue,
};
use lomi_remote_protocol::tunnel::{
    APPROVAL_DEADLINE_MS, ApprovalPending, Event, FRAME_HEADER_LEN, FrameType, Hello, HostGreeting,
    MAX_FRAME_DATA, MAX_LOGICAL_MESSAGE, OpenParams, Side, StaleEpoch, StreamClass, StreamTable,
    TunnelFrame, Welcome, decode_frames,
};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    sync::{Arc, Mutex, PoisonError},
};

/// First byte of a relay DATA frame: `0x10 | circuitId(16) | tunnel bytes`.
pub const DATA: u8 = 0x10;
pub const HANDSHAKE_MS: u64 = 10_000;
pub const MAX_DEVICES: usize = 8;
pub const MAX_TUNNELS_PER_DEVICE: usize = 8;
/// Tunnels that have not reached `Live` yet (handshake or approval), over all devices.
pub const MAX_HANDSHAKES: usize = 16;
/// Bytes a service may leave in the [`Handle`] queue before `push` refuses.
const MAX_INBOX_BYTES: usize = 8 << 20;

pub type CircuitId = [u8; 16];
pub type Id = [u8; 16];

/// What the relay attested about the device that opened a circuit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AttestedDevice {
    pub account_id: Id,
    pub device_id: Id,
    pub client_class: Option<String>,
    pub fingerprint: [u8; 32],
    pub auth_epoch: u64,
    pub expires_at: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    Read,
    Control,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admission {
    Welcome {
        level: Level,
    },
    Pending,
    /// The Host's current epochs; the device retries once.
    Stale {
        epochs: StaleEpoch,
    },
    Refuse,
}
/// Decides about a device whose bundle, key and attestation already checked out. P3a.10 supplies
/// the real one. A `Welcome` or `Pending` for a `hello.authEpoch` that differs from the attested
/// epoch is turned into a close by the engine.
pub trait Policy: Send {
    fn admit(&self, device: &AttestedDevice, hello: &Hello, code: &str) -> Admission;
    /// What the engine calls: like `admit`, but for a policy that has to find the circuit again
    /// (approvals, control requests).
    fn admit_circuit(
        &self,
        _circuit: CircuitId,
        device: &AttestedDevice,
        hello: &Hello,
        code: &str,
    ) -> Admission {
        self.admit(device, hello, code)
    }
    /// The tunnel left the table, for whatever reason; always called, also after a refusal.
    fn closed(&self, _circuit: CircuitId) {}
}

/// One entry of the account's device list (READY `state.devices`, EVENT `devices.changed`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceEntry {
    pub device_id: Id,
    pub fingerprint: [u8; 32],
    pub client_class: Option<String>,
    pub auth_epoch: u64,
    pub expires_at: u64,
}
impl DeviceEntry {
    pub fn parse(o: &Object) -> Option<Self> {
        let text = |k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
        Some(Self {
            device_id: uuid(&text("deviceId")?)?,
            fingerprint: unhex(&text("fingerprint")?)?,
            client_class: text("clientClass"),
            auth_epoch: epoch(o.get("authEpoch")?)?,
            expires_at: o.get("expiresAt").and_then(Value::as_u64)?,
        })
    }
}
/// What the relay says about the account's devices, as far as consent cares.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeviceEvent {
    /// A link was admitted: the runtime epochs it is bound to and the full device list
    /// (`None`: the server did not send one, which is not "no devices").
    Ready {
        host_access_epoch: u64,
        runtime_generation: u64,
        devices: Option<Vec<DeviceEntry>>,
    },
    Changed(DeviceEntry),
    Revoked {
        device_id: Id,
        fingerprint: Option<[u8; 32]>,
    },
    HostRevoked,
}
impl DeviceEvent {
    /// `devices.changed` without a `deviceId` (the older `grant.changed` shape) is `None`, and so
    /// is anything malformed.
    pub fn from_event(name: &str, data: &Object) -> Option<Self> {
        match name {
            "devices.changed" => DeviceEntry::parse(data).map(Self::Changed),
            "device.revoked" => Some(Self::Revoked {
                device_id: uuid(data.get("deviceId")?.as_str()?)?,
                fingerprint: match data.get("fingerprint") {
                    None | Some(Value::Null) => None,
                    Some(v) => Some(unhex(v.as_str()?)?),
                },
            }),
            _ => None,
        }
    }
}
/// Which tunnels must go after a [`DeviceEvent`].
pub type Closing = Box<dyn Fn(&AttestedDevice) -> bool>;
/// Keeps the Host's consent in step with the account's device list.
pub trait Roster: Send {
    fn apply(&mut self, event: &DeviceEvent) -> Option<Closing>;
}
/// Welcomes every device with `Read`; stale only on the attested auth epoch.
pub struct AutoRead {
    pub host_access_epoch: u64,
    pub runtime_generation: u64,
}
impl Policy for AutoRead {
    fn admit(&self, device: &AttestedDevice, hello: &Hello, _: &str) -> Admission {
        if hello.auth_epoch == device.auth_epoch {
            return Admission::Welcome { level: Level::Read };
        }
        Admission::Stale {
            epochs: StaleEpoch {
                auth_epoch: device.auth_epoch,
                host_access_epoch: self.host_access_epoch,
                runtime_generation: self.runtime_generation,
            },
        }
    }
}

/// The real terminal, chat, files and RPC (P3a.9). All callbacks run on the uplink thread and must
/// not block; `s` addresses the tunnel the call is about.
pub trait TunnelService: Send {
    fn on_tunnel_open(&mut self, _s: &mut Streams<'_>, _device: &AttestedDevice) {}
    /// A device-opened stream (kinds already checked). `Err(code)` resets it.
    fn on_stream_open(
        &mut self,
        s: &mut Streams<'_>,
        stream: u32,
        params: &OpenParams,
    ) -> Result<(), u16>;
    /// One complete logical message; stream 0 carries the RPC envelope. Credit is already given
    /// back, so a slow service must bound its own queue.
    fn on_message(&mut self, s: &mut Streams<'_>, stream: u32, data: Vec<u8>);
    /// The peer closed (`None`) or reset the stream.
    fn on_stream_close(&mut self, _s: &mut Streams<'_>, _stream: u32, _reset: Option<u16>) {}
    /// Everything queued on `stream` has been handed to the tunnel (credit was available).
    fn on_writable(&mut self, _s: &mut Streams<'_>, _stream: u32) {}
    /// Only after `on_tunnel_open`.
    fn on_tunnel_close(&mut self, circuit: CircuitId, reason: &str);
    /// First snapshot for the `directory` stream (the device asked with `sendDirectory`).
    fn directory(&mut self, device: &AttestedDevice) -> Vec<u8>;
}

/// Service access to one live tunnel from inside a callback.
pub struct Streams<'a> {
    circuit: CircuitId,
    live: &'a mut Live,
}
impl Streams<'_> {
    pub fn circuit(&self) -> CircuitId {
        self.circuit
    }
    pub fn level(&self) -> Level {
        self.live.level
    }
    /// Opens a Host-owned stream (`directory`, `transfer`); returns its id.
    pub fn open(&mut self, params: &OpenParams) -> Result<u32, &'static str> {
        self.live.open(params)
    }
    /// Queues one logical message (up to 1 MiB); it is sent as credit allows.
    pub fn send(&mut self, stream: u32, data: &[u8]) -> Result<(), &'static str> {
        self.live.send(stream, data)
    }
    /// Closes after everything queued has been sent.
    pub fn close(&mut self, stream: u32) -> Result<(), &'static str> {
        self.live.close(stream)
    }
    /// Drops what is queued and resets at once.
    pub fn reset(&mut self, stream: u32, code: u16) {
        self.live.reset(stream, code)
    }
    /// Bytes still waiting for credit.
    pub fn queued(&self, stream: u32) -> usize {
        self.live.queues.get(&stream).map_or(0, |q| q.bytes)
    }
}

/// Output for the link, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Out {
    /// One relay DATA frame body (tunnel bytes) for the circuit.
    Data { circuit: CircuitId, bytes: Vec<u8> },
    /// CALL `circuit.close`.
    Close { circuit: CircuitId },
}

#[derive(Debug)]
pub enum Command {
    Send {
        circuit: CircuitId,
        stream: u32,
        data: Vec<u8>,
    },
    CloseStream {
        circuit: CircuitId,
        stream: u32,
    },
    /// Opens a Host-owned stream (a `transfer`) and answers with its id. Dropping the command
    /// unanswered (the tunnel is gone) makes the receiver fail.
    OpenStream {
        circuit: CircuitId,
        params: OpenParams,
        reply: std::sync::mpsc::SyncSender<Result<u32, &'static str>>,
    },
    ResetStream {
        circuit: CircuitId,
        stream: u32,
        code: u16,
    },
    CloseTunnel {
        circuit: CircuitId,
    },
    Approve {
        circuit: CircuitId,
        level: Level,
    },
    /// Sets the level of every live tunnel of the device (control confirmed on the Host).
    SetLevel {
        fingerprint: [u8; 32],
        level: Level,
    },
    Deny {
        circuit: CircuitId,
    },
    /// Tells the device the owner is asked to confirm control (`Control` frame on stream 0).
    ControlPending {
        circuit: CircuitId,
        code: u32,
    },
    /// Closes every tunnel of the device (the owner revoked it on the Host).
    CloseDevice {
        fingerprint: [u8; 32],
    },
}
impl Command {
    fn size(&self) -> usize {
        64 + match self {
            Self::Send { data, .. } => data.len(),
            _ => 0,
        }
    }
}
struct Inbox {
    queue: Mutex<(VecDeque<Command>, usize)>,
    wake: Box<dyn Fn() + Send + Sync>,
}
/// Thread-safe way to push into the engine; the uplink thread applies it on its next turn.
#[derive(Clone)]
pub struct Handle(Arc<Inbox>);
impl Handle {
    pub fn new(wake: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Arc::new(Inbox {
            queue: Mutex::default(),
            wake: Box::new(wake),
        }))
    }
    /// Refuses (hands the command back) while more than 8 MiB is waiting.
    pub fn push(&self, c: Command) -> Result<(), Command> {
        {
            let mut q = self.0.queue.lock().unwrap_or_else(PoisonError::into_inner);
            if q.1 >= MAX_INBOX_BYTES {
                return Err(c);
            }
            q.1 += c.size();
            q.0.push_back(c);
        }
        (self.0.wake)();
        Ok(())
    }
    pub fn send(&self, circuit: CircuitId, stream: u32, data: Vec<u8>) -> Result<(), Command> {
        self.push(Command::Send {
            circuit,
            stream,
            data,
        })
    }
    /// What is queued, oldest first (the engine's own drain; tests read it too).
    #[doc(hidden)]
    pub fn take(&self) -> Vec<Command> {
        let mut q = self.0.queue.lock().unwrap_or_else(PoisonError::into_inner);
        q.1 = 0;
        q.0.drain(..).collect()
    }
}

enum Item {
    /// One frame of data; `true` ends the logical message.
    Chunk(Vec<u8>, bool),
    Close,
}
#[derive(Default)]
struct Queue {
    items: VecDeque<Item>,
    bytes: usize,
    closing: bool,
}
struct Live {
    noise: Noise,
    table: StreamTable,
    level: Level,
    /// OPEN, CREDIT and RESET: tiny, order-sensitive, always first.
    urgent: VecDeque<TunnelFrame>,
    queues: BTreeMap<u32, Queue>,
    /// Last stream served per class (round-robin cursor).
    cursor: [u32; 3],
    drained: Vec<u32>,
}
impl Live {
    fn open(&mut self, p: &OpenParams) -> Result<u32, &'static str> {
        let (id, frame) = self.table.open(p).map_err(|_| "open")?;
        self.urgent.push_back(frame);
        Ok(id)
    }
    fn send(&mut self, stream: u32, data: &[u8]) -> Result<(), &'static str> {
        self.table.kind_of(stream).ok_or("unknownStream")?;
        let q = self.queues.get(&stream);
        if q.is_some_and(|q| q.closing) {
            return Err("closing");
        }
        if data.len() > MAX_LOGICAL_MESSAGE
            || q.map_or(0, |q| q.bytes) + data.len() > MAX_LOGICAL_MESSAGE
        {
            return Err("backpressure");
        }
        let q = self.queues.entry(stream).or_default();
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![data]
        } else {
            data.chunks(MAX_FRAME_DATA).collect()
        };
        for (i, c) in chunks.iter().enumerate() {
            q.items
                .push_back(Item::Chunk(c.to_vec(), i + 1 == chunks.len()));
        }
        q.bytes += data.len();
        Ok(())
    }
    fn close(&mut self, stream: u32) -> Result<(), &'static str> {
        if stream == 0 || self.table.kind_of(stream).is_none() {
            return Err("unknownStream");
        }
        let q = self.queues.entry(stream).or_default();
        if !q.closing {
            q.closing = true;
            q.items.push_back(Item::Close);
        }
        Ok(())
    }
    fn reset(&mut self, stream: u32, code: u16) {
        self.queues.remove(&stream);
        if let Ok(f) = self.table.reset(stream, code) {
            self.urgent.push_back(f);
        }
    }

    /// One Noise message worth of frames: urgent ones first, then by class (interactive, control,
    /// bulk), round-robin inside a class. `None` when nothing may be sent now.
    fn next_message(&mut self) -> Result<Option<Vec<u8>>, &'static str> {
        let mut plain = Vec::new();
        while let Some(f) = self.urgent.front() {
            if plain.len() + FRAME_HEADER_LEN + f.data.len() > MAX_TUNNEL_PLAINTEXT {
                return Ok(Some(plain)); // full; the rest goes first next time
            }
            f.encode_into(&mut plain).map_err(|_| "protocol")?;
            self.urgent.pop_front();
        }
        while let Some(f) = self.pick(MAX_TUNNEL_PLAINTEXT - plain.len()) {
            f.encode_into(&mut plain).map_err(|_| "protocol")?;
        }
        Ok((!plain.is_empty()).then_some(plain))
    }
    /// Highest class first; a frame that does not fit the message ends it (no overtaking).
    fn pick(&mut self, room: usize) -> Option<TunnelFrame> {
        for (ci, class) in [
            StreamClass::Interactive,
            StreamClass::Control,
            StreamClass::Bulk,
        ]
        .into_iter()
        .enumerate()
        {
            let ids: Vec<u32> = self
                .queues
                .keys()
                .copied()
                .filter(|id| self.table.kind_of(*id).is_some_and(|k| k.class() == class))
                .collect();
            let start = ids.iter().position(|id| *id > self.cursor[ci]).unwrap_or(0);
            for id in ids[start..].iter().chain(&ids[..start]) {
                let q = self.queues.get_mut(id)?;
                let need = match q.items.front() {
                    Some(Item::Chunk(d, _)) if d.len() as u64 <= self.table.send_credit(*id) => {
                        d.len()
                    }
                    Some(Item::Close) => 0,
                    _ => continue,
                };
                if FRAME_HEADER_LEN + need > room {
                    return None;
                }
                self.cursor[ci] = *id;
                let frame = match q.items.pop_front()? {
                    Item::Chunk(d, fin) => {
                        q.bytes -= d.len();
                        if q.items.is_empty() {
                            self.drained.push(*id);
                        }
                        self.table.send_data(*id, &d, fin)
                    }
                    Item::Close => self.table.close(*id),
                };
                if self.queues.get(id).is_some_and(|q| q.items.is_empty()) {
                    self.queues.remove(id);
                }
                match frame {
                    Ok(f) => return Some(f),
                    Err(_) => return self.pick(room), // stream is gone: next candidate
                }
            }
        }
        None
    }
}

enum Phase {
    /// Noise handshake; `0` = waiting for message 1, `1` = for message 3.
    Hs(Box<TunnelHandshake>, u8),
    Pending(Box<(Noise, Hello)>),
    Live(Box<Live>),
    /// Transient while a phase is being taken apart.
    Gone,
}
struct Tunnel {
    device: AttestedDevice,
    deadline: Option<(u64, &'static str)>,
    phase: Phase,
}

pub struct Config {
    pub identity: Identity,
    pub host_id: Id,
    pub contract_hash: [u8; 32],
}
pub struct Engine {
    identity: Identity,
    host_id: Id,
    host_fingerprint: [u8; 32],
    contract_hash: [u8; 32],
    policy: Box<dyn Policy>,
    service: Box<dyn TunnelService>,
    inbox: Handle,
    tunnels: BTreeMap<CircuitId, Tunnel>,
    out: Vec<Out>,
    /// False while the relay has not confirmed authority recently: nothing new, nothing live.
    fresh: bool,
}

fn uuid(s: &str) -> Option<Id> {
    let b = s.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|i| b[*i] != b'-') {
        return None;
    }
    unhex(&s.replace('-', ""))
}
fn epoch(v: &Value) -> Option<u64> {
    v.as_u64().or_else(|| v.as_str()?.parse().ok())
}
fn parse_open(data: &Object) -> Option<(CircuitId, [u8; 16], AttestedDevice)> {
    let text = |o: &Object, k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
    let device = data.get("device")?.as_object()?;
    let att = device.get("attestation")?.as_object()?;
    Some((
        unhex(&text(data, "circuitId")?)?,
        unhex(&text(data, "nonce")?)?,
        AttestedDevice {
            account_id: uuid(&text(device, "accountId")?)?,
            device_id: uuid(&text(device, "deviceId")?)?,
            client_class: text(device, "clientClass"),
            fingerprint: unhex(&text(att, "fingerprint")?)?,
            auth_epoch: epoch(att.get("authEpoch")?)?,
            expires_at: att.get("expiresAt").and_then(Value::as_u64)?,
        },
    ))
}

impl Engine {
    pub fn new(
        cfg: Config,
        policy: Box<dyn Policy>,
        service: Box<dyn TunnelService>,
        inbox: Handle,
    ) -> Result<Self, String> {
        Ok(Self {
            host_fingerprint: cfg.identity.public_bundle().bundle.fingerprint()?,
            identity: cfg.identity,
            host_id: cfg.host_id,
            contract_hash: cfg.contract_hash,
            policy,
            service,
            inbox,
            tunnels: BTreeMap::new(),
            out: Vec::new(),
            fresh: true,
        })
    }

    pub fn take_out(&mut self) -> Vec<Out> {
        std::mem::take(&mut self.out)
    }
    pub fn len(&self) -> usize {
        self.tunnels.len()
    }
    pub fn is_empty(&self) -> bool {
        self.tunnels.is_empty()
    }
    pub fn next_deadline(&self) -> Option<u64> {
        self.tunnels
            .values()
            .filter_map(|t| t.deadline)
            .map(|d| d.0)
            .min()
    }

    /// EVENT `circuit.open` data. Over a limit, or without usable attestation: the circuit is closed.
    pub fn on_circuit_open(&mut self, data: &Object, now: u64) {
        let Some((circuit, nonce, device)) = parse_open(data) else {
            if let Some(c) = data
                .get("circuitId")
                .and_then(Value::as_str)
                .and_then(unhex)
            {
                self.out.push(Out::Close { circuit: c });
            }
            return;
        };
        if self.tunnels.contains_key(&circuit) {
            return;
        }
        if !self.fresh {
            self.out.push(Out::Close { circuit });
            return;
        }
        let devices: BTreeSet<Id> = self.tunnels.values().map(|t| t.device.device_id).collect();
        let same = self
            .tunnels
            .values()
            .filter(|t| t.device.device_id == device.device_id)
            .count();
        let starting = self
            .tunnels
            .values()
            .filter(|t| !matches!(t.phase, Phase::Live(_)))
            .count();
        let prologue = TunnelPrologue {
            contract_hash: self.contract_hash,
            path: TunnelPath::Relay,
            circuit_id: circuit,
            nonce,
            host_id: self.host_id,
            host_fingerprint: self.host_fingerprint,
            device_fingerprint: device.fingerprint,
            account_id: device.account_id,
        };
        let hs = TunnelHandshake::host(&self.identity, &prologue).ok();
        match hs {
            Some(hs)
                if same < MAX_TUNNELS_PER_DEVICE
                    && (same > 0 || devices.len() < MAX_DEVICES)
                    && starting < MAX_HANDSHAKES =>
            {
                self.tunnels.insert(
                    circuit,
                    Tunnel {
                        device,
                        deadline: Some((now + HANDSHAKE_MS, "handshakeTimeout")),
                        phase: Phase::Hs(Box::new(hs), 0),
                    },
                );
            }
            _ => self.out.push(Out::Close { circuit }),
        }
    }

    /// Closes (and tells the relay) every tunnel in any phase whose device `pick` selects.
    pub fn close_where(&mut self, why: &'static str, pick: impl Fn(&AttestedDevice) -> bool) {
        let hit: Vec<CircuitId> = self
            .tunnels
            .iter()
            .filter(|(_, t)| pick(&t.device))
            .map(|(c, _)| *c)
            .collect();
        for c in hit {
            self.close_circuit_as(c, why);
        }
    }
    /// Relay authority freshness (the Host decides; 8 s in the uplink). Going stale closes all.
    pub fn set_fresh(&mut self, fresh: bool) {
        if self.fresh && !fresh {
            self.close_where("staleAuthority", |_| true);
        }
        self.fresh = fresh;
    }
    /// Closes tunnels whose attested device authorization ended (`wall` is Unix ms).
    pub fn expire(&mut self, wall: u64) {
        self.close_where("authorizationExpired", |d| d.expires_at <= wall);
    }
    /// Earliest attested expiry (Unix ms) over all tunnels.
    pub fn next_expiry(&self) -> Option<u64> {
        self.tunnels.values().map(|t| t.device.expires_at).min()
    }
    /// A new attestation for a device (`devices.changed`): its tunnels follow the new deadline.
    pub fn refresh_device(&mut self, e: &DeviceEntry) {
        for t in self
            .tunnels
            .values_mut()
            .filter(|t| t.device.device_id == e.device_id && t.device.fingerprint == e.fingerprint)
        {
            t.device.auth_epoch = e.auth_epoch;
            t.device.expires_at = e.expires_at;
        }
    }
    /// Sets the level of the device's live tunnels.
    pub fn set_level(&mut self, fingerprint: &[u8; 32], level: Level) {
        for t in self.tunnels.values_mut() {
            if let (Phase::Live(l), true) = (&mut t.phase, t.device.fingerprint == *fingerprint) {
                l.level = level;
            }
        }
    }

    /// EVENT `circuit.closed`: the relay already dropped it.
    pub fn on_circuit_closed(&mut self, data: &Object) {
        let Some(circuit) = data
            .get("circuitId")
            .and_then(Value::as_str)
            .and_then(unhex)
        else {
            return;
        };
        let reason = data
            .get("reason")
            .and_then(Value::as_str)
            .unwrap_or("peer_closed");
        if let Some(t) = self.tunnels.remove(&circuit) {
            self.finish(circuit, t, reason, false);
        }
    }

    /// DATA body after the type byte: circuitId, then tunnel bytes. Unknown circuits are ignored.
    pub fn on_data(&mut self, bytes: &[u8], now: u64) {
        let Some((circuit, data)) = bytes.split_first_chunk::<16>() else {
            return;
        };
        let Some(mut t) = self.tunnels.remove(circuit) else {
            return;
        };
        let r = self.advance(*circuit, &mut t, data, now);
        self.settle(*circuit, t, r);
    }

    /// The link is gone: every tunnel closes, nothing is sent.
    pub fn link_down(&mut self) {
        for (circuit, t) in std::mem::take(&mut self.tunnels) {
            self.finish(circuit, t, "linkDown", false);
        }
        self.out.clear();
        self.inbox.take();
    }

    pub fn close_circuit(&mut self, circuit: CircuitId) {
        if let Some(t) = self.tunnels.remove(&circuit) {
            self.finish(circuit, t, "closed", true);
        }
    }
    pub fn deny(&mut self, circuit: CircuitId) {
        if matches!(self.tunnels.get(&circuit), Some(t) if matches!(t.phase, Phase::Pending(_))) {
            self.close_circuit_as(circuit, "denied");
        }
    }
    fn close_circuit_as(&mut self, circuit: CircuitId, why: &str) {
        if let Some(t) = self.tunnels.remove(&circuit) {
            self.finish(circuit, t, why, true);
        }
    }
    /// Sends `Welcome` for a tunnel in `Pending`.
    pub fn approve(&mut self, circuit: CircuitId, level: Level) {
        let Some(mut t) = self.tunnels.remove(&circuit) else {
            return;
        };
        if !matches!(t.phase, Phase::Pending(_)) {
            self.tunnels.insert(circuit, t);
            return;
        }
        let Phase::Pending(p) = std::mem::replace(&mut t.phase, Phase::Gone) else {
            return;
        };
        let (noise, hello) = *p;
        let r = self.welcome(circuit, &mut t, noise, &hello, level);
        self.settle(circuit, t, r);
    }

    pub fn tick(&mut self, now: u64) {
        let due: Vec<CircuitId> = self
            .tunnels
            .iter()
            .filter(|(_, t)| t.deadline.is_some_and(|d| now >= d.0))
            .map(|(c, _)| *c)
            .collect();
        for c in due {
            if let Some(t) = self.tunnels.remove(&c) {
                let why = t.deadline.map_or("deadline", |d| d.1);
                self.finish(c, t, why, true);
            }
        }
    }

    /// Applies what service threads pushed through the [`Handle`], then sends once per tunnel so
    /// the scheduler sees the whole batch.
    pub fn drain_commands(&mut self) {
        let mut touched = BTreeSet::new();
        for c in self.inbox.take() {
            // A refused call (stale stream, full queue) is dropped: the peer went away or the
            // service is out of step.
            match c {
                Command::Approve { circuit, level } => self.approve(circuit, level),
                Command::Deny { circuit } => self.deny(circuit),
                Command::ControlPending { circuit, code } => {
                    if let Some(l) = self.live(circuit)
                        && let Ok(f) = TunnelFrame::control_pending(code, APPROVAL_DEADLINE_MS)
                    {
                        l.urgent.push_back(f);
                        touched.insert(circuit);
                    }
                }
                Command::SetLevel { fingerprint, level } => self.set_level(&fingerprint, level),
                Command::CloseTunnel { circuit } => self.close_circuit(circuit),
                Command::CloseDevice { fingerprint } => {
                    self.close_where("revoked", |d| d.fingerprint == fingerprint)
                }
                Command::Send {
                    circuit,
                    stream,
                    data,
                } => {
                    if let Some(l) = self.live(circuit) {
                        let _ = l.send(stream, &data);
                        touched.insert(circuit);
                    }
                }
                Command::CloseStream { circuit, stream } => {
                    if let Some(l) = self.live(circuit) {
                        let _ = l.close(stream);
                        touched.insert(circuit);
                    }
                }
                Command::OpenStream {
                    circuit,
                    params,
                    reply,
                } => {
                    if let Some(l) = self.live(circuit) {
                        let _ = reply.send(l.open(&params));
                        touched.insert(circuit);
                    }
                }
                Command::ResetStream {
                    circuit,
                    stream,
                    code,
                } => {
                    if let Some(l) = self.live(circuit) {
                        l.reset(stream, code);
                        touched.insert(circuit);
                    }
                }
            }
        }
        for circuit in touched {
            if let Some(mut t) = self.tunnels.remove(&circuit) {
                let r = self.pump(circuit, &mut t);
                self.settle(circuit, t, r);
            }
        }
    }

    fn live(&mut self, circuit: CircuitId) -> Option<&mut Live> {
        match &mut self.tunnels.get_mut(&circuit)?.phase {
            Phase::Live(l) => Some(l),
            _ => None,
        }
    }
    fn settle(&mut self, circuit: CircuitId, t: Tunnel, r: Result<(), &'static str>) {
        match r {
            Ok(()) => {
                self.tunnels.insert(circuit, t);
            }
            Err(why) => self.finish(circuit, t, why, true),
        }
    }
    fn finish(&mut self, circuit: CircuitId, t: Tunnel, why: &str, notify: bool) {
        self.policy.closed(circuit);
        if matches!(t.phase, Phase::Live(_)) {
            self.service.on_tunnel_close(circuit, why);
        }
        if notify {
            self.out.push(Out::Close { circuit });
        }
    }

    fn advance(
        &mut self,
        circuit: CircuitId,
        t: &mut Tunnel,
        data: &[u8],
        now: u64,
    ) -> Result<(), &'static str> {
        const HS: &str = "handshake";
        match &mut t.phase {
            Phase::Hs(hs, step) if *step == 0 => {
                hs.read_message(data).map_err(|_| HS)?;
                let m2 = hs.write_message(&[]).map_err(|_| HS)?;
                *step = 1;
                self.out.push(Out::Data { circuit, bytes: m2 });
                Ok(())
            }
            Phase::Hs(..) => {
                let Phase::Hs(mut hs, _) = std::mem::replace(&mut t.phase, Phase::Gone) else {
                    return Err(HS);
                };
                let payload = hs.read_message(data).map_err(|_| HS)?;
                let hello = Hello::decode(&payload).map_err(|_| HS)?;
                let bundle: SignedBundle =
                    serde_json::from_slice(&hello.device_bundle.0).map_err(|_| HS)?;
                hs.verify_device(&bundle).map_err(|_| HS)?;
                let code = hs.confirmation_code().map_err(|_| HS)?;
                let mut noise = hs.into_transport().map_err(|_| HS)?;
                let verdict = self.policy.admit_circuit(circuit, &t.device, &hello, &code);
                if hello.auth_epoch != t.device.auth_epoch
                    && matches!(verdict, Admission::Welcome { .. } | Admission::Pending)
                {
                    return Err("staleEpoch");
                }
                match verdict {
                    Admission::Welcome { level } => self.welcome(circuit, t, noise, &hello, level),
                    Admission::Pending => {
                        let g = HostGreeting::ApprovalPending(ApprovalPending {
                            code: code.parse().map_err(|_| HS)?,
                            deadline_ms: APPROVAL_DEADLINE_MS,
                        });
                        self.greet(circuit, &mut noise, &g)?;
                        t.deadline =
                            Some((now + u64::from(APPROVAL_DEADLINE_MS), "approvalTimeout"));
                        t.phase = Phase::Pending(Box::new((noise, hello)));
                        Ok(())
                    }
                    Admission::Stale { epochs } => {
                        self.greet(circuit, &mut noise, &HostGreeting::StaleEpoch(epochs))?;
                        Err("staleEpoch") // the device retries on a new circuit
                    }
                    Admission::Refuse => Err("refused"),
                }
            }
            // The device sends nothing before the greeting that opens the tunnel.
            Phase::Pending(_) | Phase::Gone => Err("protocol"),
            Phase::Live(live) => {
                let plain = live.noise.decrypt(data).map_err(|_| "decrypt")?;
                let frames = decode_frames(&plain).map_err(|_| "protocol")?;
                for f in &frames {
                    let ev = live.table.on_frame(f).map_err(|_| "protocol")?;
                    let n = f.data.len() as u32;
                    if f.kind == FrameType::Data && n > 0 {
                        // Everything goes to the service at once: windows reopen now.
                        live.urgent.extend(live.table.grant(0, n).ok());
                        if f.stream_id != 0 && live.table.kind_of(f.stream_id).is_some() {
                            live.urgent.extend(live.table.grant(f.stream_id, n).ok());
                        }
                    }
                    let mut s = Streams { circuit, live };
                    match ev {
                        None => {}
                        Some(Event::Opened { stream_id, params }) => {
                            if let Err(code) =
                                self.service.on_stream_open(&mut s, stream_id, &params)
                            {
                                s.live.reset(stream_id, code);
                            }
                        }
                        Some(Event::Message { stream_id, data }) => {
                            self.service.on_message(&mut s, stream_id, data)
                        }
                        Some(Event::Closed { stream_id }) => {
                            s.live.queues.remove(&stream_id);
                            self.service.on_stream_close(&mut s, stream_id, None)
                        }
                        Some(Event::Reset { stream_id, code }) => {
                            s.live.queues.remove(&stream_id);
                            self.service.on_stream_close(&mut s, stream_id, Some(code))
                        }
                    }
                }
                self.pump(circuit, t)
            }
        }
    }

    fn greet(
        &mut self,
        circuit: CircuitId,
        noise: &mut Noise,
        g: &HostGreeting,
    ) -> Result<(), &'static str> {
        let plain = g.encode().map_err(|_| "protocol")?;
        let bytes = noise.encrypt(&plain).map_err(|_| "encrypt")?;
        self.out.push(Out::Data { circuit, bytes });
        Ok(())
    }

    /// Greeting, then the tunnel is live; the directory stream follows if the device asked.
    fn welcome(
        &mut self,
        circuit: CircuitId,
        t: &mut Tunnel,
        mut noise: Noise,
        hello: &Hello,
        level: Level,
    ) -> Result<(), &'static str> {
        let g = HostGreeting::Welcome(Welcome {
            directory: hello.send_directory,
        });
        self.greet(circuit, &mut noise, &g)?;
        let mut live = Box::new(Live {
            noise,
            table: StreamTable::new(Side::Host),
            level,
            urgent: VecDeque::new(),
            queues: BTreeMap::new(),
            cursor: [0; 3],
            drained: Vec::new(),
        });
        t.deadline = None;
        self.service.on_tunnel_open(
            &mut Streams {
                circuit,
                live: &mut live,
            },
            &t.device,
        );
        if hello.send_directory {
            let snapshot = self.service.directory(&t.device);
            let id = live.open(&OpenParams::Directory)?;
            live.send(id, &snapshot)?;
        }
        t.phase = Phase::Live(live);
        self.pump(circuit, t)
    }

    /// Sends every Noise message the windows allow, then tells the service about drained streams.
    fn pump(&mut self, circuit: CircuitId, t: &mut Tunnel) -> Result<(), &'static str> {
        let Phase::Live(live) = &mut t.phase else {
            return Ok(());
        };
        loop {
            while let Some(plain) = live.next_message()? {
                let bytes = live.noise.encrypt(&plain).map_err(|_| "encrypt")?;
                self.out.push(Out::Data { circuit, bytes });
            }
            let drained = std::mem::take(&mut live.drained);
            if drained.is_empty() {
                return Ok(());
            }
            for stream in drained {
                if live.table.kind_of(stream).is_some() {
                    self.service
                        .on_writable(&mut Streams { circuit, live }, stream);
                }
            }
        }
    }
}

/// Test doubles shared by the unit tests and `tests/tunnel_engine.rs`.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// Answers from a script (`Welcome { Read }` once it runs dry).
    #[derive(Default, Clone)]
    pub struct Scripted(pub Arc<Mutex<VecDeque<Admission>>>);
    impl Policy for Scripted {
        fn admit(&self, _: &AttestedDevice, _: &Hello, _: &str) -> Admission {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .pop_front()
                .unwrap_or(Admission::Welcome { level: Level::Read })
        }
    }

    /// Echoes every message on its stream; the directory is `b"dir"`. Events land in `log`.
    #[derive(Default)]
    pub struct Echo {
        pub log: Arc<Mutex<Vec<String>>>,
    }
    impl TunnelService for Echo {
        fn on_tunnel_open(&mut self, _: &mut Streams<'_>, _: &AttestedDevice) {
            self.log.lock().unwrap().push("open".into());
        }
        fn on_stream_open(
            &mut self,
            _: &mut Streams<'_>,
            stream: u32,
            _: &OpenParams,
        ) -> Result<(), u16> {
            self.log.lock().unwrap().push(format!("stream {stream}"));
            Ok(())
        }
        fn on_message(&mut self, s: &mut Streams<'_>, stream: u32, data: Vec<u8>) {
            let _ = s.send(stream, &data);
        }
        fn on_tunnel_close(&mut self, _: CircuitId, reason: &str) {
            self.log.lock().unwrap().push(format!("close {reason}"));
        }
        fn directory(&mut self, _: &AttestedDevice) -> Vec<u8> {
            b"dir".to_vec()
        }
    }
}

#[cfg(test)]
mod tests;
