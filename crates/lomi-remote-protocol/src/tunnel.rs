//! Tunnel stream framing, stream table and handshake payloads (plan-1.0/03-protokol.md 4-9, 12).
//! Sans-I/O: the caller feeds decrypted Noise plaintexts in and sends the returned frames.
//! A frame is `streamId(u32 BE) | type(u8) | flags(u8) | length(u16 BE) | data`.
//! Every `Err` returned for peer input is a protocol error: the caller closes the tunnel.
//! Scheduling (P3a.7) is not here; `StreamKind::class` only tells the scheduler what to use.
use crate::rpc::{DisplayText, EncodedPathId, PaneState, SplitAxis, TerminalDimension, text_type};
use crate::{
    CapabilitySet, ChatMessageId, ChatModelId, ChatPermissions, ChatProviderId, ChatThreadId,
    ChatTitle, PaneId, RequestId, SessionEpoch, TabId, TimeoutMs, WorkspaceEpoch, WorkspaceId,
    message_framing::{MAX_MESSAGE_LEN, MAX_PLAINTEXT_FRAME_LEN},
    rpc::{BoundedList, RpcCall, dto},
};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{BTreeMap, VecDeque};

pub const FRAME_HEADER_LEN: usize = 8;
/// Data bytes in one frame (spec: 16 KiB, "like today").
pub const MAX_FRAME_DATA: usize = MAX_PLAINTEXT_FRAME_LEN;
pub const MAX_LOGICAL_MESSAGE: usize = MAX_MESSAGE_LEN;
/// Open streams other than stream 0.
pub const MAX_OPEN_STREAMS: usize = 64;
pub const MAX_TERMINAL_STREAMS: usize = 32;
pub const STREAM_WINDOW: u64 = 64 * 1024;
pub const TUNNEL_WINDOW: u64 = 256 * 1024;
/// Handshake payloads travel in one Noise message; they stay far below it.
pub const MAX_HANDSHAKE_PAYLOAD: usize = 8 * 1024;
pub const MAX_DEVICE_BUNDLE: usize = 4096;
pub const MAX_RESUME_ENTRIES: usize = MAX_OPEN_STREAMS;
pub const APPROVAL_DEADLINE_MS: u32 = 120_000;
pub const FLAG_FIN: u8 = 0x01;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelError {
    Truncated,
    EmptyPlaintext,
    UnknownType,
    BadFlags,
    FrameTooLarge,
    BadBody,
    StreamZero,
    BadParity,
    StreamReused,
    UnknownStream,
    TooManyStreams,
    TooManyTerminals,
    IdsExhausted,
    UnknownKind,
    ReservedKind,
    KindNotAllowed,
    WindowExceeded,
    CreditOverflow,
    MessageTooLarge,
    BadPayload,
}
impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "tunnel protocol error: {self:?}")
    }
}
impl std::error::Error for TunnelError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameType {
    Open = 1,
    Data = 2,
    Credit = 3,
    Close = 4,
    Reset = 5,
}
impl FrameType {
    fn parse(v: u8) -> Result<Self, TunnelError> {
        Ok(match v {
            1 => Self::Open,
            2 => Self::Data,
            3 => Self::Credit,
            4 => Self::Close,
            5 => Self::Reset,
            _ => return Err(TunnelError::UnknownType),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelFrame {
    pub stream_id: u32,
    pub kind: FrameType,
    pub flags: u8,
    pub data: Vec<u8>,
}
impl TunnelFrame {
    fn new(stream_id: u32, kind: FrameType, flags: u8, data: Vec<u8>) -> Self {
        Self {
            stream_id,
            kind,
            flags,
            data,
        }
    }
    /// Checks flags and the body size of every frame type.
    pub fn validate(&self) -> Result<(), TunnelError> {
        if self.data.len() > MAX_FRAME_DATA {
            return Err(TunnelError::FrameTooLarge);
        }
        if self.flags & !FLAG_FIN != 0 || (self.flags != 0 && self.kind != FrameType::Data) {
            return Err(TunnelError::BadFlags);
        }
        let ok = match self.kind {
            FrameType::Open => !self.data.is_empty(),
            FrameType::Data => true,
            FrameType::Credit => self.credit_amount().is_some_and(|n| n > 0),
            FrameType::Close => self.data.is_empty(),
            FrameType::Reset => self.data.len() == 2,
        };
        if ok {
            Ok(())
        } else {
            Err(TunnelError::BadBody)
        }
    }
    fn credit_amount(&self) -> Option<u32> {
        Some(u32::from_be_bytes(self.data.as_slice().try_into().ok()?))
    }
    pub fn reset_code(&self) -> Option<u16> {
        Some(u16::from_be_bytes(self.data.as_slice().try_into().ok()?))
    }
    pub fn encode_into(&self, out: &mut Vec<u8>) -> Result<(), TunnelError> {
        self.validate()?;
        out.extend_from_slice(&self.stream_id.to_be_bytes());
        out.push(self.kind as u8);
        out.push(self.flags);
        out.extend_from_slice(&(self.data.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.data);
        Ok(())
    }
}

/// Parses one Noise plaintext into one or more valid frames.
pub fn decode_frames(plain: &[u8]) -> Result<Vec<TunnelFrame>, TunnelError> {
    if plain.is_empty() {
        return Err(TunnelError::EmptyPlaintext);
    }
    let (mut rest, mut frames) = (plain, Vec::new());
    while !rest.is_empty() {
        if rest.len() < FRAME_HEADER_LEN {
            return Err(TunnelError::Truncated);
        }
        let len = u16::from_be_bytes([rest[6], rest[7]]) as usize;
        if len > MAX_FRAME_DATA {
            return Err(TunnelError::FrameTooLarge);
        }
        let body = rest
            .get(FRAME_HEADER_LEN..FRAME_HEADER_LEN + len)
            .ok_or(TunnelError::Truncated)?;
        let frame = TunnelFrame::new(
            u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
            FrameType::parse(rest[4])?,
            rest[5],
            body.to_vec(),
        );
        frame.validate()?;
        frames.push(frame);
        rest = &rest[FRAME_HEADER_LEN + len..];
    }
    Ok(frames)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    Device,
    Host,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamClass {
    Interactive,
    Control,
    Bulk,
}
/// Declaration order equals the OPEN kind code and the postcard variant index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum StreamKind {
    #[serde(rename = "rpc")]
    Rpc,
    #[serde(rename = "directory")]
    Directory,
    #[serde(rename = "terminal")]
    Terminal,
    #[serde(rename = "chat")]
    Chat,
    #[serde(rename = "files.watch")]
    FilesWatch,
    #[serde(rename = "transfer")]
    Transfer,
    #[serde(rename = "media")]
    Media,
}
impl StreamKind {
    pub fn code(self) -> u8 {
        self as u8
    }
    pub fn class(self) -> StreamClass {
        match self {
            Self::Terminal | Self::Chat => StreamClass::Interactive,
            Self::Rpc | Self::Directory | Self::FilesWatch => StreamClass::Control,
            Self::Transfer | Self::Media => StreamClass::Bulk,
        }
    }
    /// Kinds that may appear in OPEN and be opened by `opener`.
    fn openable_by(self, opener: Side) -> Result<(), TunnelError> {
        match (self, opener) {
            (Self::Rpc, _) => Err(TunnelError::UnknownKind),
            (Self::Media, _) => Err(TunnelError::ReservedKind),
            (Self::Directory, Side::Host) | (Self::Transfer, _) => Ok(()),
            (Self::Terminal | Self::Chat | Self::FilesWatch, Side::Device) => Ok(()),
            _ => Err(TunnelError::KindNotAllowed),
        }
    }
}

// OPEN parameters (postcard). `after`/`afterSeq` are resume cursors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOpen {
    pub workspace_id: WorkspaceId,
    pub pane_id: PaneId,
    pub session_epoch: SessionEpoch,
    pub cols: TerminalDimension,
    pub rows: TerminalDimension,
    pub after_seq: Option<u64>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatAfter {
    pub message_id: ChatMessageId,
    pub stream_seq: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChatOpen {
    pub workspace_id: WorkspaceId,
    pub thread_id: ChatThreadId,
    pub after: Option<ChatAfter>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct FilesWatchOpen {
    pub workspace_id: WorkspaceId,
    pub path: EncodedPathId,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct TransferOpen {
    pub request_id: RequestId,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenParams {
    Directory,
    Terminal(TerminalOpen),
    Chat(ChatOpen),
    FilesWatch(FilesWatchOpen),
    Transfer(TransferOpen),
}
impl OpenParams {
    pub fn kind(&self) -> StreamKind {
        match self {
            Self::Directory => StreamKind::Directory,
            Self::Terminal(_) => StreamKind::Terminal,
            Self::Chat(_) => StreamKind::Chat,
            Self::FilesWatch(_) => StreamKind::FilesWatch,
            Self::Transfer(_) => StreamKind::Transfer,
        }
    }
    /// OPEN frame data: kind code followed by the postcard params.
    pub fn encode(&self) -> Result<Vec<u8>, TunnelError> {
        let body = match self {
            Self::Directory => Ok(Vec::new()),
            Self::Terminal(p) => postcard::to_allocvec(p),
            Self::Chat(p) => postcard::to_allocvec(p),
            Self::FilesWatch(p) => postcard::to_allocvec(p),
            Self::Transfer(p) => postcard::to_allocvec(p),
        }
        .map_err(|_| TunnelError::BadPayload)?;
        let mut out = vec![self.kind().code()];
        out.extend(body);
        if out.len() > MAX_FRAME_DATA {
            Err(TunnelError::FrameTooLarge)
        } else {
            Ok(out)
        }
    }
    pub fn decode(data: &[u8]) -> Result<Self, TunnelError> {
        let (&code, body) = data.split_first().ok_or(TunnelError::BadBody)?;
        Ok(match code {
            1 => {
                if !body.is_empty() {
                    return Err(TunnelError::BadPayload);
                }
                Self::Directory
            }
            2 => Self::Terminal(from_postcard(body)?),
            3 => Self::Chat(from_postcard(body)?),
            4 => Self::FilesWatch(from_postcard(body)?),
            5 => Self::Transfer(from_postcard(body)?),
            6 => return Err(TunnelError::ReservedKind),
            _ => return Err(TunnelError::UnknownKind),
        })
    }
}
/// Strict postcard decode: trailing bytes are an error.
fn from_postcard<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TunnelError> {
    let (value, rest) = postcard::take_from_bytes(bytes).map_err(|_| TunnelError::BadPayload)?;
    if rest.is_empty() {
        Ok(value)
    } else {
        Err(TunnelError::BadPayload)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Opened {
        stream_id: u32,
        params: OpenParams,
    },
    /// A complete logical message (a DATA run ending in FIN).
    Message {
        stream_id: u32,
        data: Vec<u8>,
    },
    Closed {
        stream_id: u32,
    },
    Reset {
        stream_id: u32,
        code: u16,
    },
}

struct Stream {
    kind: StreamKind,
    send: u64,
    recv: u64,
    buf: Vec<u8>,
}
/// Per-tunnel stream state for one side. Stream 0 (rpc) has no stream window of its own:
/// its DATA is limited by the tunnel window, and CREDIT on stream 0 grants the tunnel window.
pub struct StreamTable {
    side: Side,
    streams: BTreeMap<u32, Stream>,
    next_own: u64,
    last_peer: u32,
    /// Ids we closed ourselves; in-flight frames from the peer for them are dropped, not errors.
    recent_closed: VecDeque<u32>,
    send_tunnel: u64,
    recv_tunnel: u64,
    terminals: usize,
}
impl StreamTable {
    pub fn new(side: Side) -> Self {
        let rpc = Stream {
            kind: StreamKind::Rpc,
            send: 0,
            recv: 0,
            buf: Vec::new(),
        };
        Self {
            side,
            streams: BTreeMap::from([(0, rpc)]),
            next_own: if side == Side::Device { 1 } else { 2 },
            last_peer: 0,
            recent_closed: VecDeque::new(),
            send_tunnel: TUNNEL_WINDOW,
            recv_tunnel: TUNNEL_WINDOW,
            terminals: 0,
        }
    }
    pub fn kind_of(&self, id: u32) -> Option<StreamKind> {
        self.streams.get(&id).map(|s| s.kind)
    }
    /// Bytes we may still send on `id` (stream 0: the tunnel window).
    pub fn send_credit(&self, id: u32) -> u64 {
        match self.streams.get(&id) {
            Some(s) if id != 0 => s.send.min(self.send_tunnel),
            Some(_) => self.send_tunnel,
            None => 0,
        }
    }
    fn check_capacity(&self, kind: StreamKind) -> Result<(), TunnelError> {
        if self.streams.len() > MAX_OPEN_STREAMS {
            return Err(TunnelError::TooManyStreams);
        }
        if kind == StreamKind::Terminal && self.terminals >= MAX_TERMINAL_STREAMS {
            return Err(TunnelError::TooManyTerminals);
        }
        Ok(())
    }
    fn insert(&mut self, id: u32, kind: StreamKind) {
        self.terminals += (kind == StreamKind::Terminal) as usize;
        self.streams.insert(
            id,
            Stream {
                kind,
                send: STREAM_WINDOW,
                recv: STREAM_WINDOW,
                buf: Vec::new(),
            },
        );
    }
    fn remove(&mut self, id: u32) {
        if let Some(s) = self.streams.remove(&id) {
            self.terminals -= (s.kind == StreamKind::Terminal) as usize;
        }
    }
    fn forget_local(&mut self, id: u32) {
        self.remove(id);
        if self.recent_closed.len() == MAX_OPEN_STREAMS {
            self.recent_closed.pop_front();
        }
        self.recent_closed.push_back(id);
    }

    /// Opens a stream we own; returns its id and the OPEN frame to send.
    pub fn open(&mut self, params: &OpenParams) -> Result<(u32, TunnelFrame), TunnelError> {
        let kind = params.kind();
        kind.openable_by(self.side)?;
        self.check_capacity(kind)?;
        let id = u32::try_from(self.next_own).map_err(|_| TunnelError::IdsExhausted)?;
        let data = params.encode()?;
        self.next_own += 2;
        self.insert(id, kind);
        Ok((id, TunnelFrame::new(id, FrameType::Open, 0, data)))
    }
    /// Debits the windows and returns a DATA frame. `fin` ends the logical message.
    pub fn send_data(
        &mut self,
        id: u32,
        data: &[u8],
        fin: bool,
    ) -> Result<TunnelFrame, TunnelError> {
        let n = data.len() as u64;
        if data.len() > MAX_FRAME_DATA {
            return Err(TunnelError::FrameTooLarge);
        }
        if n > self.send_credit(id) {
            return Err(TunnelError::WindowExceeded);
        }
        self.send_tunnel -= n;
        if id != 0 {
            self.streams
                .get_mut(&id)
                .ok_or(TunnelError::UnknownStream)?
                .send -= n;
        }
        Ok(TunnelFrame::new(
            id,
            FrameType::Data,
            if fin { FLAG_FIN } else { 0 },
            data.to_vec(),
        ))
    }
    /// Gives the peer `n` more bytes of window (stream 0 grants the tunnel window).
    pub fn grant(&mut self, id: u32, n: u32) -> Result<TunnelFrame, TunnelError> {
        if n == 0 {
            return Err(TunnelError::BadBody);
        }
        let (window, cap) = match self.streams.get_mut(&id) {
            Some(_) if id == 0 => (&mut self.recv_tunnel, TUNNEL_WINDOW),
            Some(s) => (&mut s.recv, STREAM_WINDOW),
            None => return Err(TunnelError::UnknownStream),
        };
        *window = window
            .checked_add(u64::from(n))
            .filter(|w| *w <= cap)
            .ok_or(TunnelError::CreditOverflow)?;
        Ok(TunnelFrame::new(
            id,
            FrameType::Credit,
            0,
            n.to_be_bytes().to_vec(),
        ))
    }
    pub fn close(&mut self, id: u32) -> Result<TunnelFrame, TunnelError> {
        self.finish_local(id, FrameType::Close, Vec::new())
    }
    pub fn reset(&mut self, id: u32, code: u16) -> Result<TunnelFrame, TunnelError> {
        self.finish_local(id, FrameType::Reset, code.to_be_bytes().to_vec())
    }
    fn finish_local(
        &mut self,
        id: u32,
        kind: FrameType,
        data: Vec<u8>,
    ) -> Result<TunnelFrame, TunnelError> {
        if id == 0 {
            return Err(TunnelError::StreamZero);
        }
        if !self.streams.contains_key(&id) {
            return Err(TunnelError::UnknownStream);
        }
        self.forget_local(id);
        Ok(TunnelFrame::new(id, kind, 0, data))
    }

    /// Applies one frame received from the peer.
    pub fn on_frame(&mut self, f: &TunnelFrame) -> Result<Option<Event>, TunnelError> {
        f.validate()?;
        let id = f.stream_id;
        match f.kind {
            FrameType::Open => self.on_open(id, &f.data),
            FrameType::Data => self.on_data(id, &f.data, f.flags & FLAG_FIN != 0),
            FrameType::Credit => self.on_credit(id, u64::from(f.credit_amount().unwrap_or(0))),
            FrameType::Close | FrameType::Reset => {
                if id == 0 {
                    return Err(TunnelError::StreamZero);
                }
                if self.streams.contains_key(&id) {
                    self.remove(id);
                    return Ok(Some(match f.reset_code() {
                        Some(code) if f.kind == FrameType::Reset => Event::Reset {
                            stream_id: id,
                            code,
                        },
                        _ => Event::Closed { stream_id: id },
                    }));
                }
                self.late(id)
            }
        }
    }
    /// Frame for an id we no longer track: tolerated only for streams we closed ourselves.
    fn late(&self, id: u32) -> Result<Option<Event>, TunnelError> {
        if self.recent_closed.contains(&id) {
            Ok(None)
        } else {
            Err(TunnelError::UnknownStream)
        }
    }
    fn on_open(&mut self, id: u32, data: &[u8]) -> Result<Option<Event>, TunnelError> {
        if id == 0 {
            return Err(TunnelError::StreamZero);
        }
        // The peer's ids: even when we are the device (Host-owned), odd when we are the Host.
        if id.is_multiple_of(2) != (self.side == Side::Device) {
            return Err(TunnelError::BadParity);
        }
        if id <= self.last_peer {
            return Err(TunnelError::StreamReused);
        }
        let params = OpenParams::decode(data)?;
        let peer = if self.side == Side::Device {
            Side::Host
        } else {
            Side::Device
        };
        params.kind().openable_by(peer)?;
        self.check_capacity(params.kind())?;
        self.last_peer = id;
        self.insert(id, params.kind());
        Ok(Some(Event::Opened {
            stream_id: id,
            params,
        }))
    }
    fn on_data(&mut self, id: u32, data: &[u8], fin: bool) -> Result<Option<Event>, TunnelError> {
        let n = data.len() as u64;
        if n > self.recv_tunnel {
            return Err(TunnelError::WindowExceeded);
        }
        let Some(s) = self.streams.get_mut(&id) else {
            if self.recent_closed.contains(&id) {
                self.recv_tunnel -= n; // still occupied the tunnel window
                return Ok(None);
            }
            return Err(TunnelError::UnknownStream);
        };
        if id != 0 {
            if n > s.recv {
                return Err(TunnelError::WindowExceeded);
            }
            s.recv -= n;
        }
        if s.buf.len() + data.len() > MAX_LOGICAL_MESSAGE {
            return Err(TunnelError::MessageTooLarge);
        }
        self.recv_tunnel -= n;
        s.buf.extend_from_slice(data);
        Ok(fin.then(|| Event::Message {
            stream_id: id,
            data: std::mem::take(&mut s.buf),
        }))
    }
    fn on_credit(&mut self, id: u32, n: u64) -> Result<Option<Event>, TunnelError> {
        let (window, cap) = match self.streams.get_mut(&id) {
            Some(_) if id == 0 => (&mut self.send_tunnel, TUNNEL_WINDOW),
            Some(s) => (&mut s.send, STREAM_WINDOW),
            None => return self.late(id),
        };
        *window = window
            .checked_add(n)
            .filter(|w| *w <= cap)
            .ok_or(TunnelError::CreditOverflow)?;
        Ok(None)
    }
}

// Handshake payloads (postcard): Hello is Noise message 3's payload, HostGreeting the Host's
// first transport message. Strings and lists are bounded; `encode`/`decode` check total size.
text_type!(DeviceName, 64, false);
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum DeviceKind {
    Web,
    Mobile,
    Desktop,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResumeEntry {
    pub kind: StreamKind,
    pub cursor: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Hello {
    pub device_name: DeviceName,
    pub device_kind: DeviceKind,
    pub auth_epoch: u64,
    pub host_access_epoch: u64,
    pub runtime_generation: u64,
    pub resume: BoundedList<ResumeEntry, MAX_RESUME_ENTRIES>,
    pub send_directory: bool,
    /// Opaque signed device bundle; verified elsewhere.
    pub device_bundle: BoundedList<u8, MAX_DEVICE_BUNDLE>,
}
/// The directory itself goes on the `directory` stream; `directory` says whether it will follow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Welcome {
    pub directory: bool,
}
/// `code` is the 6-digit confirmation code as a number (0..=999999, display zero-padded).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalPending {
    pub code: u32,
    pub deadline_ms: u32,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StaleEpoch {
    pub auth_epoch: u64,
    pub host_access_epoch: u64,
    pub runtime_generation: u64,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum OlderSide {
    Host,
    Client,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpdateRequired {
    pub older_side: OlderSide,
}
/// Externally tagged (postcard has no self-describing tags).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum HostGreeting {
    Welcome(Welcome),
    ApprovalPending(ApprovalPending),
    StaleEpoch(StaleEpoch),
    UpdateRequired(UpdateRequired),
}
fn encode_payload<T: Serialize>(v: &T) -> Result<Vec<u8>, TunnelError> {
    let out = postcard::to_allocvec(v).map_err(|_| TunnelError::BadPayload)?;
    if out.len() > MAX_HANDSHAKE_PAYLOAD {
        Err(TunnelError::FrameTooLarge)
    } else {
        Ok(out)
    }
}
fn decode_payload<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, TunnelError> {
    if bytes.len() > MAX_HANDSHAKE_PAYLOAD {
        return Err(TunnelError::FrameTooLarge);
    }
    from_postcard(bytes)
}
impl Hello {
    fn validate(&self) -> Result<(), TunnelError> {
        // Rpc is implicit and media reserved: neither can be resumed.
        let bad = |e: &ResumeEntry| matches!(e.kind, StreamKind::Rpc | StreamKind::Media);
        if self.resume.0.len() > MAX_RESUME_ENTRIES
            || self.device_bundle.0.len() > MAX_DEVICE_BUNDLE
            || self.resume.0.iter().any(bad)
        {
            return Err(TunnelError::BadPayload);
        }
        Ok(())
    }
    pub fn encode(&self) -> Result<Vec<u8>, TunnelError> {
        self.validate()?;
        encode_payload(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, TunnelError> {
        let hello: Self = decode_payload(bytes)?;
        hello.validate()?;
        Ok(hello)
    }
}
impl HostGreeting {
    fn validate(&self) -> Result<(), TunnelError> {
        match self {
            Self::ApprovalPending(p)
                if p.code > 999_999 || p.deadline_ms > APPROVAL_DEADLINE_MS =>
            {
                Err(TunnelError::BadPayload)
            }
            _ => Ok(()),
        }
    }
    pub fn encode(&self) -> Result<Vec<u8>, TunnelError> {
        self.validate()?;
        encode_payload(self)
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, TunnelError> {
        let greeting: Self = decode_payload(bytes)?;
        greeting.validate()?;
        Ok(greeting)
    }
}

// Stream 0 envelope: the unversioned successor of `RpcRequest` (which keeps `v`/`type` until
// the old path is removed). Every call already carries its `workspaceId` inside its `context`
// (WorkspaceContext / mutation contexts), so no separate top-level field is added.
// `workspace_id` is only needed by calls that carry no workspace of their own (chat); the
// Host denies a call whose own workspace differs from it.
dto!(RpcEnvelope {
    request_id: RequestId,
    timeout_ms: TimeoutMs,
    workspace_id: Option<WorkspaceId>,
    #[serde(deserialize_with = "crate::rpc::deserialize_object")]
    call: RpcCall
});

impl RpcEnvelope {
    /// Same strictness as `rpc::decode_request`: raw JSON limits, then the call's own checks.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        crate::json_wire::check_raw_bytes(bytes).map_err(str::to_owned)?;
        let envelope: Self = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        envelope.call.validate().map_err(str::to_owned)?;
        Ok(envelope)
    }
}

// `directory` stream (postcard, externally tagged: postcard cannot read internal tags). The first
// message is `Snapshot`; every later one is a `Change` with the next `seq`. A change replaces or
// removes one whole workspace entry, so the device needs no diff logic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryHost {
    pub name: DisplayText,
    pub platform: DisplayText,
    pub version: DisplayText,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DirectoryLayout {
    Pane(PaneId),
    Split {
        axis: SplitAxis,
        first: Box<DirectoryLayout>,
        second: Box<DirectoryLayout>,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryTab {
    pub tab_id: TabId,
    pub name: DisplayText,
    pub layout: DirectoryLayout,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryTerminal {
    pub pane_id: PaneId,
    pub tab_id: TabId,
    pub title: DisplayText,
    pub state: PaneState,
    /// `None` while the pane has no live session.
    pub session_epoch: Option<SessionEpoch>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum DirectoryChatState {
    Idle,
    Generating,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryChat {
    pub thread_id: ChatThreadId,
    pub title: ChatTitle,
    pub provider: ChatProviderId,
    pub model: ChatModelId,
    pub mode: ChatPermissions,
    pub state: DirectoryChatState,
    /// Unix milliseconds.
    pub last_activity_at: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryWorkspace {
    pub id: WorkspaceId,
    pub epoch: WorkspaceEpoch,
    pub name: DisplayText,
    /// What this device may do there (ceiling of the workspace, limited by the device grant).
    pub capabilities: CapabilitySet,
    pub tabs: Vec<DirectoryTab>,
    pub terminals: Vec<DirectoryTerminal>,
    pub chats: Vec<DirectoryChat>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectorySnapshot {
    pub seq: u64,
    pub host: DirectoryHost,
    pub workspaces: Vec<DirectoryWorkspace>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DirectoryChange {
    /// Added or changed.
    Workspace(DirectoryWorkspace),
    /// No longer shared with this device, or gone.
    Removed(WorkspaceId),
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryUpdate {
    pub seq: u64,
    pub change: DirectoryChange,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum DirectoryMessage {
    Snapshot(DirectorySnapshot),
    Change(DirectoryUpdate),
}
impl DirectoryMessage {
    pub fn encode(&self) -> Result<Vec<u8>, TunnelError> {
        let out = postcard::to_allocvec(self).map_err(|_| TunnelError::BadPayload)?;
        if out.len() > MAX_LOGICAL_MESSAGE {
            Err(TunnelError::MessageTooLarge)
        } else {
            Ok(out)
        }
    }
    pub fn decode(bytes: &[u8]) -> Result<Self, TunnelError> {
        if bytes.len() > MAX_LOGICAL_MESSAGE {
            return Err(TunnelError::MessageTooLarge);
        }
        from_postcard(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WS: &str = "11111111-1111-4111-8111-111111111111";
    fn ws() -> WorkspaceId {
        WorkspaceId::try_from(WS.to_string()).unwrap()
    }
    fn terminal() -> OpenParams {
        OpenParams::Terminal(TerminalOpen {
            workspace_id: ws(),
            pane_id: PaneId::try_from(WS.to_string()).unwrap(),
            session_epoch: SessionEpoch::try_from(WS.to_string()).unwrap(),
            cols: TerminalDimension::try_from(80).unwrap(),
            rows: TerminalDimension::try_from(24).unwrap(),
            after_seq: Some(7),
        })
    }
    fn chat() -> OpenParams {
        OpenParams::Chat(ChatOpen {
            workspace_id: ws(),
            thread_id: ChatThreadId::try_from("a".repeat(32)).unwrap(),
            after: Some(ChatAfter {
                message_id: ChatMessageId::try_from("b".repeat(32)).unwrap(),
                stream_seq: u64::MAX,
            }),
        })
    }
    fn open(table: &mut StreamTable, p: &OpenParams) -> u32 {
        table.open(p).unwrap().0
    }
    fn pair() -> (StreamTable, StreamTable) {
        (StreamTable::new(Side::Device), StreamTable::new(Side::Host))
    }
    /// Device opens a terminal stream that the Host accepts.
    fn open_pair() -> (StreamTable, StreamTable, u32) {
        let (mut d, mut h) = pair();
        let (id, f) = d.open(&terminal()).unwrap();
        assert!(matches!(h.on_frame(&f), Ok(Some(Event::Opened { .. }))));
        (d, h, id)
    }
    fn raw(id: u32, ty: u8, flags: u8, data: &[u8]) -> Vec<u8> {
        let mut v = id.to_be_bytes().to_vec();
        v.extend([ty, flags]);
        v.extend((data.len() as u16).to_be_bytes());
        v.extend(data);
        v
    }

    #[test]
    fn frames_round_trip_and_interleave() {
        let frames = vec![
            TunnelFrame::new(
                1,
                FrameType::Open,
                0,
                OpenParams::Directory.encode().unwrap(),
            ),
            TunnelFrame::new(3, FrameType::Data, FLAG_FIN, vec![1, 2, 3]),
            TunnelFrame::new(5, FrameType::Data, 0, vec![0; MAX_FRAME_DATA]),
            TunnelFrame::new(3, FrameType::Credit, 0, 9u32.to_be_bytes().to_vec()),
            TunnelFrame::new(3, FrameType::Close, 0, vec![]),
            TunnelFrame::new(5, FrameType::Reset, 0, 4u16.to_be_bytes().to_vec()),
        ];
        let mut buf = Vec::new();
        for f in &frames {
            f.encode_into(&mut buf).unwrap();
        }
        assert_eq!(decode_frames(&buf).unwrap(), frames);
    }

    #[test]
    fn decoder_rejections() {
        use TunnelError::*;
        let credit = 1u32.to_be_bytes();
        let cases: Vec<(Vec<u8>, TunnelError)> = vec![
            (vec![], EmptyPlaintext),
            (vec![0; 7], Truncated),
            (raw(1, 2, 0, b"abc")[..10].to_vec(), Truncated),
            (raw(1, 9, 0, b""), UnknownType),
            (raw(1, 0, 0, b""), UnknownType),
            (raw(1, 2, 0x02, b""), BadFlags),
            (raw(1, 2, 0x81, b""), BadFlags),
            (raw(1, 3, FLAG_FIN, &credit), BadFlags),
            (raw(1, 4, FLAG_FIN, b""), BadFlags),
            (raw(1, 2, 0, &vec![0; MAX_FRAME_DATA + 1]), FrameTooLarge),
            (raw(1, 3, 0, &[0, 0]), BadBody),
            (raw(1, 3, 0, &[0; 4]), BadBody),
            (raw(1, 3, 0, &[0; 5]), BadBody),
            (raw(1, 4, 0, &[0]), BadBody),
            (raw(1, 5, 0, &[0]), BadBody),
            (raw(1, 5, 0, &[0; 3]), BadBody),
            (raw(1, 1, 0, b""), BadBody),
        ];
        for (bytes, want) in cases {
            assert_eq!(decode_frames(&bytes), Err(want), "{bytes:?}");
        }
        let mut ok = raw(1, 2, 0, b"x");
        ok.push(0);
        assert_eq!(decode_frames(&ok), Err(Truncated));
        let mut big = Vec::new();
        assert_eq!(
            TunnelFrame::new(1, FrameType::Data, 0, vec![0; MAX_FRAME_DATA + 1])
                .encode_into(&mut big),
            Err(FrameTooLarge)
        );
    }

    #[test]
    fn id_parity_and_reuse() {
        let (mut d, mut h) = pair();
        assert_eq!([open(&mut d, &terminal()), open(&mut d, &chat())], [1, 3]);
        assert_eq!(open(&mut h, &OpenParams::Directory), 2);
        let frame = |id| TunnelFrame::new(id, FrameType::Open, 0, terminal().encode().unwrap());
        // Host receives odd ids only, strictly increasing.
        assert!(h.on_frame(&frame(2)).is_err());
        assert!(h.on_frame(&frame(0)).is_err());
        assert!(h.on_frame(&frame(3)).is_ok());
        assert_eq!(h.on_frame(&frame(3)), Err(TunnelError::StreamReused));
        assert_eq!(h.on_frame(&frame(1)), Err(TunnelError::StreamReused));
        // Closed ids are never reused by the allocator.
        let f = d.close(1).unwrap();
        assert_eq!(f.kind, FrameType::Close);
        assert_eq!(open(&mut d, &terminal()), 5);
        // Device receives even ids only.
        let host_open = TunnelFrame::new(
            2,
            FrameType::Open,
            0,
            OpenParams::Directory.encode().unwrap(),
        );
        assert!(d.on_frame(&host_open).is_ok());
        let odd = TunnelFrame::new(
            7,
            FrameType::Open,
            0,
            OpenParams::Directory.encode().unwrap(),
        );
        assert_eq!(d.on_frame(&odd), Err(TunnelError::BadParity));
    }

    #[test]
    fn stream_and_terminal_limits() {
        let (mut d, _) = pair();
        for _ in 0..MAX_TERMINAL_STREAMS {
            open(&mut d, &terminal());
        }
        assert_eq!(
            d.open(&terminal()).unwrap_err(),
            TunnelError::TooManyTerminals
        );
        for _ in MAX_TERMINAL_STREAMS..MAX_OPEN_STREAMS {
            open(&mut d, &chat());
        }
        assert_eq!(d.open(&chat()).unwrap_err(), TunnelError::TooManyStreams);
        // Closing frees a slot (terminal count too).
        d.close(1).unwrap();
        assert!(d.open(&terminal()).is_ok());
        // Receiving side enforces the same limits.
        let (mut d, mut h) = pair();
        for i in 0..MAX_OPEN_STREAMS {
            let (_, f) = d.open(&if i < 32 { terminal() } else { chat() }).unwrap();
            h.on_frame(&f).unwrap();
        }
        let extra = TunnelFrame::new(129, FrameType::Open, 0, chat().encode().unwrap());
        assert_eq!(h.on_frame(&extra), Err(TunnelError::TooManyStreams));
    }

    #[test]
    fn kind_permissions() {
        let (mut d, mut h) = pair();
        assert_eq!(
            h.open(&terminal()).unwrap_err(),
            TunnelError::KindNotAllowed
        );
        assert_eq!(h.open(&chat()).unwrap_err(), TunnelError::KindNotAllowed);
        assert_eq!(
            d.open(&OpenParams::Directory).unwrap_err(),
            TunnelError::KindNotAllowed
        );
        let transfer = OpenParams::Transfer(TransferOpen {
            request_id: RequestId::try_from("r-1".to_string()).unwrap(),
        });
        assert!(d.open(&transfer).is_ok() && h.open(&transfer).is_ok());
        // Peer-sent forbidden OPENs.
        let dir = TunnelFrame::new(
            1,
            FrameType::Open,
            0,
            OpenParams::Directory.encode().unwrap(),
        );
        assert_eq!(h.on_frame(&dir), Err(TunnelError::KindNotAllowed));
        let term = TunnelFrame::new(2, FrameType::Open, 0, terminal().encode().unwrap());
        assert_eq!(d.on_frame(&term), Err(TunnelError::KindNotAllowed));
        // media is reserved, rpc is never in OPEN, unknown codes fail.
        for (code, err) in [
            (6, TunnelError::ReservedKind),
            (0, TunnelError::UnknownKind),
            (99, TunnelError::UnknownKind),
        ] {
            assert_eq!(OpenParams::decode(&[code]), Err(err));
            let f = TunnelFrame::new(3, FrameType::Open, 0, vec![code]);
            assert_eq!(h.on_frame(&f), Err(err));
        }
        assert_eq!(StreamKind::Terminal.class(), StreamClass::Interactive);
        assert_eq!(StreamKind::Rpc.class(), StreamClass::Control);
        assert_eq!(StreamKind::Transfer.class(), StreamClass::Bulk);
    }

    #[test]
    fn stream_zero_rules() {
        let (mut d, mut h) = pair();
        for kind in [FrameType::Close, FrameType::Reset] {
            let data = if kind == FrameType::Close {
                vec![]
            } else {
                vec![0, 1]
            };
            assert_eq!(
                h.on_frame(&TunnelFrame::new(0, kind, 0, data)),
                Err(TunnelError::StreamZero)
            );
        }
        let f = TunnelFrame::new(
            0,
            FrameType::Open,
            0,
            OpenParams::Directory.encode().unwrap(),
        );
        assert_eq!(h.on_frame(&f), Err(TunnelError::StreamZero));
        assert_eq!(d.close(0).unwrap_err(), TunnelError::StreamZero);
        let msg = d.send_data(0, b"{}", true).unwrap();
        assert_eq!(
            h.on_frame(&msg),
            Ok(Some(Event::Message {
                stream_id: 0,
                data: b"{}".to_vec()
            }))
        );
    }

    #[test]
    fn flow_control_stream_and_tunnel() {
        let (mut d, mut h, id) = open_pair();
        let chunk = vec![0u8; MAX_FRAME_DATA];
        // 4 frames fill the 64 KiB stream window; the 5th is refused locally.
        for _ in 0..4 {
            let f = d.send_data(id, &chunk, false).unwrap();
            h.on_frame(&f).unwrap();
        }
        assert_eq!(d.send_credit(id), 0);
        assert_eq!(
            d.send_data(id, b"x", false).unwrap_err(),
            TunnelError::WindowExceeded
        );
        // A peer that ignores the window is a protocol error on the receiver.
        let rogue = TunnelFrame::new(id, FrameType::Data, 0, vec![1]);
        assert_eq!(h.on_frame(&rogue), Err(TunnelError::WindowExceeded));
        // Credit restores the window.
        let credit = h.grant(id, 1000).unwrap();
        d.on_frame(&credit).unwrap();
        assert_eq!(d.send_credit(id), 1000);

        // Tunnel window: 256 KiB shared by streams; stream 0 and others both count.
        let (mut d, mut h) = pair();
        let ids: Vec<u32> = (0..5)
            .map(|_| {
                let (id, f) = d.open(&chat()).unwrap();
                h.on_frame(&f).unwrap();
                id
            })
            .collect();
        for id in &ids[..4] {
            for _ in 0..4 {
                h.on_frame(&d.send_data(*id, &chunk, false).unwrap())
                    .unwrap();
            }
        }
        assert_eq!(d.send_credit(ids[4]), 0);
        assert_eq!(d.send_credit(0), 0);
        let rogue = TunnelFrame::new(ids[4], FrameType::Data, 0, vec![1]);
        assert_eq!(h.on_frame(&rogue), Err(TunnelError::WindowExceeded));
        // Tunnel credit via stream 0 unblocks other streams.
        d.on_frame(&h.grant(0, 100).unwrap()).unwrap();
        assert_eq!(d.send_credit(ids[4]), 100);
    }

    #[test]
    fn credit_overflow() {
        let (mut d, mut h, id) = open_pair();
        let credit =
            |id, n: u32| TunnelFrame::new(id, FrameType::Credit, 0, n.to_be_bytes().to_vec());
        // Window is full already: any credit exceeds the initial window.
        assert_eq!(d.on_frame(&credit(id, 1)), Err(TunnelError::CreditOverflow));
        assert_eq!(d.on_frame(&credit(0, 1)), Err(TunnelError::CreditOverflow));
        assert_eq!(
            d.on_frame(&credit(id, u32::MAX)),
            Err(TunnelError::CreditOverflow)
        );
        // Sum of two u32::MAX credits cannot wrap either.
        d.send_data(id, &[0; 10], false).unwrap();
        assert_eq!(
            d.on_frame(&credit(id, 11)),
            Err(TunnelError::CreditOverflow)
        );
        assert!(d.on_frame(&credit(id, 10)).is_ok());
        assert_eq!(d.on_frame(&credit(id, 1)), Err(TunnelError::CreditOverflow));
        // Local grants are bounded too and zero is invalid.
        assert_eq!(h.grant(id, 1).unwrap_err(), TunnelError::CreditOverflow);
        assert_eq!(h.grant(id, 0).unwrap_err(), TunnelError::BadBody);
        // Credit for an unknown stream.
        assert_eq!(d.on_frame(&credit(99, 1)), Err(TunnelError::UnknownStream));
    }

    #[test]
    fn reassembly_limit_and_interleaving() {
        let (mut d, mut h2) = pair();
        let (a, fa) = d.open(&chat()).unwrap();
        let (b, fb) = d.open(&chat()).unwrap();
        h2.on_frame(&fa).unwrap();
        h2.on_frame(&fb).unwrap();
        // Interleaved fragments of two streams reassemble independently.
        let parts = [(a, "he"), (b, "wor"), (a, "llo"), (b, "ld")];
        let mut out = Vec::new();
        for (i, (id, s)) in parts.iter().enumerate() {
            let f = d.send_data(*id, s.as_bytes(), i >= 2).unwrap();
            if let Some(Event::Message { stream_id, data }) = h2.on_frame(&f).unwrap() {
                out.push((stream_id, data));
            }
        }
        assert_eq!(out, vec![(a, b"hello".to_vec()), (b, b"world".to_vec())]);

        // Exactly 1 MiB passes, 1 MiB + 1 fails. Sender grants credit as the receiver consumes.
        for (extra, ok) in [(0usize, true), (1, false)] {
            let (mut d, mut h, id) = open_pair();
            let mut sent = 0;
            let total = MAX_LOGICAL_MESSAGE + extra;
            let mut last = Ok(None);
            while sent < total {
                let n = (total - sent)
                    .min(MAX_FRAME_DATA)
                    .min(d.send_credit(id) as usize);
                let f = d.send_data(id, &vec![0; n], sent + n == total).unwrap();
                sent += n;
                last = h.on_frame(&f);
                if last.is_err() {
                    break;
                }
                // Receiver consumed the frame: return credit for stream and tunnel.
                d.on_frame(&h.grant(id, n as u32).unwrap()).unwrap();
                d.on_frame(&h.grant(0, n as u32).unwrap()).unwrap();
            }
            if ok {
                assert!(
                    matches!(last, Ok(Some(Event::Message { ref data, .. })) if data.len() == MAX_LOGICAL_MESSAGE)
                );
            } else {
                assert_eq!(last, Err(TunnelError::MessageTooLarge));
            }
        }
    }

    #[test]
    fn close_and_reset_transitions() {
        let (mut d, mut h, id) = open_pair();
        // Peer CLOSE ends the stream; later data is a protocol error.
        let close = d.close(id).unwrap();
        assert_eq!(
            h.on_frame(&close),
            Ok(Some(Event::Closed { stream_id: id }))
        );
        let data = TunnelFrame::new(id, FrameType::Data, 0, vec![1]);
        assert_eq!(h.on_frame(&data), Err(TunnelError::UnknownStream));
        assert_eq!(h.on_frame(&close), Err(TunnelError::UnknownStream));
        // Data the peer had in flight toward a stream we closed ourselves is dropped.
        assert_eq!(d.on_frame(&data), Ok(None));
        assert_eq!(
            d.send_data(id, b"x", false).unwrap_err(),
            TunnelError::WindowExceeded
        );

        let (mut d, mut h, id) = open_pair();
        let reset = h.reset(id, 42).unwrap();
        assert_eq!(
            d.on_frame(&reset),
            Ok(Some(Event::Reset {
                stream_id: id,
                code: 42
            }))
        );
        assert_eq!(d.on_frame(&data), Err(TunnelError::UnknownStream));
        assert_eq!(d.close(id).unwrap_err(), TunnelError::UnknownStream);
        // Terminal slot is released.
        assert!(d.open(&terminal()).is_ok());
    }

    #[test]
    fn open_params_round_trip() {
        for p in [
            OpenParams::Directory,
            terminal(),
            chat(),
            OpenParams::FilesWatch(FilesWatchOpen {
                workspace_id: ws(),
                path: EncodedPathId::try_from("abc_-1".to_string()).unwrap(),
            }),
            OpenParams::Transfer(TransferOpen {
                request_id: RequestId::try_from("r".to_string()).unwrap(),
            }),
        ] {
            let bytes = p.encode().unwrap();
            assert_eq!(bytes[0], p.kind().code());
            assert!(bytes.len() < 256);
            assert_eq!(OpenParams::decode(&bytes).unwrap(), p);
            // Trailing bytes and truncation are rejected.
            let mut extra = bytes.clone();
            extra.push(0);
            assert_eq!(OpenParams::decode(&extra), Err(TunnelError::BadPayload));
            if bytes.len() > 1 {
                assert_eq!(
                    OpenParams::decode(&bytes[..bytes.len() - 1]),
                    Err(TunnelError::BadPayload)
                );
            }
        }
        assert_eq!(OpenParams::decode(&[]), Err(TunnelError::BadBody));
        assert_eq!(
            OpenParams::decode(&[2, 0xff, 0xff]),
            Err(TunnelError::BadPayload)
        );
        // Invalid ids and out-of-range terminal sizes fail inside postcard.
        let mut bad = terminal().encode().unwrap();
        bad[1] = 0; // empty workspace id string
        assert_eq!(OpenParams::decode(&bad), Err(TunnelError::BadPayload));
    }

    fn hello() -> Hello {
        Hello {
            device_name: DeviceName::try_from("Laptop".to_string()).unwrap(),
            device_kind: DeviceKind::Web,
            auth_epoch: 1,
            host_access_epoch: u64::MAX,
            runtime_generation: 3,
            resume: BoundedList(vec![ResumeEntry {
                kind: StreamKind::Directory,
                cursor: 9,
            }]),
            send_directory: true,
            device_bundle: BoundedList(vec![0xAB; MAX_DEVICE_BUNDLE]),
        }
    }

    #[test]
    fn hello_and_greeting_round_trip_and_bounds() {
        let h = hello();
        let bytes = h.encode().unwrap();
        assert!(bytes.len() <= MAX_HANDSHAKE_PAYLOAD);
        assert_eq!(Hello::decode(&bytes).unwrap(), h);
        // Worst case stays under the payload cap.
        let mut max = hello();
        max.device_name = DeviceName::try_from("n".repeat(64)).unwrap();
        max.resume = BoundedList(vec![
            ResumeEntry {
                kind: StreamKind::Chat,
                cursor: u64::MAX
            };
            MAX_RESUME_ENTRIES
        ]);
        assert!(max.encode().unwrap().len() <= MAX_HANDSHAKE_PAYLOAD);
        // Bounds on the way out and in.
        let mut big = hello();
        big.device_bundle.0.push(0);
        assert!(big.encode().is_err());
        big.resume = BoundedList(vec![ResumeEntry {
            kind: StreamKind::Rpc,
            cursor: 0,
        }]);
        assert!(hello().resume.0.len() == 1 && big.encode().is_err());
        let mut bad_kind = hello();
        bad_kind.resume.0[0].kind = StreamKind::Media;
        assert!(bad_kind.encode().is_err());
        assert!(DeviceName::try_from("n".repeat(65)).is_err());
        assert!(DeviceName::try_from(String::new()).is_err());
        // Hand-built oversize bundle (65 > bound) is rejected by decode.
        let oversize = postcard::to_allocvec(&(
            "x",
            DeviceKind::Web,
            0u64,
            0u64,
            0u64,
            Vec::<ResumeEntry>::new(),
            false,
            vec![0u8; MAX_DEVICE_BUNDLE + 1],
        ))
        .unwrap();
        assert!(Hello::decode(&oversize).is_err());
        assert!(Hello::decode(&[MAX_HANDSHAKE_PAYLOAD as u8; MAX_HANDSHAKE_PAYLOAD + 1]).is_err());

        for g in [
            HostGreeting::Welcome(Welcome { directory: true }),
            HostGreeting::ApprovalPending(ApprovalPending {
                code: 999_999,
                deadline_ms: APPROVAL_DEADLINE_MS,
            }),
            HostGreeting::StaleEpoch(StaleEpoch {
                auth_epoch: 1,
                host_access_epoch: 2,
                runtime_generation: 3,
            }),
            HostGreeting::UpdateRequired(UpdateRequired {
                older_side: OlderSide::Host,
            }),
        ] {
            let b = g.encode().unwrap();
            assert!(b.len() < 64);
            assert_eq!(HostGreeting::decode(&b).unwrap(), g);
        }
        assert!(
            HostGreeting::ApprovalPending(ApprovalPending {
                code: 1_000_000,
                deadline_ms: 1
            })
            .encode()
            .is_err()
        );
        assert!(
            HostGreeting::ApprovalPending(ApprovalPending {
                code: 1,
                deadline_ms: APPROVAL_DEADLINE_MS + 1
            })
            .encode()
            .is_err()
        );
    }

    #[test]
    fn malformed_postcard_is_rejected() {
        let good = HostGreeting::Welcome(Welcome { directory: true })
            .encode()
            .unwrap();
        let mut trailing = good.clone();
        trailing.push(0);
        assert!(HostGreeting::decode(&trailing).is_err());
        assert!(HostGreeting::decode(&[]).is_err());
        assert!(HostGreeting::decode(&[9]).is_err()); // unknown variant
        assert!(HostGreeting::decode(&[0, 2]).is_err()); // bool must be 0/1
        assert!(Hello::decode(&[0xff; 32]).is_err());
        let h = hello().encode().unwrap();
        assert!(Hello::decode(&h[..h.len() - 1]).is_err());
    }

    #[test]
    fn rpc_envelope_has_no_version() {
        let u = "11111111-1111-4111-8111-111111111111";
        let call = format!(
            r#"{{"method":"workspace.get","params":{{"context":{{"workspaceId":"{u}","workspaceEpoch":"{u}","runtimeId":"{u}","runtimeGeneration":"1","hostAccessEpoch":"1","grantRevision":"1"}}}}}}"#
        );
        let ok = format!(r#"{{"requestId":"r1","timeoutMs":1000,"call":{call}}}"#);
        let env: RpcEnvelope = serde_json::from_str(&ok).unwrap();
        assert!(matches!(env.call, RpcCall::WorkspaceGet(_)));
        let with_v = format!(r#"{{"v":2,"requestId":"r1","timeoutMs":1000,"call":{call}}}"#);
        assert!(serde_json::from_str::<RpcEnvelope>(&with_v).is_err());
    }

    #[test]
    fn directory_messages_round_trip_in_postcard() {
        const U: &str = "11111111-1111-4111-8111-111111111111";
        let id = |s: &str| s.to_owned();
        let text = |s: &str| DisplayText::try_from(id(s)).unwrap();
        let pane = PaneId::try_from(id(U)).unwrap();
        let ws = DirectoryWorkspace {
            id: WorkspaceId::try_from(id(U)).unwrap(),
            epoch: WorkspaceEpoch::try_from(id(U)).unwrap(),
            name: text("app"),
            capabilities: crate::CapabilitySet::control_with_workspace_tools(),
            tabs: vec![DirectoryTab {
                tab_id: TabId::try_from(id(U)).unwrap(),
                name: text("main"),
                layout: DirectoryLayout::Split {
                    axis: SplitAxis::Horizontal,
                    first: Box::new(DirectoryLayout::Pane(pane)),
                    second: Box::new(DirectoryLayout::Pane(pane)),
                },
            }],
            terminals: vec![DirectoryTerminal {
                pane_id: pane,
                tab_id: TabId::try_from(id(U)).unwrap(),
                title: text("main"),
                state: PaneState::Running,
                session_epoch: Some(SessionEpoch::try_from(id(U)).unwrap()),
            }],
            chats: Vec::new(),
        };
        for m in [
            DirectoryMessage::Snapshot(DirectorySnapshot {
                seq: 0,
                host: DirectoryHost {
                    name: text("Mac"),
                    platform: text("macos"),
                    version: text("0.1.0"),
                },
                workspaces: vec![ws.clone()],
            }),
            DirectoryMessage::Change(DirectoryUpdate {
                seq: 1,
                change: DirectoryChange::Workspace(ws.clone()),
            }),
            DirectoryMessage::Change(DirectoryUpdate {
                seq: 2,
                change: DirectoryChange::Removed(ws.id),
            }),
        ] {
            let bytes = m.encode().unwrap();
            assert_eq!(DirectoryMessage::decode(&bytes).unwrap(), m);
            let mut extra = bytes.clone();
            extra.push(0);
            assert!(DirectoryMessage::decode(&extra).is_err());
        }
    }
}
