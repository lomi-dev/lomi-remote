//! Canonical logical-message framing shared by native and browser callers.
//! Each entire frame, including its header, must be inside the existing AEAD.

use std::fmt;

pub const HEADER_LEN: usize = 32;
pub const MAX_MESSAGE_LEN: usize = 1_048_576;
pub const MAX_PLAINTEXT_FRAME_LEN: usize = 16_384;
pub const MAX_FRAGMENT_PAYLOAD_LEN: usize = MAX_PLAINTEXT_FRAME_LEN - HEADER_LEN;
pub const MAX_FRAGMENTS_PER_MESSAGE: usize = MAX_MESSAGE_LEN.div_ceil(MAX_FRAGMENT_PAYLOAD_LEN);
/// Separate proposed transport bound: outer 24 + binding 24 + tag 16.
/// This constant does not alter any existing crypto or transport limit.
pub const MAX_TRANSPORT_FRAME_LEN: usize = MAX_PLAINTEXT_FRAME_LEN + 24 + 24 + 16;
pub const ASSEMBLY_TIMEOUT_MS: u64 = 5_000;
const MAGIC: [u8; 4] = *b"LMF2";
const VERSION: u8 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MessageKind {
    RpcRequest = 1,
    RpcResponse = 2,
    WorkspaceFrame = 3,
    TerminalFrame = 4,
    FileWatchFrame = 5,
}

impl MessageKind {
    pub(crate) fn parse(value: u8) -> Result<Self, FramingError> {
        match value {
            1 => Ok(Self::RpcRequest),
            2 => Ok(Self::RpcResponse),
            3 => Ok(Self::WorkspaceFrame),
            4 => Ok(Self::TerminalFrame),
            5 => Ok(Self::FileWatchFrame),
            _ => Err(FramingError::Kind),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FramingError {
    Disposed,
    Busy,
    Empty,
    Oversize,
    HeaderLength,
    Magic,
    Version,
    Kind,
    Reserved,
    MessageId,
    TotalChanged,
    KindChanged,
    Offset,
    PayloadLength,
    NoncanonicalFragment,
    Trailing,
    Overflow,
    ClockRegressed,
    Timeout,
    Allocation,
}

struct Pending {
    kind: MessageKind,
    id: u64,
    bytes: zeroize::Zeroizing<Vec<u8>>,
    offset: usize,
}

/// One pending message per direction/channel. Any error permanently disposes it.
/// Caller must dispose on abort, authority change, disconnect, or rekey.
pub struct MessageEncoder {
    next_id: Option<u64>,
    pending: Option<Pending>,
    disposed: bool,
}

impl Default for MessageEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MessageEncoder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageEncoder")
            .field(
                "buffered_bytes",
                &self.pending.as_ref().map_or(0, |p| p.bytes.len()),
            )
            .field(
                "emitted_bytes",
                &self.pending.as_ref().map_or(0, |p| p.offset),
            )
            .finish()
    }
}

impl MessageEncoder {
    pub fn new() -> Self {
        Self {
            next_id: Some(1),
            pending: None,
            disposed: false,
        }
    }

    /// Bytes retained by the active plaintext message, including unused Vec
    /// capacity. The encoder keeps this allocation until its final fragment.
    pub fn retained_bytes(&self) -> usize {
        self.pending
            .as_ref()
            .map_or(0, |pending| pending.bytes.capacity())
    }

    /// Takes ownership without copying. Capacity is bounded as well as length.
    pub fn begin(&mut self, kind: MessageKind, bytes: Vec<u8>) -> Result<u64, FramingError> {
        let result = self.begin_inner(kind, zeroize::Zeroizing::new(bytes));
        if result.is_err() {
            self.dispose();
        }
        result
    }

    fn begin_inner(
        &mut self,
        kind: MessageKind,
        bytes: zeroize::Zeroizing<Vec<u8>>,
    ) -> Result<u64, FramingError> {
        if self.disposed {
            return Err(FramingError::Disposed);
        }
        if self.pending.is_some() {
            return Err(FramingError::Busy);
        }
        if bytes.is_empty() {
            return Err(FramingError::Empty);
        }
        if bytes.len() > MAX_MESSAGE_LEN || bytes.capacity() > MAX_MESSAGE_LEN {
            return Err(FramingError::Oversize);
        }
        let id = self.next_id.ok_or(FramingError::Overflow)?;
        self.next_id = id.checked_add(1);
        self.pending = Some(Pending {
            kind,
            id,
            bytes,
            offset: 0,
        });
        Ok(id)
    }

    /// Emits at most one bounded allocation. None means no pending message.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, FramingError> {
        let result = self.next_frame_inner();
        if result.is_err() {
            self.dispose();
        }
        result
    }

    fn next_frame_inner(&mut self) -> Result<Option<Vec<u8>>, FramingError> {
        if self.disposed {
            return Err(FramingError::Disposed);
        }
        let Some(pending) = self.pending.as_mut() else {
            return Ok(None);
        };
        let remaining = pending
            .bytes
            .len()
            .checked_sub(pending.offset)
            .ok_or(FramingError::Overflow)?;
        let payload_len = remaining.min(MAX_FRAGMENT_PAYLOAD_LEN);
        let end = pending
            .offset
            .checked_add(payload_len)
            .ok_or(FramingError::Overflow)?;
        let frame_len = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(FramingError::Overflow)?;
        let mut frame = Vec::new();
        frame
            .try_reserve_exact(frame_len)
            .map_err(|_| FramingError::Allocation)?;
        frame.extend_from_slice(&MAGIC);
        frame.push(VERSION);
        frame.push(pending.kind as u8);
        frame.extend_from_slice(&[0; 2]);
        frame.extend_from_slice(&pending.id.to_be_bytes());
        frame.extend_from_slice(&(pending.bytes.len() as u32).to_be_bytes());
        frame.extend_from_slice(&(pending.offset as u32).to_be_bytes());
        frame.extend_from_slice(&(payload_len as u32).to_be_bytes());
        frame.extend_from_slice(&[0; 4]);
        frame.extend_from_slice(&pending.bytes[pending.offset..end]);
        pending.offset = end;
        if end == pending.bytes.len() {
            self.pending = None;
        }
        Ok(Some(frame))
    }

    pub fn abort(&mut self) {
        self.dispose();
    }

    /// Wipes the owned pending plaintext allocation before releasing it. Returned
    /// fragments belong to the caller and must be wiped after sealing/sending.
    pub fn dispose(&mut self) {
        self.pending = None;
        self.next_id = None;
        self.disposed = true;
    }
}

/// Opaque bytes: caller may decode UTF-8/JSON only after completion.
pub struct CompletedMessage {
    pub kind: MessageKind,
    pub id: u64,
    pub bytes: Vec<u8>,
}

impl fmt::Debug for CompletedMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompletedMessage")
            .field("byte_count", &self.bytes.len())
            .finish()
    }
}

struct Active {
    kind: MessageKind,
    id: u64,
    total: usize,
    deadline_ms: u64,
    bytes: zeroize::Zeroizing<Vec<u8>>,
}

pub struct MessageAssembler {
    next_id: Option<u64>,
    active: Option<Active>,
    last_now_ms: Option<u64>,
    disposed: bool,
}

impl Default for MessageAssembler {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for MessageAssembler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MessageAssembler")
            .field(
                "received_bytes",
                &self.active.as_ref().map_or(0, |a| a.bytes.len()),
            )
            .field(
                "declared_bytes",
                &self.active.as_ref().map_or(0, |a| a.total),
            )
            .finish()
    }
}

impl MessageAssembler {
    pub fn new() -> Self {
        Self {
            next_id: Some(1),
            active: None,
            last_now_ms: None,
            disposed: false,
        }
    }

    /// Call on every authenticated frame, using monotonic caller milliseconds.
    pub fn push(
        &mut self,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Option<CompletedMessage>, FramingError> {
        let result = self.push_inner(frame, now_ms);
        if result.is_err() {
            self.dispose();
        }
        result
    }

    /// Caller must schedule expiry even when no further frames arrive.
    pub fn expire(&mut self, now_ms: u64) -> Result<(), FramingError> {
        let result = self.check_time(now_ms);
        if result.is_err() {
            self.dispose();
        }
        result
    }

    fn check_time(&mut self, now_ms: u64) -> Result<(), FramingError> {
        if self.disposed {
            return Err(FramingError::Disposed);
        }
        if self.last_now_ms.is_some_and(|last| now_ms < last) {
            return Err(FramingError::ClockRegressed);
        }
        self.last_now_ms = Some(now_ms);
        if self
            .active
            .as_ref()
            .is_some_and(|a| now_ms >= a.deadline_ms)
        {
            return Err(FramingError::Timeout);
        }
        Ok(())
    }

    fn push_inner(
        &mut self,
        frame: &[u8],
        now_ms: u64,
    ) -> Result<Option<CompletedMessage>, FramingError> {
        self.check_time(now_ms)?;
        if frame.len() < HEADER_LEN {
            return Err(FramingError::HeaderLength);
        }
        if frame.len() > MAX_PLAINTEXT_FRAME_LEN {
            return Err(FramingError::Oversize);
        }
        if frame[0..4] != MAGIC {
            return Err(FramingError::Magic);
        }
        if frame[4] != VERSION {
            return Err(FramingError::Version);
        }
        let kind = MessageKind::parse(frame[5])?;
        if frame[6..8] != [0; 2] || frame[28..32] != [0; 4] {
            return Err(FramingError::Reserved);
        }
        // All fixed slices below are in the already validated 32-byte header.
        let id = u64::from_be_bytes(
            frame[8..16]
                .try_into()
                .map_err(|_| FramingError::HeaderLength)?,
        );
        let total = u32::from_be_bytes(
            frame[16..20]
                .try_into()
                .map_err(|_| FramingError::HeaderLength)?,
        ) as usize;
        let offset = u32::from_be_bytes(
            frame[20..24]
                .try_into()
                .map_err(|_| FramingError::HeaderLength)?,
        ) as usize;
        let payload_len = u32::from_be_bytes(
            frame[24..28]
                .try_into()
                .map_err(|_| FramingError::HeaderLength)?,
        ) as usize;
        if id == 0 || id != self.next_id.ok_or(FramingError::Overflow)? {
            return Err(FramingError::MessageId);
        }
        if total == 0 || payload_len == 0 {
            return Err(FramingError::Empty);
        }
        if total > MAX_MESSAGE_LEN {
            return Err(FramingError::Oversize);
        }
        if payload_len > MAX_FRAGMENT_PAYLOAD_LEN {
            return Err(FramingError::PayloadLength);
        }
        let expected_len = HEADER_LEN
            .checked_add(payload_len)
            .ok_or(FramingError::Overflow)?;
        if frame.len() != expected_len {
            return Err(FramingError::PayloadLength);
        }
        let end = offset
            .checked_add(payload_len)
            .ok_or(FramingError::Overflow)?;
        if end > total {
            return Err(FramingError::Trailing);
        }
        let deadline_ms = if let Some(active) = self.active.as_ref() {
            if active.id != id {
                return Err(FramingError::MessageId);
            }
            if active.kind != kind {
                return Err(FramingError::KindChanged);
            }
            if active.total != total {
                return Err(FramingError::TotalChanged);
            }
            if active.bytes.len() != offset {
                return Err(FramingError::Offset);
            }
            active.deadline_ms
        } else {
            if offset != 0 {
                return Err(FramingError::Offset);
            }
            now_ms
                .checked_add(ASSEMBLY_TIMEOUT_MS)
                .ok_or(FramingError::Overflow)?
        };
        let remaining = total.checked_sub(offset).ok_or(FramingError::Overflow)?;
        if payload_len != remaining.min(MAX_FRAGMENT_PAYLOAD_LEN) {
            return Err(FramingError::NoncanonicalFragment);
        }
        // No declared-total reservation: only validated bytes actually received.
        let active = self.active.get_or_insert_with(|| Active {
            kind,
            id,
            total,
            deadline_ms,
            bytes: zeroize::Zeroizing::new(Vec::new()),
        });
        active
            .bytes
            .try_reserve_exact(payload_len)
            .map_err(|_| FramingError::Allocation)?;
        active.bytes.extend_from_slice(&frame[HEADER_LEN..]);
        if end != total {
            return Ok(None);
        }
        let mut completed = self.active.take().ok_or(FramingError::Overflow)?;
        self.next_id = id.checked_add(1);
        Ok(Some(CompletedMessage {
            kind: completed.kind,
            id: completed.id,
            bytes: std::mem::take(&mut *completed.bytes),
        }))
    }

    pub fn abort(&mut self) {
        self.dispose();
    }

    pub fn dispose(&mut self) {
        self.active = None;
        self.next_id = None;
        self.disposed = true;
    }
}
