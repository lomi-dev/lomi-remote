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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(id: u64, total: u32, offset: u32, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::from(MAGIC);
        bytes.extend_from_slice(&[VERSION, MessageKind::RpcRequest as u8, 0, 0]);
        bytes.extend_from_slice(&id.to_be_bytes());
        bytes.extend_from_slice(&total.to_be_bytes());
        bytes.extend_from_slice(&offset.to_be_bytes());
        bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        bytes.extend_from_slice(&[0; 4]);
        bytes.extend_from_slice(payload);
        bytes
    }

    fn roundtrip(bytes: Vec<u8>) {
        let mut encoder = MessageEncoder::new();
        let mut assembler = MessageAssembler::new();
        encoder
            .begin(MessageKind::RpcRequest, bytes.clone())
            .unwrap();
        let mut completed = None;
        let mut count = 0;
        while let Some(frame) = encoder.next_frame().unwrap() {
            assert!(frame.len() <= MAX_PLAINTEXT_FRAME_LEN);
            assert!(frame.len() + 24 + 24 + 16 <= MAX_TRANSPORT_FRAME_LEN);
            assert!(completed.is_none());
            completed = assembler.push(&frame, count).unwrap();
            count += 1;
        }
        let completed = completed.unwrap();
        assert_eq!(completed.bytes, bytes);
        assert_eq!(completed.id, 1);
        assert_eq!(completed.kind, MessageKind::RpcRequest);
        assert_eq!(
            count as usize,
            bytes.len().div_ceil(MAX_FRAGMENT_PAYLOAD_LEN)
        );
        assert!(count as usize <= MAX_FRAGMENTS_PER_MESSAGE);
        if bytes.len() == MAX_MESSAGE_LEN {
            assert_eq!(count, 65);
        }
        assert!(encoder.pending.is_none());
        assert!(assembler.active.is_none());
    }

    #[test]
    fn maximum_message_roundtrip_and_exact_frame_bounds() {
        assert_eq!(MAX_FRAGMENT_PAYLOAD_LEN, 16_352);
        assert_eq!(MAX_TRANSPORT_FRAME_LEN, 16_448);
        assert_eq!(MAX_FRAGMENTS_PER_MESSAGE, 65);
        roundtrip(vec![0xa5; MAX_MESSAGE_LEN]);
        let mut encoder = MessageEncoder::new();
        encoder
            .begin(
                MessageKind::WorkspaceFrame,
                vec![7; MAX_FRAGMENT_PAYLOAD_LEN],
            )
            .unwrap();
        assert_eq!(encoder.next_frame().unwrap().unwrap().len(), 16_384);
        assert!(encoder.next_frame().unwrap().is_none());
    }

    #[test]
    fn exact_wire_header_matches_independently_constructed_bytes() {
        let mut encoder = MessageEncoder::new();
        encoder
            .begin(MessageKind::RpcRequest, vec![0x42, 0x43])
            .unwrap();
        let actual = encoder.next_frame().unwrap().unwrap();
        assert_eq!(actual, frame(1, 2, 0, &[0x42, 0x43]));
        assert_eq!(&actual[..8], b"LMF2\x01\x01\x00\x00");
        assert_eq!(&actual[8..16], &1_u64.to_be_bytes());
        assert_eq!(&actual[16..20], &2_u32.to_be_bytes());
        assert_eq!(&actual[20..24], &[0; 4]);
        assert_eq!(&actual[24..28], &2_u32.to_be_bytes());
        assert_eq!(&actual[28..32], &[0; 4]);
        assert_eq!(&actual[32..], &[0x42, 0x43]);
    }

    #[test]
    fn integer_array_json_and_split_utf8_stay_opaque() {
        // JSON for 16,384 integer bytes of 255: 65,537 bytes, without serde.
        let mut json = Vec::with_capacity(65_537);
        json.push(b'[');
        for index in 0..16_384 {
            if index != 0 {
                json.push(b',');
            }
            json.extend_from_slice(b"255");
        }
        json.push(b']');
        assert_eq!(json.len(), 65_537);
        roundtrip(json);
        let mut utf8 = vec![b'a'; MAX_FRAGMENT_PAYLOAD_LEN - 1];
        utf8.extend_from_slice("🙂".as_bytes());
        let mut encoder = MessageEncoder::new();
        encoder
            .begin(MessageKind::TerminalFrame, utf8.clone())
            .unwrap();
        let first = encoder.next_frame().unwrap().unwrap();
        assert!(std::str::from_utf8(&first[HEADER_LEN..]).is_err());
        let mut assembler = MessageAssembler::new();
        assert!(assembler.push(&first, 0).unwrap().is_none());
        let completed = assembler
            .push(&encoder.next_frame().unwrap().unwrap(), 1)
            .unwrap()
            .unwrap();
        assert_eq!(completed.bytes, utf8);
        assert!(std::str::from_utf8(&completed.bytes).is_ok());
        roundtrip(vec![0xff, 0xfe]); // No implicit UTF-8/JSON policy.
    }

    #[test]
    fn sequential_ids_all_kinds_and_no_replay() {
        let mut encoder = MessageEncoder::new();
        let mut assembler = MessageAssembler::new();
        for (index, kind) in [
            MessageKind::RpcRequest,
            MessageKind::RpcResponse,
            MessageKind::WorkspaceFrame,
            MessageKind::TerminalFrame,
            MessageKind::FileWatchFrame,
        ]
        .into_iter()
        .enumerate()
        {
            let id = index as u64 + 1;
            assert_eq!(encoder.begin(kind, vec![42]).unwrap(), id);
            let completed = assembler
                .push(&encoder.next_frame().unwrap().unwrap(), id)
                .unwrap()
                .unwrap();
            assert_eq!((completed.kind, completed.id), (kind, id));
        }
        assert_eq!(
            assembler.push(&frame(5, 1, 0, &[1]), 6).unwrap_err(),
            FramingError::MessageId
        );
        assert!(assembler.disposed);
    }

    fn rejected(bytes: &[u8], error: FramingError) {
        let mut assembler = MessageAssembler::new();
        assert_eq!(assembler.push(bytes, 0).unwrap_err(), error);
        assert!(assembler.disposed);
        assert!(assembler.active.is_none());
        assert_eq!(
            assembler.push(&frame(1, 1, 0, &[1]), 0).unwrap_err(),
            FramingError::Disposed
        );
    }

    #[test]
    fn invalid_headers_lengths_and_bounds_poison() {
        rejected(&[0; HEADER_LEN - 1], FramingError::HeaderLength);
        rejected(&frame(0, 1, 0, &[1]), FramingError::MessageId);
        rejected(&frame(2, 1, 0, &[1]), FramingError::MessageId);
        rejected(&frame(1, 0, 0, &[1]), FramingError::Empty);
        rejected(&frame(1, 1, 0, &[]), FramingError::Empty);
        rejected(
            &frame(1, MAX_MESSAGE_LEN as u32 + 1, 0, &[1]),
            FramingError::Oversize,
        );
        rejected(&frame(1, 1, 1, &[1]), FramingError::Trailing);
        rejected(&frame(1, 3, 1, &[1]), FramingError::Offset);
        rejected(
            &frame(1, 20_000, 0, &vec![1; MAX_FRAGMENT_PAYLOAD_LEN + 1]),
            FramingError::Oversize,
        );
        for (offset, value, error) in [
            (0, b'X', FramingError::Magic),
            (4, 2, FramingError::Version),
            (5, 0, FramingError::Kind),
            (5, 6, FramingError::Kind),
            (6, 1, FramingError::Reserved),
            (7, 1, FramingError::Reserved),
            (28, 1, FramingError::Reserved),
            (31, 1, FramingError::Reserved),
            (27, 2, FramingError::PayloadLength),
        ] {
            let mut bytes = frame(1, 1, 0, &[1]);
            bytes[offset] = value;
            rejected(&bytes, error);
        }
        let mut trailing = frame(1, 1, 0, &[1]);
        trailing.push(2);
        rejected(&trailing, FramingError::PayloadLength);
        let mut excessive_declared = frame(1, 1, 0, &[1]);
        excessive_declared[24..28].copy_from_slice(&u32::MAX.to_be_bytes());
        rejected(&excessive_declared, FramingError::PayloadLength);
        // The checked sum overflows on wasm32, exceeds total on 64-bit native.
        let mut assembler = MessageAssembler::new();
        assert!(matches!(
            assembler.push(&frame(1, 3, u32::MAX, &[1]), 0),
            Err(FramingError::Overflow | FramingError::Trailing)
        ));
        assert!(assembler.active.is_none());
        assert!(assembler.disposed);
    }

    #[test]
    fn canonical_fragments_reject_drip_short_middle_and_wrong_tail() {
        // Rejected before inserting Active or reserving any message storage.
        rejected(
            &frame(1, MAX_MESSAGE_LEN as u32, 0, &[1]),
            FramingError::NoncanonicalFragment,
        );
        let chunk = MAX_FRAGMENT_PAYLOAD_LEN as u32;
        let full = vec![1; MAX_FRAGMENT_PAYLOAD_LEN];
        for (total, payload, error) in [
            (3 * chunk + 1, vec![1], FramingError::NoncanonicalFragment),
            (chunk + 2, vec![1], FramingError::NoncanonicalFragment),
            (chunk + 1, vec![1, 2], FramingError::Trailing),
        ] {
            let mut assembler = MessageAssembler::new();
            assert!(
                assembler
                    .push(&frame(1, total, 0, &full), 0)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(
                assembler
                    .push(&frame(1, total, chunk, &payload), 1)
                    .unwrap_err(),
                error
            );
            assert!(assembler.active.is_none());
            assert!(assembler.disposed);
        }
    }

    #[test]
    fn duplicate_gap_changed_identity_and_interleaving_poison_and_free() {
        let full = vec![1; MAX_FRAGMENT_PAYLOAD_LEN];
        let chunk = MAX_FRAGMENT_PAYLOAD_LEN as u32;
        let total = 2 * chunk + 1;
        for (bytes, error) in [
            (frame(1, total, 0, &full), FramingError::Offset),
            (frame(1, total, chunk + 1, &full), FramingError::Offset),
            (
                frame(1, total + 1, chunk, &full),
                FramingError::TotalChanged,
            ),
            (frame(2, total, chunk, &full), FramingError::MessageId),
            (frame(2, total, 0, &full), FramingError::MessageId),
        ] {
            let mut assembler = MessageAssembler::new();
            assert!(
                assembler
                    .push(&frame(1, total, 0, &full), 0)
                    .unwrap()
                    .is_none()
            );
            assert_eq!(assembler.push(&bytes, 1).unwrap_err(), error);
            assert!(assembler.active.is_none());
            assert!(assembler.disposed);
        }
        let mut changed_kind = frame(1, total, chunk, &full);
        changed_kind[5] = MessageKind::RpcResponse as u8;
        let mut assembler = MessageAssembler::new();
        assembler.push(&frame(1, total, 0, &full), 0).unwrap();
        assert_eq!(
            assembler.push(&changed_kind, 1).unwrap_err(),
            FramingError::KindChanged
        );
        assert!(assembler.active.is_none());
    }

    #[test]
    fn timeout_is_nonsliding_and_expire_is_required_without_input() {
        let full = vec![1; MAX_FRAGMENT_PAYLOAD_LEN];
        let chunk = MAX_FRAGMENT_PAYLOAD_LEN as u32;
        let total = 2 * chunk + 1;
        let mut assembler = MessageAssembler::new();
        assembler.push(&frame(1, total, 0, &full), 10).unwrap();
        assembler
            .push(&frame(1, total, chunk, &full), 5_009)
            .unwrap();
        assert_eq!(assembler.active.as_ref().unwrap().deadline_ms, 5_010);
        assert_eq!(assembler.expire(5_010), Err(FramingError::Timeout));
        assert!(assembler.active.is_none());
        assert_eq!(assembler.expire(5_011), Err(FramingError::Disposed));
        let mut assembler = MessageAssembler::new();
        assembler.push(&frame(1, chunk + 1, 0, &full), 0).unwrap();
        assert_eq!(
            assembler
                .push(&frame(1, chunk + 1, chunk, &[2]), 5_000)
                .unwrap_err(),
            FramingError::Timeout
        );
    }

    #[test]
    fn regressing_clocks_and_deadline_overflow_poison() {
        let full = vec![1; MAX_FRAGMENT_PAYLOAD_LEN];
        let total = MAX_FRAGMENT_PAYLOAD_LEN as u32 + 1;
        let mut assembler = MessageAssembler::new();
        assembler.expire(10).unwrap();
        assert_eq!(
            assembler.push(&frame(1, 1, 0, &[1]), 9).unwrap_err(),
            FramingError::ClockRegressed
        );
        let mut assembler = MessageAssembler::new();
        assembler.push(&frame(1, total, 0, &full), 10).unwrap();
        assert_eq!(assembler.expire(9), Err(FramingError::ClockRegressed));
        assert!(assembler.active.is_none());
        let mut assembler = MessageAssembler::new();
        assert_eq!(
            assembler
                .push(&frame(1, 1, 0, &[1]), u64::MAX - 4_999)
                .unwrap_err(),
            FramingError::Overflow
        );
        assert!(assembler.active.is_none());
        let mut assembler = MessageAssembler::new();
        assembler
            .push(&frame(1, total, 0, &full), u64::MAX - ASSEMBLY_TIMEOUT_MS)
            .unwrap();
        assert_eq!(assembler.expire(u64::MAX), Err(FramingError::Timeout));
    }

    #[test]
    fn encoder_rejects_empty_oversize_capacity_and_busy_then_disposes() {
        for bytes in [
            Vec::new(),
            vec![1; MAX_MESSAGE_LEN + 1],
            Vec::with_capacity(MAX_MESSAGE_LEN + 1),
        ] {
            let expected = if bytes.is_empty() {
                FramingError::Empty
            } else {
                FramingError::Oversize
            };
            let mut encoder = MessageEncoder::new();
            assert_eq!(encoder.begin(MessageKind::RpcRequest, bytes), Err(expected));
            assert_eq!(encoder.next_frame(), Err(FramingError::Disposed));
        }
        let mut excessive_capacity = Vec::with_capacity(MAX_MESSAGE_LEN + 1);
        excessive_capacity.push(1);
        assert_eq!(
            MessageEncoder::new().begin(MessageKind::RpcRequest, excessive_capacity),
            Err(FramingError::Oversize)
        );
        let mut encoder = MessageEncoder::new();
        encoder.begin(MessageKind::RpcRequest, vec![1; 2]).unwrap();
        assert_eq!(
            encoder.begin(MessageKind::RpcResponse, vec![2]),
            Err(FramingError::Busy)
        );
        assert!(encoder.pending.is_none());
        assert_eq!(encoder.next_frame(), Err(FramingError::Disposed));
    }

    #[test]
    fn abort_and_dispose_drop_owned_buffers_permanently() {
        let mut encoder = MessageEncoder::new();
        encoder
            .begin(MessageKind::RpcRequest, vec![9; MAX_MESSAGE_LEN])
            .unwrap();
        encoder.abort();
        encoder.dispose();
        assert!(encoder.pending.is_none());
        assert_eq!(
            encoder.begin(MessageKind::RpcRequest, vec![1]),
            Err(FramingError::Disposed)
        );
        let mut assembler = MessageAssembler::new();
        assembler
            .push(
                &frame(
                    1,
                    MAX_MESSAGE_LEN as u32,
                    0,
                    &vec![9; MAX_FRAGMENT_PAYLOAD_LEN],
                ),
                0,
            )
            .unwrap();
        assert_eq!(
            assembler.active.as_ref().unwrap().bytes.len(),
            MAX_FRAGMENT_PAYLOAD_LEN
        );
        assert!(assembler.active.as_ref().unwrap().bytes.capacity() < MAX_MESSAGE_LEN);
        assembler.abort();
        assembler.dispose();
        assert!(assembler.active.is_none());
        assert_eq!(assembler.expire(0), Err(FramingError::Disposed));
    }

    #[test]
    fn id_exhaustion_is_checked_without_wrapping() {
        let mut encoder = MessageEncoder::new();
        encoder.next_id = Some(u64::MAX);
        encoder.begin(MessageKind::RpcRequest, vec![1]).unwrap();
        let last = encoder.next_frame().unwrap().unwrap();
        let mut assembler = MessageAssembler::new();
        assembler.next_id = Some(u64::MAX);
        assert_eq!(assembler.push(&last, 0).unwrap().unwrap().id, u64::MAX);
        assert_eq!(
            encoder.begin(MessageKind::RpcRequest, vec![1]),
            Err(FramingError::Overflow)
        );
        assert_eq!(
            assembler.push(&frame(1, 1, 0, &[1]), 1).unwrap_err(),
            FramingError::Overflow
        );
        assert!(encoder.pending.is_none());
        assert!(assembler.active.is_none());
    }

    #[test]
    fn debug_contains_counts_only() {
        let secret = b"DO_NOT_LOG_THIS_PAYLOAD";
        let mut encoder = MessageEncoder::new();
        encoder
            .begin(MessageKind::RpcRequest, secret.to_vec())
            .unwrap();
        assert_eq!(
            format!("{encoder:?}"),
            "MessageEncoder { buffered_bytes: 23, emitted_bytes: 0 }"
        );
        let mut assembler = MessageAssembler::new();
        let mut first_payload = vec![0; MAX_FRAGMENT_PAYLOAD_LEN];
        first_payload[..secret.len()].copy_from_slice(secret);
        assembler
            .push(
                &frame(1, MAX_FRAGMENT_PAYLOAD_LEN as u32 + 1, 0, &first_payload),
                0,
            )
            .unwrap();
        assert_eq!(
            format!("{assembler:?}"),
            "MessageAssembler { received_bytes: 16352, declared_bytes: 16353 }"
        );
        let completed = MessageAssembler::new()
            .push(&frame(1, 23, 0, secret), 0)
            .unwrap()
            .unwrap();
        assert_eq!(
            format!("{completed:?}"),
            "CompletedMessage { byte_count: 23 }"
        );
    }
}
