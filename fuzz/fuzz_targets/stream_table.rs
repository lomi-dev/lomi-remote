#![no_main]
//! Byte 0 picks the side; the rest is a lenient run of wire-format frames
//! (8-byte header + body) fed straight to `on_frame`, skipping `validate`.
use libfuzzer_sys::fuzz_target;
use lomi_remote_protocol::tunnel::{FrameType, Side, StreamTable, TunnelFrame};

fuzz_target!(|data: &[u8]| {
    let Some((&s, mut rest)) = data.split_first() else { return };
    let mut table = StreamTable::new(if s & 1 == 0 { Side::Device } else { Side::Host });
    while rest.len() >= 8 {
        let kind = match rest[4] % 5 {
            0 => FrameType::Open,
            1 => FrameType::Data,
            2 => FrameType::Credit,
            3 => FrameType::Close,
            _ => FrameType::Reset,
        };
        let len = (u16::from_be_bytes([rest[6], rest[7]]) as usize).min(rest.len() - 8);
        let frame = TunnelFrame {
            stream_id: u32::from_be_bytes([rest[0], rest[1], rest[2], rest[3]]),
            kind,
            flags: rest[5],
            data: rest[8..8 + len].to_vec(),
        };
        let _ = table.on_frame(&frame);
        rest = &rest[8 + len..];
    }
});
