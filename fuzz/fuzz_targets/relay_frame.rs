#![no_main]
use libfuzzer_sys::fuzz_target;
use lomi_remote_core::frame::{
    Direction, MAX_AUTH_FRAME_BYTES, MAX_FRAME_BYTES, decode_frame, encode_frame, frame_to_json,
};

fuzz_target!(|data: &[u8]| {
    for dir in [Direction::Client, Direction::Relay] {
        for max in [MAX_FRAME_BYTES, MAX_AUTH_FRAME_BYTES] {
            if let Ok(f) = decode_frame(data, dir, max) {
                let _ = frame_to_json(&f);
                let _ = encode_frame(&f, max);
            }
        }
    }
});
