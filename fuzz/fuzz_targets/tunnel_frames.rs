#![no_main]
use libfuzzer_sys::fuzz_target;
use lomi_remote_protocol::tunnel::decode_frames;

fuzz_target!(|data: &[u8]| {
    if let Ok(frames) = decode_frames(data) {
        // A valid plaintext re-encodes byte for byte.
        let mut out = Vec::new();
        for f in &frames {
            f.encode_into(&mut out).expect("decoded frame must re-encode");
        }
        assert_eq!(out, data);
    }
});
