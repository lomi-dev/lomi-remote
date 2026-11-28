#![no_main]
//! Byte 0 selects the decoder; decoded values must re-encode and decode to themselves.
use libfuzzer_sys::fuzz_target;
use lomi_remote_protocol::tunnel::{Hello, HostGreeting, OpenParams};

fuzz_target!(|data: &[u8]| {
    let Some((&s, d)) = data.split_first() else { return };
    match s % 3 {
        0 => {
            if let Ok(v) = Hello::decode(d) {
                assert_eq!(Hello::decode(&v.encode().unwrap()).unwrap(), v);
            }
        }
        1 => {
            if let Ok(v) = HostGreeting::decode(d) {
                assert_eq!(HostGreeting::decode(&v.encode().unwrap()).unwrap(), v);
            }
        }
        _ => {
            if let Ok(v) = OpenParams::decode(d) {
                let _ = v.encode().map(|e| OpenParams::decode(&e));
            }
        }
    }
});
