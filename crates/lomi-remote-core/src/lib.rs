//! Shared Lomi Remote client core. Pure logic only: no sockets, threads or clocks.
//!
//! * [`frame`]: relay link frame codec, pinned by `test-vectors/relay-frames.v1.json`.
//! * [`link`]: link client state machine for role `device` (sans-I/O).
//! * [`session`]: the `POST /remote/session` startup request and response.
//! * [`directory`]: on-device Host directory, merged with server data, sealed at rest.

pub mod directory;
pub mod frame;
pub mod json;
pub mod link;
pub mod session;

/// Core version, identical to the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser {
    use crate::frame::{Direction, MAX_FRAME_BYTES, decode_frame, encode_frame};
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(js_name = coreVersion)]
    pub fn core_version() -> String {
        super::version().to_owned()
    }

    /// Decodes a relay link frame and returns its canonical encoding (`None` when rejected).
    /// `from_relay` is the sender: true for READY/EVENT/REPLY, false for AUTH/CALL.
    #[wasm_bindgen(js_name = canonicalFrame)]
    pub fn canonical_frame(bytes: &[u8], from_relay: bool) -> Option<Vec<u8>> {
        let from = if from_relay {
            Direction::Relay
        } else {
            Direction::Client
        };
        encode_frame(
            &decode_frame(bytes, from, MAX_FRAME_BYTES).ok()?,
            MAX_FRAME_BYTES,
        )
        .ok()
    }
}
