//! Shared Lomi Remote client core. Pure logic only: no sockets, threads or clocks.
//!
//! * [`frame`]: relay link frame codec, pinned by `test-vectors/relay-frames.v1.json`.
//! * [`link`]: link client state machine for role `device` (sans-I/O).
//! * [`session`]: the `POST /remote/session` startup request and response.
//! * [`bridge`]: the one handle-based byte/JSON boundary every platform binds (WASM, C ABI in
//!   [`ffi`], JNI).
//! * [`tunnel`]: client tunnel (Noise handshake, streams, resume cursors) over a link circuit.
//! * [`directory`]: on-device Host directory, merged with server data, sealed at rest.

pub mod bridge;
pub mod directory;
#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
pub mod frame;
pub mod json;
pub mod link;
pub mod session;
pub mod tunnel;

/// Core version, identical to the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser {
    use wasm_bindgen::prelude::*;

    /// See [`crate::bridge::call`]; `args` is a JSON object, `payload` raw bytes. The payload is
    /// taken by value so that the copy the glue made in linear memory (it can hold a seed or
    /// directory keys) is wiped before it is freed.
    #[wasm_bindgen]
    pub fn call(handle: u32, op: &str, args: &[u8], payload: Vec<u8>) -> Vec<u8> {
        let payload = zeroize::Zeroizing::new(payload);
        crate::bridge::call(handle, op, args, &payload)
    }

    #[wasm_bindgen]
    pub fn free(handle: u32) {
        crate::bridge::free(handle);
    }
}
