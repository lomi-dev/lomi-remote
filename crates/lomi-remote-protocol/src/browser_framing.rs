//! Ownership bridge only: all wire framing and sequencing live in the core.
use crate::message_framing::{CompletedMessage, MessageAssembler, MessageEncoder, MessageKind};
use wasm_bindgen::prelude::*;

fn invalid() -> JsValue {
    JsValue::from_str("INVALID_ARGUMENT")
}

// Bounded, canonical, lossless u64 parsing. Never pass a JS Number as time/ID.
fn clock(value: &str) -> Result<u64, JsValue> {
    if value.is_empty()
        || value.len() > 20
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}

#[wasm_bindgen]
#[derive(Default)]
pub struct BrowserMessageEncoder {
    inner: MessageEncoder,
}

#[wasm_bindgen]
impl BrowserMessageEncoder {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MessageEncoder::new(),
        }
    }

    pub fn begin(&mut self, kind: u8, bytes: Vec<u8>) -> Result<String, JsValue> {
        let kind = match MessageKind::parse(kind) {
            Ok(kind) => kind,
            Err(_) => {
                self.inner.dispose();
                return Err(invalid());
            }
        };
        self.inner
            .begin(kind, bytes)
            .map(|id| id.to_string())
            .map_err(|_| invalid())
    }

    #[wasm_bindgen(js_name = nextFrame)]
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, JsValue> {
        self.inner.next_frame().map_err(|_| invalid())
    }

    pub fn dispose(&mut self) {
        self.inner.dispose();
    }
}

#[wasm_bindgen]
pub struct BrowserCompletedMessage {
    kind: u8,
    id: u64,
    bytes: Option<Vec<u8>>,
}

impl From<CompletedMessage> for BrowserCompletedMessage {
    fn from(message: CompletedMessage) -> Self {
        Self {
            kind: message.kind as u8,
            id: message.id,
            bytes: Some(message.bytes),
        }
    }
}

#[wasm_bindgen]
impl BrowserCompletedMessage {
    pub fn kind(&self) -> u8 {
        self.kind
    }

    pub fn id(&self) -> String {
        self.id.to_string()
    }

    /// Transfer the owned payload once; repeated access never copies it again.
    #[wasm_bindgen(js_name = takeBytes)]
    pub fn take_bytes(&mut self) -> Result<Vec<u8>, JsValue> {
        self.bytes.take().ok_or_else(invalid)
    }
}

#[wasm_bindgen]
#[derive(Default)]
pub struct BrowserMessageAssembler {
    inner: MessageAssembler,
}

#[wasm_bindgen]
impl BrowserMessageAssembler {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: MessageAssembler::new(),
        }
    }

    // Parse errors must poison the core, just like core framing errors.
    pub fn push(
        &mut self,
        frame: Vec<u8>,
        now_ms: &str,
    ) -> Result<Option<BrowserCompletedMessage>, JsValue> {
        let now_ms = match clock(now_ms) {
            Ok(now_ms) => now_ms,
            Err(error) => {
                self.inner.dispose();
                return Err(error);
            }
        };
        self.inner
            .push(&frame, now_ms)
            .map(|done| done.map(Into::into))
            .map_err(|_| invalid())
    }

    pub fn expire(&mut self, now_ms: &str) -> Result<(), JsValue> {
        let now_ms = match clock(now_ms) {
            Ok(now_ms) => now_ms,
            Err(error) => {
                self.inner.dispose();
                return Err(error);
            }
        };
        self.inner.expire(now_ms).map_err(|_| invalid())
    }

    pub fn dispose(&mut self) {
        self.inner.dispose();
    }
}
