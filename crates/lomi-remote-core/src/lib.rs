//! Shared Lomi Remote client core. Pure logic only: no sockets, clocks or files.
//! Skeleton for the P2.2 cross-target build proof.

/// Core version, identical to the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Encodes one frame: `kind` (1 byte), big-endian `u16` length, payload.
pub fn encode_frame(kind: u8, payload: &[u8]) -> Option<Vec<u8>> {
    let len = u16::try_from(payload.len()).ok()?;
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(payload);
    Some(out)
}

/// Decodes exactly one frame; trailing or missing bytes yield `None`.
pub fn decode_frame(bytes: &[u8]) -> Option<(u8, &[u8])> {
    let (&kind, rest) = bytes.split_first()?;
    let (len, payload) = rest.split_first_chunk::<2>()?;
    (payload.len() == usize::from(u16::from_be_bytes(*len))).then_some((kind, payload))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
mod browser {
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(js_name = coreVersion)]
    pub fn core_version() -> String {
        super::version().to_owned()
    }

    #[wasm_bindgen(js_name = encodeFrame)]
    pub fn encode_frame(kind: u8, payload: &[u8]) -> Option<Vec<u8>> {
        super::encode_frame(kind, payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip_and_version() {
        assert!(!version().is_empty());
        let f = encode_frame(7, b"hi").unwrap();
        assert_eq!(f, [7, 0, 2, b'h', b'i']);
        assert_eq!(decode_frame(&f), Some((7, &b"hi"[..])));
        assert_eq!(decode_frame(&f[..4]), None);
        assert_eq!(decode_frame(&[f.as_slice(), &[0]].concat()), None);
        assert!(encode_frame(0, &vec![0; 70_000]).is_none());
    }
}
