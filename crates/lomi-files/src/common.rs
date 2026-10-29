//! Platform-independent helpers shared by the Unix and Windows engines.

use crate::types::*;

pub(crate) use lomi_fs_policy::is_private_staging_name;

pub(crate) fn mint() -> EntryRef {
    EntryRef::from_bytes(*uuid::Uuid::new_v4().as_bytes())
}

pub(crate) fn classify(bytes: &[u8], offset: u64, truncated: bool) -> (Encoding, LineEndings) {
    if bytes.is_empty() {
        return (Encoding::Utf8, LineEndings::None);
    }
    if offset == 0 && bytes.len() >= 2 {
        let utf16 = match (bytes[0], bytes[1]) {
            (0xFF, 0xFE) => Some(Encoding::Utf16Le),
            (0xFE, 0xFF) => Some(Encoding::Utf16Be),
            _ => None,
        };
        if let Some(encoding) = utf16 {
            return (encoding, utf16_line_endings(bytes, encoding));
        }
    }
    if bytes.contains(&0) {
        return (Encoding::Binary, LineEndings::None);
    }
    let valid = match std::str::from_utf8(bytes) {
        Ok(_) => true,
        // A multi-byte scalar cut by the window edge is not an encoding error.
        Err(e) => truncated && e.error_len().is_none(),
    };
    if !valid {
        return (Encoding::Unknown, LineEndings::None);
    }
    let (mut lf, mut crlf, mut cr) = (false, false, false);
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\r' if bytes.get(i + 1) == Some(&b'\n') => {
                crlf = true;
                i += 1;
            }
            b'\r' => cr = true,
            b'\n' => lf = true,
            _ => {}
        }
        i += 1;
    }
    (Encoding::Utf8, endings(lf, crlf, cr))
}

fn endings(lf: bool, crlf: bool, cr: bool) -> LineEndings {
    match (lf, crlf, cr) {
        (false, false, false) => LineEndings::None,
        (true, false, false) => LineEndings::Lf,
        (false, true, false) => LineEndings::CrLf,
        (false, false, true) => LineEndings::Cr,
        _ => LineEndings::Mixed,
    }
}

fn utf16_line_endings(bytes: &[u8], encoding: Encoding) -> LineEndings {
    let units: Vec<u16> = bytes[2..]
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| match encoding {
            Encoding::Utf16Le => u16::from_le_bytes([pair[0], pair[1]]),
            _ => u16::from_be_bytes([pair[0], pair[1]]),
        })
        .collect();
    let (mut lf, mut crlf, mut cr) = (false, false, false);
    let mut i = 0;
    while i < units.len() {
        match units[i] {
            0x0D if units.get(i + 1) == Some(&0x0A) => {
                crlf = true;
                i += 1;
            }
            0x0D => cr = true,
            0x0A => lf = true,
            _ => {}
        }
        i += 1;
    }
    endings(lf, crlf, cr)
}
