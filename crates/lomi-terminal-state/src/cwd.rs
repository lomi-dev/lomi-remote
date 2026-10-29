//! Bounded Host-side OSC 7 scanner. This parser is deliberately independent of
//! the renderer and only produces an advisory absolute path; it never accesses
//! the filesystem or changes workspace authority.
use url::Url;

// Worst-case percent-encoded 4096-unit UTF-16 paths need under 37 KiB,
// including a bounded local authority and the OSC 7 command prefix.
const MAX_OSC_BYTES: usize = 48 * 1024;
pub(crate) const MAX_WORKING_DIRECTORY_UTF16: usize = 4096;

pub(crate) struct Osc7Parser {
    state: State,
    utf8_remaining: u8,
    local_hostnames: Vec<String>,
}

#[derive(Default)]
enum State {
    #[default]
    Ground,
    Escape,
    Csi,
    String(StringControl),
    StringEscape(StringControl),
    Osc {
        bytes: Vec<u8>,
        discard: bool,
        escape: bool,
    },
}

#[derive(Default)]
enum StringControl {
    #[default]
    Dcs,
    Sos,
    Pm,
    Apc,
}

impl Default for Osc7Parser {
    fn default() -> Self {
        let local_hostnames = ["HOSTNAME", "COMPUTERNAME"]
            .into_iter()
            .filter_map(|name| std::env::var(name).ok())
            .filter(|name| !name.is_empty() && name.len() <= 255)
            .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
            .collect();
        Self {
            state: State::Ground,
            utf8_remaining: 0,
            local_hostnames,
        }
    }
}

impl Osc7Parser {
    /// Feed exactly one PTY byte chunk and return the last valid OSC 7 path in
    /// it. Invalid or oversized reports are ignored without clearing a prior
    /// valid path held by the caller.
    pub(crate) fn advance(&mut self, input: &[u8]) -> Option<String> {
        let mut latest = None;
        for &byte in input {
            // OSC/DCS strings are UTF-8 byte streams. A continuation byte such
            // as 0x9c or 0x9d must not be reinterpreted as an 8-bit VT control.
            let continuation = if self.utf8_remaining != 0 && (0x80..=0xbf).contains(&byte) {
                self.utf8_remaining -= 1;
                true
            } else {
                self.utf8_remaining = 0;
                false
            };
            if !continuation {
                self.utf8_remaining = match byte {
                    0xc2..=0xdf => 1,
                    0xe0..=0xef => 2,
                    0xf0..=0xf4 => 3,
                    _ => 0,
                };
            }
            if let Some(path) = self.process(byte, continuation) {
                latest = Some(path);
            }
        }
        latest
    }

    fn process(&mut self, byte: u8, utf8_continuation: bool) -> Option<String> {
        let state = std::mem::take(&mut self.state);
        match state {
            State::Ground => {
                self.state = if !utf8_continuation {
                    match byte {
                        0x1b => State::Escape,
                        0x9b => State::Csi,
                        0x9d => State::Osc {
                            bytes: Vec::new(),
                            discard: false,
                            escape: false,
                        },
                        0x90 => State::String(StringControl::Dcs),
                        0x98 => State::String(StringControl::Sos),
                        0x9e => State::String(StringControl::Pm),
                        0x9f => State::String(StringControl::Apc),
                        _ => State::Ground,
                    }
                } else {
                    State::Ground
                };
                None
            }
            State::Escape => {
                self.state = match byte {
                    b'[' => State::Csi,
                    b']' => State::Osc {
                        bytes: Vec::new(),
                        discard: false,
                        escape: false,
                    },
                    b'P' => State::String(StringControl::Dcs),
                    b'X' => State::String(StringControl::Sos),
                    b'^' => State::String(StringControl::Pm),
                    b'_' => State::String(StringControl::Apc),
                    0x1b => State::Escape,
                    _ => State::Ground,
                };
                None
            }
            State::Csi => {
                self.state = if byte == 0x1b {
                    State::Escape
                } else if (0x40..=0x7e).contains(&byte) {
                    State::Ground
                } else {
                    State::Csi
                };
                None
            }
            State::String(kind) => {
                self.state = if !utf8_continuation && matches!(byte, 0x18 | 0x1a) {
                    State::Ground
                } else if !utf8_continuation && byte == 0x9c {
                    State::Ground
                } else if !utf8_continuation && byte == 0x1b {
                    // Strings cannot nest. Remember ESC only long enough to
                    // recognize ST; all other bytes stay in the outer string.
                    State::StringEscape(kind)
                } else {
                    State::String(kind)
                };
                None
            }
            State::StringEscape(kind) => {
                self.state = if !utf8_continuation && matches!(byte, 0x18 | 0x1a | 0x9c) {
                    State::Ground
                } else if byte == b'\\' {
                    State::Ground
                } else if byte == 0x1b {
                    State::StringEscape(kind)
                } else {
                    State::String(kind)
                };
                None
            }
            State::Osc {
                mut bytes,
                mut discard,
                mut escape,
            } => {
                if !utf8_continuation && (byte == 0x07 || byte == 0x9c) {
                    self.state = State::Ground;
                    return if discard {
                        None
                    } else {
                        self.parse_report(&bytes)
                    };
                }
                if !utf8_continuation && matches!(byte, 0x18 | 0x1a) {
                    self.state = State::Ground;
                    return None;
                }
                if escape {
                    escape = false;
                    if byte == b'\\' {
                        self.state = State::Ground;
                        return if discard {
                            None
                        } else {
                            self.parse_report(&bytes)
                        };
                    }
                    // An OSC payload containing another escape sequence is
                    // malformed. Continue discarding through the real string
                    // terminator so an embedded ESC ] cannot start a new OSC.
                    discard = true;
                    bytes.clear();
                }
                if !utf8_continuation && byte == 0x1b {
                    escape = true;
                } else if !utf8_continuation && (byte < 0x20 || (0x80..=0x9f).contains(&byte)) {
                    // C0/C1 controls in the body make the string invalid. Keep
                    // consuming it until BEL/ST so fake nested OSCs stay inert.
                    discard = true;
                    bytes.clear();
                } else if !discard {
                    if bytes.len() == MAX_OSC_BYTES {
                        discard = true;
                        bytes.clear();
                    } else {
                        bytes.push(byte);
                    }
                }
                self.state = State::Osc {
                    bytes,
                    discard,
                    escape,
                };
                None
            }
        }
    }

    fn parse_report(&self, bytes: &[u8]) -> Option<String> {
        let report = std::str::from_utf8(bytes).ok()?;
        let (command, uri) = report.split_once(';')?;
        if command != "7" || uri.is_empty() || uri.len() > MAX_OSC_BYTES {
            return None;
        }
        // CMD's fixed PROMPT $P expansion reports a native Windows directory;
        // it cannot percent-encode a URI. Recognize only this closed legacy
        // form on Windows Hosts. In particular, '%' remains a literal filename
        // character here, never a URI escape, and no authority becomes a UNC
        // path. The result is still advisory metadata with no filesystem use.
        #[cfg(windows)]
        if let Some(path) = cmd_directory_report(uri) {
            return Some(path);
        }
        // OSC 7 is a URI. Require the URI's ASCII representation so malformed
        // raw spaces/control bytes and ambiguous IRI spellings are rejected.
        if !uri
            .get(..7)
            .is_some_and(|scheme| scheme.eq_ignore_ascii_case("file://"))
            || uri.contains('\\')
            || !uri.bytes().all(|b| (0x21..=0x7e).contains(&b))
            || !valid_percent_escapes(uri)
        {
            return None;
        }
        let url = Url::parse(uri).ok()?;
        if !url.scheme().eq_ignore_ascii_case("file")
            || !url.username().is_empty()
            || url.password().is_some()
            || url.port().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || !self.local_authority(url.host_str())
        {
            return None;
        }
        let mut path = percent_decode_path(url.path())?;
        if path.starts_with('/')
            && path.as_bytes().get(1).is_some_and(u8::is_ascii_alphabetic)
            && path.as_bytes().get(2) == Some(&b':')
            && path.as_bytes().get(3) == Some(&b'/')
        {
            path.remove(0);
        }
        valid_native_path(&path).then_some(path)
    }

    fn local_authority(&self, authority: Option<&str>) -> bool {
        let Some(authority) = authority else {
            return true;
        };
        let normalized = authority.trim_end_matches('.').to_ascii_lowercase();
        normalized == "localhost" || self.local_hostnames.iter().any(|host| host == &normalized)
    }
}

#[cfg(windows)]
fn cmd_directory_report(report: &str) -> Option<String> {
    const PREFIX: &str = "file://localhost/";
    if !report.get(..PREFIX.len())?.eq_ignore_ascii_case(PREFIX) {
        return None;
    }
    let path = report.get(PREFIX.len()..)?;
    let bytes = path.as_bytes();
    if bytes.len() < 3 || !bytes[0].is_ascii_alphabetic() || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }
    let normalized = path.replace('\\', "/");
    valid_native_path(&normalized).then_some(normalized)
}

fn percent_decode_path(path: &str) -> Option<String> {
    let input = path.as_bytes();
    let mut decoded = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'%' {
            let high = *input.get(index + 1)?;
            let low = *input.get(index + 2)?;
            decoded.push((hex(high)? << 4) | hex(low)?);
            index += 3;
        } else {
            decoded.push(input[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn valid_percent_escapes(uri: &str) -> bool {
    let bytes = uri.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if bytes.get(index + 1).and_then(|byte| hex(*byte)).is_none()
                || bytes.get(index + 2).and_then(|byte| hex(*byte)).is_none()
            {
                return false;
            }
            index += 3;
        } else {
            index += 1;
        }
    }
    true
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn valid_native_path(path: &str) -> bool {
    if path.is_empty()
        || path.encode_utf16().count() > MAX_WORKING_DIRECTORY_UTF16
        || path.chars().any(char::is_control)
        || path.contains('\\')
        || path.starts_with("//")
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    path.starts_with('/')
        || (path.len() >= 3
            && path.as_bytes()[0].is_ascii_alphabetic()
            && path.as_bytes()[1] == b':'
            && path.as_bytes()[2] == b'/')
}
