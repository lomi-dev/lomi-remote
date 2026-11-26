//! Strict JSON reader shared by the relay frame codec and the startup response.
//!
//! Mirrors the TypeScript reference (`auth-app/src/remote/relay/frames.ts`): no
//! duplicate keys at any depth, integers only (`-?(0|[1-9][0-9]{0,15})`, at most
//! 2^53-1, no `-0`), no lone surrogates or invalid escapes, no raw control
//! characters, depth at most 8. Objects keep member order.

use serde_json::{Map, Number, Value};

/// A JSON object with insertion order preserved.
pub type Object = Map<String, Value>;

const MAX_DEPTH: usize = 8;
const MAX_SAFE: u64 = (1 << 53) - 1;

/// The input is not strict JSON; carries no detail on purpose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BadJson;

pub fn parse(text: &str) -> Result<Value, BadJson> {
    let mut p = Parser {
        s: text.as_bytes(),
        i: 0,
    };
    let v = p.value(0)?;
    p.ws();
    if p.i != p.s.len() {
        return Err(BadJson);
    }
    Ok(v)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while matches!(self.s.get(self.i), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.i += 1;
        }
    }

    fn next(&mut self) -> Option<u8> {
        let c = self.s.get(self.i).copied();
        self.i += usize::from(c.is_some());
        c
    }

    fn lit(&mut self, word: &str, v: Value) -> Result<Value, BadJson> {
        if self.s[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(BadJson)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, BadJson> {
        if depth > MAX_DEPTH {
            return Err(BadJson);
        }
        self.ws();
        match self.s.get(self.i).copied().ok_or(BadJson)? {
            b'"' => self.string().map(Value::String),
            b'{' => {
                self.i += 1;
                self.ws();
                let mut obj = Object::new();
                if self.s.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    return Ok(Value::Object(obj));
                }
                loop {
                    self.ws();
                    if self.s.get(self.i) != Some(&b'"') {
                        return Err(BadJson);
                    }
                    let key = self.string()?;
                    if obj.contains_key(&key) {
                        return Err(BadJson);
                    }
                    self.ws();
                    if self.next() != Some(b':') {
                        return Err(BadJson);
                    }
                    let v = self.value(depth + 1)?;
                    obj.insert(key, v);
                    self.ws();
                    match self.next() {
                        Some(b'}') => return Ok(Value::Object(obj)),
                        Some(b',') => {}
                        _ => return Err(BadJson),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                self.ws();
                let mut arr = Vec::new();
                if self.s.get(self.i) == Some(&b']') {
                    self.i += 1;
                    return Ok(Value::Array(arr));
                }
                loop {
                    arr.push(self.value(depth + 1)?);
                    self.ws();
                    match self.next() {
                        Some(b']') => return Ok(Value::Array(arr)),
                        Some(b',') => {}
                        _ => return Err(BadJson),
                    }
                }
            }
            b't' => self.lit("true", Value::Bool(true)),
            b'f' => self.lit("false", Value::Bool(false)),
            b'n' => self.lit("null", Value::Null),
            _ => self.number(),
        }
    }

    fn number(&mut self) -> Result<Value, BadJson> {
        let neg = self.s.get(self.i) == Some(&b'-');
        self.i += usize::from(neg);
        let start = self.i;
        while self.s.get(self.i).is_some_and(u8::is_ascii_digit) {
            self.i += 1;
        }
        let digits = &self.s[start..self.i];
        // A leading zero followed by more digits, "-0", and 17+ digits are all rejected.
        if digits.is_empty()
            || digits.len() > 16
            || (digits[0] == b'0' && (digits.len() > 1 || neg))
        {
            return Err(BadJson);
        }
        let mut n: u64 = 0;
        for d in digits {
            n = n * 10 + u64::from(d - b'0');
        }
        if n > MAX_SAFE {
            return Err(BadJson);
        }
        // `n` fits i64 (<= 2^53-1).
        Ok(Value::Number(Number::from(if neg {
            -(n as i64)
        } else {
            n as i64
        })))
    }

    fn hex4(&mut self) -> Result<u32, BadJson> {
        let mut v = 0;
        for _ in 0..4 {
            let d = (self.next().ok_or(BadJson)? as char)
                .to_digit(16)
                .ok_or(BadJson)?;
            v = v * 16 + d;
        }
        Ok(v)
    }

    fn string(&mut self) -> Result<String, BadJson> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            match self.next().ok_or(BadJson)? {
                b'"' => return String::from_utf8(out).map_err(|_| BadJson),
                b'\\' => {
                    let c = match self.next().ok_or(BadJson)? {
                        b'"' => '"',
                        b'\\' => '\\',
                        b'/' => '/',
                        b'b' => '\u{8}',
                        b'f' => '\u{c}',
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.next() != Some(b'\\') || self.next() != Some(b'u') {
                                    return Err(BadJson);
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err(BadJson);
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else {
                                hi
                            };
                            char::from_u32(cp).ok_or(BadJson)? // lone low surrogate fails here
                        }
                        _ => return Err(BadJson),
                    };
                    let mut buf = [0; 4];
                    out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
                }
                c if c < 0x20 => return Err(BadJson),
                c => out.push(c),
            }
        }
    }
}
