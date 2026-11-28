//! Relay link frame codec (`03-protokol.md` section 3): one WebSocket binary
//! message is one type byte followed by a strict UTF-8 JSON object. Writers emit
//! the canonical form (fixed key order, no whitespace); readers accept any key
//! order but apply the rejection rules of the shared vectors
//! (`test-vectors/relay-frames.v1.json`). `0x10 DATA` is rejected here:
//! the link handles it itself (`link::TYPE_DATA`).

use crate::json::{self, Object};
use serde_json::{Number, Value, json};

pub const TYPE_AUTH: u8 = 0x01;
pub const TYPE_READY: u8 = 0x02;
pub const TYPE_EVENT: u8 = 0x03;
pub const TYPE_CALL: u8 = 0x04;
pub const TYPE_REPLY: u8 = 0x05;
pub const MAX_FRAME_BYTES: usize = 65535;
pub const MAX_AUTH_FRAME_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Host,
    Device,
}

impl Role {
    fn as_str(self) -> &'static str {
        match self {
            Role::Host => "host",
            Role::Device => "device",
        }
    }
    fn parse(v: Option<&Value>) -> Result<Self, FrameError> {
        match v.and_then(Value::as_str) {
            Some("host") => Ok(Role::Host),
            Some("device") => Ok(Role::Device),
            _ => Err(FrameError::BadShape),
        }
    }
}

/// Host runtime claim carried in AUTH (same fields as the HTTP claim body).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeClaim {
    pub host_id: String,
    pub runtime_id: String,
    /// Canonical decimal string, at most `i64::MAX`.
    pub expected_generation: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadyErrorCode {
    AuthFailed,
    UpdateRequired,
    Unavailable,
    Busy,
    HostBusy,
    StaleEpoch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Older {
    Host,
    Client,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Auth {
        role: Role,
        token: String,
        contract_hash: String,
        /// Host only.
        claim: Option<RuntimeClaim>,
    },
    ReadyOk {
        role: Role,
        expires_at: u64,
        state: Object,
    },
    ReadyErr {
        code: ReadyErrorCode,
        older: Option<Older>,
    },
    Event {
        name: String,
        data: Object,
    },
    Call {
        call_id: u32,
        name: String,
        args: Object,
    },
    ReplyOk {
        call_id: u32,
        data: Object,
    },
    ReplyErr {
        call_id: u32,
        code: String,
    },
}

/// Who sends the frame: `Client` is a host or device, `Relay` is the relay.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Client,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    EmptyFrame,
    FrameTooLarge,
    UnknownType,
    WrongDirection,
    BadUtf8,
    BadJson,
    BadShape,
}

impl Frame {
    /// The direction this frame travels in.
    pub fn direction(&self) -> Direction {
        match self {
            Frame::Auth { .. } | Frame::Call { .. } => Direction::Client,
            _ => Direction::Relay,
        }
    }
}

fn is_name(s: &str) -> bool {
    let mut parts = 0;
    for p in s.split('.') {
        parts += 1;
        if parts > 4 || !(1..=16).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_lowercase()) {
            return false;
        }
    }
    true
}

fn is_error_code(s: &str) -> bool {
    let b = s.as_bytes();
    (2..=32).contains(&b.len())
        && b[0].is_ascii_uppercase()
        && b.iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == b'_')
}

fn is_token(s: &str) -> bool {
    (16..=2048).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn is_uuid(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && s != "00000000-0000-0000-0000-000000000000"
        && b.iter().enumerate().all(|(i, c)| {
            if matches!(i, 8 | 13 | 18 | 23) {
                *c == b'-'
            } else {
                c.is_ascii_digit() || (b'a'..=b'f').contains(c)
            }
        })
}

fn is_counter(s: &str) -> bool {
    s.parse::<i64>().is_ok()
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s == "0" || !s.starts_with('0'))
}

fn is_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Exactly `keys` plus any subset of `optional`, nothing else.
fn exact(o: &Object, keys: &[&str], optional: &[&str]) -> Result<(), FrameError> {
    let ok = keys.iter().all(|k| o.contains_key(*k))
        && o.keys()
            .all(|k| keys.contains(&k.as_str()) || optional.contains(&k.as_str()));
    ok.then_some(()).ok_or(FrameError::BadShape)
}

fn obj(v: Option<&Value>) -> Result<Object, FrameError> {
    match v {
        Some(Value::Object(o)) => Ok(o.clone()),
        _ => Err(FrameError::BadShape),
    }
}

fn text(v: Option<&Value>) -> Result<&str, FrameError> {
    v.and_then(Value::as_str).ok_or(FrameError::BadShape)
}

fn call_id(v: Option<&Value>) -> Result<u32, FrameError> {
    v.and_then(Value::as_u64)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or(FrameError::BadShape)
}

fn name(v: Option<&Value>) -> Result<String, FrameError> {
    let s = text(v)?;
    is_name(s).then(|| s.to_owned()).ok_or(FrameError::BadShape)
}

pub fn decode_frame(bytes: &[u8], from: Direction, max_bytes: usize) -> Result<Frame, FrameError> {
    let (&kind, body) = bytes.split_first().ok_or(FrameError::EmptyFrame)?;
    if bytes.len() > max_bytes {
        return Err(FrameError::FrameTooLarge);
    }
    let allowed = match (from, kind) {
        (_, k) if !(TYPE_AUTH..=TYPE_REPLY).contains(&k) => return Err(FrameError::UnknownType),
        (Direction::Client, TYPE_AUTH | TYPE_CALL)
        | (Direction::Relay, TYPE_READY | TYPE_EVENT | TYPE_REPLY) => true,
        _ => false,
    };
    if !allowed {
        return Err(FrameError::WrongDirection);
    }
    if kind == TYPE_AUTH && bytes.len() > MAX_AUTH_FRAME_BYTES {
        return Err(FrameError::FrameTooLarge);
    }
    let text_in = std::str::from_utf8(body).map_err(|_| FrameError::BadUtf8)?;
    let Value::Object(o) = json::parse(text_in).map_err(|_| FrameError::BadJson)? else {
        return Err(FrameError::BadShape);
    };
    let bad = FrameError::BadShape;
    match kind {
        TYPE_AUTH => {
            exact(&o, &["role", "token", "contractHash"], &["claim"])?;
            let (token, hash) = (text(o.get("token"))?, text(o.get("contractHash"))?);
            if !is_token(token) || !is_hash(hash) {
                return Err(bad);
            }
            let role = Role::parse(o.get("role"))?;
            let claim = match o.get("claim") {
                None => None,
                // Only a host claims a runtime.
                Some(c) if role == Role::Host => {
                    let c = obj(Some(c))?;
                    exact(&c, &["hostId", "runtimeId", "expectedGeneration"], &[])?;
                    let (h, r, g) = (
                        text(c.get("hostId"))?,
                        text(c.get("runtimeId"))?,
                        text(c.get("expectedGeneration"))?,
                    );
                    if !is_uuid(h) || !is_uuid(r) || !is_counter(g) {
                        return Err(bad);
                    }
                    Some(RuntimeClaim {
                        host_id: h.to_owned(),
                        runtime_id: r.to_owned(),
                        expected_generation: g.to_owned(),
                    })
                }
                Some(_) => return Err(bad),
            };
            Ok(Frame::Auth {
                role,
                token: token.to_owned(),
                contract_hash: hash.to_owned(),
                claim,
            })
        }
        TYPE_CALL => {
            exact(&o, &["callId", "name", "args"], &[])?;
            Ok(Frame::Call {
                call_id: call_id(o.get("callId"))?,
                name: name(o.get("name"))?,
                args: obj(o.get("args"))?,
            })
        }
        TYPE_EVENT => {
            exact(&o, &["name", "data"], &[])?;
            Ok(Frame::Event {
                name: name(o.get("name"))?,
                data: obj(o.get("data"))?,
            })
        }
        TYPE_READY if o.get("ok") == Some(&Value::Bool(true)) => {
            exact(&o, &["ok", "role", "expiresAt", "state"], &[])?;
            let expires_at = o
                .get("expiresAt")
                .and_then(Value::as_u64)
                .filter(|n| *n > 0)
                .ok_or(bad)?;
            Ok(Frame::ReadyOk {
                role: Role::parse(o.get("role"))?,
                expires_at,
                state: obj(o.get("state"))?,
            })
        }
        TYPE_READY => {
            exact(&o, &["ok", "error"], &[])?;
            let e = obj(o.get("error"))?;
            if o.get("ok") != Some(&Value::Bool(false)) {
                return Err(bad);
            }
            exact(&e, &["code"], &["older"])?;
            let code = match text(e.get("code"))? {
                "AUTH_FAILED" => ReadyErrorCode::AuthFailed,
                "UPDATE_REQUIRED" => ReadyErrorCode::UpdateRequired,
                "UNAVAILABLE" => ReadyErrorCode::Unavailable,
                "BUSY" => ReadyErrorCode::Busy,
                "HOST_BUSY" => ReadyErrorCode::HostBusy,
                "STALE_EPOCH" => ReadyErrorCode::StaleEpoch,
                _ => return Err(bad),
            };
            let older = match e.get("older") {
                None => None,
                Some(v) => Some(match v.as_str() {
                    Some("host") => Older::Host,
                    Some("client") => Older::Client,
                    Some("unknown") => Older::Unknown,
                    _ => return Err(bad),
                }),
            };
            Ok(Frame::ReadyErr { code, older })
        }
        _ if o.get("ok") == Some(&Value::Bool(true)) => {
            exact(&o, &["callId", "ok", "data"], &[])?;
            Ok(Frame::ReplyOk {
                call_id: call_id(o.get("callId"))?,
                data: obj(o.get("data"))?,
            })
        }
        _ => {
            exact(&o, &["callId", "ok", "error"], &[])?;
            let id = call_id(o.get("callId"))?;
            if o.get("ok") != Some(&Value::Bool(false)) {
                return Err(bad);
            }
            let e = obj(o.get("error"))?;
            exact(&e, &["code"], &[])?;
            let code = text(e.get("code"))?;
            is_error_code(code)
                .then(|| Frame::ReplyErr {
                    call_id: id,
                    code: code.to_owned(),
                })
                .ok_or(bad)
        }
    }
}

fn map(pairs: Vec<(&str, Value)>) -> Object {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn int(n: u64) -> Value {
    Value::Number(Number::from(n))
}

/// Canonical encoding. Fails when the frame would not decode on the peer.
pub fn encode_frame(frame: &Frame, max_bytes: usize) -> Result<Vec<u8>, FrameError> {
    let s = |v: &str| Value::String(v.to_owned());
    let (kind, body) = match frame {
        Frame::Auth {
            role,
            token,
            contract_hash,
            claim,
        } => {
            let mut b = map(vec![
                ("role", s(role.as_str())),
                ("token", s(token)),
                ("contractHash", s(contract_hash)),
            ]);
            if let Some(c) = claim {
                // `claim` is always the last key.
                let c = map(vec![
                    ("hostId", s(&c.host_id)),
                    ("runtimeId", s(&c.runtime_id)),
                    ("expectedGeneration", s(&c.expected_generation)),
                ]);
                b.insert("claim".into(), Value::Object(c));
            }
            (TYPE_AUTH, b)
        }
        Frame::Call {
            call_id,
            name,
            args,
        } => (
            TYPE_CALL,
            map(vec![
                ("callId", int(u64::from(*call_id))),
                ("name", s(name)),
                ("args", Value::Object(args.clone())),
            ]),
        ),
        Frame::Event { name, data } => (
            TYPE_EVENT,
            map(vec![
                ("name", s(name)),
                ("data", Value::Object(data.clone())),
            ]),
        ),
        Frame::ReadyOk {
            role,
            expires_at,
            state,
        } => (
            TYPE_READY,
            map(vec![
                ("ok", Value::Bool(true)),
                ("role", s(role.as_str())),
                ("expiresAt", int(*expires_at)),
                ("state", Value::Object(state.clone())),
            ]),
        ),
        Frame::ReadyErr { code, older } => {
            let code = match code {
                ReadyErrorCode::AuthFailed => "AUTH_FAILED",
                ReadyErrorCode::UpdateRequired => "UPDATE_REQUIRED",
                ReadyErrorCode::Unavailable => "UNAVAILABLE",
                ReadyErrorCode::Busy => "BUSY",
                ReadyErrorCode::HostBusy => "HOST_BUSY",
                ReadyErrorCode::StaleEpoch => "STALE_EPOCH",
            };
            let mut e = map(vec![("code", s(code))]);
            if let Some(o) = older {
                e.insert(
                    "older".into(),
                    s(match o {
                        Older::Host => "host",
                        Older::Client => "client",
                        Older::Unknown => "unknown",
                    }),
                );
            }
            (
                TYPE_READY,
                map(vec![
                    ("ok", Value::Bool(false)),
                    ("error", Value::Object(e)),
                ]),
            )
        }
        Frame::ReplyOk { call_id, data } => (
            TYPE_REPLY,
            map(vec![
                ("callId", int(u64::from(*call_id))),
                ("ok", Value::Bool(true)),
                ("data", Value::Object(data.clone())),
            ]),
        ),
        Frame::ReplyErr { call_id, code } => (
            TYPE_REPLY,
            map(vec![
                ("callId", int(u64::from(*call_id))),
                ("ok", Value::Bool(false)),
                ("error", Value::Object(map(vec![("code", s(code))]))),
            ]),
        ),
    };
    let mut out = vec![kind];
    serde_json::to_writer(&mut out, &Value::Object(body)).map_err(|_| FrameError::BadJson)?;
    // Validate what we are about to send with the rules the peer applies.
    decode_frame(&out, frame.direction(), max_bytes)?;
    Ok(out)
}

fn role_name(r: Role) -> &'static str {
    if r == Role::Host { "host" } else { "device" }
}

/// The frame as the vectors' `frame` object (the TypeScript `Frame` type).
pub fn frame_to_json(f: &Frame) -> Value {
    match f {
        Frame::Auth {
            role: r,
            token,
            contract_hash,
            claim,
        } => {
            let mut v = json!({"type":"AUTH","role":role_name(*r),"token":token,"contractHash":contract_hash});
            if let Some(c) = claim {
                v["claim"] = json!({"hostId":c.host_id,"runtimeId":c.runtime_id,"expectedGeneration":c.expected_generation});
            }
            v
        }
        Frame::ReadyOk {
            role: r,
            expires_at,
            state,
        } => {
            json!({"type":"READY","ok":true,"role":role_name(*r),"expiresAt":expires_at,"state":state})
        }
        Frame::ReadyErr { code, older } => {
            let code = match code {
                ReadyErrorCode::AuthFailed => "AUTH_FAILED",
                ReadyErrorCode::UpdateRequired => "UPDATE_REQUIRED",
                ReadyErrorCode::Unavailable => "UNAVAILABLE",
                ReadyErrorCode::Busy => "BUSY",
                ReadyErrorCode::HostBusy => "HOST_BUSY",
                ReadyErrorCode::StaleEpoch => "STALE_EPOCH",
            };
            let mut e = json!({ "code": code });
            if let Some(o) = older {
                e["older"] = json!(match o {
                    Older::Host => "host",
                    Older::Client => "client",
                    Older::Unknown => "unknown",
                });
            }
            json!({"type":"READY","ok":false,"error":e})
        }
        Frame::Event { name, data } => json!({"type":"EVENT","name":name,"data":data}),
        Frame::Call {
            call_id,
            name,
            args,
        } => json!({"type":"CALL","callId":call_id,"name":name,"args":args}),
        Frame::ReplyOk { call_id, data } => {
            json!({"type":"REPLY","callId":call_id,"ok":true,"data":data})
        }
        Frame::ReplyErr { call_id, code } => {
            json!({"type":"REPLY","callId":call_id,"ok":false,"error":{"code":code}})
        }
    }
}
