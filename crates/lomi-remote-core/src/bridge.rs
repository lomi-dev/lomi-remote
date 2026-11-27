//! The one boundary every platform binds: wasm-bindgen (web worker), a C ABI (iOS) and
//! JNI (Android) all call [`call`] and [`free`], so the three compilations run the same
//! code and the same shared vectors.
//!
//! * Instances (`Link`, `Directory`) live in a registry and are addressed by an opaque
//!   `u32` handle (never 0). Stateless operations take handle 0. [`free`] drops an
//!   instance (idempotent); a `Directory` zeroizes its keys on drop.
//! * `args` is a strict JSON object (UTF-8, see [`crate::json`]); `payload` is raw bytes.
//! * The result is one status byte followed by data: `0` + data on success, `1` + a JSON
//!   `{"code": ...}` object on failure. Data is JSON, raw bytes, or for link operations a
//!   record list (below), as documented per operation in `README.md`.
//!
//! Link record list: repeated `tag u8 | len u32 BE | body`. Tag 1 `Connect`, 2 `Send`
//! (body = one WebSocket binary message), 3 `Close`, 4 `Event` (body = JSON with a
//! `type` field). So frames travel as raw bytes and only events are JSON.

use crate::directory::{self, Directory, Key, NONCE_LEN};
use crate::frame::{Direction, MAX_FRAME_BYTES, decode_frame, encode_frame, frame_to_json};
use crate::json::{self, Object};
use crate::link::{
    CallError, DisconnectCause, Link, LinkConfig, LinkEvent, Now, Output, StopReason,
};
use crate::session::{
    self, Credential, DeviceState, HostEntry, RelayToken, SessionError, SessionOutcome,
    SessionResponse,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};

/// Live instances per process; a leak in the platform layer fails loudly instead of growing.
const MAX_HANDLES: usize = 64;
const KEY_LEN: usize = 32;

enum Slot {
    Link(Box<Link>),
    Dir(Box<Directory>),
}

struct Registry {
    next: u32,
    slots: BTreeMap<u32, Slot>,
}

static REGISTRY: Mutex<Registry> = Mutex::new(Registry {
    next: 1,
    slots: BTreeMap::new(),
});

type Fail = Value;
type R<T = Vec<u8>> = Result<T, Fail>;

fn fail(code: &str) -> Fail {
    json!({ "code": code })
}

fn to_bytes(v: &Value) -> Vec<u8> {
    // Serializing a `Value` cannot fail.
    serde_json::to_vec(v).unwrap_or_default()
}

/// Runs one operation. See the module docs for the result layout.
pub fn call(handle: u32, op: &str, args: &[u8], payload: &[u8]) -> Vec<u8> {
    match dispatch(handle, op, args, payload) {
        Ok(mut data) => {
            data.insert(0, 0);
            data
        }
        Err(e) => {
            let mut out = vec![1];
            out.extend(to_bytes(&e));
            out
        }
    }
}

/// Drops an instance. Unknown handles are ignored.
pub fn free(handle: u32) {
    registry().slots.remove(&handle);
}

fn registry() -> std::sync::MutexGuard<'static, Registry> {
    REGISTRY.lock().unwrap_or_else(PoisonError::into_inner)
}

fn insert(slot: Slot) -> R {
    let mut r = registry();
    if r.slots.len() >= MAX_HANDLES {
        return Err(fail("handleLimit"));
    }
    let h = r.next;
    r.next = r.next.wrapping_add(1).max(1);
    r.slots.insert(h, slot);
    Ok(to_bytes(&json!({ "handle": h })))
}

fn with_link<T>(h: u32, f: impl FnOnce(&mut Link) -> R<T>) -> R<T> {
    match registry().slots.get_mut(&h) {
        Some(Slot::Link(l)) => f(l),
        _ => Err(fail("badHandle")),
    }
}

fn with_dir<T>(h: u32, f: impl FnOnce(&mut Directory) -> R<T>) -> R<T> {
    match registry().slots.get_mut(&h) {
        Some(Slot::Dir(d)) => f(d),
        _ => Err(fail("badHandle")),
    }
}

// ---- argument helpers ----

fn parse_args(args: &[u8]) -> R<Object> {
    if args.is_empty() {
        return Ok(Object::new());
    }
    let text = std::str::from_utf8(args).map_err(|_| fail("badArgs"))?;
    match json::parse(text) {
        Ok(Value::Object(o)) => Ok(o),
        _ => Err(fail("badArgs")),
    }
}

fn arg_str<'a>(a: &'a Object, k: &str) -> R<&'a str> {
    a.get(k)
        .and_then(Value::as_str)
        .ok_or_else(|| fail("badArgs"))
}

fn arg_u64(a: &Object, k: &str) -> R<u64> {
    a.get(k)
        .and_then(Value::as_u64)
        .ok_or_else(|| fail("badArgs"))
}

fn arg_bool(a: &Object, k: &str) -> R<bool> {
    a.get(k)
        .and_then(Value::as_bool)
        .ok_or_else(|| fail("badArgs"))
}

fn arg_obj(a: &Object, k: &str) -> R<Object> {
    match a.get(k) {
        Some(Value::Object(o)) => Ok(o.clone()),
        _ => Err(fail("badArgs")),
    }
}

fn now(a: &Object) -> R<Now> {
    Ok(Now {
        mono_ms: arg_u64(a, "monoMs")?,
        wall_ms: arg_u64(a, "wallMs")?,
    })
}

fn relay_token(a: &Object) -> R<RelayToken> {
    Ok(RelayToken {
        token: arg_str(a, "token")?.to_owned(),
        expires_at: arg_u64(a, "expiresAt")?,
    })
}

fn be32(p: &[u8]) -> u32 {
    u32::from_be_bytes([p[0], p[1], p[2], p[3]])
}

/// `id u32 BE | key[32]` entries.
fn key_at(p: &[u8]) -> Key {
    let mut k = [0u8; KEY_LEN];
    k.copy_from_slice(&p[4..4 + KEY_LEN]);
    Key::new(be32(p), k)
}

// ---- dispatch ----

fn dispatch(h: u32, op: &str, args: &[u8], payload: &[u8]) -> R {
    let a = parse_args(args)?;
    match op {
        "version" => Ok(crate::version().as_bytes().to_vec()),
        "frame.decode" => {
            let f = decode_frame(payload, dir_of(&a)?, MAX_FRAME_BYTES).map_err(frame_err)?;
            Ok(to_bytes(&frame_to_json(&f)))
        }
        "frame.canonical" => {
            let f = decode_frame(payload, dir_of(&a)?, MAX_FRAME_BYTES).map_err(frame_err)?;
            encode_frame(&f, MAX_FRAME_BYTES).map_err(frame_err)
        }
        "session.request" => session_request(&a),
        "session.parse" => {
            let status = u16::try_from(arg_u64(&a, "status")?).map_err(|_| fail("badArgs"))?;
            let o = session::parse_session_response(status, payload).map_err(session_err)?;
            Ok(to_bytes(&outcome_json(&o)))
        }
        "link.new" => link_new(&a),
        "directory.new" => insert(Slot::Dir(Box::new(Directory::new(
            arg_str(&a, "accountId")?,
            arg_str(&a, "deviceId")?,
        )))),
        "directory.open" => directory_open(&a, payload),
        _ if op.starts_with("link.") => link_op(h, op, &a, payload),
        _ if op.starts_with("directory.") => directory_op(h, op, &a, payload),
        _ => Err(fail("unknownOp")),
    }
}

fn dir_of(a: &Object) -> R<Direction> {
    Ok(if arg_bool(a, "fromRelay")? {
        Direction::Relay
    } else {
        Direction::Client
    })
}

fn frame_err(e: crate::frame::FrameError) -> Fail {
    use crate::frame::FrameError::*;
    // The coarse classes of the shared vectors.
    fail(match e {
        EmptyFrame | FrameTooLarge | UnknownType | WrongDirection => "framing",
        BadUtf8 | BadJson => "encoding",
        BadShape => "shape",
    })
}

// ---- session ----

fn session_request(a: &Object) -> R {
    let credential = match a.get("refreshCredential") {
        None => Credential::Cookie,
        Some(Value::String(c)) => Credential::Refresh(c.clone()),
        Some(_) => return Err(fail("badArgs")),
    };
    let r = session::session_request(arg_str(a, "contractHash")?, &credential);
    Ok(to_bytes(&json!({
        "method": r.method,
        "path": r.path,
        "headers": r.headers,
        "body": String::from_utf8(r.body).map_err(|_| fail("badArgs"))?,
    })))
}

fn session_err(e: SessionError) -> Fail {
    let retryable = e.is_retryable();
    match e {
        SessionError::Unauthorized => fail("unauthorized"),
        SessionError::UpdateRequired => fail("updateRequired"),
        SessionError::OutcomeUnknown => fail("outcomeUnknown"),
        SessionError::TooLarge => fail("tooLarge"),
        SessionError::Malformed => fail("malformed"),
        SessionError::Http(s) => json!({ "code": "http", "status": s, "retryable": retryable }),
    }
}

fn token_json(t: &RelayToken) -> Value {
    json!({ "token": t.token, "expiresAt": t.expires_at })
}

fn host_entry_json(h: &HostEntry) -> Value {
    json!({
        "id": h.id, "name": h.name, "online": h.online,
        "accessEpoch": h.access_epoch, "runtimeGeneration": h.runtime_generation,
        "workspaces": h.workspaces.iter()
            .map(|w| json!({ "id": w.id, "name": w.name, "epoch": w.epoch }))
            .collect::<Vec<_>>(),
    })
}

fn outcome_json(o: &SessionOutcome) -> Value {
    match o {
        SessionOutcome::Degraded {
            reason,
            access_token,
            refresh_credential,
        } => json!({
            "outcome": "degraded", "reason": reason,
            "accessToken": token_json(access_token), "refreshCredential": refresh_credential,
        }),
        SessionOutcome::Full(r) => {
            let r: &SessionResponse = r;
            let device = match &r.device {
                DeviceState::Unregistered => json!({ "state": "unregistered" }),
                DeviceState::Registered { device_id } => {
                    json!({ "state": "registered", "deviceId": device_id })
                }
                DeviceState::Revoked => json!({ "state": "revoked" }),
            };
            let mut v = json!({
                "outcome": "full",
                "account": { "id": r.account.id, "email": r.account.email },
                "sessionExpiresAt": r.session_expires_at,
                "relay": token_json(&r.relay),
                "hosts": r.hosts.iter().map(host_entry_json).collect::<Vec<_>>(),
                "device": device,
            });
            if let Some(t) = &r.access_token {
                v["accessToken"] = token_json(t);
            }
            if let Some(c) = &r.refresh_credential {
                v["refreshCredential"] = json!(c);
            }
            v
        }
    }
}

// ---- link ----

fn link_new(a: &Object) -> R {
    let mut cfg = LinkConfig::new(arg_str(a, "contractHash")?);
    let set = |k: &str, slot: &mut u64| -> R<()> {
        if a.contains_key(k) {
            *slot = arg_u64(a, k)?;
        }
        Ok(())
    };
    set("callTimeoutMs", &mut cfg.call_timeout_ms)?;
    set("connectTimeoutMs", &mut cfg.connect_timeout_ms)?;
    set("readyTimeoutMs", &mut cfg.ready_timeout_ms)?;
    set("backoffMinMs", &mut cfg.backoff_min_ms)?;
    set("backoffMaxMs", &mut cfg.backoff_max_ms)?;
    set("refreshLeadMs", &mut cfg.refresh_lead_ms)?;
    let mut inflight = cfg.max_inflight as u64;
    set("maxInflight", &mut inflight)?;
    cfg.max_inflight = usize::try_from(inflight).map_err(|_| fail("badArgs"))?;
    let seed = if a.contains_key("seed") {
        arg_u64(a, "seed")?
    } else {
        return Err(fail("badArgs")); // the platform supplies the jitter seed (no RNG in the core)
    };
    insert(Slot::Link(Box::new(Link::new(cfg, seed))))
}

fn call_err(e: &CallError) -> Value {
    match e {
        CallError::NotReady => fail("notReady"),
        CallError::TooManyInflight => fail("tooManyInflight"),
        CallError::UnknownCall => fail("unknownCall"),
        CallError::BadFrame => fail("badFrame"),
        CallError::Remote(c) => json!({ "code": "remote", "remoteCode": c }),
        CallError::Timeout => fail("timeout"),
        CallError::Aborted => fail("aborted"),
    }
}

fn event_json(e: &LinkEvent) -> Value {
    match e {
        LinkEvent::Ready { expires_at, state } => {
            json!({ "type": "ready", "expiresAt": expires_at, "state": state })
        }
        LinkEvent::Server { name, data } => {
            json!({ "type": "server", "name": name, "data": data })
        }
        LinkEvent::CallDone { call_id, result } => match result {
            Ok(data) => json!({ "type": "callDone", "callId": call_id, "ok": data }),
            Err(err) => json!({ "type": "callDone", "callId": call_id, "error": call_err(err) }),
        },
        LinkEvent::TokenRefreshNeeded => json!({ "type": "tokenRefreshNeeded" }),
        LinkEvent::TokenRefreshed { expires_at } => {
            json!({ "type": "tokenRefreshed", "expiresAt": expires_at })
        }
        LinkEvent::TokenRefreshFailed { code } => {
            json!({ "type": "tokenRefreshFailed", "code": code })
        }
        LinkEvent::TokenNeeded => json!({ "type": "tokenNeeded" }),
        LinkEvent::Disconnected { cause, retry_in_ms } => json!({
            "type": "disconnected",
            "cause": match cause {
                DisconnectCause::SocketClosed => "socketClosed",
                DisconnectCause::ConnectTimeout => "connectTimeout",
                DisconnectCause::ReadyTimeout => "readyTimeout",
                DisconnectCause::Unavailable => "unavailable",
                DisconnectCause::Busy => "busy",
                DisconnectCause::Protocol => "protocol",
                DisconnectCause::TokenExpired => "tokenExpired",
            },
            "retryInMs": retry_in_ms,
        }),
        LinkEvent::Stopped(reason) => {
            let (r, older) = match reason {
                StopReason::AuthFailed => ("authFailed", None),
                StopReason::UpdateRequired { older } => (
                    "updateRequired",
                    older.map(|o| match o {
                        crate::frame::Older::Host => "host",
                        crate::frame::Older::Client => "client",
                        crate::frame::Older::Unknown => "unknown",
                    }),
                ),
                StopReason::BadToken => ("badToken", None),
                StopReason::Requested => ("requested", None),
            };
            json!({ "type": "stopped", "reason": r, "older": older })
        }
    }
}

fn record(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
}

fn records(outputs: &[Output]) -> Vec<u8> {
    let mut out = Vec::new();
    for o in outputs {
        match o {
            Output::Connect => record(&mut out, 1, &[]),
            Output::Send(b) => record(&mut out, 2, b),
            Output::Close => record(&mut out, 3, &[]),
            Output::Event(e) => record(&mut out, 4, &to_bytes(&event_json(e))),
        }
    }
    out
}

fn link_op(h: u32, op: &str, a: &Object, payload: &[u8]) -> R {
    with_link(h, |l| {
        Ok(match op {
            "link.start" => records(&l.start(relay_token(a)?, now(a)?)),
            "link.stop" => records(&l.stop()),
            "link.onOpen" => records(&l.on_open(now(a)?)),
            "link.onClose" => records(&l.on_close(now(a)?)),
            "link.onMessage" => records(&l.on_message(payload, now(a)?)),
            "link.tick" => records(&l.tick(now(a)?)),
            "link.call" => {
                let (id, out) = l
                    .call(arg_str(a, "name")?, arg_obj(a, "args")?, now(a)?)
                    .map_err(|e| call_err(&e))?;
                let mut r = Vec::new();
                record(
                    &mut r,
                    4,
                    &to_bytes(&json!({ "type": "callStarted", "callId": id })),
                );
                r.extend(records(&out));
                r
            }
            "link.refreshToken" => records(
                &l.refresh_token(relay_token(a)?, now(a)?)
                    .map_err(|e| call_err(&e))?,
            ),
            "link.nextDeadline" => to_bytes(&json!({ "deadline": l.next_deadline() })),
            "link.isReady" => to_bytes(&json!({ "ready": l.is_ready() })),
            _ => return Err(fail("unknownOp")),
        })
    })
}

// ---- directory ----

fn dir_err(e: directory::Error) -> Fail {
    use directory::Error::*;
    match e {
        Wiped => fail("wiped"),
        BadFormat => fail("badFormat"),
        Version(v) => json!({ "code": "version", "version": v }),
        Stale => fail("stale"),
        NoKey => fail("noKey"),
        Auth => fail("auth"),
        Malformed => fail("malformed"),
        Mismatch => fail("mismatch"),
    }
}

/// Payload: `n u8 | n x (key_id u32 BE | key[32]) | blob`.
fn directory_open(a: &Object, payload: &[u8]) -> R {
    let n = usize::from(*payload.first().ok_or_else(|| fail("badArgs"))?);
    let keys_end = 1 + n * (4 + KEY_LEN);
    if payload.len() < keys_end {
        return Err(fail("badArgs"));
    }
    let keys: Vec<Key> = (0..n)
        .map(|i| key_at(&payload[1 + i * (4 + KEY_LEN)..]))
        .collect();
    let min_key_id = u32::try_from(arg_u64(a, "minKeyId")?).map_err(|_| fail("badArgs"))?;
    let d = Directory::open(
        &payload[keys_end..],
        arg_str(a, "accountId")?,
        arg_str(a, "deviceId")?,
        &keys,
        min_key_id,
    )
    .map_err(dir_err)?;
    insert(Slot::Dir(Box::new(d)))
}

fn effect(e: directory::Effect) -> Vec<u8> {
    to_bytes(&json!({ "effect": match e {
        directory::Effect::Unchanged => "unchanged",
        directory::Effect::Changed => "changed",
        directory::Effect::Revoked => "revoked",
    }}))
}

fn snapshot(d: &Directory) -> Value {
    json!({
        "wiped": d.is_wiped(),
        "hosts": d.hosts().map(|h| json!({
            "id": h.id, "name": h.name, "online": h.online,
            "accessEpoch": h.access_epoch.to_string(),
            "runtimeGeneration": h.runtime_generation.to_string(),
            "workspaces": h.workspaces.iter()
                .map(|w| json!({ "id": w.id, "name": w.name, "epoch": w.epoch }))
                .collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

fn directory_op(h: u32, op: &str, a: &Object, payload: &[u8]) -> R {
    with_dir(h, |d| {
        Ok(match op {
            "directory.applySession" => {
                match session::parse_session_response(200, payload).map_err(session_err)? {
                    SessionOutcome::Full(r) => effect(d.apply_session(&r).map_err(dir_err)?),
                    SessionOutcome::Degraded { .. } => return Err(fail("degraded")),
                }
            }
            "directory.applyReadyState" => effect(
                d.apply_ready_state(&arg_obj(a, "state")?)
                    .map_err(dir_err)?,
            ),
            "directory.applyEvent" => effect(
                d.apply_event(arg_str(a, "name")?, &arg_obj(a, "data")?)
                    .map_err(dir_err)?,
            ),
            "directory.setHostName" => to_bytes(&json!({ "changed":
                d.set_host_name(arg_str(a, "hostId")?, arg_str(a, "name")?) })),
            "directory.setWorkspaceName" => to_bytes(&json!({ "changed":
                d.set_workspace_name(arg_str(a, "hostId")?, arg_str(a, "workspaceId")?, arg_str(a, "name")?) })),
            "directory.snapshot" => to_bytes(&snapshot(d)),
            "directory.wipe" => {
                d.wipe();
                Vec::new()
            }
            // Payload: `key_id u32 BE | key[32] | nonce[24]`.
            "directory.seal" => {
                if payload.len() != 4 + KEY_LEN + NONCE_LEN {
                    return Err(fail("badArgs"));
                }
                let mut nonce = [0u8; NONCE_LEN];
                nonce.copy_from_slice(&payload[4 + KEY_LEN..]);
                d.seal(&key_at(payload), nonce).map_err(dir_err)?
            }
            _ => return Err(fail("unknownOp")),
        })
    })
}
