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
//! `type` field), 5 `Stream message` (body = `stream u32 BE | bytes`, one complete logical
//! message of a tunnel stream). So frames travel as raw bytes and only events are JSON.
//! Tunnels (`Tunnel`) sit on a link: every link operation also routes the link's circuit traffic
//! into the attached tunnels and returns their records in the same list (`settle`).

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
use crate::tunnel::{self, Tunnel};
use lomi_remote_crypto::{Identity, SignedBundle};
use lomi_remote_protocol::tunnel::Hello;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::sync::{Mutex, PoisonError};
use zeroize::Zeroize;

/// Live instances per process; a leak in the platform layer fails loudly instead of growing.
const MAX_HANDLES: usize = 64;
const KEY_LEN: usize = 32;

enum Slot {
    Link(Box<Link>),
    Dir(Box<Directory>),
    /// Link handle it runs on, and the tunnel.
    Tunnel(u32, Box<Tunnel>),
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
    let key = Key::new(be32(p), k);
    k.zeroize(); // `Key::new` took a copy
    key
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
        "tunnel.new" => tunnel_new(&a, payload),
        _ if op.starts_with("tunnel.") => tunnel_op(h, op, &a, payload),
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
    set("minRefreshIntervalMs", &mut cfg.min_refresh_interval_ms)?;
    set("silenceMs", &mut cfg.silence_ms)?;
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
        LinkEvent::Stale { silent_ms } => json!({ "type": "stale", "silentMs": silent_ms }),
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
                DisconnectCause::Silence => "silence",
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

fn link_record(out: &mut Vec<u8>, o: &Output) {
    match o {
        Output::Connect => record(out, 1, &[]),
        Output::Send(b) => record(out, 2, b),
        Output::Close => record(out, 3, &[]),
        Output::Event(e) => record(out, 4, &to_bytes(&event_json(e))),
        Output::Data { .. } => {} // circuit traffic nobody claimed (e.g. a closed tunnel's circuit)
    }
}

const NO_TIME: Now = Now {
    mono_ms: 0,
    wall_ms: 0,
};

fn link_op(h: u32, op: &str, a: &Object, payload: &[u8]) -> R {
    let mut r = registry();
    let Some(Slot::Link(l)) = r.slots.get_mut(&h) else {
        return Err(fail("badHandle"));
    };
    let mut tick = false;
    // Records that precede the link's own (`callStarted`), then the link outputs.
    let (prefix, outs) = match op {
        "link.start" => (Vec::new(), l.start(relay_token(a)?, now(a)?)),
        "link.stop" => (Vec::new(), l.stop()),
        "link.onOpen" => (Vec::new(), l.on_open(now(a)?)),
        "link.onClose" => (Vec::new(), l.on_close(now(a)?)),
        "link.onMessage" => (Vec::new(), l.on_message(payload, now(a)?)),
        "link.tick" => {
            tick = true;
            (Vec::new(), l.tick(now(a)?))
        }
        "link.call" => {
            let (id, out) = l
                .call(arg_str(a, "name")?, arg_obj(a, "args")?, now(a)?)
                .map_err(|e| call_err(&e))?;
            let mut p = Vec::new();
            record(
                &mut p,
                4,
                &to_bytes(&json!({ "type": "callStarted", "callId": id })),
            );
            (p, out)
        }
        "link.refreshToken" => (
            Vec::new(),
            l.refresh_token(relay_token(a)?, now(a)?)
                .map_err(|e| call_err(&e))?,
        ),
        // Earliest of the link and its tunnels, so the platform arms one timer.
        "link.nextDeadline" => {
            let own = l.next_deadline();
            let d = tunnels_of(&r, h)
                .into_iter()
                .filter_map(|t| tunnel_ref(&r, t)?.next_deadline())
                .chain(own)
                .min();
            return Ok(to_bytes(&json!({ "deadline": d })));
        }
        "link.isReady" => return Ok(to_bytes(&json!({ "ready": l.is_ready() }))),
        "link.lastServerFrame" => {
            return Ok(to_bytes(
                &json!({ "monoMs": l.last_server_frame_mono_ms() }),
            ));
        }
        _ => return Err(fail("unknownOp")),
    };
    let t = now(a).unwrap_or(NO_TIME);
    let mut ticks = Vec::new();
    if tick {
        for th in tunnels_of(&r, h) {
            let outs = tunnel_mut(&mut r, th).map(|x| x.tick(t.mono_ms));
            ticks.extend(outs.into_iter().flatten().map(|o| (th, o)));
        }
    }
    let mut res = prefix;
    res.extend(settle(&mut r, h, t, outs, ticks));
    Ok(res)
}

// ---- tunnel ----

fn tunnels_of(r: &Registry, link: u32) -> Vec<u32> {
    r.slots
        .iter()
        .filter_map(|(h, s)| matches!(s, Slot::Tunnel(l, _) if *l == link).then_some(*h))
        .collect()
}

fn tunnel_ref(r: &Registry, h: u32) -> Option<&Tunnel> {
    match r.slots.get(&h) {
        Some(Slot::Tunnel(_, t)) => Some(t),
        _ => None,
    }
}

fn tunnel_mut(r: &mut Registry, h: u32) -> Option<&mut Tunnel> {
    match r.slots.get_mut(&h) {
        Some(Slot::Tunnel(_, t)) => Some(t),
        _ => None,
    }
}

fn link_mut(r: &mut Registry, h: u32) -> Option<&mut Link> {
    match r.slots.get_mut(&h) {
        Some(Slot::Link(l)) => Some(l),
        _ => None,
    }
}

fn tunnel_event_json(th: u32, e: &tunnel::Event) -> Value {
    use tunnel::Event::*;
    let mut v = match e {
        State(s) => json!({ "type": "tunnelState", "state": s }),
        ApprovalPending { code, deadline } => {
            json!({ "type": "tunnelState", "state": "approvalPending", "code": code, "deadline": deadline })
        }
        ControlPending { code, deadline } => {
            json!({ "type": "controlPending", "code": code, "deadline": deadline })
        }
        Open { directory } => {
            json!({ "type": "tunnelState", "state": "open", "directory": directory })
        }
        Closed { reason } => json!({ "type": "tunnelState", "state": "closed", "reason": reason }),
        UpdateRequired { older } => json!({ "type": "updateRequired", "olderSide": older }),
        StaleEpoch(s) => json!({
            "type": "staleEpoch", "authEpoch": s.auth_epoch,
            "hostAccessEpoch": s.host_access_epoch, "runtimeGeneration": s.runtime_generation,
        }),
        OutcomeUnknown { request_id } => {
            json!({ "type": "outcomeUnknown", "requestId": request_id })
        }
        StreamOpened { stream, params } => {
            let mut v = json!({ "type": "streamOpened", "stream": stream, "kind": tunnel::kind_name(params.kind()) });
            if let lomi_remote_protocol::tunnel::OpenParams::Transfer(t) = params {
                v["requestId"] = json!(t.request_id.as_str());
            }
            v
        }
        Message { stream, .. } => json!({ "type": "streamMessage", "stream": stream }),
        StreamClosed { stream } => json!({ "type": "streamClosed", "stream": stream }),
        StreamReset { stream, code } => {
            json!({ "type": "streamReset", "stream": stream, "code": code })
        }
    };
    v["tunnel"] = json!(th);
    v
}

fn tunnel_record(out: &mut Vec<u8>, th: u32, e: &tunnel::Event) {
    match e {
        // The bytes travel raw (tag 5), not in JSON.
        tunnel::Event::Message { stream, data } => {
            let mut body = stream.to_be_bytes().to_vec();
            body.extend_from_slice(data);
            record(out, 5, &body);
        }
        _ => record(out, 4, &to_bytes(&tunnel_event_json(th, e))),
    }
}

/// Runs tunnel outputs through the link and link outputs through the tunnels attached to it until
/// nothing is left to do, and returns the platform-facing records. A relay call or DATA the link
/// refuses (not Ready) closes the tunnel; link outputs a tunnel consumes (its circuit's DATA and
/// events, its own calls' results) are not shown to the platform.
fn settle(
    r: &mut Registry,
    lh: u32,
    now: Now,
    mut link_out: Vec<Output>,
    mut tun_out: Vec<(u32, tunnel::Out)>,
) -> Vec<u8> {
    let mut rec = Vec::new();
    while !link_out.is_empty() || !tun_out.is_empty() {
        for (th, o) in std::mem::take(&mut tun_out) {
            let sent = match &o {
                tunnel::Out::Event(e) => {
                    tunnel_record(&mut rec, th, e);
                    continue;
                }
                tunnel::Out::Call { name, args } => match link_mut(r, lh) {
                    Some(l) => l
                        .call(name, args.clone(), now)
                        .map(|(id, out)| (Some(id), out)),
                    None => Err(CallError::NotReady),
                },
                tunnel::Out::Data { circuit, bytes } => match link_mut(r, lh) {
                    Some(l) => l.send_data(circuit, bytes).map(|out| (None, out)),
                    None => Err(CallError::NotReady),
                },
            };
            let Some(t) = tunnel_mut(r, th) else { continue };
            match sent {
                Ok((id, out)) => {
                    if let (Some(id), tunnel::Out::Call { name, .. }) = (id, &o) {
                        t.call_started(name, id);
                    }
                    link_out.extend(out);
                }
                Err(_) => tun_out.extend(t.fail("linkDown").into_iter().map(|x| (th, x))),
            }
        }
        for o in std::mem::take(&mut link_out) {
            let mut consumed = false;
            for th in tunnels_of(r, lh) {
                if let Some(t) = tunnel_mut(r, th) {
                    let (c, outs) = t.on_link(&o, now.mono_ms);
                    consumed |= c;
                    tun_out.extend(outs.into_iter().map(|x| (th, x)));
                }
            }
            if !consumed {
                link_record(&mut rec, &o);
            }
        }
    }
    rec
}

fn hex_arg<const N: usize>(a: &Object, k: &str) -> R<[u8; N]> {
    tunnel::unhex(arg_str(a, k)?).ok_or_else(|| fail("badArgs"))
}

fn bundle_arg(a: &Object, k: &str) -> R<SignedBundle> {
    serde_json::from_value(Value::Object(arg_obj(a, k)?)).map_err(|_| fail("badArgs"))
}

/// `tunnel.new` payload: the 97-byte device identity seed blob (the platform wipes its copy).
fn tunnel_new(a: &Object, payload: &[u8]) -> R {
    let lh = u32::try_from(arg_u64(a, "link")?).map_err(|_| fail("badArgs"))?;
    if !matches!(registry().slots.get(&lh), Some(Slot::Link(_))) {
        return Err(fail("badHandle"));
    }
    let (device, host) = (bundle_arg(a, "deviceBundle")?, bundle_arg(a, "hostBundle")?);
    let identity =
        Identity::import_secret_seed_blob(payload, &device).map_err(|_| fail("badIdentity"))?;
    let mut hello = arg_obj(a, "hello")?;
    hello.insert("deviceBundle".into(), json!([]));
    let mut hello: Hello =
        serde_json::from_value(Value::Object(hello)).map_err(|_| fail("badArgs"))?;
    hello.device_bundle.0 = serde_json::to_vec(&device).map_err(|_| fail("badArgs"))?;
    let t = Tunnel::new(tunnel::Params {
        identity,
        host,
        pinned_host_fingerprint: hex_arg(a, "hostFingerprint")?,
        contract_hash: hex_arg(a, "contractHash")?,
        account_id: hex_arg(a, "accountId")?,
        host_id: hex_arg(a, "hostId")?,
        hello,
    });
    insert(Slot::Tunnel(lh, Box::new(t)))
}

fn stream_arg(a: &Object) -> R<u32> {
    u32::try_from(arg_u64(a, "stream")?).map_err(|_| fail("badArgs"))
}

fn tunnel_op(h: u32, op: &str, a: &Object, payload: &[u8]) -> R {
    let mut r = registry();
    let Some(Slot::Tunnel(lh, t)) = r.slots.get_mut(&h) else {
        return Err(fail("badHandle"));
    };
    let lh = *lh;
    let err = |e: String| fail(&e);
    match op {
        "tunnel.nextDeadline" => return Ok(to_bytes(&json!({ "deadline": t.next_deadline() }))),
        // With `stream` + `cursor`: record a cursor. Without: list `{stream, kind, cursor}`.
        "tunnel.cursors" if a.contains_key("stream") => {
            t.set_cursor(stream_arg(a)?, arg_u64(a, "cursor")?)
                .map_err(err)?;
            return Ok(Vec::new());
        }
        "tunnel.cursors" => {
            let list: Vec<Value> = t
                .cursors()
                .into_iter()
                .map(|(s, k, c)| json!({ "stream": s, "kind": tunnel::kind_name(k), "cursor": c }))
                .collect();
            return Ok(to_bytes(&json!({ "cursors": list })));
        }
        _ => {}
    }
    let n = now(a)?;
    let mut prefix = Vec::new();
    let outs = match op {
        "tunnel.start" => t.start(hex_arg(a, "random")?, n.mono_ms).map_err(err)?,
        "tunnel.tick" => t.tick(n.mono_ms),
        "tunnel.openStream" => {
            let params = a.get("params").cloned().unwrap_or_else(|| json!({}));
            let params = tunnel::open_params(arg_str(a, "kind")?, params).map_err(err)?;
            let (id, out) = t.open_stream(&params).map_err(err)?;
            record(
                &mut prefix,
                4,
                &to_bytes(&json!({ "type": "streamStarted", "stream": id, "tunnel": h })),
            );
            out
        }
        "tunnel.send" => t.send(stream_arg(a)?, payload).map_err(err)?,
        "tunnel.closeStream" => t.close_stream(stream_arg(a)?).map_err(err)?,
        "tunnel.close" => t.close(),
        _ => return Err(fail("unknownOp")),
    };
    prefix.extend(settle(
        &mut r,
        lh,
        n,
        Vec::new(),
        outs.into_iter().map(|o| (h, o)).collect(),
    ));
    Ok(prefix)
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
