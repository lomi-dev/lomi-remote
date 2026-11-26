//! Link client for role `device` (`02-architektura.md` section 2, `03-protokol.md`
//! section 3), sans-I/O. The platform owns the WebSocket and the clock:
//!
//! * it reports what happened (`start`, `on_open`, `on_message`, `on_close`,
//!   `tick`) together with the current time, and
//! * executes the returned [`Output`]s (`Connect`, `Send`, `Close`) and
//!   delivers the [`LinkEvent`]s to the UI.
//!
//! [`Link::next_deadline`] tells the platform when to call `tick` next, so no
//! polling is needed. Time is a [`Now`]: a monotonic clock for deadlines and
//! the wall clock only to convert the absolute token expiry (`expiresAt`, Unix
//! ms) into a monotonic deadline, so a wall-clock jump cannot stretch timeouts.

use crate::frame::{self, Direction, Frame, FrameError, Older, ReadyErrorCode, Role};
use crate::json::Object;
use crate::session::RelayToken;
use serde_json::Value;

/// Calls a device may send (`03-protokol.md`, "Zdarzenia i wywołania urządzenia").
pub const DEVICE_CALLS: [&str; 3] = ["circuit.open", "circuit.close", "token.update"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Now {
    /// Monotonic milliseconds (any epoch, never goes back).
    pub mono_ms: u64,
    /// Unix milliseconds.
    pub wall_ms: u64,
}

#[derive(Debug, Clone)]
pub struct LinkConfig {
    /// SHA-256 contract digest (lowercase hex) sent in AUTH.
    pub contract_hash: String,
    /// Unanswered calls (including the token refresh).
    pub max_inflight: usize,
    /// Must exceed the relay handler deadline (10 s) so the relay answers first.
    pub call_timeout_ms: u64,
    /// Socket open (platform side) deadline.
    pub connect_timeout_ms: u64,
    /// Time from AUTH to READY.
    pub ready_timeout_ms: u64,
    pub backoff_min_ms: u64,
    pub backoff_max_ms: u64,
    /// `TokenRefreshNeeded` fires this long before the token expires.
    pub refresh_lead_ms: u64,
}

impl LinkConfig {
    pub fn new(contract_hash: impl Into<String>) -> Self {
        Self {
            contract_hash: contract_hash.into(),
            max_inflight: 8,
            call_timeout_ms: 15_000,
            connect_timeout_ms: 10_000,
            ready_timeout_ms: 10_000,
            backoff_min_ms: 500,
            backoff_max_ms: 30_000,
            refresh_lead_ms: 300_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Output {
    /// Open the relay WebSocket, then call `on_open` (or `on_close` on failure).
    Connect,
    /// One binary WebSocket message.
    Send(Vec<u8>),
    /// Close the socket; do not call `on_close` for it.
    Close,
    Event(LinkEvent),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallError {
    /// `call` before READY.
    NotReady,
    TooManyInflight,
    /// Name outside [`DEVICE_CALLS`].
    UnknownCall,
    /// The call would not encode (bad name or oversize args).
    BadFrame,
    /// Relay answered with this error code.
    Remote(String),
    Timeout,
    /// The link went down before a reply.
    Aborted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectCause {
    SocketClosed,
    ConnectTimeout,
    ReadyTimeout,
    Unavailable,
    Busy,
    /// The relay sent something the codec or the link table rejects.
    Protocol,
    TokenExpired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopReason {
    /// The relay rejected the token: fetch a new session and `start` again.
    AuthFailed,
    /// Contract mismatch: show "update Host" or "refresh app" according to `older`.
    UpdateRequired {
        older: Option<Older>,
    },
    /// The token does not have the relay token shape.
    BadToken,
    Requested,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LinkEvent {
    Ready {
        expires_at: u64,
        state: Object,
    },
    /// EVENT from the relay (`presence`, `inventory.changed`, `revoked`, ...).
    Server {
        name: String,
        data: Object,
    },
    CallDone {
        call_id: u32,
        result: Result<Object, CallError>,
    },
    /// Fetch a fresh relay token and call `refresh_token`.
    TokenRefreshNeeded,
    TokenRefreshed {
        expires_at: u64,
    },
    /// `code` is the relay error code, `None` for timeout or link loss.
    TokenRefreshFailed {
        code: Option<String>,
    },
    /// No usable token (expired); fetch one and call `start`.
    TokenNeeded,
    /// The link is down; `retry_in_ms` is the jittered delay to the next attempt.
    Disconnected {
        cause: DisconnectCause,
        retry_in_ms: Option<u64>,
    },
    /// No automatic retry; the platform must act and call `start`.
    Stopped(StopReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Idle,
    Backoff(u64),
    Connecting(u64),
    Authenticating(u64),
    Ready,
}

enum Kind {
    Call,
    Refresh(RelayToken),
}

struct Inflight {
    id: u32,
    deadline: u64,
    kind: Kind,
}

pub struct Link {
    cfg: LinkConfig,
    rng: u64,
    state: State,
    token: Option<RelayToken>,
    attempt: u32,
    next_id: u32,
    inflight: Vec<Inflight>,
    expiry: Option<u64>,
    refresh_at: Option<u64>,
    refresh_asked: bool,
}

impl Link {
    /// `seed` drives the backoff jitter; tests pass a fixed one.
    pub fn new(cfg: LinkConfig, seed: u64) -> Self {
        Self {
            cfg,
            rng: seed,
            state: State::Idle,
            token: None,
            attempt: 0,
            next_id: 1,
            inflight: Vec::new(),
            expiry: None,
            refresh_at: None,
            refresh_asked: false,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.state == State::Ready
    }

    /// Supplies the relay token and connects, unless an attempt is already running
    /// or waiting in backoff (then the token is used for the next attempt).
    pub fn start(&mut self, token: RelayToken, now: Now) -> Vec<Output> {
        self.token = Some(token);
        let mut out = Vec::new();
        if self.state == State::Idle {
            self.attempt = 0;
            self.begin_connect(now, &mut out);
        }
        out
    }

    /// Closes the link without retrying.
    pub fn stop(&mut self) -> Vec<Output> {
        let mut out = Vec::new();
        self.fatal(StopReason::Requested, &mut out);
        out
    }

    /// The socket is open: send AUTH.
    pub fn on_open(&mut self, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        if !matches!(self.state, State::Connecting(_)) {
            return out;
        }
        let Some(token) = self.token.as_ref() else {
            return out;
        };
        let auth = Frame::Auth {
            role: Role::Device,
            token: token.token.clone(),
            contract_hash: self.cfg.contract_hash.clone(),
            claim: None,
        };
        match frame::encode_frame(&auth, frame::MAX_FRAME_BYTES) {
            Ok(bytes) => {
                self.state = State::Authenticating(now.mono_ms + self.cfg.ready_timeout_ms);
                out.push(Output::Send(bytes));
            }
            Err(_) => {
                self.token = None;
                self.fatal(StopReason::BadToken, &mut out);
            }
        }
        out
    }

    /// The socket closed or failed to open (platform side).
    pub fn on_close(&mut self, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        if matches!(
            self.state,
            State::Connecting(_) | State::Authenticating(_) | State::Ready
        ) {
            self.disconnect(DisconnectCause::SocketClosed, now, &mut out);
        }
        out
    }

    /// One binary WebSocket message from the relay.
    pub fn on_message(&mut self, bytes: &[u8], now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        if !matches!(self.state, State::Authenticating(_) | State::Ready) {
            return out; // late message for a socket we already gave up on
        }
        let frame = match frame::decode_frame(bytes, Direction::Relay, frame::MAX_FRAME_BYTES) {
            Ok(f) => f,
            Err(_) => return self.violation(now, out),
        };
        match (self.state, frame) {
            (
                State::Authenticating(_),
                Frame::ReadyOk {
                    role: Role::Device,
                    expires_at,
                    state,
                },
            ) => {
                self.state = State::Ready;
                self.attempt = 0;
                self.refresh_asked = false;
                self.set_expiry(expires_at, now);
                if let Some(t) = self.token.as_mut() {
                    t.expires_at = expires_at;
                }
                out.push(Output::Event(LinkEvent::Ready { expires_at, state }));
            }
            (State::Authenticating(_), Frame::ReadyErr { code, older }) => match code {
                ReadyErrorCode::AuthFailed => {
                    self.token = None;
                    self.fatal(StopReason::AuthFailed, &mut out);
                }
                ReadyErrorCode::UpdateRequired => {
                    self.fatal(StopReason::UpdateRequired { older }, &mut out)
                }
                ReadyErrorCode::Unavailable => {
                    out.push(Output::Close);
                    self.disconnect(DisconnectCause::Unavailable, now, &mut out);
                }
                ReadyErrorCode::Busy => {
                    out.push(Output::Close);
                    self.disconnect(DisconnectCause::Busy, now, &mut out);
                }
                // Host-only outcomes; a device never gets them.
                ReadyErrorCode::HostBusy | ReadyErrorCode::StaleEpoch => {
                    return self.violation(now, out);
                }
            },
            (State::Ready, Frame::Event { name, data }) => {
                out.push(Output::Event(LinkEvent::Server { name, data }))
            }
            (State::Ready, Frame::ReplyOk { call_id, data }) => {
                self.reply(call_id, Ok(data), now, &mut out)
            }
            (State::Ready, Frame::ReplyErr { call_id, code }) => {
                self.reply(call_id, Err(code), now, &mut out)
            }
            _ => return self.violation(now, out),
        }
        out
    }

    /// Sends a device call and returns its id; the result arrives as `CallDone`.
    /// `token.update` goes through [`Link::refresh_token`] instead.
    pub fn call(
        &mut self,
        name: &str,
        args: Object,
        now: Now,
    ) -> Result<(u32, Vec<Output>), CallError> {
        if name == "token.update" || !DEVICE_CALLS.contains(&name) {
            return Err(CallError::UnknownCall);
        }
        self.send_call(name, args, Kind::Call, now)
    }

    /// Hands the relay a fresh token (after `TokenRefreshNeeded`) without dropping the link.
    pub fn refresh_token(&mut self, token: RelayToken, now: Now) -> Result<Vec<Output>, CallError> {
        let mut args = Object::new();
        args.insert("token".into(), Value::String(token.token.clone()));
        self.send_call("token.update", args, Kind::Refresh(token), now)
            .map(|(_, out)| out)
    }

    /// Advances timers: backoff end, connect/READY/call deadlines, token refresh and expiry.
    pub fn tick(&mut self, now: Now) -> Vec<Output> {
        let mut out = Vec::new();
        let m = now.mono_ms;
        match self.state {
            State::Backoff(t) if m >= t => self.begin_connect(now, &mut out),
            State::Connecting(t) if m >= t => {
                out.push(Output::Close);
                self.disconnect(DisconnectCause::ConnectTimeout, now, &mut out);
            }
            State::Authenticating(t) if m >= t => {
                out.push(Output::Close);
                self.disconnect(DisconnectCause::ReadyTimeout, now, &mut out);
            }
            State::Ready if self.expiry.is_some_and(|e| m >= e) => {
                out.push(Output::Close);
                self.token = None;
                self.disconnect(DisconnectCause::TokenExpired, now, &mut out);
            }
            State::Ready if !self.refresh_asked && self.refresh_at.is_some_and(|r| m >= r) => {
                self.refresh_asked = true;
                out.push(Output::Event(LinkEvent::TokenRefreshNeeded));
            }
            _ => {}
        }
        // Calls that outlived their deadline (the connection may be gone by now).
        let mut i = 0;
        while i < self.inflight.len() {
            if self.inflight[i].deadline <= m {
                let f = self.inflight.remove(i);
                out.push(Output::Event(match f.kind {
                    Kind::Call => LinkEvent::CallDone {
                        call_id: f.id,
                        result: Err(CallError::Timeout),
                    },
                    Kind::Refresh(_) => LinkEvent::TokenRefreshFailed { code: None },
                }));
            } else {
                i += 1;
            }
        }
        out
    }

    /// Earliest monotonic time at which `tick` has work, `None` when only I/O can move the link.
    pub fn next_deadline(&self) -> Option<u64> {
        let state = match self.state {
            State::Backoff(t) | State::Connecting(t) | State::Authenticating(t) => Some(t),
            State::Ready => self
                .expiry
                .into_iter()
                .chain(self.refresh_at.filter(|_| !self.refresh_asked))
                .min(),
            State::Idle => None,
        };
        state
            .into_iter()
            .chain(self.inflight.iter().map(|f| f.deadline))
            .min()
    }

    fn send_call(
        &mut self,
        name: &str,
        args: Object,
        kind: Kind,
        now: Now,
    ) -> Result<(u32, Vec<Output>), CallError> {
        if self.state != State::Ready {
            return Err(CallError::NotReady);
        }
        if self.inflight.len() >= self.cfg.max_inflight {
            return Err(CallError::TooManyInflight);
        }
        while self.inflight.iter().any(|f| f.id == self.next_id) {
            self.next_id = self.next_id.wrapping_add(1);
        }
        let id = self.next_id;
        self.next_id = id.wrapping_add(1);
        let bytes = frame::encode_frame(
            &Frame::Call {
                call_id: id,
                name: name.to_owned(),
                args,
            },
            frame::MAX_FRAME_BYTES,
        )
        .map_err(|_: FrameError| CallError::BadFrame)?;
        self.inflight.push(Inflight {
            id,
            deadline: now.mono_ms + self.cfg.call_timeout_ms,
            kind,
        });
        Ok((id, vec![Output::Send(bytes)]))
    }

    fn reply(&mut self, id: u32, result: Result<Object, String>, now: Now, out: &mut Vec<Output>) {
        // A late reply for a call that already timed out is dropped.
        let Some(i) = self.inflight.iter().position(|f| f.id == id) else {
            return;
        };
        let f = self.inflight.remove(i);
        out.push(Output::Event(match (f.kind, result) {
            (Kind::Call, r) => LinkEvent::CallDone {
                call_id: id,
                result: r.map_err(CallError::Remote),
            },
            (Kind::Refresh(t), Ok(_)) => {
                let expires_at = t.expires_at;
                self.set_expiry(expires_at, now);
                self.refresh_asked = false;
                self.token = Some(t);
                LinkEvent::TokenRefreshed { expires_at }
            }
            (Kind::Refresh(_), Err(code)) => LinkEvent::TokenRefreshFailed { code: Some(code) },
        }));
    }

    fn set_expiry(&mut self, expires_at: u64, now: Now) {
        let remaining = expires_at.saturating_sub(now.wall_ms);
        self.expiry = Some(now.mono_ms + remaining);
        self.refresh_at = Some(now.mono_ms + remaining.saturating_sub(self.cfg.refresh_lead_ms));
    }

    fn begin_connect(&mut self, now: Now, out: &mut Vec<Output>) {
        match &self.token {
            Some(t) if t.expires_at > now.wall_ms => {
                self.state = State::Connecting(now.mono_ms + self.cfg.connect_timeout_ms);
                out.push(Output::Connect);
            }
            _ => {
                self.token = None;
                self.state = State::Idle;
                out.push(Output::Event(LinkEvent::TokenNeeded));
            }
        }
    }

    /// Malformed or out-of-table frame from the relay: drop the socket and retry.
    fn violation(&mut self, now: Now, mut out: Vec<Output>) -> Vec<Output> {
        out.push(Output::Close);
        self.disconnect(DisconnectCause::Protocol, now, &mut out);
        out
    }

    fn abort_inflight(&mut self, out: &mut Vec<Output>) {
        for f in self.inflight.drain(..) {
            out.push(Output::Event(match f.kind {
                Kind::Call => LinkEvent::CallDone {
                    call_id: f.id,
                    result: Err(CallError::Aborted),
                },
                Kind::Refresh(_) => LinkEvent::TokenRefreshFailed { code: None },
            }));
        }
        self.expiry = None;
        self.refresh_at = None;
    }

    /// Link lost: abort calls, then wait out a backoff (or, with no token, ask for one).
    fn disconnect(&mut self, cause: DisconnectCause, now: Now, out: &mut Vec<Output>) {
        self.abort_inflight(out);
        if self.token.is_none() {
            self.state = State::Idle;
            out.push(Output::Event(LinkEvent::Disconnected {
                cause,
                retry_in_ms: None,
            }));
            out.push(Output::Event(LinkEvent::TokenNeeded));
            return;
        }
        let delay = self.backoff_delay();
        self.state = State::Backoff(now.mono_ms + delay);
        out.push(Output::Event(LinkEvent::Disconnected {
            cause,
            retry_in_ms: Some(delay),
        }));
    }

    fn fatal(&mut self, reason: StopReason, out: &mut Vec<Output>) {
        if self.state == State::Idle {
            return;
        }
        if matches!(
            self.state,
            State::Connecting(_) | State::Authenticating(_) | State::Ready
        ) {
            out.push(Output::Close);
        }
        self.abort_inflight(out);
        self.state = State::Idle;
        out.push(Output::Event(LinkEvent::Stopped(reason)));
    }

    /// Exponential from `backoff_min_ms` to `backoff_max_ms`, jittered into [d/2, d].
    fn backoff_delay(&mut self) -> u64 {
        let d = self
            .cfg
            .backoff_min_ms
            .saturating_mul(1 << self.attempt.min(20))
            .min(self.cfg.backoff_max_ms);
        self.attempt = self.attempt.saturating_add(1);
        d / 2 + self.rand() % (d - d / 2 + 1)
    }

    /// splitmix64: tiny, seedable, good enough for jitter.
    fn rand(&mut self) -> u64 {
        self.rng = self.rng.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.rng;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}
