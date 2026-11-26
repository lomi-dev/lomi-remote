//! Startup request `POST /remote/session` (`03-protokol.md` section 2,
//! `02-architektura.md` section 2). One exchange returns the account, a relay
//! token, the Host list and the device state. The platform performs the HTTP
//! call; the core builds the request and parses the response.
//!
//! Shapes follow the server (`auth-app` `src/remote/api/session.ts`). The server
//! knows no Host or workspace names (they come from the Host), so names are
//! optional. Times are Unix ms; access epochs and runtime generations are decimal strings;
//! workspace epochs are opaque UUIDs.
//! Unknown fields in the response are ignored; missing or mistyped ones are an error.

use crate::json::{self, Object};
use serde_json::Value;

pub const SESSION_PATH: &str = "/remote/session";
/// Largest response body the core parses.
pub const MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Short-lived token for the relay link (and its absolute expiry, Unix ms).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayToken {
    pub token: String,
    pub expires_at: u64,
}

/// How the client authenticates the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Credential {
    /// Browser: the session cookie, attached by the platform HTTP stack
    /// (`credentials: "include"`); nothing goes into the body.
    Cookie,
    /// Mobile and desktop: the refresh credential, sent in the body.
    Refresh(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: &'static str,
    pub path: &'static str,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn session_request(contract_hash: &str, credential: &Credential) -> HttpRequest {
    let mut body = Object::new();
    body.insert(
        "contractHash".into(),
        Value::String(contract_hash.to_owned()),
    );
    if let Credential::Refresh(c) = credential {
        body.insert("refreshCredential".into(), Value::String(c.clone()));
    }
    HttpRequest {
        method: "POST",
        path: SESSION_PATH,
        headers: vec![("content-type".into(), "application/json".into())],
        // Serializing a map of strings cannot fail.
        body: serde_json::to_vec(&Value::Object(body)).unwrap_or_default(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub email: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Workspace {
    pub id: String,
    /// Not sent by the server; known only from the Host.
    pub name: Option<String>,
    /// Opaque lowercase UUID: a different value means the workspace was replaced or reshared.
    pub epoch: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostEntry {
    pub id: String,
    /// Not sent by the server; known only from the Host.
    pub name: Option<String>,
    pub online: bool,
    /// Decimal strings, as in the relay frames.
    pub access_epoch: String,
    pub runtime_generation: String,
    pub workspaces: Vec<Workspace>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    Unregistered,
    Registered { device_id: String },
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionResponse {
    pub account: Account,
    /// End of the login session, Unix ms.
    pub session_expires_at: u64,
    pub relay: RelayToken,
    pub hosts: Vec<HostEntry>,
    pub device: DeviceState,
    /// Mobile only: new access token and rotated refresh credential for the platform to store.
    pub access_token: Option<RelayToken>,
    /// Opaque (`<sessionId>.<refreshToken>`): store and send back as is.
    pub refresh_credential: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionError {
    /// 401/403: sign in again.
    Unauthorized,
    /// 409 `UPDATE_REQUIRED`: client and server contracts differ; update before any data.
    UpdateRequired,
    /// 409 `OUTCOME_UNKNOWN`: the mobile refresh credential may have rotated and the
    /// response was lost. Re-authenticate (sign in again); do not retry the same credential.
    OutcomeUnknown,
    /// Other non-200 status.
    Http(u16),
    TooLarge,
    /// Not strict JSON or not the expected shape.
    Malformed,
}

impl SessionError {
    /// Worth repeating with backoff (server or gateway trouble), as opposed to fatal for this credential.
    pub fn is_retryable(&self) -> bool {
        matches!(self, SessionError::Http(408 | 425 | 429 | 500..=599))
    }
}

type R<T> = Result<T, SessionError>;

fn field<'a>(o: &'a Object, k: &str) -> R<&'a Value> {
    o.get(k).ok_or(SessionError::Malformed)
}
fn string(o: &Object, k: &str) -> R<String> {
    field(o, k)?
        .as_str()
        .map(str::to_owned)
        .ok_or(SessionError::Malformed)
}
fn opt_string(o: &Object, k: &str) -> R<Option<String>> {
    o.get(k)
        .filter(|v| !v.is_null())
        .map(|v| v.as_str().map(str::to_owned).ok_or(SessionError::Malformed))
        .transpose()
}
fn uuid(o: &Object, k: &str) -> R<String> {
    let s = string(o, k)?;
    let ok = s.len() == 36
        && s.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_digit() || (b'a'..=b'f').contains(&b),
        });
    if ok {
        Ok(s)
    } else {
        Err(SessionError::Malformed)
    }
}
fn uint(o: &Object, k: &str) -> R<u64> {
    field(o, k)?
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or(SessionError::Malformed)
}
fn object<'a>(o: &'a Object, k: &str) -> R<&'a Object> {
    field(o, k)?.as_object().ok_or(SessionError::Malformed)
}
fn array<'a>(o: &'a Object, k: &str) -> R<&'a Vec<Value>> {
    field(o, k)?.as_array().ok_or(SessionError::Malformed)
}
fn element(v: &Value) -> R<&Object> {
    v.as_object().ok_or(SessionError::Malformed)
}
fn token(o: &Object) -> R<RelayToken> {
    Ok(RelayToken {
        token: string(o, "token")?,
        expires_at: uint(o, "expiresAt")?,
    })
}

/// One Host entry, as in the startup response and in `inventory.changed` events.
pub(crate) fn parse_host(h: &Object) -> R<HostEntry> {
    Ok(HostEntry {
        id: string(h, "hostId")?,
        name: opt_string(h, "name")?,
        online: field(h, "online")?
            .as_bool()
            .ok_or(SessionError::Malformed)?,
        access_epoch: string(h, "accessEpoch")?,
        runtime_generation: string(h, "runtimeGeneration")?,
        workspaces: array(h, "workspaces")?
            .iter()
            .map(|w| {
                let w = element(w)?;
                Ok(Workspace {
                    id: string(w, "workspaceId")?,
                    name: opt_string(w, "name")?,
                    epoch: uuid(w, "workspaceEpoch")?,
                })
            })
            .collect::<R<_>>()?,
    })
}

fn conflict(body: &[u8]) -> SessionError {
    let code = (body.len() <= MAX_RESPONSE_BYTES)
        .then(|| std::str::from_utf8(body).ok())
        .flatten()
        .and_then(|t| json::parse(t).ok())
        .and_then(|v| v.get("code").and_then(Value::as_str).map(str::to_owned));
    match code.as_deref() {
        Some("UPDATE_REQUIRED") => SessionError::UpdateRequired,
        Some("OUTCOME_UNKNOWN") => SessionError::OutcomeUnknown,
        _ => SessionError::Http(409),
    }
}

/// Result of a 200 answer from `POST /remote/session`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionOutcome {
    Full(Box<SessionResponse>),
    /// A mobile refresh rotated the credential, but a later server step failed, so the answer
    /// has no account, relay token, Hosts or device. The old refresh credential is dead (reusing
    /// it is a replay and revokes the mobile session).
    ///
    /// Rule: persist `access_token` and `refresh_credential` BEFORE anything else, then call
    /// again, either with `Credential::Refresh(refresh_credential)` or with the saved access
    /// token as Bearer and no credential. Do not touch the directory (nothing to merge) and do
    /// not treat this as a sign-out.
    Degraded {
        /// Uppercase server error code of the failed step (for example `AUTH_REQUIRED`,
        /// `SERVICE_UNAVAILABLE`); for display and logs, not for control flow.
        reason: String,
        access_token: RelayToken,
        /// Opaque; store and send back as is.
        refresh_credential: String,
    },
}

pub fn parse_session_response(status: u16, body: &[u8]) -> R<SessionOutcome> {
    match status {
        200 => {}
        401 | 403 => return Err(SessionError::Unauthorized),
        409 => return Err(conflict(body)),
        s => return Err(SessionError::Http(s)),
    }
    if body.len() > MAX_RESPONSE_BYTES {
        return Err(SessionError::TooLarge);
    }
    let text = std::str::from_utf8(body).map_err(|_| SessionError::Malformed)?;
    let Value::Object(root) = json::parse(text).map_err(|_| SessionError::Malformed)? else {
        return Err(SessionError::Malformed);
    };
    if root.contains_key("degraded") {
        let reason = string(&root, "reason")?;
        if root.get("degraded") != Some(&Value::Bool(true))
            || reason.is_empty()
            || reason.len() > 64
            || !reason
                .bytes()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        {
            return Err(SessionError::Malformed);
        }
        return Ok(SessionOutcome::Degraded {
            reason,
            access_token: token(object(&root, "accessToken")?)?,
            refresh_credential: string(&root, "refreshCredential")?,
        });
    }
    let account = object(&root, "account")?;
    let device = object(&root, "device")?;
    let hosts = array(&root, "hosts")?
        .iter()
        .map(|h| parse_host(element(h)?))
        .collect::<R<_>>()?;
    Ok(SessionOutcome::Full(Box::new(SessionResponse {
        account: Account {
            id: string(account, "id")?,
            email: opt_string(account, "email")?,
        },
        session_expires_at: uint(&root, "sessionExpiresAt")?,
        relay: token(object(&root, "relay")?)?,
        hosts,
        device: match string(device, "state")?.as_str() {
            "unregistered" => DeviceState::Unregistered,
            "registered" => DeviceState::Registered {
                device_id: string(device, "deviceId")?,
            },
            "revoked" => DeviceState::Revoked,
            _ => return Err(SessionError::Malformed),
        },
        access_token: root
            .get("accessToken")
            .map(|v| token(element(v)?))
            .transpose()?,
        refresh_credential: opt_string(&root, "refreshCredential")?,
    })))
}
