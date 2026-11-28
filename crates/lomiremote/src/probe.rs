//! `lomiremote probe`: a headless device client on the shared core (plan-1.0 P3a.13).
//!
//! Signs in like the desktop app (loopback PKCE login), calls `POST /remote/session`, keeps a
//! device identity in its own directory, registers it with `POST /remote/devices`, opens the relay
//! link and a tunnel through `lomi_remote_core::bridge` over a real WebSocket, and runs a fixed
//! scenario. Every step prints one `T <step> <ms>` line (ms since the probe started, or the step's
//! own duration where the name says so). A test and measurement tool, not a product client.
//!
//! The Host bundle is an input (`--host-identity`, the `{canonicalCbor, signature}` the Host
//! registered): the protocol has no client-facing source for it yet.
use clap::ArgMatches;
use lomi_host_http::{BudgetStop, RelayConnection, RelayTransport};
use lomi_remote_core::bridge;
use lomi_remote_crypto::{Identity, Role, SignedBundle};
use lomi_remote_protocol::{
    EnrollmentProof, EntryId, WorkspaceId, ipc::LocalRelayEndpoint, tunnel::DirectoryMessage,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    net::TcpListener,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
    task::Poll,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type R<T> = Result<T, String>;
const IO: Duration = Duration::from_secs(5);
const RPC_TIMEOUT_MS: u64 = 30_000;

fn ok_check() -> Result<(), BudgetStop> {
    Ok(())
}

// ---- small helpers ----------------------------------------------------------------------------

fn urandom<const N: usize>() -> R<[u8; N]> {
    let mut b = [0u8; N];
    fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .map_err(|e| format!("urandom: {e}"))?;
    Ok(b)
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> R<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.bytes().all(|c| c.is_ascii_hexdigit()) {
        return Err("bad hex".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// RFC 4648 base64url without padding (PKCE values).
pub fn b64url(b: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in b.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..=c.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

/// A dashed UUID as its 16 bytes.
pub fn uuid_bytes(s: &str) -> R<[u8; 16]> {
    let raw = unhex(&s.replace('-', ""))?;
    raw.try_into().map_err(|_| format!("not a uuid: {s}"))
}

fn write_private(path: &Path, bytes: &[u8]) -> R<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| format!("{}: {e}", tmp.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())?;
    f.sync_all().map_err(|e| e.to_string())?;
    fs::rename(&tmp, path).map_err(|e| e.to_string())
}

/// First value under key `k` anywhere in `v` (depth first).
pub fn find_key<'a>(v: &'a Value, k: &str) -> Option<&'a Value> {
    match v {
        Value::Object(o) => o.get(k).or_else(|| o.values().find_map(|x| find_key(x, k))),
        Value::Array(a) => a.iter().find_map(|x| find_key(x, k)),
        _ => None,
    }
}

fn cell_texts(v: &Value, out: &mut String) {
    match v {
        // A run of `repeat` equal cells; blank cells are not sent.
        Value::Object(o) if o.contains_key("cell") => {
            let text = o["cell"]["text"].as_str().unwrap_or_default();
            out.push_str(
                &text.repeat(o.get("repeat").and_then(Value::as_u64).unwrap_or(1) as usize),
            );
        }
        Value::Object(o) => o.values().for_each(|x| cell_texts(x, out)),
        Value::Array(a) => a.iter().for_each(|x| cell_texts(x, out)),
        _ => {}
    }
}

// ---- bridge records -------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum Rec {
    Connect,
    Send(Vec<u8>),
    Close,
    Ev(Value),
    Msg(u32, Vec<u8>),
}

/// The record list of a link/tunnel operation: `tag u8 | len u32 BE | body`.
pub fn records(mut b: &[u8]) -> R<Vec<Rec>> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 5 {
            return Err("short record".into());
        }
        let n = u32::from_be_bytes(b[1..5].try_into().unwrap()) as usize;
        let body = b.get(5..5 + n).ok_or("record overruns")?.to_vec();
        out.push(match b[0] {
            1 => Rec::Connect,
            2 => Rec::Send(body),
            3 => Rec::Close,
            4 => Rec::Ev(serde_json::from_slice(&body).map_err(|e| e.to_string())?),
            5 if body.len() >= 4 => Rec::Msg(
                u32::from_be_bytes(body[..4].try_into().unwrap()),
                body[4..].to_vec(),
            ),
            t => return Err(format!("record tag {t}")),
        });
        b = &b[5 + n..];
    }
    Ok(out)
}

fn core(h: u32, op: &str, args: &Value, payload: &[u8]) -> R<Vec<u8>> {
    let out = bridge::call(h, op, &serde_json::to_vec(args).unwrap(), payload);
    match out.split_first() {
        Some((0, d)) => Ok(d.to_vec()),
        Some((_, e)) => Err(format!("{op}: {}", String::from_utf8_lossy(e))),
        None => Err(format!("{op}: empty answer")),
    }
}

// ---- HTTP -----------------------------------------------------------------------------------

struct Http {
    agent: ureq::Agent,
    auth_origin: String,
    api_origin: String,
}

impl Http {
    fn new(auth_origin: String, api_origin: String) -> R<Self> {
        let tls = ureq::tls::TlsConfig::builder();
        // Debug builds only, like lomi-host-http's dev CA: trust a local stack's CA instead.
        #[cfg(debug_assertions)]
        let tls = match std::env::var_os("LOMI_REMOTE_DEV_EXTRA_CA") {
            Some(path) => {
                let pem = fs::read(&path).map_err(|e| format!("dev CA: {e}"))?;
                let certs: Vec<_> = ureq::tls::parse_pem(&pem)
                    .filter_map(|i| match i {
                        Ok(ureq::tls::PemItem::Certificate(c)) => Some(c),
                        _ => None,
                    })
                    .collect();
                if certs.is_empty() {
                    return Err("dev CA: no certificate".into());
                }
                tls.root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
            }
            None => tls,
        };
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(15)))
            .tls_config(tls.build())
            .build();
        Ok(Self {
            agent: ureq::Agent::new_with_config(config),
            auth_origin,
            api_origin,
        })
    }

    fn done(r: Result<ureq::http::Response<ureq::Body>, ureq::Error>) -> R<(u16, Vec<u8>)> {
        let mut r = r.map_err(|e| format!("http: {e}"))?;
        let status = r.status().as_u16();
        let body = r
            .body_mut()
            .with_config()
            .limit(1 << 20)
            .read_to_vec()
            .map_err(|e| format!("http body: {e}"))?;
        Ok((status, body))
    }

    fn post(&self, url: &str, bearer: Option<&str>, body: &[u8]) -> R<(u16, Vec<u8>)> {
        let mut req = self
            .agent
            .post(url)
            .header("content-type", "application/json");
        if let Some(t) = bearer {
            req = req.header("authorization", &format!("Bearer {t}"));
        }
        Self::done(req.send(body))
    }

    fn delete(&self, url: &str, bearer: &str) -> R<(u16, Vec<u8>)> {
        Self::done(
            self.agent
                .delete(url)
                .header("authorization", &format!("Bearer {bearer}"))
                .call(),
        )
    }
}

fn json_of(status: u16, body: &[u8], what: &str) -> R<Value> {
    let v: Value = serde_json::from_slice(body).unwrap_or(Value::Null);
    if status != 200 {
        return Err(format!(
            "{what}: HTTP {status} {}",
            v.get("code")
                .or_else(|| find_key(&v, "code"))
                .map(Value::to_string)
                .unwrap_or_default()
        ));
    }
    Ok(v)
}

// ---- login (desktop loopback PKCE) ----------------------------------------------------------

/// Desktop login: start, wait on the loopback callback (approved in the browser or by the local
/// stack's `desktop-login-approve.sh`), exchange. Returns the bearer access token.
fn login(http: &Http, client_id: &str) -> R<String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let redirect = format!(
        "http://127.0.0.1:{}/auth/callback",
        listener.local_addr().map_err(|e| e.to_string())?.port()
    );
    let state = b64url(&urandom::<32>()?);
    let verifier = b64url(&urandom::<32>()?);
    let challenge = b64url(&Sha256::digest(verifier.as_bytes()));
    let body = json!({"clientId": client_id, "redirectUri": redirect, "state": state, "codeChallenge": challenge});
    let (s, b) = http.post(
        &format!("{}/v1/desktop/start", http.auth_origin),
        None,
        body.to_string().as_bytes(),
    )?;
    json_of(s, &b, "desktop/start")?;
    eprintln!("probe: login started; approve it (desktop-login-approve.sh) within 5 min");
    let (mut sock, _) = listener.accept().map_err(|e| e.to_string())?;
    sock.set_read_timeout(Some(IO)).ok();
    let mut buf = vec![0u8; 8192];
    let n = sock.read(&mut buf).map_err(|e| e.to_string())?;
    let line = String::from_utf8_lossy(&buf[..n])
        .lines()
        .next()
        .unwrap_or_default()
        .to_owned();
    let _ = sock.write_all(
        b"HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\nconnection: close\r\n\r\nprobe: signed in\n",
    );
    let target = line.split(' ').nth(1).ok_or("bad callback request")?;
    let url = url::Url::parse(&format!("http://127.0.0.1{target}")).map_err(|e| e.to_string())?;
    let q = |k: &str| {
        url.query_pairs()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.into_owned())
    };
    if q("state").as_deref() != Some(state.as_str()) {
        return Err("callback state mismatch".into());
    }
    let code = q("code").ok_or("callback without code")?;
    let body = json!({"clientId": client_id, "code": code, "codeVerifier": verifier, "redirectUri": redirect});
    let (s, b) = http.post(
        &format!("{}/v1/desktop/exchange", http.auth_origin),
        None,
        body.to_string().as_bytes(),
    )?;
    let v = json_of(s, &b, "desktop/exchange")?;
    v["access_token"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "exchange without access_token".into())
}

// ---- options --------------------------------------------------------------------------------

struct Opts {
    dir: PathBuf,
    client_id: String,
    relay: String,
    contract_hash: String,
    host_id: String,
    host_identity: PathBuf,
    workspace: String,
    approve_cmd: Option<String>,
    revoke_cmd: Option<String>,
    scenario: String,
    keys: usize,
}

fn opts(a: &ArgMatches) -> Opts {
    let s = |k: &str| a.get_one::<String>(k).cloned().unwrap_or_default();
    Opts {
        dir: a.get_one::<PathBuf>("dir").cloned().unwrap_or_default(),
        client_id: s("client-id"),
        relay: s("relay-endpoint"),
        contract_hash: s("contract-hash"),
        host_id: s("host-id"),
        host_identity: a
            .get_one::<PathBuf>("host-identity")
            .cloned()
            .unwrap_or_default(),
        workspace: s("workspace"),
        approve_cmd: a.get_one::<String>("approve-cmd").cloned(),
        revoke_cmd: a.get_one::<String>("revoke-cmd").cloned(),
        scenario: s("scenario"),
        keys: a.get_one::<usize>("keys").copied().unwrap_or(20),
    }
}

// ---- the client -----------------------------------------------------------------------------

struct Client {
    t0: Instant,
    http: Http,
    token: String,
    relay: RelayTransport,
    conn: Option<RelayConnection>,
    link: u32,
    tunnel: u32,
    events: Vec<(u64, Value)>,
    msgs: Vec<(u64, u32, Vec<u8>)>,
    refresh: bool,
    seq: u64,
    hash: String,
}

impl Drop for Client {
    fn drop(&mut self) {
        bridge::free(self.tunnel);
        bridge::free(self.link);
    }
}

impl Client {
    fn ms(&self) -> u64 {
        self.t0.elapsed().as_millis() as u64
    }
    fn t(&self, step: &str) {
        println!("T {step} {}", self.ms());
    }
    fn at(&self, mut v: Value) -> Value {
        v["monoMs"] = json!(self.ms() + 1);
        v["wallMs"] = json!(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_millis() as u64)
        );
        v
    }
    fn op(&mut self, h: u32, op: &str, args: Value, payload: &[u8]) -> R<()> {
        let d = core(h, op, &self.at(args), payload)?;
        self.exec(&d)
    }
    fn exec(&mut self, d: &[u8]) -> R<()> {
        for rec in records(d)? {
            let ms = self.ms();
            match rec {
                Rec::Connect => match self.relay.connect_link(Instant::now() + IO, &ok_check) {
                    Ok(c) => {
                        self.conn = Some(c);
                        self.op(self.link, "link.onOpen", json!({}), &[])?;
                    }
                    Err(e) => {
                        eprintln!("probe: relay connect failed: {e:?}");
                        self.op(self.link, "link.onClose", json!({}), &[])?;
                    }
                },
                Rec::Send(b) => {
                    let failed = match self.conn.as_mut() {
                        Some(c) => c.send_binary(&b, Instant::now() + IO, &ok_check).is_err(),
                        None => false,
                    };
                    if failed {
                        self.conn = None;
                        self.op(self.link, "link.onClose", json!({}), &[])?;
                    }
                }
                Rec::Close => self.conn = None,
                Rec::Ev(v) => {
                    if v["type"] != "server" {
                        eprintln!("probe: {ms} ms event {v}");
                    }
                    self.refresh |= v["type"] == "tokenRefreshNeeded";
                    self.events.push((ms, v));
                }
                Rec::Msg(s, b) => self.msgs.push((ms, s, b)),
            }
        }
        Ok(())
    }

    /// Reads what the socket has, runs due timers. True when something arrived.
    fn pump(&mut self) -> R<bool> {
        let mut progressed = false;
        while let Some(c) = self.conn.as_mut() {
            match c.poll_binary(Instant::now() + IO, &ok_check) {
                Ok(Poll::Ready(b)) => {
                    progressed = true;
                    self.op(self.link, "link.onMessage", json!({}), &b)?;
                }
                Ok(Poll::Pending) => break,
                Err(e) => {
                    eprintln!("probe: relay socket: {e:?}");
                    self.conn = None;
                    self.op(self.link, "link.onClose", json!({}), &[])?;
                }
            }
        }
        let d: Value =
            serde_json::from_slice(&core(self.link, "link.nextDeadline", &json!({}), &[])?)
                .map_err(|e| e.to_string())?;
        if d["deadline"].as_u64().is_some_and(|d| d <= self.ms() + 1) {
            self.op(self.link, "link.tick", json!({}), &[])?;
        }
        if std::mem::take(&mut self.refresh) {
            let s = session(&self.http, &self.token, &self.hash)?;
            let r = &s["relay"];
            self.op(
                self.link,
                "link.refreshToken",
                json!({"token": r["token"], "expiresAt": r["expiresAt"]}),
                &[],
            )?;
        }
        Ok(progressed)
    }

    fn wait(&mut self, what: &str, timeout: Duration, done: impl Fn(&Self) -> bool) -> R<()> {
        let start = Instant::now();
        while !done(self) {
            if start.elapsed() > timeout {
                return Err(format!("timed out waiting for {what}"));
            }
            if !self.pump()? {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }

    fn state_closed(&self) -> Option<String> {
        self.events
            .iter()
            .find(|(_, e)| e["type"] == "tunnelState" && e["state"] == "closed")
            .map(|(_, e)| e["reason"].as_str().unwrap_or_default().to_owned())
    }
    fn tunnel_state(&self, state: &str) -> Option<(u64, Value)> {
        self.events
            .iter()
            .find(|(_, e)| e["type"] == "tunnelState" && e["state"] == state)
            .cloned()
    }

    fn stream_msgs(&self, stream: u32) -> impl Iterator<Item = &(u64, u32, Vec<u8>)> {
        self.msgs.iter().filter(move |(_, s, _)| *s == stream)
    }

    /// One rpc envelope on `stream`; waits for the answer with its request id.
    fn request(&mut self, stream: u32, ws: Option<&str>, call: Value) -> R<(Value, Duration)> {
        self.seq += 1;
        let id = format!("probe-{}", self.seq);
        let mut body = json!({"requestId": id, "timeoutMs": RPC_TIMEOUT_MS, "call": call});
        if let Some(w) = ws {
            body["workspaceId"] = json!(w);
        }
        let from = self.msgs.len();
        let start = Instant::now();
        self.op(
            self.tunnel,
            "tunnel.send",
            json!({"stream": stream}),
            body.to_string().as_bytes(),
        )?;
        let find = |c: &Self| -> Option<Value> {
            c.msgs[from..]
                .iter()
                .filter(|(_, s, _)| *s == stream)
                .filter_map(|(_, _, b)| serde_json::from_slice::<Value>(b).ok())
                .find(|v| v["requestId"] == id)
        };
        self.wait(&format!("answer {id}"), Duration::from_secs(35), |c| {
            find(c).is_some() || c.state_closed().is_some()
        })?;
        let v = find(self).ok_or_else(|| format!("tunnel closed: {:?}", self.state_closed()))?;
        Ok((v, start.elapsed()))
    }

    /// The payload of a `transfer` answer's stream, once the Host closed it.
    fn transfer(&mut self, answer: &Value) -> R<Vec<u8>> {
        let stream = answer["transferStream"]
            .as_u64()
            .ok_or("transfer without stream")? as u32;
        self.wait("transfer", Duration::from_secs(30), |c| {
            c.events.iter().any(|(_, e)| {
                e["type"] == "streamClosed" && e["stream"].as_u64() == Some(u64::from(stream))
            })
        })?;
        Ok(self
            .stream_msgs(stream)
            .flat_map(|(_, _, b)| b.clone())
            .collect())
    }

    fn open_stream(&mut self, kind: &str, params: Value) -> R<u32> {
        let from = self.events.len();
        self.op(
            self.tunnel,
            "tunnel.openStream",
            json!({"kind": kind, "params": params}),
            &[],
        )?;
        self.events[from..]
            .iter()
            .find(|(_, e)| e["type"] == "streamStarted")
            .and_then(|(_, e)| e["stream"].as_u64())
            .map(|s| s as u32)
            .ok_or_else(|| "no streamStarted".into())
    }
}

fn session(http: &Http, token: &str, hash: &str) -> R<Value> {
    let req: Value = serde_json::from_slice(&core(
        0,
        "session.request",
        &json!({"contractHash": hash}),
        &[],
    )?)
    .map_err(|e| e.to_string())?;
    let body = req["body"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_u64())
                .map(|x| x as u8)
                .collect::<Vec<u8>>()
        })
        .or_else(|| req["body"].as_str().map(|s| s.as_bytes().to_vec()))
        .ok_or("session.request without body")?;
    let (s, b) = http.post(
        &format!("{}/remote/session", http.api_origin),
        Some(token),
        &body,
    )?;
    if s != 200 {
        return Err(format!(
            "session: HTTP {s} {}",
            String::from_utf8_lossy(&b)
                .chars()
                .take(120)
                .collect::<String>()
        ));
    }
    serde_json::from_slice(&b).map_err(|e| e.to_string())
}

/// Loads the device identity for `device_id`, or makes and stores a new one.
fn device_identity(dir: &Path, account: [u8; 16], device: [u8; 16]) -> R<Identity> {
    let (seed_p, bundle_p) = (dir.join("device.seed"), dir.join("device.json"));
    if let (Ok(seed), Ok(bundle)) = (fs::read(&seed_p), fs::read(&bundle_p))
        && let Ok(bundle) = serde_json::from_slice::<SignedBundle>(&bundle)
        && bundle.bundle.subject_id == device
        && bundle.bundle.account_id == account
    {
        return Identity::import_secret_seed_blob(&seed, &bundle).map_err(|e| e.to_string());
    }
    let id = Identity::generate(account, device, Role::Device, 1).map_err(|e| e.to_string())?;
    write_private(
        &seed_p,
        &id.export_secret_seed_blob().map_err(|e| e.to_string())?,
    )?;
    write_private(
        &bundle_p,
        &serde_json::to_vec(&id.public_bundle()).map_err(|e| e.to_string())?,
    )?;
    Ok(id)
}

/// `POST /remote/devices`: challenge, then the signature. Returns the device row.
fn register(http: &Http, token: &str, id: &Identity) -> R<Value> {
    let url = format!("{}/remote/devices", http.api_origin);
    let bundle = serde_json::to_value(id.public_bundle()).map_err(|e| e.to_string())?;
    let (s, b) = http.post(
        &url,
        Some(token),
        json!({"bundle": bundle}).to_string().as_bytes(),
    )?;
    let c = json_of(s, &b, "devices challenge")?;
    let challenge: [u8; 32] = unhex(c["challenge"].as_str().ok_or("no challenge")?)?
        .try_into()
        .map_err(|_| "challenge length")?;
    let sig = id
        .sign_device_registration(&challenge)
        .map_err(|e| e.to_string())?;
    let body = json!({"bundle": bundle, "challenge": hex(&challenge), "signature": hex(&sig)});
    let (s, b) = http.post(&url, Some(token), body.to_string().as_bytes())?;
    Ok(json_of(s, &b, "devices register")?["device"].clone())
}

fn shell(cmd: &str, fingerprint: &str) -> R<String> {
    let out = std::process::Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .env("PROBE_FINGERPRINT", fingerprint)
        .output()
        .map_err(|e| e.to_string())?;
    if !out.status.success() {
        return Err(format!(
            "command failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

pub fn run(args: &ArgMatches) -> u8 {
    let o = opts(args);
    match scenario(&o) {
        Ok(()) => {
            println!("RESULT ok");
            0
        }
        Err(e) => {
            println!("RESULT failed: {e}");
            1
        }
    }
}

fn scenario(o: &Opts) -> R<()> {
    let t0 = Instant::now();
    fs::create_dir_all(&o.dir).map_err(|e| e.to_string())?;
    fs::set_permissions(&o.dir, std::os::unix::fs::PermissionsExt::from_mode(0o700))
        .map_err(|e| e.to_string())?;
    let relay_ep = LocalRelayEndpoint::try_from(o.relay.clone()).map_err(str::to_owned)?;
    let auth_origin =
        std::env::var("PROBE_AUTH_ORIGIN").unwrap_or_else(|_| "https://localhost:8443".into());
    let api_origin =
        std::env::var("PROBE_API_ORIGIN").unwrap_or_else(|_| "https://localhost:8444".into());
    let http = Http::new(auth_origin, api_origin)?;
    let ms = || t0.elapsed().as_millis() as u64;

    // 1. login once, then the session
    let token_p = o.dir.join("token");
    let mut token = fs::read_to_string(&token_p).unwrap_or_default();
    let mut s = if token.is_empty() {
        Err("no token".to_owned())
    } else {
        session(&http, &token, &o.contract_hash)
    };
    if s.as_ref()
        .is_err_and(|e| e.contains("401") || e == "no token")
    {
        token = login(&http, &o.client_id)?;
        write_private(&token_p, token.as_bytes())?;
        println!("T login {}", ms());
        // The desktop app's next step: a direct consumer authority for this session.
        let (st, b) = http.post(
            &format!("{}/v2/remote/consumer-authorizations", http.auth_origin),
            Some(&token),
            b"{}",
        )?;
        json_of(st, &b, "consumer authorization")?;
        println!("T consumer-authorization {}", ms());
        s = session(&http, &token, &o.contract_hash);
    }
    let s = s?;
    println!("T session {}", ms());
    let account = s["account"]["id"].as_str().ok_or("no account")?.to_owned();
    let device_id = s["device"]["deviceId"]
        .as_str()
        .ok_or("no device id")?
        .to_owned();
    let host = s["hosts"]
        .as_array()
        .and_then(|h| h.iter().find(|h| h["hostId"] == o.host_id.as_str()))
        .ok_or("host not in the session inventory")?
        .clone();
    eprintln!(
        "probe: account {account} device {device_id} host online={} workspaces={}",
        host["online"],
        host["workspaces"].as_array().map_or(0, Vec::len)
    );

    // 2. device identity and registration
    let identity = device_identity(&o.dir, uuid_bytes(&account)?, uuid_bytes(&device_id)?)?;
    let fingerprint = hex(&identity
        .public_bundle()
        .bundle
        .fingerprint()
        .map_err(|e| e.to_string())?);
    println!("I device-fingerprint {fingerprint}");
    let registered = register(&http, &token, &identity);
    println!("T register {}", ms());
    let auth_epoch = match &registered {
        Ok(d) => d["authEpoch"]
            .as_str()
            .and_then(|e| e.parse().ok())
            .unwrap_or(1u64),
        Err(e) if o.scenario == "after-revoke" => {
            println!("NEG register-after-revoke refused: {e}");
            1
        }
        Err(e) => return Err(e.clone()),
    };

    // 3. Host bundle (pinned)
    let proof: EnrollmentProof = serde_json::from_slice(
        &fs::read(&o.host_identity).map_err(|e| format!("host identity: {e}"))?,
    )
    .map_err(|e| format!("host identity: {e}"))?;
    let host_bundle = SignedBundle::from_wire(&proof).map_err(|e| e.to_string())?;
    let host_fp = host_bundle
        .bundle
        .fingerprint()
        .map_err(|e| e.to_string())?;

    // 4. link
    let link = {
        let seed = u64::from_be_bytes(urandom::<8>()?) & ((1 << 53) - 1);
        let h: Value = serde_json::from_slice(&core(
            0,
            "link.new",
            &json!({"contractHash": o.contract_hash, "seed": seed}),
            &[],
        )?)
        .map_err(|e| e.to_string())?;
        h["handle"].as_u64().ok_or("link handle")? as u32
    };
    let mut c = Client {
        t0,
        http,
        token,
        relay: RelayTransport::new(relay_ep).map_err(|e| format!("{e:?}"))?,
        conn: None,
        link,
        tunnel: 0,
        events: Vec::new(),
        msgs: Vec::new(),
        refresh: false,
        seq: 0,
        hash: o.contract_hash.clone(),
    };
    let r = &s["relay"];
    c.op(
        link,
        "link.start",
        json!({"token": r["token"], "expiresAt": r["expiresAt"]}),
        &[],
    )?;
    c.wait("link ready", Duration::from_secs(10), |c| {
        c.events
            .iter()
            .any(|(_, e)| e["type"] == "ready" || e["type"] == "stopped")
    })?;
    if !c.events.iter().any(|(_, e)| e["type"] == "ready") {
        let stop = c
            .events
            .iter()
            .find(|(_, e)| e["type"] == "stopped")
            .map(|(_, e)| e["reason"].to_string());
        if o.scenario == "after-revoke" {
            println!(
                "NEG link-after-revoke refused: {}",
                stop.unwrap_or_default()
            );
            return Ok(());
        }
        return Err(format!("link stopped before ready: {stop:?}"));
    }
    c.t("link.ready");

    // 5. tunnel
    let seed = identity
        .export_secret_seed_blob()
        .map_err(|e| e.to_string())?;
    let num = |v: &Value| v.as_str().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
    let tun: Value = serde_json::from_slice(&core(
        0,
        "tunnel.new",
        &json!({
            "link": link,
            "deviceBundle": serde_json::to_value(identity.public_bundle()).unwrap(),
            "hostBundle": serde_json::to_value(&host_bundle).unwrap(),
            "hostFingerprint": hex(&host_fp),
            "contractHash": o.contract_hash,
            "accountId": hex(&uuid_bytes(&account)?),
            "hostId": hex(&uuid_bytes(&o.host_id)?),
            "hello": {
                "deviceName": "probe", "deviceKind": "desktop", "authEpoch": auth_epoch,
                "hostAccessEpoch": num(&host["accessEpoch"]),
                "runtimeGeneration": num(&host["runtimeGeneration"]),
                "resume": [], "sendDirectory": true,
            },
        }),
        &seed,
    )?)
    .map_err(|e| e.to_string())?;
    drop(seed);
    c.tunnel = tun["handle"].as_u64().ok_or("tunnel handle")? as u32;
    let open_at = c.ms();
    let random = hex(&urandom::<32>()?);
    c.op(c.tunnel, "tunnel.start", json!({"random": random}), &[])?;
    c.wait("tunnel open", Duration::from_secs(130), |c| {
        c.tunnel_state("open").is_some() || c.state_closed().is_some()
    })?;
    if let Some(reason) = c.state_closed() {
        if o.scenario == "after-revoke" {
            println!("NEG tunnel-after-revoke refused: {reason}");
            return Ok(());
        }
        return Err(format!("tunnel closed: {reason}"));
    }
    let (open_ms, _) = c.tunnel_state("open").unwrap();
    println!("T tunnel.open {open_ms}");
    println!("T tunnel.open.duration {}", open_ms - open_at);
    if o.scenario == "after-revoke" {
        return Err("tunnel opened after revoke".into());
    }

    // directory (Host-opened stream, first message = snapshot)
    let dir_stream = c
        .events
        .iter()
        .find(|(_, e)| e["type"] == "streamOpened" && e["kind"] == "directory")
        .and_then(|(_, e)| e["stream"].as_u64());
    c.wait("directory", Duration::from_secs(10), |c| {
        c.events
            .iter()
            .find(|(_, e)| e["type"] == "streamOpened" && e["kind"] == "directory")
            .and_then(|(_, e)| e["stream"].as_u64())
            .is_some_and(|s| c.stream_msgs(s as u32).next().is_some())
    })?;
    let dir_stream = dir_stream
        .or_else(|| {
            c.events
                .iter()
                .find(|(_, e)| e["type"] == "streamOpened" && e["kind"] == "directory")
                .and_then(|(_, e)| e["stream"].as_u64())
        })
        .unwrap() as u32;
    let (dir_ms, _, first) = c.stream_msgs(dir_stream).next().unwrap().clone();
    println!("T directory {dir_ms}");
    let DirectoryMessage::Snapshot(snapshot) =
        DirectoryMessage::decode(&first).map_err(|e| format!("directory: {e:?}"))?
    else {
        return Err("first directory message is not a snapshot".into());
    };
    let ws = snapshot
        .workspaces
        .iter()
        .find(|w| w.name.as_str() == o.workspace)
        .ok_or_else(|| format!("workspace {} not in the directory", o.workspace))?
        .clone();
    println!(
        "I directory host={} workspaces={} ws={} terminals={} chats={} caps={:?}",
        snapshot.host.name.as_str(),
        snapshot.workspaces.len(),
        String::from(ws.id),
        ws.terminals.len(),
        ws.chats.len(),
        ws.capabilities
    );

    match o.scenario.as_str() {
        "revoke-server" => {
            let at = Instant::now();
            let (s, b) = c.http.delete(
                &format!("{}/remote/devices/{device_id}", c.http.api_origin),
                &c.token,
            )?;
            println!(
                "T revoke.delete.duration {} (HTTP {s} {})",
                at.elapsed().as_millis(),
                String::from_utf8_lossy(&b)
            );
            let after = Instant::now();
            c.wait("close after revoke", Duration::from_secs(10), |c| {
                c.state_closed().is_some()
            })?;
            println!(
                "NEG revoke-server tunnel closed {} ms after DELETE returned (reason {})",
                after.elapsed().as_millis(),
                c.state_closed().unwrap_or_default()
            );
            return Ok(());
        }
        "revoke-host" => {
            let cmd = o.revoke_cmd.as_deref().ok_or("--revoke-cmd needed")?;
            let at = Instant::now();
            let out = shell(cmd, &fingerprint)?;
            println!("T revoke.cmd.duration {} ({out})", at.elapsed().as_millis());
            let after = Instant::now();
            c.wait("close after host revoke", Duration::from_secs(10), |c| {
                c.state_closed().is_some()
            })?;
            println!(
                "NEG revoke-host tunnel closed {} ms after the command returned (reason {})",
                after.elapsed().as_millis(),
                c.state_closed().unwrap_or_default()
            );
            return Ok(());
        }
        _ => {}
    }

    // terminal
    let pane = ws
        .terminals
        .iter()
        .find(|t| t.session_epoch.is_some())
        .ok_or("no running terminal in the workspace")?;
    let ws_id = String::from(ws.id);
    let open_at = Instant::now();
    let ts = c.open_stream(
        "terminal",
        json!({"workspaceId": ws_id, "paneId": String::from(pane.pane_id),
               "sessionEpoch": String::from(pane.session_epoch.unwrap()), "cols": 80, "rows": 24}),
    )?;
    c.wait("terminal first frame", Duration::from_secs(10), |c| {
        c.stream_msgs(ts).next().is_some()
    })?;
    println!(
        "T terminal.first-frame.duration {}",
        open_at.elapsed().as_millis()
    );
    let frames = |c: &Client, ty: &str| -> Vec<Value> {
        c.stream_msgs(ts)
            .filter_map(|(_, _, b)| serde_json::from_slice::<Value>(b).ok())
            .filter(|v| v["type"] == ty)
            .collect()
    };
    c.wait("snapshot", Duration::from_secs(10), |c| {
        !frames(c, "snapshotComplete").is_empty()
    })?;
    println!(
        "T terminal.snapshot.duration {}",
        open_at.elapsed().as_millis()
    );
    let trace: Vec<String> = c
        .stream_msgs(ts)
        .map(|(ms, _, b)| {
            let t = serde_json::from_slice::<Value>(b).ok();
            format!(
                "{ms}:{}:{}",
                t.as_ref().and_then(|v| v["type"].as_str()).unwrap_or("?"),
                b.len()
            )
        })
        .collect();
    eprintln!("probe: snapshot frames {}", trace.join(" "));
    let meta = frames(&c, "snapshotMetadata")
        .first()
        .cloned()
        .ok_or("no snapshotMetadata")?;
    let terminal = meta["data"]["terminal"].clone();
    let sub = meta["data"]["subscriptionId"].clone();
    let context = terminal["workspace"].clone();
    let claim = json!({"method": "terminal.claim", "params": {
        "terminal": terminal, "subscriptionId": sub, "renderedThroughSeq": "0"}});
    let (refused, _) = c.request(ts, None, claim.clone())?;
    let code = refused["error"]["code"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    println!("I claim.read {} {code}", refused["type"]);
    let lease = if refused["type"] == "result" {
        println!("WARN claim was granted without approval");
        (
            refused["result"]["params"]["lease"].clone(),
            refused.clone(),
        )
    } else {
        if code != "SCOPE_DENIED" {
            return Err(format!("claim at Read: {refused}"));
        }
        let cmd = o.approve_cmd.as_deref().ok_or("--approve-cmd needed")?;
        let at = Instant::now();
        let out = shell(cmd, &fingerprint)?;
        println!(
            "T approve.cmd.duration {} ({out})",
            at.elapsed().as_millis()
        );
        // the approval reaches the live tunnel asynchronously: retry the claim for a few seconds
        let mut granted = None;
        let at = Instant::now();
        while at.elapsed() < Duration::from_secs(10) {
            let (v, d) = c.request(ts, None, claim.clone())?;
            if v["type"] == "result" {
                println!(
                    "T claim.control.duration {} (after approve {} ms)",
                    d.as_millis(),
                    at.elapsed().as_millis()
                );
                granted = Some((v["result"]["params"]["lease"].clone(), v.clone()));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        granted.ok_or("claim still refused after approve")?
    };
    let (lease, claimed) = lease;
    let first_seq = find_key(&claimed, "nextInputSeq")
        .and_then(|v| {
            v.as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or(v.as_u64())
        })
        .unwrap_or(1);

    // input: one echo line, then single keys for the round trip
    let mut seq = first_seq - 1;
    // Input ids and sequences carry on across leases of the session: start where the Host says.
    let next_id = find_key(&claimed, "nextInputId")
        .and_then(|v| v.as_str().and_then(|s| s.parse::<u64>().ok()))
        .unwrap_or(1);
    let id_base = next_id - first_seq;
    let mut input = |c: &mut Client, bytes: &[u8]| -> R<Value> {
        seq += 1;
        let call = json!({"method": "terminal.input", "params": {
            "terminal": terminal, "lease": lease, "inputId": (id_base + seq).to_string(),
            "inputSeq": seq.to_string(), "bytes": bytes}});
        Ok(c.request(ts, None, call)?.0)
    };
    // Cell texts of the grid patches (JSON in the delta chunk bytes), in order.
    let delta_text = |c: &Client, from: usize| -> String {
        let bytes: Vec<u8> = c.msgs[from..]
            .iter()
            .filter(|(_, s, _)| *s == ts)
            .filter_map(|(_, _, b)| serde_json::from_slice::<Value>(b).ok())
            .filter(|v| v["type"].as_str().is_some_and(|t| t.starts_with("delta")))
            .filter_map(|v| find_key(&v, "bytes").cloned())
            .filter_map(|b| b.as_array().cloned())
            .flatten()
            .filter_map(|x| x.as_u64().map(|x| x as u8))
            .collect();
        let mut out = String::new();
        // shortcut: chunks are joined per message; a patch split over two deltas still parses per run.
        let mut d = serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>();
        while let Some(Ok(v)) = d.next() {
            cell_texts(&v, &mut out);
        }
        out
    };
    let marker = format!("probe-{}", u32::from_be_bytes(urandom::<4>()?) % 100_000);
    let from = c.msgs.len();
    let at = Instant::now();
    let r = input(&mut c, format!("echo {marker}\n").as_bytes())?;
    if r["type"] != "result" {
        return Err(format!("input refused: {r}"));
    }
    // the command line echo and the output: the marker twice
    c.wait("echo in deltas", Duration::from_secs(10), |c| {
        delta_text(c, from).contains(&marker)
    })
    .map_err(|e| {
        format!(
            "{e} (delta text: {:?})",
            delta_text(&c, from).chars().take(4000).collect::<String>()
        )
    })?;
    println!(
        "T terminal.echo-line.duration {} ({marker})",
        at.elapsed().as_millis()
    );

    let mut rtts = Vec::new();
    for _ in 0..o.keys {
        let from = c.msgs.len();
        let at = Instant::now();
        let r = input(&mut c, b"x")?;
        if r["type"] != "result" {
            return Err(format!("key refused: {r}"));
        }
        let deltas = |c: &Client| {
            c.msgs[from..]
                .iter()
                .filter(|(_, s, _)| *s == ts)
                .filter_map(|(_, _, b)| serde_json::from_slice::<Value>(b).ok())
                .any(|v| v["type"] == "deltaComplete" || v["type"] == "delta")
        };
        c.wait("key echo", Duration::from_secs(5), deltas)?;
        rtts.push(at.elapsed().as_secs_f64() * 1000.0);
    }
    input(&mut c, &[0x15])?; // Ctrl-U: clear the typed keys
    rtts.sort_by(|a, b| a.partial_cmp(b).unwrap());
    if !rtts.is_empty() {
        println!(
            "T terminal.key-echo.p50 {:.1} (n={} min={:.1} max={:.1})",
            rtts[rtts.len() / 2],
            rtts.len(),
            rtts[0],
            rtts[rtts.len() - 1]
        );
    }

    // chat
    let (providers, _) = c.request(
        0,
        Some(&ws_id),
        json!({"method": "chat.providers", "params": {}}),
    )?;
    println!("I chat.providers {}", providers["type"]);
    if let Some(chat) = ws.chats.first() {
        let at = Instant::now();
        let cs = c.open_stream(
            "chat",
            json!({"workspaceId": ws_id, "threadId": String::from(chat.thread_id), "after": null}),
        )?;
        match c.wait("chat frame", Duration::from_secs(10), |c| {
            c.stream_msgs(cs).next().is_some()
        }) {
            Ok(()) => println!("T chat.first-frame.duration {}", at.elapsed().as_millis()),
            Err(e) => println!("WARN chat stream: {e}"),
        }
    } else {
        println!(
            "I chat not available: no thread in the directory (providers answer: {})",
            providers.to_string().chars().take(200).collect::<String>()
        );
    }

    // files
    let root = String::from(
        EntryId::from_bytes(
            WorkspaceId::try_from(ws_id.clone())
                .map_err(|e| e.to_string())?
                .to_bytes(),
        )
        .map_err(str::to_owned)?,
    );
    let (list, d) = c.request(
        0,
        None,
        json!({"method": "files.list", "params": {
        "context": context, "parentEntryId": root, "cursor": null, "limit": 50}}),
    )?;
    if list["type"] != "result" {
        return Err(format!("files.list: {list}"));
    }
    println!("T files.list.duration {}", d.as_millis());
    let entry = |name: &str| {
        list["result"]["params"]["entries"]
            .as_array()
            .and_then(|a| a.iter().find(|e| e["displayName"] == name))
            .cloned()
    };
    for (name, transfer) in [("probe-small.txt", false), ("probe-big.txt", true)] {
        let e = entry(name).ok_or_else(|| format!("{name} not listed"))?;
        let (r, d) = c.request(
            0,
            None,
            json!({"method": "files.read", "params": {
            "context": context, "entryId": e["entryId"], "fileRevision": null,
            "offset": "0", "maxBytes": 1_048_576}}),
        )?;
        let len = if r["type"] == "transfer" {
            let at = Instant::now();
            let p = c.transfer(&r)?;
            println!(
                "T files.read.transfer.duration {} (+{} ms stream)",
                d.as_millis(),
                at.elapsed().as_millis()
            );
            p.len()
        } else if r["type"] == "result" {
            println!("T files.read.inline.duration {}", d.as_millis());
            r["result"]["params"]["bytes"]
                .as_array()
                .map_or(0, Vec::len)
        } else {
            return Err(format!("files.read {name}: {r}"));
        };
        let size = r["result"]["params"]["metadata"]["size"]
            .as_str()
            .unwrap_or("?")
            .to_owned();
        println!(
            "I files.read {name} type={} bytes={len} size={size}",
            r["type"]
        );
        if transfer != (r["type"] == "transfer") || size != len.to_string() {
            return Err(format!("files.read {name}: unexpected answer shape"));
        }
    }

    // git
    let (repos, _) = c.request(
        0,
        None,
        json!({"method": "git.repositories", "params": {"context": context}}),
    )?;
    let repo = repos["result"]["params"]["repositories"][0]["repositoryId"].clone();
    if !repo.is_string() {
        return Err(format!("git.repositories: {repos}"));
    }
    let (status, d) = c.request(0, None, json!({"method": "git.status", "params": {
        "context": context, "repositoryId": repo, "stateToken": null, "cursor": null, "limit": 50}}))?;
    if status["type"] != "result" {
        return Err(format!("git.status after {} ms: {status}", d.as_millis()));
    }
    println!(
        "T git.status.duration {} (entries={})",
        d.as_millis(),
        status["result"]["params"]["entries"]
            .as_array()
            .map_or(0, Vec::len)
    );
    let (diff, d) = c.request(0, None, json!({"method": "git.diff", "params": {
        "context": context, "repositoryId": repo, "stateToken": status["result"]["params"]["stateToken"],
        "entryId": null, "view": "worktree", "cursor": null, "limit": 50}}))?;
    let files = if diff["type"] == "transfer" {
        serde_json::from_slice::<Value>(&c.transfer(&diff)?).map_err(|e| e.to_string())?
    } else if diff["type"] == "result" {
        diff["result"]["params"]["files"].clone()
    } else {
        return Err(format!("git.diff: {diff}"));
    };
    println!(
        "T git.diff.duration {} (type={} files={})",
        d.as_millis(),
        diff["type"],
        files.as_array().map_or(0, Vec::len)
    );

    c.op(c.tunnel, "tunnel.close", json!({}), &[])?;
    let _ = c.wait("close", Duration::from_secs(3), |c| {
        c.state_closed().is_some()
    });
    c.t("done");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foo"), "Zm9v");
        assert_eq!(b64url(b"foob"), "Zm9vYg");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        assert_eq!(b64url(&[0; 32]).len(), 43, "a PKCE value is 43 characters");
    }

    #[test]
    fn records_parse_and_reject_overruns() {
        let mut b = vec![1, 0, 0, 0, 0];
        b.extend([5, 0, 0, 0, 6, 0, 0, 0, 2, b'h', b'i']);
        b.extend([4, 0, 0, 0, 2, b'{', b'}']);
        let r = records(&b).unwrap();
        assert!(matches!(r[0], Rec::Connect));
        assert!(matches!(&r[1], Rec::Msg(2, d) if d == b"hi"));
        assert!(matches!(&r[2], Rec::Ev(v) if v.is_object()));
        assert!(records(&[2, 0, 0, 0, 9, 1]).is_err());
        assert!(records(&[9, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn uuid_and_key_helpers() {
        let b = uuid_bytes("002e0502-0f7a-423d-8630-61e7500d9ef1").unwrap();
        assert_eq!(hex(&b), "002e05020f7a423d863061e7500d9ef1");
        assert!(uuid_bytes("xyz").is_err());
        let v = json!({"a": [{"b": 1}, {"terminal": {"x": 2}}]});
        assert_eq!(find_key(&v, "terminal").unwrap()["x"], 2);
        assert!(find_key(&v, "none").is_none());
    }
}
