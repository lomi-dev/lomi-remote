//! Remote 1.0 Host uplink (plan-1.0 P2.1/P2.14/P2.15): one WebSocket to the relay
//! `/relay` path that replaces the periodic HTTP heartbeat and the two pending
//! polls, and carries `publication.put` and `token.update`.
//!
//! The uplink is subordinate to the actor. It holds no credential of its own and
//! decides nothing: the actor keeps calling the same `DataTransport` methods with
//! its own token and runtime binding, and these calls either go to HTTP (uplink
//! off, down, stale or not matching the binding) or are answered from the link.
//! A call is the only thing that keeps the link alive (`OFFER_TTL`), so a paused,
//! gated or logged-out actor drops the link by itself. See docs/uplink.md.
//!
//! Off unless `LOMI_REMOTE_UPLINK=<64 lowercase hex relay contract hash>`.
use crate::{BudgetStop, DataFailure, Error, RelayConnection, RelayTransport, Result, budget};
use lomi_remote_core::{
    frame::{
        Direction, Frame, MAX_FRAME_BYTES, ReadyErrorCode, Role, RuntimeClaim, decode_frame,
        encode_frame,
    },
    json::Object,
};
use lomi_remote_protocol::{
    DecimalU64, HostAccessCredential, HostId, RuntimeId, http::*, ipc::LocalRelayEndpoint,
};
use serde_json::Value;
use std::{
    collections::VecDeque,
    sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, PoisonError},
    task::Poll,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub mod tunnels;

// Development switch: debug builds only until a proper configuration field exists.
#[cfg(debug_assertions)]
const ENV: &str = "LOMI_REMOTE_UPLINK";
/// The link lives only while the actor keeps calling heartbeat.
const OFFER_TTL: Duration = Duration::from_secs(10);
/// Newest `authority.fresh` that still counts as fresh: 3 s plus the 5 s a heartbeat
/// grants stays inside the 8 s the plan allows between relay confirmation and use.
const FRESH_MAX_AGE: Duration = Duration::from_secs(3);
/// Tunnels need a relay-confirmed authority this recent (`authority.fresh` comes every 2 s); past
/// it every tunnel closes and no new one opens until the next one arrives.
const TUNNEL_FRESH_MAX: Duration = Duration::from_secs(8);
const FRESHNESS_MS: u64 = 5_000;
/// A synthesized heartbeat needs at least this much confirmed server lease left (the heartbeat
/// DTO requires `freshness_ms <= lease_ms`); below it the heartbeat goes to HTTP.
const MIN_LEASE_MS: u64 = FRESHNESS_MS;
/// No `authority.fresh` for this long: the link is half-open, close and reconnect.
const HALF_OPEN: Duration = Duration::from_secs(15);
/// A cached runtime read is only granted this long after the actor's rotation point.
const CACHED_READ_TTL: Duration = Duration::from_secs(2);
/// How long after the last peer-scope HTTP call or wake hint heartbeats stay on HTTP.
const PEER_ACTIVE: Duration = Duration::from_secs(30);
/// A peer read needs an HTTP heartbeat this recent (the server's freshness is 5 s).
const HTTP_FRESH: Duration = Duration::from_secs(3);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READY_TIMEOUT: Duration = Duration::from_secs(5);
const CALL_TIMEOUT: Duration = Duration::from_secs(12);
const IO: Duration = Duration::from_secs(5);
/// Chunk bodies stay under the 64 KiB frame limit with room for the envelope.
const CHUNK_BYTES: usize = 60_000;
const MAX_CHUNKS: usize = 32;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a runtime claim names; compared as a whole, never partially.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Binding {
    host: String,
    runtime_id: String,
    generation: u64,
    epoch: u64,
}
impl Binding {
    fn runtime(&self) -> Option<RuntimeBinding> {
        Some(RuntimeBinding {
            runtime_id: RuntimeId::try_from(self.runtime_id.clone()).ok()?,
            runtime_generation: DecimalU64(self.generation),
            host_access_epoch: DecimalU64(self.epoch),
        })
    }
    fn new(host: HostId, runtime: &RuntimeBinding) -> Self {
        Self {
            host: host.into(),
            runtime_id: runtime.runtime_id.into(),
            generation: runtime.runtime_generation.0,
            epoch: runtime.host_access_epoch.0,
        }
    }
}

struct Desired {
    binding: Binding,
    token: Zeroizing<String>,
    offered_at: Instant,
}
struct Live {
    binding: Binding,
    last_fresh: Instant,
    /// Server lease as the relay last confirmed it (READY `leaseMs`, then `leaseRemainingMs` of
    /// `authority.fresh`, or a real HTTP heartbeat). Never extended locally.
    lease_until: Instant,
    /// The relay holds the token the actor currently has (no token.update pending).
    token_current: bool,
    /// Publication sequence the server holds, as far as this link knows: from READY,
    /// advanced by our own acknowledged publications, `None` after an uncertain write
    /// until a real runtime read tells it again.
    publication_seq: Option<u64>,
}
impl Live {
    /// Confirmed lease left, if enough for a synthesized heartbeat.
    fn lease_ms(&self, now: Instant) -> Option<u64> {
        let ms = u64::try_from(self.lease_until.saturating_duration_since(now).as_millis()).ok()?;
        (ms >= MIN_LEASE_MS).then_some(ms.min(30_000))
    }
    fn usable(&self, binding: &Binding, now: Instant) -> bool {
        &self.binding == binding && now.saturating_duration_since(self.last_fresh) <= FRESH_MAX_AGE
    }
}
#[derive(Default)]
struct State {
    endpoint: Option<LocalRelayEndpoint>,
    desired: Option<Desired>,
    live: Option<Live>,
    jobs: VecDeque<Arc<Job>>,
    /// Wake hints: [channels, pairings]. A set flag means the next pending read must hit HTTP.
    fetch: [bool; 2],
    /// Peer (pairing/channel) traffic is on HTTP until here. Those routes still require the
    /// server's 5 s freshness, which only HTTP heartbeats keep continuous (the relay's batched
    /// write leaves gaps), so heartbeats stay on HTTP while peers are active (until P3).
    peer_until: Option<Instant>,
    http_heartbeat_at: Option<Instant>,
    /// The actor's worker-unit rotation read may be served from the link until here.
    cached_read_until: Option<Instant>,
    /// Bumped by `link_reset` (system sleep): a running link older than this is closed.
    reset_gen: u64,
    thread: bool,
}
impl State {
    fn peer_active(&self, now: Instant) -> bool {
        self.peer_until.is_some_and(|until| now < until)
    }
}
struct Shared {
    contract_hash: String,
    state: Mutex<State>,
    changed: Condvar,
    wake: Wake,
    /// Device tunnels (P3a.7); only the uplink thread works on it while a link is up.
    tunnels: Mutex<Option<tunnels::Engine>>,
    /// Consent follows the account's device list (P3a.10). Lock order: never held with `tunnels`.
    roster: Mutex<Option<Box<dyn tunnels::Roster>>>,
    /// The READY of the current link, replayed into a roster installed after it.
    last_ready: Mutex<Option<tunnels::DeviceEvent>>,
}

#[cfg_attr(not(debug_assertions), allow(dead_code))] // release builds never create it
impl Shared {
    fn new(contract_hash: String) -> Self {
        Self {
            contract_hash,
            state: Mutex::default(),
            changed: Condvar::new(),
            wake: Wake::new(),
            tunnels: Mutex::new(None),
            roster: Mutex::new(None),
            last_ready: Mutex::new(None),
        }
    }
}

/// Monotonic ms for the tunnel engine.
fn now_ms() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64
}

/// Hands the uplink the Host's tunnel engine (identity, policy, service); `None` while the uplink
/// is off. Tunnels exist only while a link is up and all close when it drops.
pub fn install_tunnels(
    config: tunnels::Config,
    policy: Box<dyn tunnels::Policy>,
    service: Box<dyn tunnels::TunnelService>,
) -> Option<tunnels::Handle> {
    let sh = shared()?;
    let handle = tunnels::Handle::new(move || sh.wake.wake());
    let engine = tunnels::Engine::new(config, policy, service, handle.clone()).ok()?;
    *lock(&sh.tunnels) = Some(engine);
    Some(handle)
}
/// Hands the uplink what keeps consent in step with device-list events; without it tunnels do not
/// follow revocations, so install it together with the engine.
pub fn install_roster(roster: Box<dyn tunnels::Roster>) {
    if let Some(sh) = shared() {
        *lock(&sh.roster) = Some(roster);
        // A link that came up before this call has already said READY.
        let ready = lock(&sh.last_ready).clone();
        if let Some(ready) = ready {
            apply_device(sh, &ready);
        }
    }
}
fn wall_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}
/// A late `authority.fresh` (a 3 s network delay) is no reason to drop tunnels; 8 s is.
fn tunnels_fresh(silent: Duration) -> bool {
    silent <= TUNNEL_FRESH_MAX
}
/// Roster first (grants, list), then the engine closes what it names.
fn apply_device(sh: &Shared, event: &tunnels::DeviceEvent) {
    match event {
        tunnels::DeviceEvent::Ready { .. } => *lock(&sh.last_ready) = Some(event.clone()),
        tunnels::DeviceEvent::HostRevoked => *lock(&sh.last_ready) = None,
        _ => {}
    }
    let closing = lock(&sh.roster).as_mut().and_then(|r| r.apply(event));
    if let Some(engine) = lock(&sh.tunnels).as_mut() {
        if let tunnels::DeviceEvent::Changed(entry) = event {
            engine.refresh_device(entry);
        }
        if let Some(closing) = closing {
            engine.close_where("deviceRevoked", closing);
        }
    }
}
/// The relay contract hash this uplink runs with (the engine's prologue needs the same bytes).
pub fn contract_hash() -> Option<[u8; 32]> {
    lomi_remote_core::tunnel::unhex(&shared()?.contract_hash)
}

static SHARED: OnceLock<Option<Shared>> = OnceLock::new();
fn shared() -> Option<&'static Shared> {
    SHARED
        .get_or_init(|| {
            #[cfg(not(debug_assertions))]
            return None;
            #[cfg(debug_assertions)]
            let hash = std::env::var(ENV).ok()?;
            #[cfg(debug_assertions)]
            {
                let ok = hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
                ok.then(|| Shared::new(hash))
            }
        })
        .as_ref()
}

pub fn enabled() -> bool {
    shared().is_some()
}
/// The actor tells the uplink which relay its configuration pins. Without it the
/// uplink never starts.
pub fn set_endpoint(endpoint: &LocalRelayEndpoint) {
    let Some(sh) = shared() else { return };
    let mut st = lock(&sh.state);
    if st.endpoint.as_ref() != Some(endpoint) {
        st.endpoint = Some(endpoint.clone());
        sh.changed.notify_all();
        sh.wake.wake();
    }
}
/// Actor-side token hand-off (P2.15): called right after a rotation is durably
/// accepted. The uplink sends `token.update` on the live link without closing it.
/// The binding is kept; the next heartbeat call refreshes it anyway.
pub fn offer_token(host: HostId, token: &HostAccessCredential) {
    if let Some(sh) = shared() {
        offer_token_on(sh, host, token);
    }
}
fn offer_token_on(sh: &Shared, host: HostId, token: &HostAccessCredential) {
    let mut st = lock(&sh.state);
    if let Some(d) = st.desired.as_mut()
        && d.binding.host == String::from(host)
        && d.token.as_str() != token.expose_wire()
    {
        d.token = Zeroizing::new(token.expose_wire().to_owned());
        d.offered_at = Instant::now();
        if let Some(live) = st.live.as_mut() {
            live.token_current = false;
        }
        sh.wake.wake();
    }
}
fn offer(
    sh: &'static Shared,
    host: HostId,
    runtime: &RuntimeBinding,
    token: &HostAccessCredential,
) {
    let binding = Binding::new(host, runtime);
    let mut st = lock(&sh.state);
    let changed = match st.desired.as_mut() {
        Some(d) if d.binding == binding && d.token.as_str() == token.expose_wire() => {
            d.offered_at = Instant::now();
            false
        }
        previous => {
            let token_changed = previous.is_some_and(|d| d.binding == binding);
            st.desired = Some(Desired {
                binding,
                token: Zeroizing::new(token.expose_wire().to_owned()),
                offered_at: Instant::now(),
            });
            if let (true, Some(live)) = (token_changed, st.live.as_mut()) {
                live.token_current = false; // the thread sends token.update and clears this on the ack
            }
            true
        }
    };
    let was_live = st.live.is_some();
    let spawn = st.endpoint.is_some() && !st.thread;
    if spawn {
        st.thread = true;
    }
    drop(st);
    if spawn
        && std::thread::Builder::new()
            .name("lomi-uplink".into())
            .spawn(move || run(sh))
            .is_err()
    {
        lock(&sh.state).thread = false;
    }
    if changed || !was_live {
        sh.changed.notify_all();
    }
    if changed {
        sh.wake.wake();
    }
}

/// Heartbeat answered from the link, or `None` to use HTTP. Also the offer that keeps the link alive.
pub(crate) fn heartbeat(
    host: HostId,
    runtime: &RuntimeBinding,
    access: &HostAccessCredential,
) -> Option<HeartbeatResult> {
    heartbeat_on(shared()?, host, runtime, access)
}
fn heartbeat_on(
    sh: &'static Shared,
    host: HostId,
    runtime: &RuntimeBinding,
    access: &HostAccessCredential,
) -> Option<HeartbeatResult> {
    offer(sh, host, runtime, access);
    let binding = Binding::new(host, runtime);
    let st = lock(&sh.state);
    let live = st.live.as_ref()?;
    let now = Instant::now();
    if !live.usable(&binding, now) || st.peer_active(now) {
        return None;
    }
    Some(HeartbeatResult {
        runtime: runtime.clone(),
        lease_ms: DecimalU64(live.lease_ms(now)?),
        freshness_ms: DecimalU64(FRESHNESS_MS),
    })
}

/// The actor's worker-unit rotation (every ~15 s, even idle) is about to re-read the runtime:
/// that one read may be answered from the link. Every other runtime read stays HTTP.
pub fn allow_cached_runtime_read() {
    if let Some(sh) = shared() {
        lock(&sh.state).cached_read_until = Some(Instant::now() + CACHED_READ_TTL);
    }
}
/// A reconciliation (fresh read demanded, unknown outcome) needs the server's answer.
pub fn forbid_cached_runtime_read() {
    if let Some(sh) = shared() {
        lock(&sh.state).cached_read_until = None;
    }
}
/// The system slept (`Instant` does not count it): drop the link and its freshness at once, so
/// the first heartbeat after wake goes to HTTP and the thread reconnects.
pub fn link_reset() {
    if let Some(sh) = shared() {
        let mut st = lock(&sh.state);
        st.reset_gen += 1;
        st.live = None;
        st.cached_read_until = None;
        drop(st);
        sh.wake.wake();
    }
}
/// One-shot: consumed by the read that asks, whatever the answer.
pub(crate) fn runtime_get_cached(host: HostId) -> Option<HostRuntimeGetResult> {
    let sh = shared()?;
    let granted = lock(&sh.state)
        .cached_read_until
        .take()
        .is_some_and(|until| Instant::now() < until);
    if granted {
        runtime_get_on(sh, host)
    } else {
        None
    }
}
fn runtime_get_on(sh: &Shared, host: HostId) -> Option<HostRuntimeGetResult> {
    let st = lock(&sh.state);
    let (live, desired) = (st.live.as_ref()?, st.desired.as_ref()?);
    let host_text = String::from(host);
    if live.binding != desired.binding
        || st.peer_active(Instant::now())
        || live.binding.host != host_text
        || !live.usable(&desired.binding, Instant::now())
    {
        return None;
    }
    Some(HostRuntimeGetResult {
        host_id: host,
        host_access_epoch: DecimalU64(live.binding.epoch),
        runtime_generation: DecimalU64(live.binding.generation),
        runtime: Some(live.binding.runtime()?),
        publication_seq: DecimalU64(live.publication_seq?),
        lease_ms: DecimalU64(live.lease_ms(Instant::now())?),
        freshness_ms: DecimalU64(FRESHNESS_MS),
    })
}
/// A real runtime read: the server's sequence for the runtime this link holds.
pub(crate) fn note_runtime_get(result: &HostRuntimeGetResult) {
    let Some(sh) = shared() else { return };
    let mut st = lock(&sh.state);
    if let Some(live) = st.live.as_mut()
        && result
            .runtime
            .as_ref()
            .is_some_and(|r| Binding::new(result.host_id, r) == live.binding)
    {
        live.publication_seq = Some(result.publication_seq.0);
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Pending {
    Channels = 0,
    Pairings = 1,
}
#[derive(PartialEq, Eq)]
pub(crate) enum Gate {
    /// Uplink off or not usable: plain HTTP, as before.
    Http,
    /// Uplink usable and no wake hint: answer "nothing pending" without a request.
    Skip,
    /// A wake hint (or an unfinished read): do the HTTP read and report back.
    Fetch,
}
pub(crate) fn pending_gate(kind: Pending) -> Gate {
    shared().map_or(Gate::Http, |sh| pending_gate_on(sh, kind))
}
fn pending_gate_on(sh: &Shared, kind: Pending) -> Gate {
    let mut st = lock(&sh.state);
    let usable = match (st.live.as_ref(), st.desired.as_ref()) {
        (Some(live), Some(d)) => live.usable(&d.binding, Instant::now()),
        _ => false,
    };
    if !usable {
        return Gate::Http;
    }
    if !st.fetch[kind as usize] {
        return Gate::Skip;
    }
    // A hint: peer routes need server freshness, so heartbeats go to HTTP from now on and the
    // read waits (its hint is kept) until one has just succeeded.
    let now = Instant::now();
    st.peer_until = Some(now + PEER_ACTIVE);
    if st
        .http_heartbeat_at
        .is_some_and(|at| now.saturating_duration_since(at) <= HTTP_FRESH)
    {
        st.fetch[kind as usize] = false;
        Gate::Fetch
    } else {
        Gate::Skip
    }
}
/// Any peer-scope HTTP call (pairing, channel, ticket, admission): keep heartbeats on HTTP.
pub(crate) fn note_peer_http() {
    if let Some(sh) = shared() {
        lock(&sh.state).peer_until = Some(Instant::now() + PEER_ACTIVE);
    }
}
/// A heartbeat that really went to the server.
pub(crate) fn note_http_heartbeat(started: Instant, lease_ms: u64) {
    if let Some(sh) = shared() {
        let mut st = lock(&sh.state);
        st.http_heartbeat_at = Some(Instant::now());
        if let Some(live) = st.live.as_mut() {
            live.lease_until = live
                .lease_until
                .max(started + Duration::from_millis(lease_ms));
        }
    }
}
/// A publication went over HTTP while a link exists: the server's sequence moved (or may have).
pub(crate) fn note_http_publication() {
    if let Some(sh) = shared()
        && let Some(live) = lock(&sh.state).live.as_mut()
    {
        live.publication_seq = None;
    }
}
/// After a `Gate::Fetch` read: keep reading until the server says empty, so a
/// proposal already fetched but not yet handled is never forgotten.
pub(crate) fn pending_done(kind: Pending, empty_ok: bool) {
    if let (Some(sh), false) = (shared(), empty_ok) {
        lock(&sh.state).fetch[kind as usize] = true;
    }
}

/// `publication.put` over the link, or `None` to use HTTP. Same single-attempt rule as
/// HTTP: no replay, and an uncertain outcome is `OutcomeUnknown` so the actor reconciles.
pub(crate) fn publication(
    host: HostId,
    params: &PublicationParams,
    access: &HostAccessCredential,
    budget_state: Option<&budget::State>,
) -> Option<Result<PublicationResult>> {
    publication_on(shared()?, host, params, access, budget_state)
}
fn publication_on(
    sh: &Shared,
    host: HostId,
    params: &PublicationParams,
    access: &HostAccessCredential,
    budget_state: Option<&budget::State>,
) -> Option<Result<PublicationResult>> {
    let outcome = publication_job(sh, host, params, access, budget_state)?;
    if outcome.is_err()
        && let Some(live) = lock(&sh.state).live.as_mut()
    {
        // Any non-Ok result may or may not have moved the server's sequence.
        live.publication_seq = None;
    }
    Some(outcome)
}
fn publication_job(
    sh: &Shared,
    host: HostId,
    params: &PublicationParams,
    access: &HostAccessCredential,
    budget_state: Option<&budget::State>,
) -> Option<Result<PublicationResult>> {
    let binding = Binding::new(host, &params.runtime);
    let chunks = publication_chunks(params)?;
    let job = Arc::new(Job {
        binding: binding.clone(),
        next: params.publication_seq.0,
        chunks,
        out: Mutex::new(JobOut::Pending {
            final_sent: false,
            abandoned: false,
        }),
        cv: Condvar::new(),
    });
    {
        let mut st = lock(&sh.state);
        let live = st.live.as_ref()?;
        // A pending token.update means the relay would still check the old token hash; a call
        // with another token than the one the link holds is not the actor's current one.
        let same_token = st
            .desired
            .as_ref()
            .is_some_and(|d| d.token.as_str() == access.expose_wire());
        if !live.usable(&binding, Instant::now()) || !live.token_current || !same_token {
            return None;
        }
        st.jobs.push_back(job.clone());
    }
    sh.wake.wake();
    let limit = match budget::remaining(budget_state) {
        Ok(limit) => limit,
        Err(error) => return Some(Err(job.abandon(error))),
    };
    let start = Instant::now();
    let mut out = lock(&job.out);
    loop {
        if let JobOut::Done(result) = &*out {
            return Some(result.map(|seq| PublicationResult {
                runtime: params.runtime.clone(),
                publication_seq: DecimalU64(seq),
            }));
        }
        let stop = match budget_state.map(budget::State::check) {
            Some(Err(error)) => Some(error),
            _ if start.elapsed() >= limit => Some(Error::Timeout),
            _ => None,
        };
        if let Some(error) = stop {
            drop(out);
            return Some(Err(job.abandon(error)));
        }
        out = job
            .cv
            .wait_timeout(out, Duration::from_millis(20))
            .unwrap_or_else(PoisonError::into_inner)
            .0;
    }
}

enum JobOut {
    Pending { final_sent: bool, abandoned: bool },
    Done(Result<u64>),
}
struct Job {
    binding: Binding,
    next: u64,
    chunks: Vec<Object>,
    out: Mutex<JobOut>,
    cv: Condvar,
}
impl Job {
    fn finish(&self, result: Result<u64>) {
        let mut out = lock(&self.out);
        if matches!(&*out, JobOut::Pending { .. }) {
            *out = JobOut::Done(result);
        }
        self.cv.notify_all();
    }
    /// The caller gives up: if the final chunk may have reached the relay the outcome is unknown.
    fn abandon(&self, error: Error) -> Error {
        let mut out = lock(&self.out);
        match &mut *out {
            JobOut::Pending {
                final_sent,
                abandoned,
            } => {
                *abandoned = true;
                if *final_sent {
                    Error::DataRemote(DataFailure::OutcomeUnknown)
                } else {
                    error
                }
            }
            JobOut::Done(result) => result.err().unwrap_or(error),
        }
    }
    fn is_abandoned(&self) -> bool {
        matches!(
            &*lock(&self.out),
            JobOut::Pending {
                abandoned: true,
                ..
            }
        )
    }
    /// Atomic with `abandon`: false (and nothing marked) if the caller already gave up.
    fn mark_final_sent(&self) -> bool {
        match &mut *lock(&self.out) {
            JobOut::Pending {
                final_sent,
                abandoned: false,
            } => {
                *final_sent = true;
                true
            }
            _ => false,
        }
    }
    fn final_sent(&self) -> bool {
        matches!(
            &*lock(&self.out),
            JobOut::Pending {
                final_sent: true,
                ..
            }
        )
    }
}

/// Splits a publication into relay chunks of about `CHUNK_BYTES` of JSON. A workspace
/// that does not fit continues as a repeated entry at the start of the next chunk, the
/// one repetition the relay accepts. `None` when it cannot be sent this way.
fn publication_chunks(params: &PublicationParams) -> Option<Vec<Object>> {
    let size = |v: &Value| serde_json::to_string(v).map(|s| s.len()).ok();
    let mut chunks: Vec<Vec<Value>> = vec![Vec::new()];
    let mut used = 0usize;
    for workspace in params.workspaces.as_slice() {
        let Value::Object(mut head) = serde_json::to_value(workspace).ok()? else {
            return None;
        };
        let Some(Value::Array(terminals)) = head.remove("terminals") else {
            return None;
        };
        let with = |terminals: Vec<Value>| {
            let mut entry = head.clone();
            entry.insert("terminals".into(), Value::Array(terminals));
            Value::Object(entry)
        };
        let base = size(&with(Vec::new()))? + 1;
        let mut entry: Vec<Value> = Vec::new();
        let mut entry_size = base;
        for terminal in terminals {
            let add = size(&terminal)? + 1;
            if used + entry_size + add > CHUNK_BYTES && (used > 0 || !entry.is_empty()) {
                if !entry.is_empty() {
                    chunks.last_mut()?.push(with(std::mem::take(&mut entry)));
                }
                chunks.push(Vec::new());
                used = 0;
                entry_size = base;
            }
            entry.push(terminal);
            entry_size += add;
        }
        chunks.last_mut()?.push(with(entry));
        used += entry_size;
    }
    if chunks.len() > MAX_CHUNKS {
        return None;
    }
    let count = chunks.len();
    chunks
        .into_iter()
        .enumerate()
        .map(|(index, workspaces)| {
            let mut args = Object::new();
            args.insert(
                "expectedPublicationSeq".into(),
                params.expected_publication_seq.0.to_string().into(),
            );
            args.insert(
                "publicationSeq".into(),
                params.publication_seq.0.to_string().into(),
            );
            let mut chunk = Object::new();
            chunk.insert("index".into(), index.into());
            chunk.insert("count".into(), count.into());
            args.insert("chunk".into(), Value::Object(chunk));
            args.insert("workspaces".into(), Value::Array(workspaces));
            Some(args)
        })
        .collect()
}

/// A reply code to the error the HTTP route would have produced.
fn reply_error(code: &str, final_chunk: bool) -> Error {
    Error::DataRemote(match code {
        "STALE_EPOCH" => DataFailure::StaleEpoch,
        "AUTH_FAILED" => DataFailure::AuthRequired,
        "INVALID_ARGUMENT" => DataFailure::InvalidArgument,
        // The relay may have committed the final write before answering: reconcile.
        "UNAVAILABLE" | "TIMEOUT" if final_chunk => DataFailure::OutcomeUnknown,
        _ => DataFailure::ServiceUnavailable,
    })
}

#[derive(Debug, PartialEq, Eq)]
enum Refusal {
    Busy,
    StaleEpoch,
    AuthFailed,
    Unavailable,
    UpdateRequired,
    Invalid,
}
struct Ready {
    lease_ms: u64,
    publication_seq: u64,
    /// `None`: the server sent no list (flag off) or one we cannot read; never "no devices".
    devices: Option<Vec<tunnels::DeviceEntry>>,
}
fn auth_frame(contract_hash: &str, token: &str, binding: &Binding) -> Option<Zeroizing<Vec<u8>>> {
    let frame = Frame::Auth {
        role: Role::Host,
        token: token.to_owned(),
        contract_hash: contract_hash.to_owned(),
        claim: Some(RuntimeClaim {
            host_id: binding.host.clone(),
            runtime_id: binding.runtime_id.clone(),
            // The actor already claimed over HTTP: the claim is idempotent for the same
            // runtime id and the generation it was made from.
            expected_generation: binding.generation.checked_sub(1)?.to_string(),
        }),
    };
    encode_frame(&frame, MAX_FRAME_BYTES)
        .ok()
        .map(Zeroizing::new)
}
fn parse_ready(bytes: &[u8], binding: &Binding) -> std::result::Result<Ready, Refusal> {
    match decode_frame(bytes, Direction::Relay, MAX_FRAME_BYTES).map_err(|_| Refusal::Invalid)? {
        Frame::ReadyOk {
            role: Role::Host,
            state,
            ..
        } => {
            let text = |o: &Object, k: &str| o.get(k).and_then(Value::as_str).map(str::to_owned);
            let runtime = state
                .get("runtime")
                .and_then(Value::as_object)
                .ok_or(Refusal::Invalid)?;
            let same = text(&state, "hostId").as_deref() == Some(binding.host.as_str())
                && text(runtime, "runtimeId").as_deref() == Some(binding.runtime_id.as_str())
                && text(runtime, "runtimeGeneration") == Some(binding.generation.to_string())
                && text(runtime, "hostAccessEpoch") == Some(binding.epoch.to_string());
            let seq = text(&state, "publicationSeq").and_then(|s| s.parse().ok());
            // `leaseMs` is the remaining lease as a decimal string.
            let lease = text(&state, "leaseMs").and_then(|s| s.parse::<u64>().ok());
            match (same, lease, seq) {
                (true, Some(lease_ms), Some(publication_seq)) if lease_ms > 0 => Ok(Ready {
                    lease_ms,
                    publication_seq,
                    devices: state
                        .get("devices")
                        .and_then(Value::as_array)
                        .and_then(|a| {
                            a.iter()
                                .map(|v| tunnels::DeviceEntry::parse(v.as_object()?))
                                .collect()
                        }),
                }),
                _ => Err(Refusal::Invalid),
            }
        }
        Frame::ReadyErr { code, .. } => Err(match code {
            ReadyErrorCode::AuthFailed => Refusal::AuthFailed,
            ReadyErrorCode::HostBusy => Refusal::Busy,
            ReadyErrorCode::StaleEpoch => Refusal::StaleEpoch,
            ReadyErrorCode::UpdateRequired => Refusal::UpdateRequired,
            ReadyErrorCode::Unavailable | ReadyErrorCode::Busy => Refusal::Unavailable,
        }),
        _ => Err(Refusal::Invalid),
    }
}

enum Inflight {
    Token {
        call_id: u32,
        token: Zeroizing<String>,
        sent: Instant,
    },
    Chunk {
        call_id: u32,
        sent: Instant,
    },
}
impl Inflight {
    fn call_id(&self) -> u32 {
        match self {
            Self::Token { call_id, .. } | Self::Chunk { call_id, .. } => *call_id,
        }
    }
    fn sent(&self) -> Instant {
        match self {
            Self::Token { sent, .. } | Self::Chunk { sent, .. } => *sent,
        }
    }
}
/// Protocol state of one admitted link. Pure: frames in, frames out; the thread does the I/O.
struct Session {
    call_id: u32,
    sent_token: Zeroizing<String>,
    inflight: Option<Inflight>,
    job: Option<(Arc<Job>, usize)>,
    /// `circuit.close` calls whose reply is ignored (the circuit may already be gone).
    close_calls: VecDeque<u32>,
}
enum Effect {
    /// `authority.fresh`, with the relay-confirmed server lease left (ms) if it carried one.
    Fresh(Option<u64>),
    Wake(Pending),
    Device(tunnels::DeviceEvent),
    TokenAcked,
    /// The server's publication sequence after our publication: known, or lost track of.
    Published(Option<u64>),
    /// Close the link and reconnect (revoked, refused token update, protocol violation).
    Close,
}
impl Session {
    fn new(token: Zeroizing<String>) -> Self {
        Self {
            call_id: 0,
            sent_token: token,
            inflight: None,
            job: None,
            close_calls: VecDeque::new(),
        }
    }
    fn circuit_close(&mut self, circuit: &tunnels::CircuitId) -> Option<Vec<u8>> {
        let mut args = Object::new();
        args.insert(
            "circuitId".into(),
            lomi_remote_core::tunnel::hex(circuit).into(),
        );
        let (call_id, bytes) = self.call("circuit.close", args)?;
        if self.close_calls.len() == 256 {
            self.close_calls.pop_front();
        }
        self.close_calls.push_back(call_id);
        Some(bytes)
    }
    fn call(&mut self, name: &str, args: Object) -> Option<(u32, Vec<u8>)> {
        self.call_id = self.call_id.checked_add(1)?;
        let frame = Frame::Call {
            call_id: self.call_id,
            name: name.to_owned(),
            args,
        };
        Some((self.call_id, encode_frame(&frame, MAX_FRAME_BYTES).ok()?))
    }
    /// The next frame to send, if nothing is in flight: the new token first (the relay
    /// tolerates the old hash for 20 s only), then publication chunks in order.
    fn next_send(
        &mut self,
        token: &str,
        binding: &Binding,
        queue: &mut VecDeque<Arc<Job>>,
    ) -> Option<Vec<u8>> {
        if self.inflight.is_some() {
            return None;
        }
        if token != self.sent_token.as_str() {
            let mut args = Object::new();
            args.insert("token".into(), token.into());
            let (call_id, bytes) = self.call("token.update", args)?;
            self.inflight = Some(Inflight::Token {
                call_id,
                token: Zeroizing::new(token.to_owned()),
                sent: Instant::now(),
            });
            return Some(bytes);
        }
        while self.job.is_none() {
            let job = queue.pop_front()?;
            if job.is_abandoned() {
                continue;
            }
            if &job.binding != binding {
                job.finish(Err(Error::DataRemote(DataFailure::ServiceUnavailable)));
                continue;
            }
            self.job = Some((job, 0));
        }
        let (job, index) = self.job.as_mut()?;
        if job.is_abandoned() {
            self.job = None;
            return self.next_send(token, binding, queue);
        }
        let args = job.chunks.get(*index)?.clone();
        let last = *index + 1 == job.chunks.len();
        let job = job.clone();
        if last && !job.mark_final_sent() {
            self.job = None; // abandoned between the check above and now: nothing goes out
            return self.next_send(token, binding, queue);
        }
        let (call_id, bytes) = self.call("publication.put", args)?;
        self.inflight = Some(Inflight::Chunk {
            call_id,
            sent: Instant::now(),
        });
        Some(bytes)
    }
    fn on_frame(&mut self, frame: Frame) -> Vec<Effect> {
        match frame {
            Frame::Event { name, data } => match name.as_str() {
                "authority.fresh" => vec![Effect::Fresh(
                    data.get("leaseRemainingMs")
                        .and_then(Value::as_str)
                        .and_then(|s| s.parse().ok()),
                )],
                "channel.pending" => vec![Effect::Wake(Pending::Channels)],
                "pairing.pending" => vec![Effect::Wake(Pending::Pairings)],
                "host.revoked" => vec![
                    Effect::Device(tunnels::DeviceEvent::HostRevoked),
                    Effect::Close,
                ],
                // A revocation we cannot read is not ignored: reconnect and reconcile at READY.
                "device.revoked" => match tunnels::DeviceEvent::from_event(&name, &data) {
                    Some(e) => vec![Effect::Device(e)],
                    None => vec![Effect::Close],
                },
                "devices.changed" => tunnels::DeviceEvent::from_event(&name, &data)
                    .map(Effect::Device)
                    .into_iter()
                    .collect(),
                // circuit.* never gets here (see `drive`).
                _ => vec![],
            },
            Frame::ReplyOk { call_id, .. } | Frame::ReplyErr { call_id, .. }
                if self.close_calls.contains(&call_id) =>
            {
                self.close_calls.retain(|c| *c != call_id);
                vec![]
            }
            Frame::ReplyOk { call_id, data }
                if self.inflight.as_ref().map(Inflight::call_id) == Some(call_id) =>
            {
                match self.inflight.take() {
                    Some(Inflight::Token { token, .. }) => {
                        if data.get("expiresAt").and_then(Value::as_u64).is_none() {
                            return vec![Effect::Close];
                        }
                        self.sent_token = token;
                        vec![Effect::TokenAcked]
                    }
                    Some(Inflight::Chunk { .. }) => {
                        let Some((job, index)) = self.job.as_mut() else {
                            return vec![Effect::Close];
                        };
                        if *index + 1 < job.chunks.len() {
                            *index += 1;
                            return vec![];
                        }
                        let seq = data
                            .get("publicationSeq")
                            .and_then(Value::as_str)
                            .and_then(|s| s.parse::<u64>().ok())
                            .filter(|seq| *seq == job.next);
                        job.finish(seq.ok_or(Error::DataRemote(DataFailure::OutcomeUnknown)));
                        self.job = None;
                        vec![Effect::Published(seq)]
                    }
                    None => vec![Effect::Close],
                }
            }
            Frame::ReplyErr { call_id, code }
                if self.inflight.as_ref().map(Inflight::call_id) == Some(call_id) =>
            {
                match self.inflight.take() {
                    Some(Inflight::Chunk { .. }) => {
                        let Some((job, index)) = self.job.take() else {
                            return vec![Effect::Close];
                        };
                        let last = index + 1 == job.chunks.len();
                        job.finish(Err(reply_error(&code, last)));
                        // Before the final chunk nothing was committed; after it, who knows.
                        if last {
                            vec![Effect::Published(None)]
                        } else {
                            vec![]
                        }
                    }
                    _ => vec![Effect::Close],
                }
            }
            _ => vec![Effect::Close],
        }
    }
    /// The link is gone: a publication whose final chunk was already sent is unknown.
    fn fail_jobs(&mut self, queue: &mut VecDeque<Arc<Job>>) {
        if let Some((job, _)) = self.job.take() {
            job.finish(Err(if job.final_sent() {
                Error::DataRemote(DataFailure::OutcomeUnknown)
            } else {
                Error::DataRemote(DataFailure::ServiceUnavailable)
            }));
        }
        for job in queue.drain(..) {
            job.finish(Err(Error::DataRemote(DataFailure::ServiceUnavailable)));
        }
    }
    fn next_timeout(&self) -> Option<Duration> {
        self.inflight
            .as_ref()
            .map(|i| (i.sent() + CALL_TIMEOUT).saturating_duration_since(Instant::now()))
    }
}

fn backoff(failures: u32) -> Duration {
    let base = Duration::from_millis(500).saturating_mul(1 << failures.saturating_sub(1).min(6));
    let base = base.min(Duration::from_secs(30));
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.subsec_nanos());
    // 50..100 % of the base so Hosts restarted together do not reconnect together.
    base / 2 + base.mul_f64(f64::from(nanos % 1000) / 2000.0)
}

fn run(sh: &'static Shared) {
    let mut failures = 0u32;
    loop {
        let (endpoint, desired_binding) = {
            let mut st = lock(&sh.state);
            loop {
                // An actor that stopped calling (pause, logout) leaves no token behind.
                if st
                    .desired
                    .as_ref()
                    .is_some_and(|d| d.offered_at.elapsed() >= OFFER_TTL)
                {
                    st.desired = None;
                }
                let ready = st.desired.is_some();
                match (&st.endpoint, ready) {
                    (Some(endpoint), true) => {
                        break (
                            endpoint.clone(),
                            st.desired.as_ref().map(|d| d.binding.clone()),
                        );
                    }
                    _ => st = sh.changed.wait(st).unwrap_or_else(PoisonError::into_inner),
                }
            }
        };
        let Some(binding) = desired_binding else {
            continue;
        };
        let started = Instant::now();
        let reached_ready = connect_and_drive(sh, &endpoint, &binding);
        {
            let mut st = lock(&sh.state);
            st.live = None;
            if st
                .desired
                .as_ref()
                .is_some_and(|d| d.offered_at.elapsed() >= OFFER_TTL)
            {
                st.desired = None;
            }
        }
        failures = if reached_ready && started.elapsed() > Duration::from_secs(10) {
            0
        } else {
            failures.saturating_add(1)
        };
        // Wait out the backoff; a different binding (actor re-claimed) or an idle actor ends it early.
        let until = Instant::now() + backoff(failures);
        let mut st = lock(&sh.state);
        while Instant::now() < until && st.desired.as_ref().is_some_and(|d| d.binding == binding) {
            st = sh
                .changed
                .wait_timeout(st, until.saturating_duration_since(Instant::now()))
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }
}

/// True once the relay admitted the link (READY ok).
fn connect_and_drive(
    sh: &'static Shared,
    endpoint: &LocalRelayEndpoint,
    binding: &Binding,
) -> bool {
    let check = || -> std::result::Result<(), BudgetStop> { Ok(()) };
    let (token, generation) = {
        let st = lock(&sh.state);
        match st.desired.as_ref() {
            Some(d) if &d.binding == binding => (d.token.clone(), st.reset_gen),
            _ => return false,
        }
    };
    let Ok(transport) = RelayTransport::new(endpoint.clone()) else {
        return false;
    };
    let Ok(mut conn) = transport.connect_link(Instant::now() + CONNECT_TIMEOUT, &check) else {
        return false;
    };
    let Some(auth) = auth_frame(&sh.contract_hash, &token, binding) else {
        return false;
    };
    if conn
        .send_binary(&auth, Instant::now() + IO, &check)
        .is_err()
    {
        return false;
    }
    let ready_deadline = Instant::now() + READY_TIMEOUT;
    let reply = loop {
        match conn.poll_binary(ready_deadline, &check) {
            Ok(Poll::Ready(bytes)) => break bytes,
            Ok(Poll::Pending) if Instant::now() < ready_deadline => sh.wake.wait(
                &conn,
                ready_deadline.saturating_duration_since(Instant::now()),
            ),
            _ => return false,
        }
    };
    let Ok(ready) = parse_ready(&reply, binding) else {
        return false;
    };
    let now = Instant::now();
    {
        let mut st = lock(&sh.state);
        if st.reset_gen != generation {
            conn.close();
            return false; // the system slept while connecting
        }
        let current = st
            .desired
            .as_ref()
            .is_some_and(|d| &d.binding == binding && d.token.as_str() == token.as_str());
        st.live = Some(Live {
            binding: binding.clone(),
            last_fresh: now,
            lease_until: now + Duration::from_millis(ready.lease_ms),
            token_current: current,
            publication_seq: Some(ready.publication_seq),
        });
        // Once on every connect: whatever arrived while the link was down.
        st.fetch = [true, true];
    }
    apply_device(
        sh,
        &tunnels::DeviceEvent::Ready {
            host_access_epoch: binding.epoch,
            runtime_generation: binding.generation,
            devices: ready.devices,
        },
    );
    let mut session = Session::new(token);
    let _ = drive(sh, &mut conn, &mut session, binding, generation);
    conn.close();
    if let Some(engine) = lock(&sh.tunnels).as_mut() {
        engine.link_down();
    }
    *lock(&sh.last_ready) = None;
    let mut st = lock(&sh.state);
    st.live = None;
    session.fail_jobs(&mut st.jobs);
    true
}

fn drive(
    sh: &'static Shared,
    conn: &mut RelayConnection,
    session: &mut Session,
    binding: &Binding,
    generation: u64,
) -> Result<()> {
    let check = || -> std::result::Result<(), BudgetStop> { Ok(()) };
    loop {
        let mut progressed = false;
        while let Poll::Ready(bytes) = conn.poll_binary(Instant::now() + IO, &check)? {
            progressed = true;
            if bytes.first() == Some(&tunnels::DATA) {
                if bytes.len() < 17 {
                    return Err(Error::InvalidResponse);
                }
                if let Some(engine) = lock(&sh.tunnels).as_mut() {
                    engine.on_data(&bytes[1..], now_ms());
                }
                continue;
            }
            let frame = decode_frame(&bytes, Direction::Relay, MAX_FRAME_BYTES)
                .map_err(|_| Error::InvalidResponse)?;
            if let Frame::Event { name, data } = &frame
                && matches!(name.as_str(), "circuit.open" | "circuit.closed")
            {
                if let Some(engine) = lock(&sh.tunnels).as_mut() {
                    if name == "circuit.open" {
                        engine.on_circuit_open(data, now_ms());
                    } else {
                        engine.on_circuit_closed(data);
                    }
                }
                continue;
            }
            for effect in session.on_frame(frame) {
                if let Effect::Device(event) = &effect {
                    apply_device(sh, event);
                    continue;
                }
                if matches!(effect, Effect::Fresh(_)) {
                    apply_device(sh, &tunnels::DeviceEvent::Fresh);
                }
                let mut st = lock(&sh.state);
                match effect {
                    Effect::Close => return Err(Error::RelayClosed),
                    Effect::Device(_) => {}
                    Effect::Fresh(lease_left) => {
                        if let Some(live) = st.live.as_mut() {
                            let now = Instant::now();
                            live.last_fresh = now;
                            if let Some(ms) = lease_left {
                                live.lease_until = now + Duration::from_millis(ms);
                            }
                        }
                    }
                    Effect::Wake(kind) => {
                        st.fetch[kind as usize] = true;
                        st.peer_until = Some(Instant::now() + PEER_ACTIVE);
                    }
                    Effect::Published(seq) => {
                        if let Some(live) = st.live.as_mut() {
                            live.publication_seq = seq;
                        }
                    }
                    Effect::TokenAcked => {
                        let current = st
                            .desired
                            .as_ref()
                            .is_some_and(|d| d.token.as_str() == session.sent_token.as_str());
                        if let Some(live) = st.live.as_mut() {
                            live.token_current = current;
                        }
                    }
                }
            }
        }
        flush_tunnels(sh, conn, session)?;
        let (token, idle, same_binding, silent) = {
            let st = lock(&sh.state);
            if st.reset_gen != generation {
                return Ok(());
            }
            let silent = st
                .live
                .as_ref()
                .map(|l| l.last_fresh.elapsed())
                .unwrap_or(HALF_OPEN);
            match st.desired.as_ref() {
                Some(d) => (
                    d.token.clone(),
                    d.offered_at.elapsed(),
                    d.binding == *binding,
                    silent,
                ),
                None => return Ok(()),
            }
        };
        // Half-open (relay or path gone without a close): reconnect.
        if silent >= HALF_OPEN {
            return Err(Error::Timeout);
        }
        // The actor stopped calling (paused, logged out, gated) or re-claimed: drop the link.
        if idle >= OFFER_TTL || !same_binding {
            return Ok(());
        }
        let outgoing = {
            let mut st = lock(&sh.state);
            session.next_send(&token, binding, &mut st.jobs)
        };
        if let Some(bytes) = outgoing {
            conn.send_binary(&bytes, Instant::now() + IO, &check)?;
            continue;
        }
        if session.next_timeout().is_some_and(|left| left.is_zero()) {
            return Err(Error::Timeout);
        }
        if progressed {
            continue;
        }
        let tunnel_left = lock(&sh.tunnels)
            .as_ref()
            .and_then(tunnels::Engine::next_deadline)
            .map(|d| Duration::from_millis(d.saturating_sub(now_ms())));
        // Wake for the next attested expiry and for the moment authority turns stale.
        let expiry_left = lock(&sh.tunnels)
            .as_ref()
            .and_then(tunnels::Engine::next_expiry)
            .map(|e| Duration::from_millis(e.saturating_sub(wall_ms())));
        let limit = (OFFER_TTL - idle)
            .min(HALF_OPEN - silent)
            .min(expiry_left.unwrap_or(OFFER_TTL))
            .min(
                TUNNEL_FRESH_MAX
                    .checked_sub(silent)
                    .filter(|d| !d.is_zero())
                    .unwrap_or(OFFER_TTL),
            )
            .min(session.next_timeout().unwrap_or(OFFER_TTL))
            .min(tunnel_left.unwrap_or(OFFER_TTL));
        sh.wake.wait(conn, limit);
    }
}

/// Runs engine deadlines and service commands, then writes what the engine has to send.
fn flush_tunnels(
    sh: &'static Shared,
    conn: &mut RelayConnection,
    session: &mut Session,
) -> Result<()> {
    let check = || -> std::result::Result<(), BudgetStop> { Ok(()) };
    let fresh = lock(&sh.state)
        .live
        .as_ref()
        .is_some_and(|l| tunnels_fresh(l.last_fresh.elapsed()));
    let outs = match lock(&sh.tunnels).as_mut() {
        Some(engine) => {
            engine.set_fresh(fresh);
            engine.expire(wall_ms());
            engine.drain_commands();
            engine.tick(now_ms());
            engine.take_out()
        }
        None => return Ok(()),
    };
    for out in outs {
        let bytes = match out {
            tunnels::Out::Data { circuit, bytes } => {
                [&[tunnels::DATA][..], &circuit, &bytes].concat()
            }
            tunnels::Out::Close { circuit } => {
                session.circuit_close(&circuit).ok_or(Error::RelayClosed)?
            }
        };
        conn.send_binary(&bytes, Instant::now() + IO, &check)?;
    }
    Ok(())
}

/// Wakes the uplink thread out of its readiness wait (publication job, token hand-off).
struct Wake {
    #[cfg(unix)]
    pair: Option<(
        std::os::unix::net::UnixStream,
        std::os::unix::net::UnixStream,
    )>,
}
#[cfg_attr(not(debug_assertions), allow(dead_code))]
impl Wake {
    fn new() -> Self {
        Self {
            #[cfg(unix)]
            pair: std::os::unix::net::UnixStream::pair()
                .ok()
                .filter(|(a, b)| {
                    a.set_nonblocking(true).is_ok() && b.set_nonblocking(true).is_ok()
                }),
        }
    }
    fn wake(&self) {
        #[cfg(unix)]
        if let Some((tx, _)) = &self.pair {
            let _ = std::io::Write::write(&mut &*tx, &[1]);
        }
    }
    /// poll(2) on the link and the wake pipe, so neither a frame nor a job waits for a timer.
    fn wait(&self, conn: &RelayConnection, limit: Duration) {
        #[cfg(unix)]
        {
            let mut fds = vec![libc::pollfd {
                fd: conn.wait_fd().unwrap_or(-1),
                events: libc::POLLIN,
                revents: 0,
            }];
            if let Some((_, rx)) = &self.pair {
                use std::os::fd::AsRawFd;
                fds.push(libc::pollfd {
                    fd: rx.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                });
            }
            let ms = limit.as_micros().div_ceil(1000).min(i32::MAX as u128) as libc::c_int;
            // SAFETY: live, correctly sized pollfd array.
            unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, ms) };
            if let Some((_, rx)) = &self.pair {
                let mut sink = [0u8; 64];
                while matches!(std::io::Read::read(&mut &*rx, &mut sink), Ok(n) if n > 0) {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = conn;
            std::thread::sleep(limit.min(Duration::from_millis(10)));
        }
    }
}

#[cfg(test)]
mod tests;
