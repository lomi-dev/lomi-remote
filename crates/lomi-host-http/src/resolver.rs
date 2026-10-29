//! At most one process-wide native lookup, even when getaddrinfo never returns.
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    time::{Duration, Instant},
};
use ureq::{
    http::Uri,
    unversioned::{
        resolver::{ResolvedSocketAddrs, Resolver},
        transport::NextTimeout,
    },
};

struct Job {
    authority: String,
    response: SyncSender<Option<Vec<SocketAddr>>>,
}
struct Worker {
    jobs: SyncSender<Job>,
    busy: Arc<AtomicBool>,
    _join: std::thread::JoinHandle<()>,
}
static WORKER: OnceLock<Result<Worker, ()>> = OnceLock::new();
fn worker() -> Result<&'static Worker, ()> {
    WORKER
        .get_or_init(|| {
            spawn_worker(|authority| {
                authority
                    .to_socket_addrs()
                    .map(|addresses| ipv4_first(addresses.take(16).collect()))
                    .ok()
            })
        })
        .as_ref()
        .map_err(|_| ())
}
fn spawn_worker(
    lookup: impl Fn(&str) -> Option<Vec<SocketAddr>> + Send + 'static,
) -> Result<Worker, ()> {
    let (jobs, receiver) = mpsc::sync_channel::<Job>(1);
    let busy = Arc::new(AtomicBool::new(false));
    let active = busy.clone();
    let join = std::thread::Builder::new()
        .name("lomi-host-dns".into())
        .spawn(move || {
            while let Ok(job) = receiver.recv() {
                let addresses = lookup(&job.authority);
                // Each request owns its response receiver. A timed-out result cannot
                // be consumed by a later request. Never block on a stale receiver.
                active.store(false, Ordering::Release);
                let _ = job.response.try_send(addresses);
            }
        })
        .map_err(|_| ())?;
    Ok(Worker {
        jobs,
        busy,
        _join: join,
    })
}
pub(super) fn initialize() -> Result<(), ()> {
    worker().map(|_| ())
}
impl Worker {
    fn lookup_budget(
        &self,
        authority: String,
        timeout: Duration,
        budget: Option<&super::budget::State>,
    ) -> Result<Option<Vec<SocketAddr>>, ()> {
        let deadline = Instant::now() + timeout;
        if budget.is_some_and(|state| state.io_check(deadline).is_err()) {
            return Err(());
        }
        if self
            .busy
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err(());
        }
        let (response, receiver) = mpsc::sync_channel(1);
        if self
            .jobs
            .try_send(Job {
                authority,
                response,
            })
            .is_err()
        {
            self.busy.store(false, Ordering::Release);
            return Err(());
        }
        loop {
            if budget.is_some_and(|state| state.io_check(deadline).is_err())
                || Instant::now() >= deadline
            {
                return Err(());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            match receiver.recv_timeout(remaining.min(Duration::from_millis(10))) {
                Ok(value) => {
                    if Instant::now() >= deadline
                        || budget.is_some_and(|state| state.io_check(deadline).is_err())
                    {
                        return Err(());
                    }
                    return Ok(value);
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => return Err(()),
            }
        }
    }
}
// Relay uses the SAME process-wide worker and a request-private response
// receiver. Dropped/cancelled lookup results can never reach a successor.
pub(crate) fn relay_addresses(
    host: &str,
    port: u16,
    state: &super::budget::State,
) -> super::Result<Vec<SocketAddr>> {
    let remaining = state.check()?;
    // An IP literal needs no lookup. It must not contend for (or be refused by)
    // the single process-wide native lookup slot that real names share.
    if let Some(address) = literal_address(host, port) {
        return Ok(vec![address]);
    }
    let addresses = worker()
        .map_err(|_| super::Error::ResolverUnavailable)?
        .lookup_budget(
            format!("{host}:{port}"),
            remaining.min(Duration::from_secs(3)),
            Some(state),
        )
        .map_err(|_| {
            state
                .check()
                .err()
                .unwrap_or(super::Error::ResolverUnavailable)
        })?;
    state.check()?;
    addresses
        .filter(|addresses| !addresses.is_empty())
        .ok_or(super::Error::Network)
}
/// The product policy is DNS/IPv4: put IPv4 answers first (stable otherwise) so
/// the single TCP attempt does not depend on the platform's resolver ordering
/// (Windows answers `localhost` with `::1` before `127.0.0.1`).
fn ipv4_first(mut addresses: Vec<SocketAddr>) -> Vec<SocketAddr> {
    addresses.sort_by_key(|address| address.is_ipv6());
    addresses
}
fn literal_address(host: &str, port: u16) -> Option<SocketAddr> {
    let host = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host);
    host.parse::<std::net::IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}
#[derive(Debug)]
pub(super) struct BoundedResolver;
impl Resolver for BoundedResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        resolve(uri, config, timeout, None)
    }
}
#[derive(Debug)]
pub(super) struct BudgetResolver(pub(super) Arc<super::budget::State>);
impl Resolver for BudgetResolver {
    fn resolve(
        &self,
        uri: &Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        resolve(uri, config, timeout, Some(&self.0))
    }
}
fn resolve(
    uri: &Uri,
    _config: &ureq::config::Config,
    timeout: NextTimeout,
    budget: Option<&super::budget::State>,
) -> Result<ResolvedSocketAddrs, ureq::Error> {
    let host = uri.host().ok_or(ureq::Error::HostNotFound)?;
    let port = uri.port_u16().unwrap_or(443);
    // Config's canonical authority allows DNS/IPv4 only. No URL credentials
    // enter this worker. Clamp to the remaining ureq/global deadline.
    let duration = if timeout.after.is_not_happening() {
        Duration::from_secs(3)
    } else {
        (*timeout.after).min(Duration::from_secs(3))
    };
    let addresses = worker()
        .map_err(|_| ureq::Error::HostNotFound)?
        .lookup_budget(format!("{host}:{port}"), duration, budget)
        .map_err(|_| ureq::Error::Timeout(timeout.reason))?
        .ok_or(ureq::Error::HostNotFound)?;
    let mut out = BoundedResolver.empty();
    for address in addresses {
        out.push(address);
    }
    if out.is_empty() {
        Err(ureq::Error::HostNotFound)
    } else {
        Ok(out)
    }
}
