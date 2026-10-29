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
    #[cfg(test)]
    fn lookup(&self, authority: String, timeout: Duration) -> Result<Option<Vec<SocketAddr>>, ()> {
        self.lookup_budget(authority, timeout, None)
    }
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
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ip_literals_resolve_without_the_shared_lookup_slot() {
        assert_eq!(
            literal_address("127.0.0.1", 4433),
            Some("127.0.0.1:4433".parse().unwrap())
        );
        assert_eq!(
            literal_address("[::1]", 443),
            Some("[::1]:443".parse().unwrap())
        );
        assert_eq!(literal_address("relay.example", 443), None);
        assert_eq!(literal_address("127.0.0.1.example", 443), None);
        assert_eq!(literal_address("", 443), None);
    }
    #[test]
    fn ipv4_answers_precede_ipv6_in_stable_order() {
        let sorted = ipv4_first(vec![
            "[::1]:1".parse().unwrap(),
            "10.0.0.2:1".parse().unwrap(),
            "[::2]:1".parse().unwrap(),
            "10.0.0.1:1".parse().unwrap(),
        ]);
        let text: Vec<_> = sorted.iter().map(ToString::to_string).collect();
        assert_eq!(text, ["10.0.0.2:1", "10.0.0.1:1", "[::1]:1", "[::2]:1"]);
    }
    struct Fixture {
        worker: Option<Worker>,
        release: Option<SyncSender<()>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.try_send(());
            }
            if let Some(Worker { jobs, _join, .. }) = self.worker.take() {
                drop(jobs);
                _join.join().unwrap();
            }
        }
    }
    #[test]
    fn stalled_lookup_has_one_worker_and_fails_fast_until_release() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = calls.clone();
        let worker = spawn_worker(move |_| {
            let call = count.fetch_add(1, Ordering::SeqCst);
            started_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Some(vec![SocketAddr::from(([127, 0, 0, 1], 443 + call as u16))])
        })
        .unwrap();
        let fixture = Fixture {
            worker: Some(worker),
            release: Some(release_tx),
        };
        let worker = fixture.worker.as_ref().unwrap();
        assert!(
            worker
                .lookup("public.invalid:443".into(), Duration::from_millis(20))
                .is_err()
        );
        started_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..100 {
            assert!(
                worker
                    .lookup("public.invalid:443".into(), Duration::from_secs(3))
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        fixture.release.as_ref().unwrap().send(()).unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(1);
        while worker.busy.load(Ordering::Acquire) {
            assert!(std::time::Instant::now() < deadline);
            std::thread::yield_now();
        }
        // A different request never sees the old request's stale address result.
        fixture.release.as_ref().unwrap().send(()).unwrap();
        let addresses = worker
            .lookup("other.invalid:443".into(), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        assert_eq!(addresses, vec![SocketAddr::from(([127, 0, 0, 1], 444))]);
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        drop(fixture);
    }
}

#[cfg(test)]
mod budget_dns_regressions {
    use super::*;
    use crate::{BudgetStop, Error, budget};
    use std::sync::atomic::AtomicUsize;

    struct JoinedLookupFixture {
        worker: Option<Worker>,
        release: Option<SyncSender<()>>,
        cancel: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for JoinedLookupFixture {
        fn drop(&mut self) {
            if let Some(release) = self.release.take() {
                let _ = release.try_send(());
            }
            if let Some(Worker { jobs, _join, .. }) = self.worker.take() {
                drop(jobs);
                let _ = _join.join();
            }
            if let Some(cancel) = self.cancel.take() {
                let _ = cancel.join();
            }
        }
    }
    #[test]
    fn budgeted_dns_receiver_cancel_keeps_original_sticky_check_and_single_worker() {
        let (started_tx, started_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        // Exercise the existing single-worker machinery with a bounded synthetic
        // lookup, never a native DNS call or another resolver/thread pool.
        let worker = spawn_worker(move |_| {
            count.fetch_add(1, Ordering::SeqCst);
            let _ = started_tx.try_send(());
            let _ = release_rx.recv_timeout(Duration::from_secs(2));
            Some(vec![SocketAddr::from(([127, 0, 0, 1], 443))])
        })
        .unwrap();
        let latch = Arc::new(AtomicBool::new(false));
        let sticky = Arc::new(AtomicBool::new(false));
        let (cancel_latch, seen) = (latch.clone(), sticky.clone());
        let cancel = std::thread::spawn(move || {
            if started_rx.recv_timeout(Duration::from_secs(1)).is_err() {
                return;
            }
            cancel_latch.store(true, Ordering::SeqCst);
            let limit = Instant::now() + Duration::from_secs(1);
            while !seen.load(Ordering::SeqCst) && Instant::now() < limit {
                std::thread::sleep(Duration::from_millis(1));
            }
            cancel_latch.store(false, Ordering::SeqCst);
        });
        let fixture = JoinedLookupFixture {
            worker: Some(worker),
            release: Some(release_tx),
            cancel: Some(cancel),
        };
        let worker = fixture.worker.as_ref().unwrap();
        let check = || {
            if latch.load(Ordering::SeqCst) {
                sticky.store(true, Ordering::SeqCst);
            }
            if sticky.load(Ordering::SeqCst) {
                Err(BudgetStop::Cancelled)
            } else {
                Ok(())
            }
        };
        let started = Instant::now();
        let result = budget::run(started + Duration::from_secs(3), &check, |state| {
            worker
                .lookup_budget(
                    "synthetic.invalid:443".into(),
                    Duration::from_secs(2),
                    Some(&state),
                )
                .map_err(|_| Error::Timeout)
        });
        assert_eq!(result, Err(Error::Cancelled));
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(sticky.load(Ordering::SeqCst));
        assert!(worker.busy.load(Ordering::Acquire));
        for _ in 0..10 {
            assert!(
                worker
                    .lookup("other.invalid:443".into(), Duration::from_secs(1))
                    .is_err()
            );
        }
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        // Drop always releases the one pending lookup, closes its queue, and
        // joins both owned threads, including when an earlier assertion unwinds.
        drop(fixture);
        assert!(!latch.load(Ordering::SeqCst));
        assert_eq!(check(), Err(BudgetStop::Cancelled));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
}
