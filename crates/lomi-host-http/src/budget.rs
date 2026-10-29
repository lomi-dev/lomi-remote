//! Original-operation budget bridge. No owner, provider, credential or network
//! work runs on the scoped watcher. All socket I/O stays on the calling worker.
use super::{Error, Result};
use std::{
    fmt,
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, Ordering},
        mpsc,
    },
    time::{Duration, Instant},
};
use ureq::unversioned::transport::{
    Buffers, ConnectionDetails, Connector, LazyBuffers, NextTimeout, RustlsConnector, Transport,
};

const QUANTUM: Duration = Duration::from_millis(10);
/// Terminal result of the caller's actual, already-admitted operation check.
/// The callback must check that same operation; it must not admit or renew one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetStop {
    Cancelled,
    Deadline,
}
pub(crate) type Check<'a> = dyn Fn() -> std::result::Result<(), BudgetStop> + Sync + 'a;

#[derive(Debug)]
pub(crate) struct State {
    deadline: Instant,
    terminal: AtomicU8,
}
impl State {
    pub(crate) fn new(original_deadline: Instant) -> Self {
        Self {
            deadline: original_deadline.min(Instant::now() + Duration::from_secs(15)),
            terminal: AtomicU8::new(0),
        }
    }
    fn publish(&self, stop: BudgetStop) {
        let _ = self.terminal.compare_exchange(
            0,
            match stop {
                BudgetStop::Cancelled => 1,
                BudgetStop::Deadline => 2,
            },
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
    pub(crate) fn check(&self) -> Result<Duration> {
        if Instant::now() >= self.deadline {
            self.publish(BudgetStop::Deadline);
        }
        match self.terminal.load(Ordering::Acquire) {
            1 => Err(Error::Cancelled),
            2 => Err(Error::Timeout),
            _ => Ok(self.deadline.saturating_duration_since(Instant::now())),
        }
    }
    pub(crate) fn io_check(&self, deadline: Instant) -> std::result::Result<(), ureq::Error> {
        self.check().map_err(|_| stopped())?;
        if Instant::now() >= deadline {
            return Err(stopped());
        }
        Ok(())
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.deadline
    }
}
fn stopped() -> ureq::Error {
    io::Error::new(io::ErrorKind::TimedOut, "HTTP budget stopped").into()
}

pub(crate) fn run<T>(
    deadline: Instant,
    check: &Check<'_>,
    request: impl FnOnce(Arc<State>) -> Result<T>,
) -> Result<T> {
    let state = Arc::new(State::new(deadline));
    if let Err(stop) = check() {
        state.publish(stop);
    }
    state.check()?;
    std::thread::scope(|scope| {
        // Dropping the sender wakes the watcher on every return and on unwind.
        // scope joins even when the request or callback panics.
        let (done, receiver) = mpsc::channel::<()>();
        let observed = state.clone();
        struct PanicStop(Arc<State>);
        impl Drop for PanicStop {
            fn drop(&mut self) {
                if std::thread::panicking() {
                    self.0.publish(BudgetStop::Cancelled);
                }
            }
        }
        let watcher = std::thread::Builder::new()
            .name("lomi-http-budget".into())
            .spawn_scoped(scope, move || {
                let _panic_stop = PanicStop(observed.clone());
                loop {
                    if let Err(stop) = check() {
                        observed.publish(stop);
                        return;
                    }
                    if observed.check().is_err() {
                        return;
                    }
                    match receiver.recv_timeout(QUANTUM) {
                        Err(mpsc::RecvTimeoutError::Timeout) => {}
                        _ => return,
                    }
                }
            })
            .map_err(|_| Error::Network)?;
        let result = request(state.clone());
        drop(done);
        // Explicit join before final authoritative check / result publication.
        if let Err(panic) = watcher.join() {
            std::panic::resume_unwind(panic);
        }
        if let Err(stop) = check() {
            state.publish(stop);
        }
        state.check()?;
        result
    })
}

pub(crate) fn remaining(state: Option<&State>) -> Result<Duration> {
    let duration = match state {
        Some(state) => state.check()?,
        None => Duration::from_secs(15),
    };
    // ureq normalizes zero to a second. Never hand it a zero budget.
    if duration.is_zero() {
        Err(Error::Timeout)
    } else {
        Ok(duration.min(Duration::from_secs(15)))
    }
}
pub(crate) fn agent(config: ureq::config::Config, state: Arc<State>) -> Result<ureq::Agent> {
    super::resolver::initialize().map_err(|_| {
        super::diagnostics::failure(
            lomi_remote_protocol::ipc::DiagnosticCode::DnsUnavailable,
            lomi_remote_protocol::ipc::DoctorHealth::TransportUnavailable,
            lomi_remote_protocol::ipc::DoctorHealth::Unknown,
        );
        Error::ResolverUnavailable
    })?;
    Ok(ureq::Agent::with_parts(
        config,
        BudgetConnector {
            state: state.clone(),
        },
        super::resolver::BudgetResolver(state),
    ))
}
#[derive(Debug)]
struct BudgetConnector {
    state: Arc<State>,
}
impl Connector<()> for BudgetConnector {
    type Out = Box<dyn Transport>;
    fn connect(
        &self,
        details: &ConnectionDetails,
        _: Option<()>,
    ) -> std::result::Result<Option<Self::Out>, ureq::Error> {
        self.state.io_check(self.state.deadline())?;
        // Created once for all address attempts, TCP and the entire TLS handshake.
        let deadline =
            relative_deadline(details.timeout, Duration::from_secs(5)).min(self.state.deadline());
        let mut last = None;
        for address in &details.addrs {
            self.state.io_check(deadline)?;
            match connect_socket(*address, &self.state, deadline) {
                Ok(stream) => {
                    if details.config.no_delay() {
                        stream.set_nodelay(true)?;
                    }
                    let handshaking = Arc::new(AtomicBool::new(true));
                    let transport = BudgetTcp {
                        stream,
                        buffers: LazyBuffers::new(
                            details.config.input_buffer_size(),
                            details.config.output_buffer_size(),
                        ),
                        state: self.state.clone(),
                        connect_deadline: deadline,
                        handshaking: handshaking.clone(),
                        stages: Vec::new(),
                    };
                    // Keep stock rustls chain/name/time/signature verification.
                    let tls = RustlsConnector::default().connect(details, Some(transport))?;
                    self.state.io_check(deadline)?;
                    handshaking.store(false, Ordering::Release);
                    return Ok(tls.map(|transport| Box::new(transport) as Box<dyn Transport>));
                }
                Err(error) => {
                    self.state.io_check(deadline)?;
                    match &error {
                        ureq::Error::Io(error)
                            if matches!(
                                error.kind(),
                                io::ErrorKind::ConnectionRefused
                                    | io::ErrorKind::HostUnreachable
                                    | io::ErrorKind::NetworkUnreachable
                                    | io::ErrorKind::AddrNotAvailable
                            ) =>
                        {
                            last = Some(error.kind())
                        }
                        _ => return Err(error),
                    }
                }
            }
        }
        Err(io::Error::from(last.unwrap_or(io::ErrorKind::ConnectionRefused)).into())
    }
}
fn relative_deadline(timeout: NextTimeout, cap: Duration) -> Instant {
    Instant::now()
        + if timeout.after.is_not_happening() {
            cap
        } else {
            (*timeout.after).min(cap)
        }
}
fn pending_connect(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::WouldBlock {
        return true;
    }
    // std has no portable InProgress ErrorKind on the supported compiler.
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd",
        target_os = "dragonfly"
    ))]
    {
        return matches!(error.raw_os_error(), Some(36 | 37));
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return matches!(error.raw_os_error(), Some(115 | 114));
    }
    #[cfg(windows)]
    {
        return matches!(error.raw_os_error(), Some(10035..=10037));
    }
    #[allow(unreachable_code)]
    false
}
fn pause(state: &State, deadline: Instant) -> std::result::Result<(), ureq::Error> {
    state.io_check(deadline)?;
    std::thread::sleep(QUANTUM.min(deadline.saturating_duration_since(Instant::now())));
    state.io_check(deadline)
}
pub(crate) fn connect_socket(
    address: SocketAddr,
    state: &State,
    deadline: Instant,
) -> std::result::Result<TcpStream, ureq::Error> {
    state.io_check(deadline)?;
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_nonblocking(true)?;
    match socket.connect(&address.into()) {
        Ok(()) => {}
        Err(error) if pending_connect(&error) => await_connected(state, deadline, || {
            if let Some(error) = socket.take_error()? {
                return Err(error);
            }
            Ok(socket.peer_addr().is_ok())
        })?,
        Err(error) => return Err(error.into()),
    }
    state.io_check(deadline)?;
    let stream: TcpStream = socket.into();
    state.io_check(deadline)?;
    stream.set_nodelay(true)?;
    state.io_check(deadline)?;
    Ok(stream)
}
fn await_connected(
    state: &State,
    deadline: Instant,
    mut ready: impl FnMut() -> io::Result<bool>,
) -> std::result::Result<(), ureq::Error> {
    loop {
        pause(state, deadline)?;
        let connected = ready()?;
        state.io_check(deadline)?;
        if connected {
            return Ok(());
        }
    }
}
struct BudgetTcp {
    stream: TcpStream,
    buffers: LazyBuffers,
    state: Arc<State>,
    connect_deadline: Instant,
    handshaking: Arc<AtomicBool>,
    stages: Vec<(ureq::Timeout, Instant)>,
}
impl fmt::Debug for BudgetTcp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BudgetTcp")
    }
}
impl BudgetTcp {
    fn stage_deadline(&mut self, timeout: NextTimeout) -> Instant {
        if self.handshaking.load(Ordering::Acquire) {
            return self.connect_deadline;
        }
        if let Some((_, deadline)) = self
            .stages
            .iter()
            .find(|(reason, _)| *reason == timeout.reason)
        {
            return *deadline;
        }
        let cap = match timeout.reason {
            ureq::Timeout::SendRequest | ureq::Timeout::SendBody => Duration::from_secs(2),
            ureq::Timeout::RecvResponse | ureq::Timeout::RecvBody => Duration::from_secs(5),
            _ => Duration::from_secs(15),
        };
        let deadline = relative_deadline(timeout, cap).min(self.state.deadline());
        self.stages.push((timeout.reason, deadline));
        deadline
    }
}
// Explicit partial-write cursor: a prefix accepted by the kernel is never sent
// again. The same absolute deadline is checked before and after every progress.
fn write_until(
    writer: &mut impl Write,
    bytes: &[u8],
    state: &State,
    deadline: Instant,
) -> std::result::Result<(), ureq::Error> {
    let mut offset = 0;
    while offset < bytes.len() {
        state.io_check(deadline)?;
        match writer.write(&bytes[offset..]) {
            Ok(0) => return Err(io::Error::from(io::ErrorKind::WriteZero).into()),
            Ok(amount) => offset += amount,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => pause(state, deadline)?,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
        state.io_check(deadline)?;
    }
    Ok(())
}
impl Transport for BudgetTcp {
    fn buffers(&mut self) -> &mut dyn Buffers {
        &mut self.buffers
    }
    fn transmit_output(
        &mut self,
        amount: usize,
        timeout: NextTimeout,
    ) -> std::result::Result<(), ureq::Error> {
        let deadline = self.stage_deadline(timeout);
        write_until(
            &mut self.stream,
            &self.buffers.output()[..amount],
            &self.state,
            deadline,
        )
    }
    fn await_input(&mut self, timeout: NextTimeout) -> std::result::Result<bool, ureq::Error> {
        let deadline = self.stage_deadline(timeout);
        loop {
            self.state.io_check(deadline)?;
            match self.stream.read(self.buffers.input_append_buf()) {
                Ok(amount) => {
                    self.state.io_check(deadline)?;
                    self.buffers.input_appended(amount);
                    return Ok(amount > 0);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    pause(&self.state, deadline)?
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    fn is_open(&mut self) -> bool {
        self.state.check().is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[test]
    fn partial_write_cursor_never_replays_accepted_prefix() {
        struct Partial {
            bytes: Vec<u8>,
            calls: usize,
        }
        impl Write for Partial {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.calls += 1;
                if self.calls.is_multiple_of(3) {
                    return Err(io::ErrorKind::WouldBlock.into());
                }
                let amount = bytes.len().min(3);
                self.bytes.extend_from_slice(&bytes[..amount]);
                Ok(amount)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let state = State::new(Instant::now() + Duration::from_secs(1));
        let mut writer = Partial {
            bytes: Vec::new(),
            calls: 0,
        };
        write_until(
            &mut writer,
            b"exactly-once-prefix",
            &state,
            state.deadline(),
        )
        .unwrap();
        assert_eq!(writer.bytes, b"exactly-once-prefix");
        assert!(writer.calls > 3);
    }
    #[test]
    fn cancel_is_sticky_and_prevents_connect_before_socket_creation() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = State::new(Instant::now() + Duration::from_secs(1));
        state.publish(BudgetStop::Cancelled);
        state.publish(BudgetStop::Deadline);
        assert_eq!(state.check(), Err(Error::Cancelled));
        assert!(connect_socket(listener.local_addr().unwrap(), &state, state.deadline()).is_err());
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
    }
    #[test]
    fn connect_socket_returns_tcp_nodelay_stream_before_transport_setup() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let state = State::new(Instant::now() + Duration::from_secs(2));
        let stream =
            connect_socket(listener.local_addr().unwrap(), &state, state.deadline()).unwrap();
        assert!(stream.nodelay().unwrap());

        let deadline = Instant::now() + Duration::from_secs(1);
        let peer = loop {
            match listener.accept() {
                Ok((peer, _)) => break peer,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("loopback accept failed: {error}"),
            }
        };
        drop(stream);
        drop(peer);
    }
    #[test]
    fn cancellation_stops_an_in_progress_connect_wait() {
        let state = State::new(Instant::now() + Duration::from_secs(1));
        let mut polls = 0;
        let result = await_connected(&state, state.deadline(), || {
            polls += 1;
            state.publish(BudgetStop::Cancelled);
            Ok(false)
        });
        assert!(result.is_err());
        assert_eq!(polls, 1);
        assert_eq!(state.check(), Err(Error::Cancelled));
    }
    #[test]
    fn watcher_is_joined_after_success_error_and_request_unwind() {
        for outcome in 0..3 {
            let calls = AtomicUsize::new(0);
            let check = || {
                calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(
                    Instant::now() + Duration::from_secs(1),
                    &check,
                    |_| -> Result<()> {
                        std::thread::sleep(Duration::from_millis(25));
                        match outcome {
                            0 => Ok(()),
                            1 => Err(Error::InvalidResponse),
                            _ => panic!("synthetic request unwind"),
                        }
                    },
                )
            }));
            assert_eq!(result.is_err(), outcome == 2);
            let after = calls.load(Ordering::SeqCst);
            std::thread::sleep(Duration::from_millis(25));
            assert_eq!(calls.load(Ordering::SeqCst), after);
        }
    }
    #[test]
    fn fixed_connect_deadline_is_not_restarted_by_repeated_tls_io() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (_peer, _) = listener.accept().unwrap();
        let state = Arc::new(State::new(Instant::now() + Duration::from_secs(1)));
        let deadline = Instant::now() + Duration::from_millis(20);
        let mut transport = BudgetTcp {
            stream,
            buffers: LazyBuffers::new(128, 128),
            state,
            connect_deadline: deadline,
            handshaking: Arc::new(AtomicBool::new(true)),
            stages: Vec::new(),
        };
        let timeout = NextTimeout {
            after: ureq::unversioned::transport::time::Duration::from_secs(5),
            reason: ureq::Timeout::Connect,
        };
        assert_eq!(transport.stage_deadline(timeout), deadline);
        std::thread::sleep(Duration::from_millis(25));
        assert_eq!(transport.stage_deadline(timeout), deadline);
        let fixed = transport.stage_deadline(timeout);
        assert!(transport.state.io_check(fixed).is_err());
    }
}

#[cfg(test)]
mod watcher_check_panic_regressions {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    #[test]
    fn watcher_check_panic_publishes_terminal_stop_and_is_joined_before_unwind_returns() {
        // The test owns and joins the caller thread; the budget scope owns and
        // joins its watcher. No borrowed fixture thread can escape an assertion.
        let calls = Arc::new(AtomicUsize::new(0));
        let observed_stop = Arc::new(AtomicBool::new(false));
        let (count, stopped) = (calls.clone(), observed_stop.clone());
        let caller = std::thread::spawn(move || {
            let caller_id = std::thread::current().id();
            let request_started = AtomicBool::new(false);
            let check = || {
                count.fetch_add(1, Ordering::SeqCst);
                if std::thread::current().id() != caller_id
                    && request_started.load(Ordering::Acquire)
                {
                    panic!("synthetic authoritative-check panic");
                }
                Ok(())
            };
            let started = Instant::now();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                run(
                    started + Duration::from_secs(3),
                    &check,
                    |state| -> Result<()> {
                        request_started.store(true, Ordering::Release);
                        let safety_limit = Instant::now() + Duration::from_secs(1);
                        while Instant::now() < safety_limit {
                            if state.check() == Err(Error::Cancelled) {
                                stopped.store(true, Ordering::Release);
                                return Err(Error::Cancelled);
                            }
                            std::thread::sleep(Duration::from_millis(2));
                        }
                        Err(Error::Timeout)
                    },
                )
            }));
            let panic = result.expect_err("watcher panic must propagate after join");
            assert_eq!(
                panic.downcast_ref::<&str>(),
                Some(&"synthetic authoritative-check panic")
            );
            assert!(started.elapsed() < Duration::from_secs(1));
        });
        caller.join().unwrap();
        assert!(observed_stop.load(Ordering::Acquire));
        let after_join = calls.load(Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(calls.load(Ordering::SeqCst), after_join);
    }
}
