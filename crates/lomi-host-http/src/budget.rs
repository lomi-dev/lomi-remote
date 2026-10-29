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
