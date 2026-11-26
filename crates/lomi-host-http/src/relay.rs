//! Synchronous WSS bytes only. No reconnect, discovery, RPC or authority minting.
use crate::{BudgetStop, Error, Result, budget, resolver};
use lomi_remote_protocol::{
    admission::WssAdmissionFrame, ipc::LocalRelayEndpoint, message_framing::MAX_TRANSPORT_FRAME_LEN,
};
use serde::Deserialize;
use std::{
    fmt,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream},
    sync::Arc,
    time::{Duration, Instant},
};
use tungstenite::{Message, WebSocket, protocol::WebSocketConfig};
use zeroize::Zeroizing;

/// Running total of bytes read from any relay socket: lets the actor tell
/// "readable and being consumed" from "readable and left unread".
static BYTES_READ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
pub fn relay_bytes_read() -> u64 {
    BYTES_READ.load(std::sync::atomic::Ordering::Relaxed)
}
const QUANTUM: Duration = Duration::from_millis(10);
const READY_LIMIT: usize = 125;
const ADMISSION_LIMIT: usize = lomi_remote_protocol::admission::WSS_ADMISSION_MAX_BYTES;
type TlsSocket = rustls::StreamOwned<rustls::ClientConnection, RelaySocket>;
type Socket = WebSocket<TlsSocket>;

/// Uses only the independently committed canonical relay endpoint. TLS always
/// verifies the normal WebPKI chain, time and endpoint hostname, with SNI.
/// Debug and errors contain no endpoint, ticket, headers or application bytes.
pub struct RelayTransport {
    endpoint: LocalRelayEndpoint,
    tls: Arc<rustls::ClientConfig>,
}
impl fmt::Debug for RelayTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayTransport")
    }
}
impl RelayTransport {
    pub fn new(endpoint: LocalRelayEndpoint) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(debug_assertions)]
        for der in super::dev_ca::extra_roots()?.unwrap_or_default() {
            roots.add(der).map_err(|_| Error::InvalidConfig)?;
        }
        Self::with_roots(endpoint, roots)
    }
    fn with_roots(endpoint: LocalRelayEndpoint, roots: rustls::RootCertStore) -> Result<Self> {
        let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::InvalidConfig)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            endpoint,
            tls: Arc::new(tls),
        })
    }

    /// The timestamp is captured BEFORE requesting the one-use ticket, never
    /// when this method starts. DNS/TCP/TLS/upgrade/admission/ready all share
    /// min(original deadline, ticket request start + expires_in_ms). A failed
    /// attempt is never retried here; the caller must not replay its ticket.
    /// Returns once the relay authenticates the ticket; the peer's `ready`
    /// arrives through `poll_binary` under the same bound, so waiting for the
    /// browser never blocks the caller's thread.
    /// `check` checks the original Operation only, without Domain/Store locks.
    pub fn connect(
        &self,
        admission: &WssAdmissionFrame,
        ticket_request_started: Instant,
        expires_in_ms: u64,
        original_deadline: Instant,
        check: &(dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> Result<RelayConnection> {
        if !(1..=5_000).contains(&expires_in_ms) || ticket_request_started > Instant::now() {
            return Err(Error::Request);
        }
        let deadline = original_deadline.min(
            ticket_request_started
                .checked_add(Duration::from_millis(expires_in_ms))
                .ok_or(Error::Request)?,
        );
        budget::run(deadline, check, |state| {
            state.check()?;
            // The server's v2 admission grammar is deliberately narrower than
            // the generic secret DTO: unescaped base64url ticket, 43..128 bytes.
            let ticket = admission.ticket.expose_wire().as_bytes();
            if !(43..=128).contains(&ticket.len())
                || !ticket
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
            {
                return Err(Error::Request);
            }
            let body =
                Zeroizing::new(serde_json::to_string(admission).map_err(|_| Error::Request)?);
            if body.len() > ADMISSION_LIMIT {
                return Err(Error::Request);
            }
            let uri: tungstenite::http::Uri = self
                .endpoint
                .as_str()
                .parse()
                .map_err(|_| Error::InvalidConfig)?;
            let host = uri.host().ok_or(Error::InvalidConfig)?;
            let port = uri.port_u16().unwrap_or(443);
            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(|_| Error::InvalidConfig)?;
            let addresses = resolver::relay_addresses(host, port, &state)?;
            // Exactly one TCP attempt. No hidden fallback/reconnect/replay.
            let address = addresses.into_iter().next().ok_or(Error::Network)?;
            let tcp = budget::connect_socket(address, &state, state.deadline())
                .map_err(crate::network_error)?;
            tcp.set_nodelay(true).map_err(|_| Error::Network)?;
            let connection = rustls::ClientConnection::new(self.tls.clone(), server_name)
                .map_err(|_| Error::InvalidConfig)?;
            let stream = rustls::StreamOwned::new(
                connection,
                RelaySocket {
                    tcp,
                    state: Some(state.clone()),
                    polling: false,
                },
            );
            // client_with_config uses this exact verified TLS stream, never its
            // own DNS/connect/TLS/redirect convenience path. All handshake errors
            // are immediately collapsed; no response headers/body escape.
            let (mut socket, _) = tungstenite::client::client_with_config(
                self.endpoint.as_str(),
                stream,
                Some(config(READY_LIMIT)),
            )
            .map_err(|error| match error {
                tungstenite::HandshakeError::Failure(error) => ws_error(error),
                tungstenite::HandshakeError::Interrupted(_) => Error::Network,
            })?;
            state.check()?;
            socket
                .send(Message::Text(body.as_str().into()))
                .map_err(ws_error)?;
            state.check()?;
            loop {
                state.check()?;
                match socket.read().map_err(ws_error)? {
                    Message::Text(text) => match relay_status(text.as_str())? {
                        RelayStatus::Authenticated => break,
                        RelayStatus::Ready => return Err(Error::InvalidResponse),
                    },
                    Message::Ping(_) => socket.flush().map_err(ws_error)?,
                    Message::Pong(_) => {}
                    _ => return Err(Error::InvalidResponse),
                }
            }
            socket.set_config(|c| {
                c.max_message_size = Some(MAX_TRANSPORT_FRAME_LEN);
                c.max_frame_size = Some(MAX_TRANSPORT_FRAME_LEN);
            });
            state.check()?;
            socket.get_mut().sock.state = None;
            Ok(RelayConnection {
                socket: Some(socket),
                ready_deadline: Some(deadline),
            })
        })
    }
}
fn config(limit: usize) -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(1024)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * MAX_TRANSPORT_FRAME_LEN + 512)
        .max_message_size(Some(limit))
        .max_frame_size(Some(limit))
}

/// An admitted socket carries no owner proof and retains no borrowed Operation,
/// callback or HTTP budget. Every binary operation needs its own original bound.
/// Any failure (including cancellation, malformed input or uncertain write)
/// consumes/closes this connection. No queued application bytes are resent.
pub struct RelayConnection {
    socket: Option<Socket>,
    // Until the relay reports `ready`: the ticket bound the old blocking wait had.
    ready_deadline: Option<Instant>,
}
enum RelayStatus {
    Authenticated,
    Ready,
}
fn relay_status(text: &str) -> Result<RelayStatus> {
    #[derive(Deserialize)]
    #[serde(tag = "type", deny_unknown_fields)]
    enum Status {
        #[serde(rename = "authenticated")]
        Authenticated {
            #[serde(rename = "expiresAt")]
            expires_at: u64,
        },
        #[serde(rename = "ready")]
        Ready {},
    }
    match serde_json::from_str::<Status>(text).map_err(|_| Error::InvalidResponse)? {
        Status::Authenticated { expires_at }
            if (1..=9_007_199_254_740_991).contains(&expires_at) =>
        {
            Ok(RelayStatus::Authenticated)
        }
        Status::Ready {} => Ok(RelayStatus::Ready),
        _ => Err(Error::InvalidResponse),
    }
}
enum Polled {
    Frame(Vec<u8>),
    Ready,
    Pending,
}
impl fmt::Debug for RelayConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayConnection")
    }
}
impl RelayConnection {
    pub fn is_closed(&self) -> bool {
        self.socket.is_none()
    }
    /// Descriptor of the underlying TCP stream, only for a readiness wait
    /// (poll). Never read, write or close through it.
    #[cfg(unix)]
    pub fn wait_fd(&self) -> Option<std::os::fd::RawFd> {
        use std::os::fd::AsRawFd;
        self.socket
            .as_ref()
            .map(|socket| socket.get_ref().get_ref().tcp.as_raw_fd())
    }
    /// Immediate local shutdown. Never waits for a peer close handshake.
    pub fn close(&mut self) {
        self.socket.take();
    }

    pub fn send_binary(
        &mut self,
        ciphertext: &[u8],
        original_deadline: Instant,
        check: &(dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> Result<()> {
        if ciphertext.is_empty()
            || ciphertext.len() > MAX_TRANSPORT_FRAME_LEN
            || self.ready_deadline.is_some()
        {
            self.close();
            return Err(Error::Request);
        }
        self.operation(original_deadline, check, |socket, state| {
            state.check()?;
            // send queues exactly once and flushes. Any partial/unknown failure
            // drops the entire socket instead of retrying a Message or flush.
            socket
                .send(Message::Binary(ciphertext.to_vec().into()))
                .map_err(ws_error)?;
            state.check()?;
            Ok(())
        })
    }
    /// Cooperatively inspect at most one incoming WebSocket message. WouldBlock
    /// preserves the same rustls and tungstenite parser, including partial TLS
    /// records and fragmented WebSocket messages. Only real budget expiry closes.
    pub fn poll_binary(
        &mut self,
        original_deadline: Instant,
        check: &(dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> Result<std::task::Poll<Vec<u8>>> {
        let awaiting_ready = self.ready_deadline;
        if awaiting_ready.is_some_and(|deadline| Instant::now() >= deadline) {
            self.close();
            return Err(Error::Timeout);
        }
        let deadline =
            awaiting_ready.map_or(original_deadline, |ready| ready.min(original_deadline));
        let polled = self.operation(deadline, check, |socket, state| {
            state.check()?;
            socket.get_mut().sock.polling = true;
            let read = socket.read();
            socket.get_mut().sock.polling = false;
            state.check()?;
            match read {
                Ok(Message::Binary(bytes))
                    if awaiting_ready.is_none()
                        && !bytes.is_empty()
                        && bytes.len() <= MAX_TRANSPORT_FRAME_LEN =>
                {
                    Ok(Polled::Frame(bytes.to_vec()))
                }
                Ok(Message::Text(text)) if awaiting_ready.is_some() => {
                    match relay_status(text.as_str())? {
                        RelayStatus::Ready => Ok(Polled::Ready),
                        RelayStatus::Authenticated => Err(Error::InvalidResponse),
                    }
                }
                Ok(Message::Ping(_)) => {
                    // A pong flush is a write: uncertainty is terminal.
                    socket.flush().map_err(ws_error)?;
                    state.check()?;
                    Ok(Polled::Pending)
                }
                Ok(Message::Pong(_)) => Ok(Polled::Pending),
                Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    Ok(Polled::Pending)
                }
                Err(error) => Err(ws_error(error)),
                _ => Err(Error::InvalidResponse),
            }
        })?;
        Ok(match polled {
            Polled::Frame(bytes) => std::task::Poll::Ready(bytes),
            Polled::Ready => {
                self.ready_deadline = None;
                std::task::Poll::Pending
            }
            Polled::Pending => std::task::Poll::Pending,
        })
    }
    pub fn read_binary(
        &mut self,
        original_deadline: Instant,
        check: &(dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> Result<Vec<u8>> {
        if self.ready_deadline.is_some() {
            self.close();
            return Err(Error::Request);
        }
        self.operation(original_deadline, check, |socket, state| {
            loop {
                state.check()?;
                match socket.read().map_err(ws_error)? {
                    Message::Binary(bytes)
                        if !bytes.is_empty() && bytes.len() <= MAX_TRANSPORT_FRAME_LEN =>
                    {
                        state.check()?;
                        return Ok(bytes.to_vec());
                    }
                    Message::Ping(_) => socket.flush().map_err(ws_error)?,
                    Message::Pong(_) => {}
                    _ => return Err(Error::InvalidResponse),
                }
            }
        })
    }
    fn operation<T>(
        &mut self,
        deadline: Instant,
        check: &budget::Check<'_>,
        perform: impl FnOnce(&mut Socket, &budget::State) -> Result<T>,
    ) -> Result<T> {
        // Taken before all checks: error/unwind can never leave a replayable
        // tungstenite write buffer or a socket with a borrowed budget behind.
        let mut socket = self.socket.take().ok_or(Error::RelayClosed)?;
        let result = budget::run(deadline, check, |state| {
            socket.get_mut().sock.state = Some(state.clone());
            perform(&mut socket, &state)
        });
        if result.is_ok() {
            socket.get_mut().sock.state = None;
            self.socket = Some(socket);
        }
        result
    }
}

fn ws_error(error: tungstenite::Error) -> Error {
    match error {
        tungstenite::Error::Http(response) if response.status().is_redirection() => Error::Redirect,
        tungstenite::Error::Http(_) => Error::HttpStatus,
        tungstenite::Error::Capacity(_) => Error::ResponseTooLarge,
        tungstenite::Error::ConnectionClosed | tungstenite::Error::AlreadyClosed => {
            Error::RelayClosed
        }
        tungstenite::Error::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Error::Timeout
        }
        tungstenite::Error::Io(_) | tungstenite::Error::Tls(_) => Error::Network,
        _ => Error::InvalidResponse,
    }
}
struct RelaySocket {
    tcp: TcpStream,
    state: Option<Arc<budget::State>>,
    polling: bool,
}

impl RelaySocket {
    fn write_tcp(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tcp.write(bytes)
    }
    fn current(&self) -> io::Result<&budget::State> {
        let state = self
            .state
            .as_deref()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))?;
        state
            .check()
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        Ok(state)
    }
    fn pause(&self, write: bool) -> io::Result<()> {
        let remaining = self
            .current()?
            .check()
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        budget::wait_ready(&self.tcp, write, QUANTUM.min(remaining));
        self.current()?;
        Ok(())
    }
}
impl Read for RelaySocket {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        loop {
            self.current()?;
            match self.tcp.read(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock && self.polling => {
                    return Err(error);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.pause(false)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    self.current()?;
                    if let Ok(n) = &result {
                        BYTES_READ.fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
                    }
                    return result;
                }
            }
        }
    }
}
impl Write for RelaySocket {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        loop {
            self.current()?;
            match self.write_tcp(bytes) {
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.pause(true)?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    self.current()?;
                    return result;
                }
            }
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        self.current()?;
        Ok(())
    }
}
impl Drop for RelaySocket {
    fn drop(&mut self) {
        let _ = self.tcp.shutdown(Shutdown::Both);
    }
}

#[cfg(test)]
mod tests {
    use super::{RelayStatus, relay_status};

    #[test]
    fn loopback_relay_endpoints_with_explicit_ports_are_canonical() {
        for host in ["localhost", "127.0.0.1"] {
            let endpoint = format!("wss://{host}:8445/v2/relay");
            assert!(super::LocalRelayEndpoint::try_from(endpoint).is_ok());
        }
    }

    #[test]
    fn relay_status_accepts_only_exact_authenticated_and_ready() {
        assert!(matches!(
            relay_status(r#"{"type":"authenticated","expiresAt":1}"#),
            Ok(RelayStatus::Authenticated)
        ));
        assert!(matches!(
            relay_status(r#"{"type":"ready"}"#),
            Ok(RelayStatus::Ready)
        ));
        for text in [
            r#"{"type":"authenticated","expiresAt":0}"#,
            r#"{"type":"authenticated","expiresAt":9007199254740992}"#,
            r#"{"type":"ready","extra":1}"#,
            r#"{"type":"other"}"#,
            "not json",
        ] {
            assert!(relay_status(text).is_err(), "{text}");
        }
    }
}
