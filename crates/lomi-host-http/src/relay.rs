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
            let mut authenticated = false;
            loop {
                state.check()?;
                match socket.read().map_err(ws_error)? {
                    Message::Text(text) => {
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
                        match serde_json::from_str::<Status>(text.as_str())
                            .map_err(|_| Error::InvalidResponse)?
                        {
                            Status::Authenticated { expires_at }
                                if !authenticated
                                    && (1..=9_007_199_254_740_991).contains(&expires_at) =>
                            {
                                authenticated = true
                            }
                            Status::Ready {} if authenticated => break,
                            _ => return Err(Error::InvalidResponse),
                        }
                    }
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
        if ciphertext.is_empty() || ciphertext.len() > MAX_TRANSPORT_FRAME_LEN {
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
        self.operation(original_deadline, check, |socket, state| {
            state.check()?;
            socket.get_mut().sock.polling = true;
            let read = socket.read();
            socket.get_mut().sock.polling = false;
            state.check()?;
            match read {
                Ok(Message::Binary(bytes))
                    if !bytes.is_empty() && bytes.len() <= MAX_TRANSPORT_FRAME_LEN =>
                {
                    Ok(std::task::Poll::Ready(bytes.to_vec()))
                }
                Ok(Message::Ping(_)) => {
                    // A pong flush is a write: uncertainty is terminal.
                    socket.flush().map_err(ws_error)?;
                    state.check()?;
                    Ok(std::task::Poll::Pending)
                }
                Ok(Message::Pong(_)) => Ok(std::task::Poll::Pending),
                Err(tungstenite::Error::Io(error)) if error.kind() == io::ErrorKind::WouldBlock => {
                    Ok(std::task::Poll::Pending)
                }
                Err(error) => Err(ws_error(error)),
                _ => Err(Error::InvalidResponse),
            }
        })
    }
    pub fn read_binary(
        &mut self,
        original_deadline: Instant,
        check: &(dyn Fn() -> std::result::Result<(), BudgetStop> + Sync),
    ) -> Result<Vec<u8>> {
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
    fn pause(&self) -> io::Result<()> {
        let remaining = self
            .current()?
            .check()
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
        std::thread::sleep(QUANTUM.min(remaining));
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
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.pause()?,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                result => {
                    self.current()?;
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
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => self.pause()?,
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
