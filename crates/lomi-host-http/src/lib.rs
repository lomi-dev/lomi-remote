//! Blocking HTTPS/WSS transport for host credential DTOs and opaque relay bytes. No retry policy.
//! Run on a dedicated bounded host worker, never a PTY or async executor thread.
use lomi_host_auth::Config;
use lomi_remote_protocol::*;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fmt,
    io::{self, Read, Write},
    sync::Arc,
    time::Duration,
};
use zeroize::Zeroizing;
mod budget;
mod data;
pub use budget::BudgetStop;
pub use budget_api::{BudgetDataTransport, BudgetTransport};
mod budget_api;
pub mod diagnostics;
mod relay;
mod resolver;
pub use data::{DataFailure, DataTransport, RemoteApiOrigin};
pub use relay::{RelayConnection, RelayTransport};

const REQUEST_LIMIT: usize = 16 * 1024;
const RESPONSE_LIMIT: usize = 32 * 1024;

/// Closed errors intentionally carry no library errors, headers, URLs or body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidConfig,
    Remote(HostFailure),
    DataRemote(DataFailure),
    Request,
    Network,
    Timeout,
    Cancelled,
    Redirect,
    HttpStatus,
    /// Temporary gateway failure; the server-side outcome remains unknown.
    GatewayUnavailable,
    ResponseTooLarge,
    InvalidResponse,
    ResolverUnavailable,
    RelayClosed,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidConfig => "HOST_HTTP_CONFIG",
            Self::Remote(failure) => failure.safe_code(),
            Self::DataRemote(failure) => failure.safe_code(),
            Self::Request => "HOST_HTTP_REQUEST",
            Self::Network => "HOST_HTTP_NETWORK",
            Self::Timeout => "HOST_HTTP_TIMEOUT",
            Self::Cancelled => "HOST_HTTP_CANCELLED",
            Self::Redirect => "HOST_HTTP_REDIRECT",
            Self::HttpStatus => "HOST_HTTP_STATUS",
            Self::GatewayUnavailable => "HOST_HTTP_GATEWAY_UNAVAILABLE",
            Self::ResponseTooLarge => "HOST_HTTP_RESPONSE_LIMIT",
            Self::InvalidResponse => "HOST_HTTP_RESPONSE",
            Self::ResolverUnavailable => "HOST_HTTP_RESOLVER",
            Self::RelayClosed => "HOST_RELAY_CLOSED",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;

/// Canonical credential-endpoint failures. No response-provided text is retained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostFailure {
    InvalidArgument,
    AuthRequired,
    ResourceNotFound,
    OutcomeUnknown,
    ServiceUnavailable,
}
impl HostFailure {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::InvalidArgument => ErrorCode::InvalidArgument,
            Self::AuthRequired => ErrorCode::AuthRequired,
            Self::ResourceNotFound => ErrorCode::ResourceNotFound,
            Self::OutcomeUnknown => ErrorCode::OutcomeUnknown,
            Self::ServiceUnavailable => ErrorCode::ServiceUnavailable,
        }
    }
    pub fn effect(self) -> Effect {
        if self == Self::OutcomeUnknown {
            Effect::Unknown
        } else {
            Effect::None
        }
    }
    pub fn retryable(self) -> bool {
        self == Self::ServiceUnavailable
    }
    fn safe_code(self) -> &'static str {
        match self {
            Self::InvalidArgument => "HOST_HTTP_INVALID_ARGUMENT",
            Self::AuthRequired => "HOST_HTTP_AUTH_REQUIRED",
            Self::ResourceNotFound => "HOST_HTTP_RESOURCE_NOT_FOUND",
            Self::OutcomeUnknown => "HOST_HTTP_OUTCOME_UNKNOWN",
            Self::ServiceUnavailable => "HOST_HTTP_SERVICE_UNAVAILABLE",
        }
    }
}

/// The caller owns cadence, original request identity, deadlines and durable state.
/// Success is authenticated to the configuration's origin; no response chooses a URL.
pub enum PollOutcome {
    Approved {
        bootstrap: EnrollmentBootstrapCredential,
        context: HostEnrollmentTokenContext,
        expires_in_seconds: u64,
    },
    Pending,
    SlowDown,
    Expired,
    Denied,
    InvalidRequest,
    InvalidGrant,
    RateLimited,
}

/// No public arbitrary URL, header, root certificate or proxy configuration.
/// Existing direct methods have transport-local caps only. Use `with_budget`
/// to bind a named request to its original operation.
pub struct Transport {
    budget: Option<Arc<budget::State>>,
    agent: ureq::Agent,
    origin: String,
    client: String,
}
impl Transport {
    pub fn new(config: &Config) -> Result<Self> {
        Self::with_tls(config, tls_config())
    }

    fn with_tls(config: &Config, tls: ureq::tls::TlsConfig) -> Result<Self> {
        // Config is publicly deserializable; its constructor is not a trust gate.
        config.validate().map_err(|_| {
            diagnostics::failure(
                ipc::DiagnosticCode::NetworkConfigurationInvalid,
                ipc::DoctorHealth::Unknown,
                ipc::DoctorHealth::Unknown,
            );
            Error::InvalidConfig
        })?;
        let agent = configured_agent(tls)?;
        Ok(Self {
            budget: None,
            agent,
            origin: config.origin().to_owned(),
            client: config.public_client_id().to_owned(),
        })
    }
    pub fn initiate(&self, request: &EnrollmentInitiateParams) -> Result<EnrollmentInitiateResult> {
        if request.client_id.expose_wire() != self.client {
            return Err(Error::Request);
        }
        self.post("/v2/remote/enrollments", request, None)
    }
    pub fn exchange(
        &self,
        request: &HostAuthorizationExchangeParams,
    ) -> Result<HostAuthorizationResult> {
        self.post("/v2/remote/host-authorizations/exchange", request, None)
    }
    pub fn refresh(
        &self,
        request: &HostAuthorizationRefreshParams,
    ) -> Result<HostAuthorizationResult> {
        self.post("/v2/remote/host-authorizations/refresh", request, None)
    }
    /// Only the credential returned alongside HostAuth::registration_request.
    pub fn register(
        &self,
        request: &HostRegisterParams,
        unconfirmed_access: &HostAccessCredential,
    ) -> Result<HostRegisterResult> {
        self.post(
            "/v2/remote/hosts/register",
            request,
            Some(unconfirmed_access),
        )
    }
    /// A revoked credential can acknowledge its own revocation without granting
    /// access elsewhere. Callers must validate the returned host and epoch.
    pub fn revoke(
        &self,
        host_id: HostId,
        request: &HostRevokeParams,
        access: &HostAccessCredential,
    ) -> Result<HostRevokeResult> {
        self.post(
            &format!("/v2/remote/hosts/{}/revoke", String::from(host_id)),
            request,
            Some(access),
        )
    }
    /// Acknowledges an already-revoked host authorization family with its
    /// retained refresh proof. The proof is sent only in the HTTPS JSON body;
    /// this request never uses Bearer or cookie authorization.
    pub fn revocation_ack(
        &self,
        host_id: HostId,
        request: &HostRevocationAckParams,
    ) -> Result<HostRevokeResult> {
        self.post(
            &format!("/v2/remote/hosts/{}/revocation-ack", String::from(host_id)),
            request,
            None,
        )
    }
    /// Retires one exact family using a fresh host-key proof. The request is
    /// authenticated by its HTTPS body proof, never by Bearer or cookie state.
    pub fn self_retire(
        &self,
        host_id: HostId,
        request: &HostSelfRetirementParams,
    ) -> Result<HostRevokeResult> {
        if request.validate_time_window().is_err() {
            return Err(Error::Request);
        }
        self.post(
            &format!("/v2/remote/hosts/{}/retire", String::from(host_id)),
            request,
            None,
        )
    }
    /// Acknowledges retirement of one historical enrollment using its signed
    /// enrollment proof. The proof is sent only in the HTTPS JSON body; this
    /// request never uses Bearer or cookie authorization.
    pub fn enrollment_revocation_ack(
        &self,
        host_id: HostId,
        request: &HostEnrollmentRevocationAckParams,
    ) -> Result<HostEnrollmentRevocationAckResult> {
        self.post(
            &format!(
                "/v2/remote/hosts/{}/enrollment-revocation-ack",
                String::from(host_id)
            ),
            request,
            None,
        )
    }
    pub fn poll(&self, device: &DeviceCode) -> Result<PollOutcome> {
        #[derive(Serialize)]
        struct Poll<'a> {
            grant_type: &'static str,
            device_code: &'a str,
            client_id: &'a str,
        }
        let request = Poll {
            grant_type: "urn:ietf:params:oauth:grant-type:device_code",
            device_code: device.expose_wire(),
            client_id: &self.client,
        };
        let (status, bytes) = self.send("/api/auth/device/token", &request, None)?;
        parse_poll(status, &bytes)
    }
    fn post<T: Serialize, R: DeserializeOwned>(
        &self,
        path: &str,
        request: &T,
        access: Option<&HostAccessCredential>,
    ) -> Result<R> {
        let (status, bytes) = self.send(path, request, access)?;
        if status != 200 {
            return Err(host_failure(status, &bytes));
        }
        decode(&bytes)
    }
    fn send<T: Serialize>(
        &self,
        path: &str,
        request: &T,
        access: Option<&HostAccessCredential>,
    ) -> Result<(u16, Zeroizing<Vec<u8>>)> {
        let body = encode(request)?;
        let url = format!("{}{path}", self.origin);
        let mut builder = self
            .agent
            .post(&url)
            .header("content-type", "application/json")
            .header("accept", "application/json");
        let bearer = access.map(|token| Zeroizing::new(format!("Bearer {}", token.expose_wire())));
        if let Some(value) = &bearer {
            builder = builder.header("authorization", value.as_str());
        }
        // One send only. POST bodies are never rebuilt or retried by this crate.
        let remaining = budget::remaining(self.budget.as_deref())?;
        let mut response = builder
            .config()
            .timeout_global(Some(remaining))
            .build()
            .send(body.as_slice())
            .map_err(network_error)?;
        diagnostics::response_received();
        let status = response.status().as_u16();
        // A gateway body is never credential authority; callers retain their exact intent.
        if matches!(status, 502 | 503 | 504) {
            return Err(Error::GatewayUnavailable);
        }
        if (300..400).contains(&status) {
            return Err(Error::Redirect);
        }
        let bytes = read_response(&mut response)?;
        Ok((status, bytes))
    }
}
fn configured_agent(tls: ureq::tls::TlsConfig) -> Result<ureq::Agent> {
    resolver::initialize().map_err(|_| {
        diagnostics::failure(
            ipc::DiagnosticCode::DnsUnavailable,
            ipc::DoctorHealth::TransportUnavailable,
            ipc::DoctorHealth::Unknown,
        );
        Error::ResolverUnavailable
    })?;
    let cfg = ureq::Agent::config_builder()
        .https_only(true)
        .proxy(None)
        .max_redirects(0)
        .max_redirects_will_error(false)
        .http_status_as_error(false)
        .max_response_header_size(16 * 1024)
        .max_idle_connections(0)
        .timeout_global(Some(Duration::from_secs(15)))
        .timeout_per_call(Some(Duration::from_secs(15)))
        .timeout_resolve(Some(Duration::from_secs(3)))
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_send_request(Some(Duration::from_secs(2)))
        .timeout_send_body(Some(Duration::from_secs(2)))
        .timeout_recv_response(Some(Duration::from_secs(5)))
        .timeout_recv_body(Some(Duration::from_secs(5)))
        .tls_config(tls)
        .build();
    Ok(ureq::Agent::with_parts(
        cfg,
        ureq::unversioned::transport::DefaultConnector::default(),
        resolver::BoundedResolver,
    ))
}
fn tls_config() -> ureq::tls::TlsConfig {
    ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .build()
}
fn network_error(error: ureq::Error) -> Error {
    diagnostics::transport_error(&error);
    match error {
        ureq::Error::Timeout(_) => Error::Timeout,
        ureq::Error::Io(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            Error::Timeout
        }
        _ => Error::Network,
    }
}
struct Bounded(Zeroizing<Vec<u8>>);
impl Write for Bounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > REQUEST_LIMIT - self.0.len() {
            return Err(io::Error::other("request limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn encode<T: Serialize>(value: &T) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = Bounded(Zeroizing::new(Vec::with_capacity(REQUEST_LIMIT)));
    serde_json::to_writer(&mut out, value).map_err(|_| Error::Request)?;
    Ok(out.0)
}
fn read_response(response: &mut ureq::http::Response<ureq::Body>) -> Result<Zeroizing<Vec<u8>>> {
    read_response_bounded(response, RESPONSE_LIMIT)
}
fn read_response_bounded(
    response: &mut ureq::http::Response<ureq::Body>,
    limit: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if let Some(length) = response.headers().get("content-length") {
        let length: u64 = length
            .to_str()
            .map_err(|_| Error::InvalidResponse)?
            .parse()
            .map_err(|_| Error::InvalidResponse)?;
        if length > limit as u64 {
            return Err(Error::ResponseTooLarge);
        }
    }
    validate_response_headers(response.headers())?;
    // One extra byte distinguishes an exact budget followed by EOF from overflow.
    // Never call read at allowance zero: ureq's LimitReader errors before EOF.
    let mut bytes = Zeroizing::new(vec![0; limit + 1]);
    let mut used = 0;
    let mut reader = response
        .body_mut()
        .with_config()
        .limit((limit + 1) as u64)
        .reader();
    loop {
        let read = reader
            .read(&mut bytes[used..])
            .map_err(|error| network_error(error.into()))?;
        if read == 0 {
            break;
        }
        used += read;
        if used > limit {
            return Err(Error::ResponseTooLarge);
        }
    }
    bytes.truncate(used);
    Ok(bytes)
}
fn validate_response_headers(headers: &ureq::http::HeaderMap) -> Result<()> {
    // Compression features are disabled, and no response may select a decoder.
    if headers.contains_key("content-encoding") {
        return Err(Error::InvalidResponse);
    }
    let mut values = headers.get_all("content-type").iter();
    let value = values.next().ok_or(Error::InvalidResponse)?;
    if values.next().is_some() {
        return Err(Error::InvalidResponse);
    }
    let value = value.to_str().map_err(|_| Error::InvalidResponse)?;
    let mut parts = value.split(';');
    if !parts
        .next()
        .unwrap_or_default()
        .trim()
        .eq_ignore_ascii_case("application/json")
    {
        return Err(Error::InvalidResponse);
    }
    if let Some(parameter) = parts.next() {
        let (name, charset) = parameter.split_once('=').ok_or(Error::InvalidResponse)?;
        let charset = charset.trim();
        if !name.trim().eq_ignore_ascii_case("charset")
            || !(charset.eq_ignore_ascii_case("utf-8") || charset.eq_ignore_ascii_case("\"utf-8\""))
            || parts.next().is_some()
        {
            return Err(Error::InvalidResponse);
        }
    }
    Ok(())
}
// These endpoint response schemas contain only objects and scalar fields.
// Serde's derived struct visitor also accepts positional arrays, so reject array
// delimiters before deserialization, while preserving brackets inside strings.
fn object_json(bytes: &[u8], restricted_text: bool) -> bool {
    if bytes.iter().find(|byte| !byte.is_ascii_whitespace()) != Some(&b'{')
        || (restricted_text && bytes.iter().any(|byte| !byte.is_ascii() || *byte == b'\\'))
    {
        return false;
    }
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'[' | b']' => return false,
                _ => {}
            }
        }
    }
    !quoted
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    // Existing strict secret alphabets need no escaping. Avoid serde's owned
    // escape scratch allocations for secret-bearing successful responses.
    if !object_json(bytes, true) {
        return Err(Error::InvalidResponse);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)
}
// Host credential errors are stricter than the protocol's general RemoteError:
// exactly five fields, empty object details and no operation/status lookup.
fn host_failure(status: u16, bytes: &[u8]) -> Error {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct HostError<'a> {
        code: ErrorCode,
        message: &'a str,
        retryable: bool,
        effect: Effect,
        details: EmptyDetails,
    }
    struct EmptyDetails;
    impl<'de> Deserialize<'de> for EmptyDetails {
        fn deserialize<D: serde::Deserializer<'de>>(
            deserializer: D,
        ) -> std::result::Result<Self, D::Error> {
            struct EmptyMap;
            impl<'de> serde::de::Visitor<'de> for EmptyMap {
                type Value = EmptyDetails;
                fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                    formatter.write_str("an empty details object")
                }
                fn visit_map<A: serde::de::MapAccess<'de>>(
                    self,
                    mut map: A,
                ) -> std::result::Result<EmptyDetails, A::Error> {
                    if map.next_key::<serde::de::IgnoredAny>()?.is_some() {
                        return Err(serde::de::Error::custom("nonempty details"));
                    }
                    Ok(EmptyDetails)
                }
            }
            deserializer.deserialize_map(EmptyMap)
        }
    }
    if !object_json(bytes, true) {
        return Error::HttpStatus;
    }
    let wire: HostError<'_> = match serde_json::from_slice(bytes) {
        Ok(wire) => wire,
        Err(_) => return Error::HttpStatus,
    };
    let failure = match wire.code {
        ErrorCode::InvalidArgument => HostFailure::InvalidArgument,
        ErrorCode::AuthRequired => HostFailure::AuthRequired,
        ErrorCode::ResourceNotFound => HostFailure::ResourceNotFound,
        ErrorCode::OutcomeUnknown => HostFailure::OutcomeUnknown,
        ErrorCode::ServiceUnavailable => HostFailure::ServiceUnavailable,
        _ => return Error::HttpStatus,
    };
    let _ = wire.details;
    if status != wire.code.http_status()
        || wire.message != wire.code.message()
        || wire.effect != failure.effect()
        || wire.retryable != failure.retryable()
    {
        return Error::HttpStatus;
    }
    Error::Remote(failure)
}

fn parse_poll(status: u16, bytes: &[u8]) -> Result<PollOutcome> {
    if status == 200 {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Approved<'a> {
            access_token: &'a str,
            token_type: &'a str,
            expires_in: u64,
            scope: &'a str,
            host_enrollment: HostEnrollmentTokenContext,
        }
        if !object_json(bytes, true) {
            return Err(Error::InvalidResponse);
        }
        let approved: Approved<'_> =
            serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
        if approved.token_type != "Bearer"
            || approved.expires_in == 0
            || approved.expires_in > 9_007_199_254_740_991
            || approved.scope.len() > 1024
        {
            return Err(Error::InvalidResponse);
        }
        let bootstrap = approved
            .access_token
            .to_owned()
            .try_into()
            .map_err(|_| Error::InvalidResponse)?;
        return Ok(PollOutcome::Approved {
            bootstrap,
            context: approved.host_enrollment,
            expires_in_seconds: approved.expires_in,
        });
    }
    if status == 429 {
        return Ok(PollOutcome::RateLimited);
    }
    if status != 400 && status != 403 {
        return Err(Error::HttpStatus);
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct OAuthError<'a> {
        error: &'a str,
        #[serde(default)]
        error_description: serde::de::IgnoredAny,
    }
    if !object_json(bytes, false) {
        return Err(Error::InvalidResponse);
    }
    let error: OAuthError<'_> =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)?;
    let _ = error.error_description;
    // The host enrollment transaction gate uses 403 for revoked, consumed,
    // expired or disabled enrollment. No other OAuth outcome is valid on 403.
    if status == 403 {
        return if error.error == "access_denied" {
            Ok(PollOutcome::Denied)
        } else {
            Err(Error::InvalidResponse)
        };
    }
    Ok(match error.error {
        "authorization_pending" => PollOutcome::Pending,
        "slow_down" => PollOutcome::SlowDown,
        "expired_token" => PollOutcome::Expired,
        "access_denied" => PollOutcome::Denied,
        "invalid_request" => PollOutcome::InvalidRequest,
        "invalid_grant" => PollOutcome::InvalidGrant,
        _ => return Err(Error::InvalidResponse),
    })
}

#[cfg(test)]
mod gateway_response_tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;
    use std::time::Instant;

    fn send_response(status: u16, headers: &str) -> Result<(u16, Zeroizing<Vec<u8>>)> {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let response =
            format!("HTTP/1.1 {status} Test\r\nConnection: close\r\n{headers}\r\n<html>");
        let server = thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let mut socket = loop {
                match listener.accept() {
                    Ok((socket, _)) => break socket,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        assert!(Instant::now() < deadline, "test client did not connect");
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("test accept failed: {error}"),
                }
            };
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096);
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let mut body = [0; 2];
            socket.read_exact(&mut body).unwrap();
            assert_eq!(&body, b"{}");
            std::io::Write::write_all(&mut socket, response.as_bytes()).unwrap();
        });
        // Exercise the production response path; only this private fixture permits HTTP.
        let agent = ureq::Agent::config_builder()
            .https_only(false)
            .proxy(None)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let transport = Transport {
            budget: None,
            agent,
            origin: format!("http://{address}"),
            client: "test".into(),
        };
        let result = transport.send("/test", &serde_json::json!({}), None);
        server.join().unwrap();
        result
    }

    fn send_self_retirement() -> (Result<HostRevokeResult>, String) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                socket.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let request_headers = String::from_utf8(headers.clone()).unwrap();
            let content_length = request_headers
                .lines()
                .find_map(|line| {
                    line.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .and_then(|length| length.parse::<usize>().ok())
                })
                .unwrap();
            let mut body = vec![0; content_length];
            socket.read_exact(&mut body).unwrap();
            let response_body =
                r#"{"hostId":"11111111-1111-4111-8111-111111111111","hostAccessEpoch":"3"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response_body}",
                response_body.len()
            );
            std::io::Write::write_all(&mut socket, response.as_bytes()).unwrap();
            (request_headers, body)
        });
        let agent = ureq::Agent::config_builder()
            .https_only(false)
            .proxy(None)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(Duration::from_secs(2)))
            .build()
            .into();
        let transport = Transport {
            budget: None,
            agent,
            origin: format!("http://{address}"),
            client: "test".into(),
        };
        let host_id = HostId::try_from("11111111-1111-4111-8111-111111111111".to_owned()).unwrap();
        let request: HostSelfRetirementParams = serde_json::from_str(
            r#"{"hostAuthorizationId":"22222222-2222-4222-8222-222222222222","operationId":"33333333-3333-4333-8333-333333333333","expectedHostAccessEpoch":"2","preparedAt":"1700000000","expiresAt":"1700000300","refresh":"refresh_token","proof":{"canonicalCbor":"aa","signature":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}"#,
        )
        .unwrap();
        let result = transport.self_retire(host_id, &request);
        let (headers, body) = server.join().unwrap();
        (
            result,
            format!("{headers}\n{}", String::from_utf8(body).unwrap()),
        )
    }

    #[test]
    fn self_retirement_posts_exact_host_route_without_bearer_or_cookie() {
        let (result, request) = send_self_retirement();
        assert_eq!(
            result.unwrap(),
            HostRevokeResult {
                host_id: HostId::try_from("11111111-1111-4111-8111-111111111111".to_owned())
                    .unwrap(),
                host_access_epoch: DecimalU64(3),
            }
        );
        let headers = request.split_once("\r\n\r\n").unwrap().0;
        assert!(
            headers.starts_with(
                "POST /v2/remote/hosts/11111111-1111-4111-8111-111111111111/retire HTTP/1.1\r\n"
            ),
            "unexpected request: {headers:?}"
        );
        let lower_headers = headers.to_ascii_lowercase();
        for forbidden in ["authorization:", "cookie:", "origin:", "sec-fetch-"] {
            assert!(
                !lower_headers.contains(forbidden),
                "unexpected {forbidden} header"
            );
        }
        assert!(request.contains("\"hostAuthorizationId\""));
        assert!(request.contains("\"proof\""));
    }

    #[test]
    fn opaque_gateway_responses_do_not_read_or_accept_the_body() {
        for status in [502, 503, 504] {
            for headers in [
                "Content-Type: text/html\r\nContent-Length: 6\r\n",
                "Content-Type: application/json\r\nContent-Encoding: gzip\r\nContent-Length: 6\r\n",
                "Content-Type: application/json\r\nContent-Length: 1000000000\r\n",
            ] {
                assert_eq!(
                    send_response(status, headers).unwrap_err(),
                    Error::GatewayUnavailable
                );
            }
        }
    }

    #[test]
    fn other_statuses_retain_strict_headers_and_redirect_rejection() {
        for status in [200, 401, 500] {
            assert_eq!(
                send_response(status, "Content-Type: text/html\r\nContent-Length: 6\r\n")
                    .unwrap_err(),
                Error::InvalidResponse
            );
        }
        assert_eq!(
            send_response(
                302,
                "Location: https://unexpected.example/\r\nContent-Length: 6\r\n"
            )
            .unwrap_err(),
            Error::Redirect
        );
    }
}
