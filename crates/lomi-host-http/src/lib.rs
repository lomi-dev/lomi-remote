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
    ResponseTooLarge,
    InvalidResponse,
    ResolverUnavailable,
    RelayClosed,
    #[cfg(feature = "test-fixtures")]
    FixtureTls,
    #[cfg(feature = "test-fixtures")]
    FixtureIoConnect,
    #[cfg(feature = "test-fixtures")]
    FixtureIoTls,
    #[cfg(feature = "test-fixtures")]
    FixtureIoOther,
    #[cfg(feature = "test-fixtures")]
    FixtureConnect,
    #[cfg(feature = "test-fixtures")]
    FixtureHost,
    #[cfg(feature = "test-fixtures")]
    FixtureProtocol,
    #[cfg(feature = "test-fixtures")]
    FixtureOther,
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
            Self::ResponseTooLarge => "HOST_HTTP_RESPONSE_LIMIT",
            Self::InvalidResponse => "HOST_HTTP_RESPONSE",
            Self::ResolverUnavailable => "HOST_HTTP_RESOLVER",
            Self::RelayClosed => "HOST_RELAY_CLOSED",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureTls => "HOST_HTTP_FIXTURE_TLS",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureIoConnect => "HOST_HTTP_FIXTURE_IO_CONNECT",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureIoTls => "HOST_HTTP_FIXTURE_IO_TLS",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureIoOther => "HOST_HTTP_FIXTURE_IO_OTHER",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureConnect => "HOST_HTTP_FIXTURE_CONNECT",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureHost => "HOST_HTTP_FIXTURE_HOST",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureProtocol => "HOST_HTTP_FIXTURE_PROTOCOL",
            #[cfg(feature = "test-fixtures")]
            Self::FixtureOther => "HOST_HTTP_FIXTURE_OTHER",
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
    #[cfg(any(test, feature = "test-fixtures"))]
    pub fn with_test_root(config: &Config, root_der: &[u8]) -> Result<Self> {
        let tls = ureq::tls::TlsConfig::builder()
            .provider(ureq::tls::TlsProvider::Rustls)
            .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .root_certs(ureq::tls::RootCerts::new_with_certs(&[
                ureq::tls::Certificate::from_der(root_der).to_owned(),
            ]))
            .build();
        Self::with_tls(config, tls)
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
    #[cfg(feature = "test-fixtures")]
    {
        match &error {
            ureq::Error::Timeout(_) => Error::Timeout,
            ureq::Error::Tls(_) | ureq::Error::Rustls(_) => Error::FixtureTls,
            ureq::Error::Io(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
                Error::FixtureIoConnect
            }
            ureq::Error::Io(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::InvalidData
                        | io::ErrorKind::ConnectionReset
                ) =>
            {
                Error::FixtureIoTls
            }
            ureq::Error::Io(_) => Error::FixtureIoOther,
            ureq::Error::HostNotFound => Error::FixtureHost,
            ureq::Error::ConnectionFailed => Error::FixtureConnect,
            ureq::Error::Protocol(_) => Error::FixtureProtocol,
            _ => Error::FixtureOther,
        }
    }
    #[cfg(not(feature = "test-fixtures"))]
    {
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
mod tests {
    include!("tests.rs");
    mod relay_tests {
        include!("relay_tests.rs");
    }
    mod budget_network_tests {
        include!("budget_network_tests.rs");
    }
    mod data_tests {
        include!("data_tests.rs");
    }
}
