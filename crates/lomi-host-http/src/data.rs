//! Fixed host-access data routes; callers retain all runtime and consent policy.
use super::*;

struct DataBounded(Zeroizing<Vec<u8>>, usize);
impl Write for DataBounded {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.1 - self.0.len() {
            return Err(io::Error::other("request limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) fn encode_bounded<T: Serialize>(value: &T, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut out = DataBounded(Zeroizing::new(Vec::with_capacity(limit)), limit);
    serde_json::to_writer(&mut out, value).map_err(|_| Error::Request)?;
    Ok(out.0)
}

const LARGE: usize = 1024 * 1024;
const PAIRING_RESPONSE: usize = 128 * 1024;

/// Canonical data-route failures, separate from credential endpoint semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataFailure {
    InvalidArgument,
    AuthRequired,
    ScopeDenied,
    ResourceNotFound,
    StaleEpoch,
    HostBusy,
    IdempotencyConflict,
    ResourceExhausted,
    OutcomeUnknown,
    ServiceUnavailable,
}
impl DataFailure {
    pub fn code(self) -> ErrorCode {
        match self {
            Self::InvalidArgument => ErrorCode::InvalidArgument,
            Self::AuthRequired => ErrorCode::AuthRequired,
            Self::ScopeDenied => ErrorCode::ScopeDenied,
            Self::ResourceNotFound => ErrorCode::ResourceNotFound,
            Self::StaleEpoch => ErrorCode::StaleEpoch,
            Self::HostBusy => ErrorCode::HostBusy,
            Self::IdempotencyConflict => ErrorCode::IdempotencyConflict,
            Self::ResourceExhausted => ErrorCode::ResourceExhausted,
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
        matches!(
            self,
            Self::HostBusy | Self::ResourceExhausted | Self::ServiceUnavailable
        )
    }
    pub(super) fn safe_code(self) -> &'static str {
        match self {
            Self::InvalidArgument => "HOST_HTTP_DATA_INVALID_ARGUMENT",
            Self::AuthRequired => "HOST_HTTP_DATA_AUTH_REQUIRED",
            Self::ScopeDenied => "HOST_HTTP_DATA_SCOPE_DENIED",
            Self::ResourceNotFound => "HOST_HTTP_DATA_RESOURCE_NOT_FOUND",
            Self::StaleEpoch => "HOST_HTTP_DATA_STALE_EPOCH",
            Self::HostBusy => "HOST_HTTP_DATA_HOST_BUSY",
            Self::IdempotencyConflict => "HOST_HTTP_DATA_IDEMPOTENCY_CONFLICT",
            Self::ResourceExhausted => "HOST_HTTP_DATA_RESOURCE_EXHAUSTED",
            Self::OutcomeUnknown => "HOST_HTTP_DATA_OUTCOME_UNKNOWN",
            Self::ServiceUnavailable => "HOST_HTTP_DATA_SERVICE_UNAVAILABLE",
        }
    }
}
#[derive(Clone, Copy)]
pub(super) enum Scope {
    Runtime,
    Peer,
}

/// An explicitly pinned Remote API origin, distinct from the identity origin.
/// The caller must obtain this pin from trusted configuration, never a response.
/// No deserialization or mutation can bypass the canonical origin checks.
pub struct RemoteApiOrigin(pub(super) String);
impl RemoteApiOrigin {
    pub fn new(identity: &Config, pinned_remote_origin: String) -> Result<Self> {
        identity.validate().map_err(|_| Error::InvalidConfig)?;
        validate_remote_origin(&pinned_remote_origin)?;
        if pinned_remote_origin == identity.origin() {
            return Err(Error::InvalidConfig);
        }
        Ok(Self(pinned_remote_origin))
    }
}
// Match HostAuth Config's deliberately narrow canonical DNS/IPv4 authority
// syntax, without reusing its identity/audience configuration for data routing.
fn validate_remote_origin(origin: &str) -> Result<()> {
    let authority = origin
        .strip_prefix("https://")
        .ok_or(Error::InvalidConfig)?;
    let (hostname, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if origin.len() > 180
        || hostname.len() > 253
        || hostname.is_empty()
        || hostname.starts_with('.')
        || hostname.ends_with('.')
        || hostname.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
        || port.is_some_and(|p| {
            p.is_empty()
                || p.starts_with('0')
                || p == "443"
                || p.parse::<u16>().is_err()
                || !p.bytes().all(|b| b.is_ascii_digit())
        })
    {
        return Err(Error::InvalidConfig);
    }
    let last = hostname.rsplit('.').next().ok_or(Error::InvalidConfig)?;
    let numeric_ending = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .or_else(|| last.strip_prefix("0X"))
            .is_some_and(|suffix| suffix.bytes().all(|b| b.is_ascii_hexdigit()));
    if numeric_ending
        && !hostname
            .parse::<std::net::Ipv4Addr>()
            .is_ok_and(|address| address.to_string() == hostname)
    {
        return Err(Error::InvalidConfig);
    }
    Ok(())
}

/// Host-access data routes go only to the separately pinned Remote API listener.
/// Identity enrollment and credential methods remain on `Transport`.
/// Direct methods have transport-local caps only; use `with_budget` for an
/// original operation deadline and authoritative cancellation check.
pub struct DataTransport {
    pub(super) budget: Option<Arc<budget::State>>,
    pub(super) agent: ureq::Agent,
    pub(super) origin: RemoteApiOrigin,
}
impl DataTransport {
    pub fn new(origin: RemoteApiOrigin) -> Result<Self> {
        Self::with_tls(origin, tls_config())
    }

    pub(super) fn with_tls(origin: RemoteApiOrigin, tls: ureq::tls::TlsConfig) -> Result<Self> {
        Ok(Self {
            budget: None,
            agent: configured_agent(tls)?,
            origin,
        })
    }
    pub fn runtime_get(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<HostRuntimeGetResult> {
        self.data_get(
            &format!("/v2/remote/hosts/{}/runtime", String::from(host)),
            access,
            RESPONSE_LIMIT,
            Scope::Runtime,
        )
    }
    pub fn runtime_claim(
        &self,
        host: HostId,
        request: &RuntimeClaimParams,
        access: &HostAccessCredential,
    ) -> Result<RuntimeClaimResult> {
        self.data_mutate(
            "POST",
            &format!("/v2/remote/hosts/{}/runtime/claim", String::from(host)),
            request,
            access,
            LARGE,
            RESPONSE_LIMIT,
            Scope::Runtime,
        )
    }
    pub fn heartbeat(
        &self,
        host: HostId,
        request: &HeartbeatParams,
        access: &HostAccessCredential,
    ) -> Result<HeartbeatResult> {
        self.data_mutate(
            "POST",
            &format!("/v2/remote/hosts/{}/heartbeat", String::from(host)),
            request,
            access,
            LARGE,
            RESPONSE_LIMIT,
            Scope::Runtime,
        )
    }
    pub fn publication(
        &self,
        host: HostId,
        request: &PublicationParams,
        access: &HostAccessCredential,
    ) -> Result<PublicationResult> {
        self.data_mutate(
            "PUT",
            &format!("/v2/remote/hosts/{}/publication", String::from(host)),
            request,
            access,
            LARGE,
            RESPONSE_LIMIT,
            Scope::Runtime,
        )
    }
    /// Pending reads may commit tombstones. A failed GET does not imply no effect.
    pub fn pairing_pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<PairingPendingResult> {
        self.data_get(
            &format!("/v2/remote/hosts/{}/pairings/pending", String::from(host)),
            access,
            LARGE,
            Scope::Peer,
        )
    }
    /// Reconcile an exact retained decision; callers recheck current authority.
    /// A read can commit expiry tombstones; failure does not imply no effect.
    pub fn pairing_get(
        &self,
        pairing: PairingId,
        access: &HostAccessCredential,
    ) -> Result<PairingResult> {
        self.data_get(
            &format!("/v2/remote/pairings/{}", String::from(pairing)),
            access,
            PAIRING_RESPONSE,
            Scope::Peer,
        )
    }
    pub fn pairing_decision(
        &self,
        pairing: PairingId,
        request: &PairingDecisionParams,
        access: &HostAccessCredential,
    ) -> Result<PairingResult> {
        self.data_mutate(
            "POST",
            &format!("/v2/remote/pairings/{}/decision", String::from(pairing)),
            request,
            access,
            REQUEST_LIMIT,
            PAIRING_RESPONSE,
            Scope::Peer,
        )
    }
    /// Pending reads may commit tombstones. A failed GET does not imply no effect.
    pub fn channel_pending(
        &self,
        host: HostId,
        access: &HostAccessCredential,
    ) -> Result<ChannelPendingResult> {
        self.data_get(
            &format!("/v2/remote/hosts/{}/channels/pending", String::from(host)),
            access,
            LARGE,
            Scope::Peer,
        )
    }
    /// Reconcile retained admission without issuing a replacement ticket.
    /// Callers verify exact context and fresh authority before accepting it.
    pub fn channel_get(
        &self,
        channel: ChannelId,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult> {
        self.data_get(
            &format!("/v2/remote/channels/{}", String::from(channel)),
            access,
            LARGE,
            Scope::Peer,
        )
    }
    pub fn channel_admission(
        &self,
        channel: ChannelId,
        request: &ChannelAdmissionParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelResult> {
        self.data_mutate(
            "POST",
            &format!("/v2/remote/channels/{}/admission", String::from(channel)),
            request,
            access,
            REQUEST_LIMIT,
            LARGE,
            Scope::Peer,
        )
    }
    /// The caller retains the original observation time and ticket deadline.
    pub fn channel_ticket(
        &self,
        channel: ChannelId,
        request: &ChannelTicketParams,
        access: &HostAccessCredential,
    ) -> Result<ChannelTicketResult> {
        let result: ChannelTicketResult = self.data_mutate(
            "POST",
            &format!("/v2/remote/channels/{}/tickets", String::from(channel)),
            request,
            access,
            REQUEST_LIMIT,
            RESPONSE_LIMIT,
            Scope::Peer,
        )?;
        if !(1..=5000).contains(&result.expires_in_ms.0) {
            return Err(Error::InvalidResponse);
        }
        Ok(result)
    }
    fn data_get<R: DeserializeOwned>(
        &self,
        path: &str,
        access: &HostAccessCredential,
        limit: usize,
        scope: Scope,
    ) -> Result<R> {
        let bearer = Zeroizing::new(format!("Bearer {}", access.expose_wire()));
        let builder = self
            .agent
            .get(format!("{}{path}", self.origin.0))
            .header("accept", "application/json")
            .header("authorization", bearer.as_str());
        let remaining = budget::remaining(self.budget.as_deref())?;
        let response = builder
            .config()
            .timeout_global(Some(remaining))
            .build()
            .call()
            .map_err(network_error)?;
        diagnostics::response_received();
        data_response(response, limit, scope)
    }
    #[allow(clippy::too_many_arguments)]
    fn data_mutate<T: Serialize, R: DeserializeOwned>(
        &self,
        method: &str,
        path: &str,
        request: &T,
        access: &HostAccessCredential,
        request_limit: usize,
        response_limit: usize,
        scope: Scope,
    ) -> Result<R> {
        let body = encode_bounded(request, request_limit)?;
        let bearer = Zeroizing::new(format!("Bearer {}", access.expose_wire()));
        let url = format!("{}{path}", self.origin.0);
        let builder = if method == "PUT" {
            self.agent.put(url)
        } else {
            self.agent.post(url)
        };
        // One send only; no retry, body replay or semantic recovery.
        let builder = builder
            .header("accept", "application/json")
            .header("content-type", "application/json")
            .header("authorization", bearer.as_str());
        let remaining = budget::remaining(self.budget.as_deref())?;
        let response = builder
            .config()
            .timeout_global(Some(remaining))
            .build()
            .send(body.as_slice())
            .map_err(data_mutation_network_error)?;
        diagnostics::response_received();
        data_response(response, response_limit, scope)
    }
}
fn data_mutation_network_error(error: ureq::Error) -> Error {
    diagnostics::transport_error(&error);
    // These failures happen before a connection can carry the HTTP mutation.
    // For errors after connect, ureq does not expose whether the request body
    // reached the server, so callers must reconcile instead of replaying it.
    let definitely_not_sent = match &error {
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => true,
        ureq::Error::Io(io_error) => io_error.kind() == io::ErrorKind::ConnectionRefused,
        _ => false,
    };
    if definitely_not_sent {
        network_error(error)
    } else {
        Error::DataRemote(DataFailure::OutcomeUnknown)
    }
}
fn data_response<R: DeserializeOwned>(
    mut response: ureq::http::Response<ureq::Body>,
    limit: usize,
    scope: Scope,
) -> Result<R> {
    let status = response.status().as_u16();
    if (300..400).contains(&status) {
        return Err(Error::Redirect);
    }
    let mut cache = response.headers().get_all("cache-control").iter();
    if cache.next().and_then(|v| v.to_str().ok()) != Some("no-store") || cache.next().is_some() {
        return Err(Error::InvalidResponse);
    }
    let bytes = read_response_bounded(&mut response, limit)?;
    if status != 200 {
        return Err(data_failure(status, &bytes, scope));
    }
    decode_data(&bytes)
}
pub(super) fn decode_data<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    // Canonical DTO map visitors reject positional DTO arrays while bounded list
    // wrappers accept actual lists. No intermediate secret-bearing JSON tree.
    if bytes.iter().find(|b| !b.is_ascii_whitespace()) != Some(&b'{')
        || bytes.iter().any(|b| !b.is_ascii() || *b == b'\\')
    {
        return Err(Error::InvalidResponse);
    }
    serde_json::from_slice(bytes).map_err(|_| Error::InvalidResponse)
}
pub(super) fn data_failure(status: u16, bytes: &[u8], scope: Scope) -> Error {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire<'a> {
        code: ErrorCode,
        message: &'a str,
        retryable: bool,
        effect: Effect,
        details: Empty,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Empty {}
    // Errors have no list fields, retaining the stricter object/scalar guard.
    if !object_json(bytes, true) {
        return Error::HttpStatus;
    }
    let Ok(wire) = serde_json::from_slice::<Wire<'_>>(bytes) else {
        return Error::HttpStatus;
    };
    let failure = match wire.code {
        ErrorCode::InvalidArgument => DataFailure::InvalidArgument,
        ErrorCode::AuthRequired => DataFailure::AuthRequired,
        ErrorCode::ScopeDenied => DataFailure::ScopeDenied,
        ErrorCode::ResourceNotFound => DataFailure::ResourceNotFound,
        ErrorCode::StaleEpoch => DataFailure::StaleEpoch,
        ErrorCode::OutcomeUnknown => DataFailure::OutcomeUnknown,
        ErrorCode::ServiceUnavailable => DataFailure::ServiceUnavailable,
        ErrorCode::HostBusy if matches!(scope, Scope::Runtime) => DataFailure::HostBusy,
        ErrorCode::IdempotencyConflict if matches!(scope, Scope::Peer) => {
            DataFailure::IdempotencyConflict
        }
        ErrorCode::ResourceExhausted if matches!(scope, Scope::Peer) => {
            DataFailure::ResourceExhausted
        }
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
    Error::DataRemote(failure)
}
