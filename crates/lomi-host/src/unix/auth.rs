//! Host-owned credential worker. Only this thread opens the selected provider.
use super::owner_domain::{Error as DomainError, Operation as OwnerOperation};
use super::shared_owner::{
    AuthSelectionSnapshot, AuthStatusSnapshot, Error as OwnerError, SharedOwner,
};
use super::*;
use lomi_host_auth::{Config, HostAuth, RetainedRevocationAcknowledgement, Status};
use lomi_host_http::{PollOutcome, Transport};
use lomi_platform::secrets::{self, SecretStorage, Selection};
use lomi_remote_protocol::{
    DecimalU64, HostEnrollmentRevocationAckParams, HostEnrollmentRevocationAckResult, OperationId,
    ipc::LocalAuthConfiguration,
};
use std::sync::mpsc::{self, SyncSender};
use std::time::{SystemTime, UNIX_EPOCH};
#[path = "channel.rs"]
pub(super) mod channel;
#[path = "cloud.rs"]
pub(super) mod cloud;
#[cfg(all(unix, test, feature = "cloud-fixture"))]
mod device_cycle_fixture;
#[path = "remote_ingress.rs"]
mod remote_ingress;

#[cfg(test)]
pub(super) use cloud::DataApi as CloudDataApi;
#[cfg(any(unix, windows))]
pub(super) use cloud::OwnedNormalPublicationObservation;
#[cfg(test)]
pub(super) use cloud::with_normal_publication_test_worker;
#[cfg(any(unix, windows))]
pub(super) use cloud::{
    NormalPublicationDriver, NormalPublicationObservation, NormalPublicationOriginError,
};
#[path = "peer.rs"]
pub(super) mod peer;
#[path = "remote_connection.rs"]
pub(super) mod remote_connection;

fn owner_local_error(error: OwnerError) -> LocalError {
    match error {
        OwnerError::Store(error) => store_error(error),
        _ => LocalError::Unavailable,
    }
}
fn owner_busy(error: &OwnerError) -> bool {
    matches!(
        error,
        OwnerError::Domain(DomainError::Busy) | OwnerError::Store(StoreError::Busy)
    )
}
// LoginStart reads a config/generation pair before admitting its one writer.
// If either snapshot is contended, retry the pair under the SAME operation so
// no stale config is combined with a later generation. The closure returns only
// owned snapshots; SharedOwner has dropped both guards before this wait.
fn login_start_snapshot(
    operation: &OwnerOperation<'_>,
    mut read_pair: impl FnMut() -> Result<(AuthSelectionSnapshot, AuthStatusSnapshot), OwnerError>,
) -> Result<(AuthSelectionSnapshot, AuthStatusSnapshot), LocalError> {
    loop {
        operation.check().map_err(|_| LocalError::Unavailable)?;
        match read_pair() {
            Ok(snapshot) => return Ok(snapshot),
            Err(error) if owner_busy(&error) => {
                let remaining = operation
                    .deadline()
                    .saturating_duration_since(std::time::Instant::now());
                let wait = remaining.min(Duration::from_millis(10));
                if !wait.is_zero() {
                    std::thread::park_timeout(wait);
                }
            }
            Err(error) => return Err(owner_local_error(error)),
        }
    }
}
// Retry only typed read contention, outside both owner guards. Never repeat a
// provider/effect stage, admit another operation, or turn ordinary Busy into a
// permanent authorization failure.
macro_rules! worker_read {
    ($runtime:expr, $read:expr) => {{
        let runtime = $runtime;
        loop {
            if let Err(error) = runtime.check() {
                break Err(error);
            }
            match $read {
                Ok(value) => break Ok(value),
                Err(error) if owner_busy(&error) => {
                    if let Err(error) = runtime.busy() {
                        break Err(error);
                    }
                }
                Err(error) => break Err(StepError::from(error)),
            }
        }
    }};
}
macro_rules! commit_local_turn {
    ($turn:expr, $operation:expr) => {{
        loop {
            $operation.check().map_err(|_| LocalError::Unavailable)?;
            match $turn.try_commit() {
                Err(error) if owner_busy(&error) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                result => break result.map_err(owner_local_error),
            }
        }
    }};
}
macro_rules! commit_worker_turn {
    ($turn:expr, $runtime:expr) => {{
        loop {
            if $runtime.check().is_err() {
                break Err(OwnerError::Domain(DomainError::Stale));
            }
            match $turn.try_commit() {
                Err(error) if owner_busy(&error) => {
                    if $runtime.busy().is_err() {
                        break Err(OwnerError::Domain(DomainError::Stale));
                    }
                }
                result => break result,
            }
        }
    }};
}

#[derive(Clone)]
pub(super) struct Handle {
    owner: Arc<SharedOwner>,
    wake: SyncSender<Command>,
    state: Arc<Mutex<View>>,
    retry_requested: Arc<AtomicBool>,
    gate: Arc<AtomicBool>,
    paused: Arc<AtomicBool>,
    #[cfg(any(unix, windows))]
    public_setup: Option<Arc<super::public_configuration::PublicSetup>>,
}
enum Command {
    Wake(OperationId),
    Configure,
    Logout,
}
struct View {
    status: LocalLoginStatus,
    presentation: Option<LocalLoginPresentation>,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    auth_poll_observation: Option<AuthPollObservation>,
}
fn initial() -> View {
    View {
        status: LocalLoginStatus {
            phase: LocalAuthPhase::Unconfigured,
            storage: LocalAuthStorage::Unconfigured,
            network: LocalAuthNetwork::Idle,
            generation: DecimalU64(0),
            locked: true,
            pending_cloud_revoke: false,
            operation_id: None,
            access_expires_at: None,
            refresh_at: None,
        },
        presentation: None,
        #[cfg(all(unix, test, feature = "cloud-fixture"))]
        auth_poll_observation: None,
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Default)]
struct AuthPollObservation {
    records: u8,
    overflow_emitted: bool,
    failure_emitted: bool,
    ready_records: Vec<AuthReadyRecord>,
    ready_overflow_emitted: bool,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthPollObservation {
    const RECORD_LIMIT: u8 = 16;
    const READY_RECORD_LIMIT: usize = 64;

    fn observe(
        &mut self,
        result: &Result<PollOutcome, lomi_host_http::Error>,
    ) -> Option<AuthPollTrace> {
        if self.overflow_emitted {
            return None;
        }
        if self.records == Self::RECORD_LIMIT {
            self.overflow_emitted = true;
            return Some(AuthPollTrace::Overflow);
        }
        self.records += 1;
        Some(AuthPollTrace::Record {
            ordinal: self.records,
            outcome: poll_outcome_label(result),
        })
    }

    fn observe_ready(&mut self, record: AuthReadyRecord) -> Option<AuthReadyTrace> {
        if self.ready_overflow_emitted || self.ready_records.contains(&record) {
            return None;
        }
        if self.ready_records.len() == Self::READY_RECORD_LIMIT {
            self.ready_overflow_emitted = true;
            return Some(AuthReadyTrace::Overflow);
        }
        self.ready_records.push(record);
        Some(AuthReadyTrace::Record(record))
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn observe_auth_poll(
    view: &mut View,
    result: &Result<PollOutcome, lomi_host_http::Error>,
) -> Option<AuthPollTrace> {
    view.auth_poll_observation.as_mut()?.observe(result)
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn observe_auth_ready(
    view: &mut View,
    stage: AuthReadyStage,
    outcome: AuthReadyOutcome,
) -> Option<AuthReadyTrace> {
    view.auth_poll_observation
        .as_mut()?
        .observe_ready(AuthReadyRecord { stage, outcome })
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn emit_auth_ready(state: &Mutex<View>, stage: AuthReadyStage, outcome: AuthReadyOutcome) {
    let trace = state
        .lock()
        .ok()
        .and_then(|mut view| observe_auth_ready(&mut view, stage, outcome));
    if let Some(trace) = trace {
        trace.emit();
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn observe_auth_failure(
    view: &mut View,
    phase: AuthFailurePhase,
    error: &lomi_host_auth::Error,
) -> Option<AuthFailureTrace> {
    let observation = view.auth_poll_observation.as_mut()?;
    if observation.failure_emitted {
        return None;
    }
    observation.failure_emitted = true;
    Some(AuthFailureTrace {
        phase,
        code: auth_failure_code(error),
    })
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn auth_failure_code(error: &lomi_host_auth::Error) -> AuthFailureCode {
    match error {
        lomi_host_auth::Error::InvalidResponse => AuthFailureCode::InvalidResponse,
        lomi_host_auth::Error::ClockRollback => AuthFailureCode::ClockRollback,
        lomi_host_auth::Error::Expired => AuthFailureCode::Expired,
        lomi_host_auth::Error::InvalidState => AuthFailureCode::InvalidState,
        lomi_host_auth::Error::InvalidBundle => AuthFailureCode::InvalidBundle,
        lomi_host_auth::Error::InvalidConfig => AuthFailureCode::InvalidConfig,
        lomi_host_auth::Error::Sealed => AuthFailureCode::Sealed,
        lomi_host_auth::Error::PollTooEarly => AuthFailureCode::PollTooEarly,
        lomi_host_auth::Error::Storage(_) => AuthFailureCode::Storage,
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum AuthReadyStage {
    Factory,
    Begin,
    Prepare,
    Send,
    Clock,
    Accept,
    Publish,
    Done,
    Abort,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthReadyStage {
    fn label(self) -> &'static str {
        match self {
            Self::Factory => "factory",
            Self::Begin => "begin",
            Self::Prepare => "prepare",
            Self::Send => "send",
            Self::Clock => "clock",
            Self::Accept => "accept",
            Self::Publish => "publish",
            Self::Done => "done",
            Self::Abort => "abort",
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthReadyFailure {
    Stale,
    DomainBusy,
    DomainStale,
    DomainCancelled,
    DomainDeadline,
    DomainOther,
    ProviderInvalidResponse,
    ProviderClockRollback,
    ProviderExpired,
    ProviderInvalidState,
    ProviderInvalidBundle,
    ProviderInvalidConfig,
    ProviderSealed,
    ProviderPollTooEarly,
    ProviderStorage,
    StoreBusy,
    StoreFenced,
    StoreStorage,
    StoreInvalid,
    StoreOther,
    HttpConfig,
    HttpResolver,
    HttpRequest,
    HttpNetwork,
    HttpTimeout,
    HttpCancelled,
    HttpTls,
    HttpConnect,
    HttpTransport,
    HttpInvalidResponse,
    HttpAuthRequired,
    HttpRemote,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthReadyFailure {
    fn label(self) -> &'static str {
        match self {
            Self::Stale => "error_stale",
            Self::DomainBusy => "error_domain_busy",
            Self::DomainStale => "error_domain_stale",
            Self::DomainCancelled => "error_domain_cancelled",
            Self::DomainDeadline => "error_domain_deadline",
            Self::DomainOther => "error_domain_other",
            Self::ProviderInvalidResponse => "error_provider_invalid_response",
            Self::ProviderClockRollback => "error_provider_clock_rollback",
            Self::ProviderExpired => "error_provider_expired",
            Self::ProviderInvalidState => "error_provider_invalid_state",
            Self::ProviderInvalidBundle => "error_provider_invalid_bundle",
            Self::ProviderInvalidConfig => "error_provider_invalid_config",
            Self::ProviderSealed => "error_provider_sealed",
            Self::ProviderPollTooEarly => "error_provider_poll_too_early",
            Self::ProviderStorage => "error_provider_storage",
            Self::StoreBusy => "error_store_busy",
            Self::StoreFenced => "error_store_fenced",
            Self::StoreStorage => "error_store_storage",
            Self::StoreInvalid => "error_store_invalid",
            Self::StoreOther => "error_store_other",
            Self::HttpConfig => "error_http_config",
            Self::HttpResolver => "error_http_resolver",
            Self::HttpRequest => "error_http_request",
            Self::HttpNetwork => "error_http_network",
            Self::HttpTimeout => "error_http_timeout",
            Self::HttpCancelled => "error_http_cancelled",
            Self::HttpTls => "error_http_tls",
            Self::HttpConnect => "error_http_connect",
            Self::HttpTransport => "error_http_transport",
            Self::HttpInvalidResponse => "error_http_invalid_response",
            Self::HttpAuthRequired => "error_http_auth_required",
            Self::HttpRemote => "error_http_remote",
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthReadyOutcome {
    Enter,
    Ok,
    Busy,
    Complete,
    Error(AuthReadyFailure),
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthReadyOutcome {
    fn label(self) -> &'static str {
        match self {
            Self::Enter => "enter",
            Self::Ok => "ok",
            Self::Busy => "busy",
            Self::Complete => "complete",
            Self::Error(error) => error.label(),
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthReadyRecord {
    stage: AuthReadyStage,
    outcome: AuthReadyOutcome,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthReadyTrace {
    Record(AuthReadyRecord),
    Overflow,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthReadyTrace {
    fn write_to(self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Record(record) => writeln!(
                output,
                "LOMI_AUTH_ACTOR_READY={}:{}",
                record.stage.label(),
                record.outcome.label()
            ),
            Self::Overflow => writeln!(output, "LOMI_AUTH_ACTOR_READY=overflow"),
        }
    }

    fn emit(self) {
        use std::io::Write as _;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        if self.write_to(&mut output).is_ok() {
            let _ = output.flush();
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn auth_ready_failure(error: &super::shared_owner::WorkerReadyError) -> AuthReadyFailure {
    match error {
        super::shared_owner::WorkerReadyError::Stale => AuthReadyFailure::Stale,
        super::shared_owner::WorkerReadyError::Domain(DomainError::Busy) => {
            AuthReadyFailure::DomainBusy
        }
        super::shared_owner::WorkerReadyError::Domain(DomainError::Stale) => {
            AuthReadyFailure::DomainStale
        }
        super::shared_owner::WorkerReadyError::Domain(DomainError::Cancelled) => {
            AuthReadyFailure::DomainCancelled
        }
        super::shared_owner::WorkerReadyError::Domain(DomainError::Deadline) => {
            AuthReadyFailure::DomainDeadline
        }
        super::shared_owner::WorkerReadyError::Domain(_) => AuthReadyFailure::DomainOther,
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::InvalidResponse) => {
            AuthReadyFailure::ProviderInvalidResponse
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::ClockRollback) => {
            AuthReadyFailure::ProviderClockRollback
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::Expired) => {
            AuthReadyFailure::ProviderExpired
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::InvalidState) => {
            AuthReadyFailure::ProviderInvalidState
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::InvalidBundle) => {
            AuthReadyFailure::ProviderInvalidBundle
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::InvalidConfig) => {
            AuthReadyFailure::ProviderInvalidConfig
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::Sealed) => {
            AuthReadyFailure::ProviderSealed
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::PollTooEarly) => {
            AuthReadyFailure::ProviderPollTooEarly
        }
        super::shared_owner::WorkerReadyError::Provider(lomi_host_auth::Error::Storage(_)) => {
            AuthReadyFailure::ProviderStorage
        }
        super::shared_owner::WorkerReadyError::Store(lomi_host_store::StoreError::Busy) => {
            AuthReadyFailure::StoreBusy
        }
        super::shared_owner::WorkerReadyError::Store(lomi_host_store::StoreError::Fenced) => {
            AuthReadyFailure::StoreFenced
        }
        super::shared_owner::WorkerReadyError::Store(lomi_host_store::StoreError::Storage) => {
            AuthReadyFailure::StoreStorage
        }
        super::shared_owner::WorkerReadyError::Store(lomi_host_store::StoreError::Invalid) => {
            AuthReadyFailure::StoreInvalid
        }
        super::shared_owner::WorkerReadyError::Store(_) => AuthReadyFailure::StoreOther,
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::InvalidConfig) => {
            AuthReadyFailure::HttpConfig
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::ResolverUnavailable) => {
            AuthReadyFailure::HttpResolver
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::Request) => {
            AuthReadyFailure::HttpRequest
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::Network) => {
            AuthReadyFailure::HttpNetwork
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::Timeout) => {
            AuthReadyFailure::HttpTimeout
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::Cancelled) => {
            AuthReadyFailure::HttpCancelled
        }
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::FixtureTls)
        | super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::FixtureIoTls) => {
            AuthReadyFailure::HttpTls
        }
        super::shared_owner::WorkerReadyError::Http(
            lomi_host_http::Error::FixtureIoConnect | lomi_host_http::Error::FixtureConnect,
        ) => AuthReadyFailure::HttpConnect,
        super::shared_owner::WorkerReadyError::Http(
            lomi_host_http::Error::InvalidResponse
            | lomi_host_http::Error::Redirect
            | lomi_host_http::Error::HttpStatus
            | lomi_host_http::Error::ResponseTooLarge
            | lomi_host_http::Error::FixtureProtocol,
        ) => AuthReadyFailure::HttpInvalidResponse,
        super::shared_owner::WorkerReadyError::Http(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired,
        )) => AuthReadyFailure::HttpAuthRequired,
        super::shared_owner::WorkerReadyError::Http(
            lomi_host_http::Error::Remote(_) | lomi_host_http::Error::DataRemote(_),
        ) => AuthReadyFailure::HttpRemote,
        super::shared_owner::WorkerReadyError::Http(
            lomi_host_http::Error::RelayClosed
            | lomi_host_http::Error::FixtureIoOther
            | lomi_host_http::Error::FixtureHost
            | lomi_host_http::Error::FixtureOther,
        ) => AuthReadyFailure::HttpTransport,
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn emit_auth_ready_error(
    state: &Mutex<View>,
    stage: AuthReadyStage,
    error: &super::shared_owner::WorkerReadyError,
) {
    emit_auth_ready(
        state,
        stage,
        AuthReadyOutcome::Error(auth_ready_failure(error)),
    );
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn emit_auth_failure(state: &Mutex<View>, phase: AuthFailurePhase, error: &lomi_host_auth::Error) {
    let trace = state
        .lock()
        .ok()
        .and_then(|mut view| observe_auth_failure(&mut view, phase, error));
    if let Some(trace) = trace {
        trace.emit();
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailurePhase {
    Approve,
    PrepareExchange,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthFailurePhase {
    fn label(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::PrepareExchange => "prepare_exchange",
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailureCode {
    InvalidResponse,
    ClockRollback,
    Expired,
    InvalidState,
    InvalidBundle,
    InvalidConfig,
    Sealed,
    PollTooEarly,
    Storage,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthFailureCode {
    fn label(self) -> &'static str {
        match self {
            Self::InvalidResponse => "invalid_response",
            Self::ClockRollback => "clock_rollback",
            Self::Expired => "expired",
            Self::InvalidState => "invalid_state",
            Self::InvalidBundle => "invalid_bundle",
            Self::InvalidConfig => "invalid_config",
            Self::Sealed => "sealed",
            Self::PollTooEarly => "poll_too_early",
            Self::Storage => "storage",
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AuthFailureTrace {
    phase: AuthFailurePhase,
    code: AuthFailureCode,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthFailureTrace {
    fn write_to(self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        writeln!(
            output,
            "LOMI_AUTH_ACTOR_FAILURE={}:{}",
            self.phase.label(),
            self.code.label()
        )
    }

    fn emit(self) {
        use std::io::Write as _;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        if self.write_to(&mut output).is_ok() {
            let _ = output.flush();
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn poll_outcome_label(result: &Result<PollOutcome, lomi_host_http::Error>) -> &'static str {
    match result {
        Ok(PollOutcome::Pending) => "authorization_pending",
        Ok(PollOutcome::SlowDown) => "slow_down",
        Ok(PollOutcome::RateLimited) => "rate_limited",
        Ok(PollOutcome::Approved { .. }) => "approved",
        Ok(PollOutcome::Expired) => "expired_token",
        Ok(PollOutcome::Denied) => "access_denied",
        Ok(PollOutcome::InvalidRequest) => "invalid_request",
        Ok(PollOutcome::InvalidGrant) => "invalid_grant",
        Err(_) => "rejected_response",
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Debug, PartialEq, Eq)]
enum AuthPollTrace {
    Record { ordinal: u8, outcome: &'static str },
    Overflow,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl AuthPollTrace {
    fn write_to(&self, output: &mut impl std::io::Write) -> std::io::Result<()> {
        match self {
            Self::Record { ordinal, outcome } => {
                writeln!(output, "LOMI_AUTH_ACTOR_POLL={ordinal}:{outcome}")
            }
            Self::Overflow => writeln!(output, "LOMI_AUTH_ACTOR_POLL=overflow"),
        }
    }

    fn emit(self) {
        use std::io::Write as _;

        let stdout = std::io::stdout();
        let mut output = stdout.lock();
        if self.write_to(&mut output).is_ok() {
            let _ = output.flush();
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
mod auth_poll_observation_tests {
    use super::*;

    fn approved() -> PollOutcome {
        PollOutcome::Approved {
            bootstrap: "synthetic_bootstrap".to_owned().try_into().unwrap(),
            context: lomi_remote_protocol::HostEnrollmentTokenContext {
                account_id: lomi_remote_protocol::AccountId::from_bytes([1; 16]).unwrap(),
                challenge: "aa".to_owned().try_into().unwrap(),
            },
            expires_in_seconds: 300,
        }
    }

    #[test]
    fn auth_poll_observation_is_disabled_by_default() {
        let mut view = initial();
        assert!(observe_auth_poll(&mut view, &Ok(PollOutcome::Pending)).is_none());
        assert!(view.auth_poll_observation.is_none());
        assert!(
            observe_auth_failure(
                &mut view,
                AuthFailurePhase::Approve,
                &lomi_host_auth::Error::ClockRollback,
            )
            .is_none()
        );
    }

    #[test]
    fn auth_failure_trace_uses_closed_labels_and_emits_once() {
        let cases = [
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::InvalidResponse,
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_response\n",
            ),
            (
                AuthFailurePhase::PrepareExchange,
                lomi_host_auth::Error::ClockRollback,
                "LOMI_AUTH_ACTOR_FAILURE=prepare_exchange:clock_rollback\n",
            ),
            (
                AuthFailurePhase::PrepareExchange,
                lomi_host_auth::Error::Expired,
                "LOMI_AUTH_ACTOR_FAILURE=prepare_exchange:expired\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::InvalidState,
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_state\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::InvalidBundle,
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_bundle\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::InvalidConfig,
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_config\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::Sealed,
                "LOMI_AUTH_ACTOR_FAILURE=approve:sealed\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::PollTooEarly,
                "LOMI_AUTH_ACTOR_FAILURE=approve:poll_too_early\n",
            ),
            (
                AuthFailurePhase::Approve,
                lomi_host_auth::Error::Storage(secrets::Error::Io),
                "LOMI_AUTH_ACTOR_FAILURE=approve:storage\n",
            ),
        ];
        let mut output = Vec::new();
        for (phase, error, expected) in cases {
            let mut view = initial();
            view.auth_poll_observation = Some(AuthPollObservation::default());
            let trace = observe_auth_failure(&mut view, phase, &error).unwrap();
            trace.write_to(&mut output).unwrap();
            assert!(observe_auth_failure(&mut view, phase, &error).is_none());
            assert!(view.auth_poll_observation.as_ref().unwrap().failure_emitted);
            assert_eq!(
                String::from_utf8(output.clone()).unwrap().lines().last(),
                Some(expected.trim_end())
            );
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_response\n",
                "LOMI_AUTH_ACTOR_FAILURE=prepare_exchange:clock_rollback\n",
                "LOMI_AUTH_ACTOR_FAILURE=prepare_exchange:expired\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_state\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_bundle\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:invalid_config\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:sealed\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:poll_too_early\n",
                "LOMI_AUTH_ACTOR_FAILURE=approve:storage\n",
            )
        );
    }

    #[test]
    fn auth_poll_observation_uses_closed_labels_for_results_and_errors() {
        let cases = [
            (Ok(PollOutcome::Pending), "authorization_pending"),
            (Ok(PollOutcome::SlowDown), "slow_down"),
            (Ok(PollOutcome::RateLimited), "rate_limited"),
            (Ok(approved()), "approved"),
            (Ok(PollOutcome::Expired), "expired_token"),
            (Ok(PollOutcome::Denied), "access_denied"),
            (Ok(PollOutcome::InvalidRequest), "invalid_request"),
            (Ok(PollOutcome::InvalidGrant), "invalid_grant"),
            (
                Err(lomi_host_http::Error::InvalidResponse),
                "rejected_response",
            ),
        ];
        let mut observation = AuthPollObservation::default();
        let mut output = Vec::new();
        for (index, (result, outcome)) in cases.iter().enumerate() {
            let trace = observation.observe(result).unwrap();
            assert_eq!(
                trace,
                AuthPollTrace::Record {
                    ordinal: (index + 1) as u8,
                    outcome: *outcome,
                }
            );
            trace.write_to(&mut output).unwrap();
        }
        let output = String::from_utf8(output).unwrap();
        assert_eq!(
            output,
            concat!(
                "LOMI_AUTH_ACTOR_POLL=1:authorization_pending\n",
                "LOMI_AUTH_ACTOR_POLL=2:slow_down\n",
                "LOMI_AUTH_ACTOR_POLL=3:rate_limited\n",
                "LOMI_AUTH_ACTOR_POLL=4:approved\n",
                "LOMI_AUTH_ACTOR_POLL=5:expired_token\n",
                "LOMI_AUTH_ACTOR_POLL=6:access_denied\n",
                "LOMI_AUTH_ACTOR_POLL=7:invalid_request\n",
                "LOMI_AUTH_ACTOR_POLL=8:invalid_grant\n",
                "LOMI_AUTH_ACTOR_POLL=9:rejected_response\n",
            )
        );
    }

    #[test]
    fn auth_poll_observation_caps_records_and_reports_overflow_once() {
        let mut observation = AuthPollObservation::default();
        let mut output = Vec::new();
        for ordinal in 1..=AuthPollObservation::RECORD_LIMIT {
            let trace = observation.observe(&Ok(PollOutcome::Pending)).unwrap();
            assert_eq!(
                trace,
                AuthPollTrace::Record {
                    ordinal,
                    outcome: "authorization_pending",
                }
            );
            trace.write_to(&mut output).unwrap();
        }
        let overflow = observation.observe(&Ok(PollOutcome::Pending)).unwrap();
        assert_eq!(overflow, AuthPollTrace::Overflow);
        overflow.write_to(&mut output).unwrap();
        assert!(observation.observe(&Ok(PollOutcome::Pending)).is_none());

        let output = String::from_utf8(output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), 17);
        assert_eq!(lines[0], "LOMI_AUTH_ACTOR_POLL=1:authorization_pending");
        assert_eq!(lines[15], "LOMI_AUTH_ACTOR_POLL=16:authorization_pending");
        assert_eq!(lines[16], "LOMI_AUTH_ACTOR_POLL=overflow");
    }

    #[test]
    fn ready_observation_is_disabled_by_default() {
        let mut view = initial();
        assert!(
            observe_auth_ready(&mut view, AuthReadyStage::Factory, AuthReadyOutcome::Enter,)
                .is_none()
        );
        assert!(view.auth_poll_observation.is_none());
    }

    #[test]
    fn ready_trace_uses_closed_stage_and_failure_labels() {
        let stages = [
            (AuthReadyStage::Factory, "factory"),
            (AuthReadyStage::Begin, "begin"),
            (AuthReadyStage::Prepare, "prepare"),
            (AuthReadyStage::Send, "send"),
            (AuthReadyStage::Clock, "clock"),
            (AuthReadyStage::Accept, "accept"),
            (AuthReadyStage::Publish, "publish"),
            (AuthReadyStage::Done, "done"),
            (AuthReadyStage::Abort, "abort"),
        ];
        let mut output = Vec::new();
        for (stage, label) in stages {
            AuthReadyTrace::Record(AuthReadyRecord {
                stage,
                outcome: AuthReadyOutcome::Enter,
            })
            .write_to(&mut output)
            .unwrap();
            assert_eq!(stage.label(), label);
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "LOMI_AUTH_ACTOR_READY=factory:enter\n",
                "LOMI_AUTH_ACTOR_READY=begin:enter\n",
                "LOMI_AUTH_ACTOR_READY=prepare:enter\n",
                "LOMI_AUTH_ACTOR_READY=send:enter\n",
                "LOMI_AUTH_ACTOR_READY=clock:enter\n",
                "LOMI_AUTH_ACTOR_READY=accept:enter\n",
                "LOMI_AUTH_ACTOR_READY=publish:enter\n",
                "LOMI_AUTH_ACTOR_READY=done:enter\n",
                "LOMI_AUTH_ACTOR_READY=abort:enter\n",
            )
        );

        let mut output = Vec::new();
        for (outcome, label) in [
            (AuthReadyOutcome::Enter, "enter"),
            (AuthReadyOutcome::Ok, "ok"),
            (AuthReadyOutcome::Busy, "busy"),
            (AuthReadyOutcome::Complete, "complete"),
        ] {
            assert_eq!(outcome.label(), label);
            AuthReadyTrace::Record(AuthReadyRecord {
                stage: AuthReadyStage::Send,
                outcome,
            })
            .write_to(&mut output)
            .unwrap();
        }
        assert_eq!(
            String::from_utf8(output).unwrap(),
            concat!(
                "LOMI_AUTH_ACTOR_READY=send:enter\n",
                "LOMI_AUTH_ACTOR_READY=send:ok\n",
                "LOMI_AUTH_ACTOR_READY=send:busy\n",
                "LOMI_AUTH_ACTOR_READY=send:complete\n",
            )
        );

        let domain_errors = [
            (DomainError::Busy, "error_domain_busy"),
            (DomainError::Stale, "error_domain_stale"),
            (DomainError::Cancelled, "error_domain_cancelled"),
            (DomainError::Deadline, "error_domain_deadline"),
            (DomainError::Denied, "error_domain_other"),
            (DomainError::Poisoned, "error_domain_other"),
            (DomainError::Exhausted, "error_domain_other"),
            (DomainError::Unfinished, "error_domain_other"),
        ];
        for (error, expected) in domain_errors {
            let error = super::super::shared_owner::WorkerReadyError::Domain(error);
            assert_eq!(auth_ready_failure(&error).label(), expected);
        }

        let provider_errors = [
            (
                lomi_host_auth::Error::InvalidResponse,
                "error_provider_invalid_response",
            ),
            (
                lomi_host_auth::Error::ClockRollback,
                "error_provider_clock_rollback",
            ),
            (lomi_host_auth::Error::Expired, "error_provider_expired"),
            (
                lomi_host_auth::Error::InvalidState,
                "error_provider_invalid_state",
            ),
            (
                lomi_host_auth::Error::InvalidBundle,
                "error_provider_invalid_bundle",
            ),
            (
                lomi_host_auth::Error::InvalidConfig,
                "error_provider_invalid_config",
            ),
            (lomi_host_auth::Error::Sealed, "error_provider_sealed"),
            (
                lomi_host_auth::Error::PollTooEarly,
                "error_provider_poll_too_early",
            ),
            (
                lomi_host_auth::Error::Storage(secrets::Error::Io),
                "error_provider_storage",
            ),
        ];
        for (error, expected) in provider_errors {
            let error = super::super::shared_owner::WorkerReadyError::Provider(error);
            assert_eq!(auth_ready_failure(&error).label(), expected);
        }

        let store_errors = [
            (lomi_host_store::StoreError::Busy, "error_store_busy"),
            (lomi_host_store::StoreError::Fenced, "error_store_fenced"),
            (lomi_host_store::StoreError::Storage, "error_store_storage"),
            (lomi_host_store::StoreError::Invalid, "error_store_invalid"),
            (lomi_host_store::StoreError::NotFound, "error_store_other"),
            (
                lomi_host_store::StoreError::RevisionConflict,
                "error_store_other",
            ),
            (
                lomi_host_store::StoreError::IdempotencyConflict,
                "error_store_other",
            ),
            (
                lomi_host_store::StoreError::ResourceExhausted,
                "error_store_other",
            ),
            (
                lomi_host_store::StoreError::AlreadyStarted,
                "error_store_other",
            ),
            (
                lomi_host_store::StoreError::SchemaVersion,
                "error_store_other",
            ),
            (lomi_host_store::StoreError::Backup, "error_store_other"),
        ];
        for (error, expected) in store_errors {
            let error = super::super::shared_owner::WorkerReadyError::Store(error);
            assert_eq!(auth_ready_failure(&error).label(), expected);
        }

        let http_errors = [
            (lomi_host_http::Error::InvalidConfig, "error_http_config"),
            (
                lomi_host_http::Error::ResolverUnavailable,
                "error_http_resolver",
            ),
            (lomi_host_http::Error::Request, "error_http_request"),
            (lomi_host_http::Error::Network, "error_http_network"),
            (lomi_host_http::Error::Timeout, "error_http_timeout"),
            (lomi_host_http::Error::Cancelled, "error_http_cancelled"),
            (lomi_host_http::Error::FixtureTls, "error_http_tls"),
            (lomi_host_http::Error::FixtureIoTls, "error_http_tls"),
            (
                lomi_host_http::Error::FixtureIoConnect,
                "error_http_connect",
            ),
            (lomi_host_http::Error::FixtureConnect, "error_http_connect"),
            (
                lomi_host_http::Error::InvalidResponse,
                "error_http_invalid_response",
            ),
            (
                lomi_host_http::Error::Redirect,
                "error_http_invalid_response",
            ),
            (
                lomi_host_http::Error::HttpStatus,
                "error_http_invalid_response",
            ),
            (
                lomi_host_http::Error::ResponseTooLarge,
                "error_http_invalid_response",
            ),
            (
                lomi_host_http::Error::FixtureProtocol,
                "error_http_invalid_response",
            ),
            (
                lomi_host_http::Error::Remote(lomi_host_http::HostFailure::AuthRequired),
                "error_http_auth_required",
            ),
            (
                lomi_host_http::Error::Remote(lomi_host_http::HostFailure::InvalidArgument),
                "error_http_remote",
            ),
            (
                lomi_host_http::Error::DataRemote(lomi_host_http::DataFailure::InvalidArgument),
                "error_http_remote",
            ),
            (lomi_host_http::Error::RelayClosed, "error_http_transport"),
            (
                lomi_host_http::Error::FixtureIoOther,
                "error_http_transport",
            ),
            (lomi_host_http::Error::FixtureHost, "error_http_transport"),
            (lomi_host_http::Error::FixtureOther, "error_http_transport"),
        ];
        for (error, expected) in http_errors {
            let error = super::super::shared_owner::WorkerReadyError::Http(error);
            assert_eq!(auth_ready_failure(&error).label(), expected);
        }
        assert_eq!(AuthReadyFailure::Stale.label(), "error_stale");
    }

    #[test]
    fn ready_trace_deduplicates_and_caps_records_with_one_overflow() {
        let stages = [
            AuthReadyStage::Factory,
            AuthReadyStage::Begin,
            AuthReadyStage::Prepare,
            AuthReadyStage::Send,
            AuthReadyStage::Clock,
            AuthReadyStage::Accept,
            AuthReadyStage::Publish,
            AuthReadyStage::Done,
            AuthReadyStage::Abort,
        ];
        let failures = [
            AuthReadyFailure::Stale,
            AuthReadyFailure::DomainBusy,
            AuthReadyFailure::DomainStale,
            AuthReadyFailure::DomainCancelled,
            AuthReadyFailure::DomainDeadline,
            AuthReadyFailure::DomainOther,
            AuthReadyFailure::ProviderInvalidResponse,
            AuthReadyFailure::ProviderClockRollback,
            AuthReadyFailure::ProviderExpired,
            AuthReadyFailure::ProviderInvalidState,
            AuthReadyFailure::ProviderInvalidBundle,
            AuthReadyFailure::ProviderInvalidConfig,
            AuthReadyFailure::ProviderSealed,
            AuthReadyFailure::ProviderPollTooEarly,
            AuthReadyFailure::ProviderStorage,
            AuthReadyFailure::StoreBusy,
            AuthReadyFailure::StoreFenced,
            AuthReadyFailure::StoreStorage,
            AuthReadyFailure::StoreInvalid,
            AuthReadyFailure::StoreOther,
            AuthReadyFailure::HttpConfig,
            AuthReadyFailure::HttpResolver,
            AuthReadyFailure::HttpRequest,
            AuthReadyFailure::HttpNetwork,
            AuthReadyFailure::HttpTimeout,
            AuthReadyFailure::HttpCancelled,
            AuthReadyFailure::HttpTls,
            AuthReadyFailure::HttpConnect,
            AuthReadyFailure::HttpTransport,
            AuthReadyFailure::HttpInvalidResponse,
            AuthReadyFailure::HttpAuthRequired,
            AuthReadyFailure::HttpRemote,
        ];
        let progress = [
            AuthReadyOutcome::Enter,
            AuthReadyOutcome::Ok,
            AuthReadyOutcome::Busy,
            AuthReadyOutcome::Complete,
        ];
        let mut records = Vec::new();
        for stage in stages {
            for outcome in progress {
                records.push(AuthReadyRecord { stage, outcome });
            }
        }
        for failure in failures {
            records.push(AuthReadyRecord {
                stage: AuthReadyStage::Factory,
                outcome: AuthReadyOutcome::Error(failure),
            });
        }
        assert!(records.len() > AuthPollObservation::READY_RECORD_LIMIT);

        let mut observation = AuthPollObservation::default();
        let mut output = Vec::new();
        for record in records.iter().take(AuthPollObservation::READY_RECORD_LIMIT) {
            observation
                .observe_ready(*record)
                .unwrap()
                .write_to(&mut output)
                .unwrap();
        }
        assert!(observation.observe_ready(records[0]).is_none());
        let overflow = observation
            .observe_ready(records[AuthPollObservation::READY_RECORD_LIMIT])
            .unwrap();
        assert_eq!(overflow, AuthReadyTrace::Overflow);
        overflow.write_to(&mut output).unwrap();
        assert!(
            observation
                .observe_ready(records[AuthPollObservation::READY_RECORD_LIMIT])
                .is_none()
        );

        let output = String::from_utf8(output).unwrap();
        let lines: Vec<_> = output.lines().collect();
        assert_eq!(lines.len(), AuthPollObservation::READY_RECORD_LIMIT + 1);
        assert_eq!(lines.last(), Some(&"LOMI_AUTH_ACTOR_READY=overflow"));
        assert_eq!(lines[0], "LOMI_AUTH_ACTOR_READY=factory:enter");
    }
}
pub(super) fn configuration(
    identity: &lomi_host_store::Identity,
    config: &LocalAuthConfiguration,
) -> Result<Config, LocalError> {
    config.validate().map_err(|_| LocalError::InvalidArgument)?;
    match config.provider {
        #[cfg(target_os = "linux")]
        LocalAuthProvider::LinuxSecretService => {}
        #[cfg(unix)]
        LocalAuthProvider::ProtectedFile => {}
        #[cfg(target_os = "macos")]
        LocalAuthProvider::MacOsKeychain => {
            let path = Path::new(
                config
                    .keychain_path
                    .as_ref()
                    .ok_or(LocalError::InvalidArgument)?
                    .as_str(),
            );
            if !path.is_absolute()
                || path.canonicalize().ok().as_deref() != Some(path)
                || !path.is_file()
            {
                return Err(LocalError::InvalidArgument);
            }
        }
        #[cfg(windows)]
        LocalAuthProvider::WindowsDpapi => {}
        _ => return Err(LocalError::InvalidArgument),
    }
    let identity = Config::new(
        identity.host_id,
        identity.profile_id,
        config.origin.as_str().to_owned(),
        config
            .client_id
            .as_str()
            .to_owned()
            .try_into()
            .map_err(|_| LocalError::InvalidArgument)?,
    )
    .map_err(|_| LocalError::InvalidArgument)?;
    if let Some(origin) = &config.remote_api_origin {
        lomi_host_http::RemoteApiOrigin::new(&identity, origin.as_str().to_owned())
            .map_err(|_| LocalError::InvalidArgument)?;
    }
    Ok(identity)
}
impl Handle {
    #[cfg(any(unix, windows))]
    fn configure_public(
        &self,
        setup: &super::public_configuration::PublicSetup,
        operation: &OwnerOperation<'_>,
        config: &LocalAuthConfiguration,
    ) -> Result<LocalResult, LocalError> {
        // Validation can perform filesystem IO, hence runs after the owned
        // identity snapshot has released Domain/Store and before pending intent.
        let identity = self.owner.identity(operation).map_err(owner_local_error)?;
        configuration(&identity, config)?;
        let _request = loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.request.try_lock() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(LocalError::Unavailable),
            }
        };
        let mut turn = self
            .owner
            .begin_public_configuration(operation, config.clone())
            .map_err(owner_local_error)?;
        setup.pending.store(true, Ordering::Release);
        if let Ok(mut view) = self.state.lock() {
            view.presentation = None;
        }
        self.paused.store(true, Ordering::Release);
        self.gate.store(true, Ordering::Release);
        // The announcement precedes IO exclusion. Logout uses neither request
        // nor IO and can persist its fence while this writer waits for IO.
        let _exclusive = loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.io.try_write() {
                Ok(guard) => break guard,
                Err(std::sync::TryLockError::WouldBlock) => {
                    std::thread::park_timeout(Duration::from_millis(10))
                }
                Err(std::sync::TryLockError::Poisoned(_)) => return Err(LocalError::Unavailable),
            }
        };
        loop {
            operation.check().map_err(|_| LocalError::Unavailable)?;
            match setup.configure_owned(&mut turn) {
                Ok(()) => break,
                Err(LocalError::Unavailable) if turn.is_pending() => {
                    std::thread::park_timeout(Duration::from_millis(10));
                }
                Err(error) => {
                    set_failed(&self.state, LocalAuthStorage::Unavailable, &self.gate);
                    return Err(error);
                }
            }
        }
        setup.pending.store(false, Ordering::Release);
        self.paused.store(false, Ordering::Release);
        self.retry_requested.store(true, Ordering::Release);
        let _ = self.wake.try_send(Command::Configure);
        Ok(LocalResult::AuthConfigured {})
    }
    pub(super) fn is_authorized(&self, operation: &OwnerOperation<'_>) -> bool {
        #[cfg(any(unix, windows))]
        if self
            .public_setup
            .as_ref()
            .is_some_and(|setup| setup.pending.load(Ordering::Acquire))
        {
            return false;
        }
        !self.gate.load(Ordering::Acquire)
            && !self.paused.load(Ordering::Acquire)
            && self
                .owner
                .remote_authorization(operation)
                .is_ok_and(|state| !state.locked && !state.pending_cloud_revoke)
    }
    pub(super) fn dispatch(
        &self,
        operation: &OwnerOperation<'_>,
        call: LocalCall,
    ) -> Result<LocalResult, LocalError> {
        match call {
            LocalCall::AuthConfigure(params) => {
                #[cfg(any(unix, windows))]
                if let Some(setup) = &self.public_setup {
                    return self.configure_public(setup, operation, &params.configuration);
                }
                // Public file configuration is Unix-only. Do not silently use
                // the legacy database-only writer on another platform.
                Err(LocalError::Unavailable)
            }
            LocalCall::LoginStart(params) => {
                #[cfg(any(unix, windows))]
                if self
                    .public_setup
                    .as_ref()
                    .is_some_and(|s| s.pending.load(Ordering::Acquire))
                {
                    return Err(LocalError::Unavailable);
                }
                let (selected, status) = login_start_snapshot(operation, || {
                    Ok((
                        self.owner.auth_selection(operation)?,
                        self.owner.auth_status(operation)?,
                    ))
                })?;
                let config = selected.configuration.ok_or(LocalError::InvalidArgument)?;
                configuration(&selected.identity, &config)?;
                let generation = status.authorization.generation;
                let mut turn = self
                    .owner
                    .begin_login(operation, params.operation_id, config, generation)
                    .map_err(owner_local_error)?;
                let intent = commit_local_turn!(turn, operation)?;
                self.retry_requested.store(true, Ordering::Release);
                let _ = self.wake.try_send(Command::Wake(intent.operation_id));
                Ok(LocalResult::LoginAccepted(LocalLoginAccepted {
                    operation_id: intent.operation_id,
                    generation: DecimalU64(intent.generation),
                }))
            }
            LocalCall::Logout(_) => {
                self.gate.store(true, Ordering::Release);
                let outcome = self
                    .owner
                    .begin_local_logout(operation)
                    .map_err(owner_local_error)
                    .and_then(|mut turn| commit_local_turn!(turn, operation));
                let state = match outcome {
                    Ok(state) => state,
                    Err(error) => {
                        self.retry_requested.store(false, Ordering::Release);
                        self.paused.store(true, Ordering::Release);
                        set_failed(&self.state, LocalAuthStorage::Unavailable, &self.gate);
                        return Err(error);
                    }
                };
                self.retry_requested.store(true, Ordering::Release);
                let _ = self.wake.try_send(Command::Logout);
                let mut view = self.state.lock().map_err(|_| LocalError::Unavailable)?;
                view.presentation = None;
                view.status.phase = LocalAuthPhase::PendingRevoke;
                view.status.generation = DecimalU64(state.generation);
                view.status.locked = true;
                view.status.pending_cloud_revoke = true;
                view.status.operation_id = None;
                Ok(LocalResult::LoginStatus(view.status.clone()))
            }
            LocalCall::LoginStatus {} | LocalCall::LoginPresentation {} => {
                let snapshot = self
                    .owner
                    .auth_status(operation)
                    .map_err(owner_local_error)?;
                let state = snapshot.authorization;
                let intent = snapshot.intent;
                let deferred_intent = snapshot.deferred_intent;
                let view = self.state.lock().map_err(|_| LocalError::Unavailable)?;
                if matches!(call, LocalCall::LoginPresentation {}) {
                    if state.pending_cloud_revoke
                        || intent.is_none()
                        || view.status.generation.0 != state.generation
                        || view.status.operation_id != intent.map(|i| i.operation_id)
                    {
                        return Err(LocalError::Conflict);
                    }
                    return view
                        .presentation
                        .clone()
                        .map(LocalResult::LoginPresentation)
                        .ok_or(LocalError::Unavailable);
                }
                let mut status = view.status.clone();
                status.generation = DecimalU64(state.generation);
                status.locked = !self.is_authorized(operation);
                status.pending_cloud_revoke = state.pending_cloud_revoke;
                status.operation_id = if state.pending_cloud_revoke {
                    deferred_intent.map(|i| i.operation_id)
                } else {
                    intent.map(|i| i.operation_id)
                };
                if state.pending_cloud_revoke {
                    status.phase = LocalAuthPhase::PendingRevoke;
                } else if state.locked && status.phase == LocalAuthPhase::Ready {
                    status.phase = LocalAuthPhase::Locked;
                }
                Ok(LocalResult::LoginStatus(status))
            }
            _ => Err(LocalError::InvalidArgument),
        }
    }
}

pub(super) fn start(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
) -> (Handle, thread::JoinHandle<()>) {
    start_with_options(
        endpoint,
        owner,
        stopping,
        coordinator,
        StartOptions::production(),
    )
}

/// Runs the normal Actor with fixture-pinned auth HTTPS and no downstream API
/// scope. `ready_from_existing_worker` installs this same AuthTransport under
/// cfg(test), so registration/refresh also use the pinned root rather than its
/// otherwise-unused configured transport.
#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn start_with_auth_fixture(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
    root_der: Vec<u8>,
    ack_checkpoint: Option<SyncSender<()>>,
) -> (Handle, thread::JoinHandle<()>) {
    start_with_options(
        endpoint,
        owner,
        stopping,
        coordinator,
        StartOptions {
            transport: AuthTransportFactory::TestRoot(root_der),
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            fixture_mode: Some(FixtureMode::AuthOnly),
            ack_checkpoint,
        },
    )
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
const FIXTURE_ROOT_LIMIT: usize = 16 * 1024;

#[cfg(all(unix, test, feature = "cloud-fixture"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FixtureMode {
    AuthOnly,
    CloudOnly,
    JoinedCloud,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
impl FixtureMode {
    fn rejects_configured_remote_api(self) -> bool {
        matches!(self, Self::AuthOnly)
    }

    fn api_scheduling(self) -> (bool, bool) {
        match self {
            Self::AuthOnly => (false, false),
            // Cloud always runs in Ready. `enabled` controls only the
            // downstream peer/channel scheduler after Cloud yields an
            // eligibility observation.
            Self::CloudOnly => (false, false),
            Self::JoinedCloud => (true, true),
        }
    }
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn fixture_api_scheduling(mode: Option<FixtureMode>) -> (bool, bool) {
    mode.map(FixtureMode::api_scheduling)
        .unwrap_or((true, true))
}

/// Opaque roots can only be constructed after bounded DER validation.
#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) struct CloudFixtureRoots {
    auth: Vec<u8>,
    remote_api: Vec<u8>,
}
#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) struct JoinedCloudFixtureRoots {
    auth: Vec<u8>,
    remote_api: Vec<u8>,
    relay: Vec<u8>,
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn validate_fixture_root(root_der: &[u8]) -> Result<(), lomi_host_http::Error> {
    if root_der.is_empty() || root_der.len() > FIXTURE_ROOT_LIMIT {
        return Err(lomi_host_http::Error::InvalidConfig);
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(root_der.to_vec()))
        .map_err(|_| lomi_host_http::Error::InvalidConfig)
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) fn validate_cloud_fixture_roots(
    auth_root_der: Vec<u8>,
    remote_api_root_der: Vec<u8>,
) -> Result<CloudFixtureRoots, lomi_host_http::Error> {
    validate_fixture_root(&auth_root_der)?;
    validate_fixture_root(&remote_api_root_der)?;
    Ok(CloudFixtureRoots {
        auth: auth_root_der,
        remote_api: remote_api_root_der,
    })
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) fn validate_joined_cloud_fixture_roots(
    auth_root_der: Vec<u8>,
    remote_api_root_der: Vec<u8>,
    relay_root_der: Vec<u8>,
) -> Result<JoinedCloudFixtureRoots, lomi_host_http::Error> {
    validate_fixture_root(&auth_root_der)?;
    validate_fixture_root(&remote_api_root_der)?;
    validate_fixture_root(&relay_root_der)?;
    Ok(JoinedCloudFixtureRoots {
        auth: auth_root_der,
        remote_api: remote_api_root_der,
        relay: relay_root_der,
    })
}

/// Same Auth worker, but with two explicitly supplied fixture roots and Cloud
/// enabled while peer/channel scheduling remains disabled.
#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) fn start_with_cloud_fixture(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
    roots: CloudFixtureRoots,
) -> (Handle, thread::JoinHandle<()>) {
    let public_setup = Arc::new(
        super::public_configuration::PublicSetup::with_remote_api_test_root(
            endpoint.clone(),
            roots.remote_api,
        )
        .expect("CloudFixtureRoots validates the same bounded remote API DER"),
    );
    start_with_options_and_setup(
        endpoint,
        owner,
        stopping,
        coordinator,
        StartOptions {
            transport: AuthTransportFactory::TestRoot(roots.auth),
            fixture_mode: Some(FixtureMode::CloudOnly),
            ack_checkpoint: None,
        },
        Some(public_setup),
    )
}

/// Same managed actor in JoinedCloud mode. The three validated DER roots are
/// explicit inputs: auth, Remote API and relay transport never consult ambient
/// environment or fall back to scripted responses.
#[cfg(all(unix, test, feature = "cloud-fixture"))]
pub(super) fn start_with_joined_cloud_fixture(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
    roots: JoinedCloudFixtureRoots,
) -> (Handle, thread::JoinHandle<()>) {
    let public_setup = Arc::new(
        super::public_configuration::PublicSetup::with_joined_cloud_test_roots(
            endpoint.clone(),
            roots.remote_api,
            roots.relay,
        )
        .expect("JoinedCloudFixtureRoots validates both downstream DER roots"),
    );
    start_with_options_and_setup(
        endpoint,
        owner,
        stopping,
        coordinator,
        StartOptions {
            transport: AuthTransportFactory::TestRoot(roots.auth),
            fixture_mode: Some(FixtureMode::JoinedCloud),
            ack_checkpoint: None,
        },
        Some(public_setup),
    )
}

struct StartOptions {
    transport: AuthTransportFactory,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    fixture_mode: Option<FixtureMode>,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    ack_checkpoint: Option<SyncSender<()>>,
}
impl StartOptions {
    fn production() -> Self {
        Self {
            transport: AuthTransportFactory::System,
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            fixture_mode: None,
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            ack_checkpoint: None,
        }
    }
}
enum AuthTransportFactory {
    System,
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    TestRoot(Vec<u8>),
}
impl AuthTransportFactory {
    fn build(&self, config: &Config) -> std::result::Result<Transport, lomi_host_http::Error> {
        match self {
            Self::System => Transport::new(config),
            #[cfg(all(unix, test, feature = "cloud-fixture"))]
            Self::TestRoot(root_der) => Transport::with_test_root(config, root_der),
        }
    }
}

fn start_with_options(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
    options: StartOptions,
) -> (Handle, thread::JoinHandle<()>) {
    start_with_options_and_setup(endpoint, owner, stopping, coordinator, options, None)
}

fn start_with_options_and_setup(
    endpoint: Arc<OwnerEndpoint>,
    owner: Arc<SharedOwner>,
    stopping: Arc<AtomicBool>,
    coordinator: std::sync::Weak<super::Coordinator>,
    options: StartOptions,
    fixture_public_setup: Option<Arc<super::public_configuration::PublicSetup>>,
) -> (Handle, thread::JoinHandle<()>) {
    let (wake, receiver) = mpsc::sync_channel(8);
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    let initial_view = {
        let mut view = initial();
        if options.fixture_mode == Some(FixtureMode::AuthOnly) {
            view.auth_poll_observation = Some(AuthPollObservation::default());
        }
        view
    };
    #[cfg(not(all(unix, test, feature = "cloud-fixture")))]
    let initial_view = initial();
    let state = Arc::new(Mutex::new(initial_view));
    let retry_requested = Arc::new(AtomicBool::new(false));
    let gate = Arc::new(AtomicBool::new(true));
    let paused = Arc::new(AtomicBool::new(false));
    #[cfg(any(unix, windows))]
    let public_setup = fixture_public_setup.unwrap_or_else(|| {
        Arc::new(super::public_configuration::PublicSetup::new(
            endpoint.clone(),
        ))
    });
    let handle = Handle {
        owner: owner.clone(),
        wake,
        state: state.clone(),
        retry_requested: retry_requested.clone(),
        gate: gate.clone(),
        paused: paused.clone(),
        #[cfg(any(unix, windows))]
        public_setup: Some(public_setup.clone()),
    };
    let worker = thread::spawn(move || {
        let anchor = Instant::now();
        let wall = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        let mut explicit_retry = false;
        while !stopping.load(Ordering::Acquire) {
            if explicit_retry && !await_explicit_retry(&receiver, &stopping, &retry_requested) {
                return;
            }
            explicit_retry = false;
            #[cfg(any(unix, windows))]
            let _public_io = match public_setup.enter_owned(&paused) {
                Ok(Some(guard)) => guard,
                Ok(None) => {
                    let _ = receiver.recv_timeout(Duration::from_millis(250));
                    continue;
                }
                Err(()) => {
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    return;
                }
            };
            #[cfg(not(any(unix, windows)))]
            paused.store(false, Ordering::Release);
            retry_requested.store(false, Ordering::Release);
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(60), &stopping);
            let aborted = std::cell::Cell::new(false);
            let runtime = Runtime {
                aborted: &aborted,
                owner: &owner,
                operation: &operation,
                #[cfg(any(unix, windows))]
                public_io: &_public_io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: wall.saturating_add(anchor.elapsed().as_secs()),
                anchor: Instant::now(),
            };
            let base = match observed(runtime) {
                Ok(base) => base,
                Err(_) => {
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    explicit_retry = true;
                    continue;
                }
            };
            let attempt_anchor = Instant::now();
            let runtime = Runtime {
                base,
                anchor: attempt_anchor,
                ..runtime
            };
            let selected = worker_read!(runtime, owner.auth_selection(&operation))
                .map_err(|_| ())
                .and_then(|snapshot| {
                    snapshot
                        .configuration
                        .map(|c| {
                            #[cfg(all(unix, test, feature = "cloud-fixture"))]
                            if options
                                .fixture_mode
                                .is_some_and(FixtureMode::rejects_configured_remote_api)
                                && c.remote_api_origin.is_some()
                            {
                                return Err(());
                            }
                            configuration(&snapshot.identity, &c)
                                .map(|trusted| (c, trusted))
                                .map_err(|_| ())
                        })
                        .transpose()
                });
            let selected = match selected {
                Ok(value) => value,
                Err(()) => {
                    suspend(runtime);
                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                    explicit_retry = true;
                    continue;
                }
            };
            if let Some((selected, trusted)) = selected {
                if runtime.check().is_err() {
                    continue;
                }
                let provider: Result<Box<dyn SecretStorage + '_>, secrets::Error> = match selected
                    .provider
                {
                    #[cfg(target_os = "linux")]
                    LocalAuthProvider::LinuxSecretService => {
                        lomi_platform::secret_service::SecretService::open(
                            endpoint.profile(),
                            Selection::SecretService,
                            endpoint.discovery().profile_id,
                        )
                        .map(|p| Box::new(p) as Box<dyn SecretStorage>)
                    }
                    #[cfg(unix)]
                    LocalAuthProvider::ProtectedFile => platform::secrets::ProtectedFile::open(
                        endpoint.profile(),
                        Selection::ProtectedFile(
                            secrets::ProtectedFileAcknowledgement::OsPermissionsOnly,
                        ),
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    #[cfg(target_os = "macos")]
                    LocalAuthProvider::MacOsKeychain => platform::keychain::MacOsKeychain::open(
                        endpoint.profile(),
                        Selection::MacOsKeychain,
                        endpoint.discovery().profile_id,
                        Path::new(selected.keychain_path.as_ref().unwrap().as_str()),
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    #[cfg(windows)]
                    LocalAuthProvider::WindowsDpapi => platform::secrets::WindowsDpapi::open(
                        endpoint.profile(),
                        Selection::WindowsDpapi,
                    )
                    .map(|p| Box::new(p) as Box<dyn SecretStorage>),
                    _ => Err(secrets::Error::Unavailable),
                };
                match provider {
                    Ok(mut provider) => {
                        if runtime.check().is_err() {
                            continue;
                        }
                        let now = base.saturating_add(attempt_anchor.elapsed().as_secs());
                        match HostAuth::open(provider.as_mut(), trusted.clone(), now) {
                            Ok(mut auth) => {
                                if runtime.check().is_err() {
                                    continue;
                                }
                                if !qualify_cloud_history(runtime, auth.status()) {
                                    suspend(runtime);
                                    set_failed(&state, LocalAuthStorage::Unavailable, &gate);
                                    explicit_retry = true;
                                    continue;
                                }
                                if let Ok(transport) = options.transport.build(&trusted) {
                                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                                    let (enabled, channels_enabled) =
                                        fixture_api_scheduling(options.fixture_mode);
                                    #[cfg(not(all(unix, test, feature = "cloud-fixture")))]
                                    let (enabled, channels_enabled) = (true, true);
                                    let apis = InjectedApis {
                                        data: None,
                                        pairing: None,
                                        channel: None,
                                        enabled,
                                        channels_enabled,
                                    };
                                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                                    if let Some(checkpoint) = options.ack_checkpoint.as_ref() {
                                        run_with_apis_and_coordinator_with_checkpoint(
                                            &mut auth,
                                            &transport,
                                            &trusted,
                                            Some(&selected),
                                            runtime,
                                            apis,
                                            coordinator.clone(),
                                            checkpoint,
                                        );
                                    } else {
                                        run_with_apis_and_coordinator(
                                            &mut auth,
                                            &transport,
                                            &trusted,
                                            Some(&selected),
                                            runtime,
                                            apis,
                                            coordinator.clone(),
                                        );
                                    }
                                    #[cfg(not(all(unix, test, feature = "cloud-fixture")))]
                                    run_with_apis_and_coordinator(
                                        &mut auth,
                                        &transport,
                                        &trusted,
                                        Some(&selected),
                                        runtime,
                                        apis,
                                        coordinator.clone(),
                                    );
                                    explicit_retry = true;
                                } else {
                                    set_failed(&state, LocalAuthStorage::Available, &gate);
                                }
                            }
                            Err(error) => {
                                suspend(runtime);
                                auth_failed(&state, error, &gate);
                                explicit_retry = true;
                            }
                        }
                    }
                    Err(error) => {
                        suspend(runtime);
                        set_failed(&state, storage(error.state()), &gate);
                    }
                }
            }
            if stopping.load(Ordering::Acquire) {
                break;
            }
            if explicit_retry {
                continue;
            }
            // A locked/unavailable selected provider never selects a replacement.
            let _ = receiver.recv_timeout(Duration::from_secs(1));
        }
    });
    (handle, worker)
}
fn qualify_cloud_history(runtime: Runtime<'_>, status: Status) -> bool {
    let Ok(history) = worker_read!(runtime, runtime.owner.auth_history(runtime.operation)) else {
        return false;
    };
    match status {
        Status::ExchangePrepared | Status::Unconfirmed | Status::Ready | Status::Rotating => {
            mark_cloud_possible(runtime, history.authorization.generation).is_ok()
        }
        Status::Revoked => true,
        _ => history.cloud_may_exist == Some(false),
    }
}
fn mark_cloud_possible(runtime: Runtime<'_>, generation: u64) -> Result<(), StepError> {
    let mut turn = runtime
        .owner
        .begin_mark_cloud_authorization_possible(runtime.operation, generation)?;
    commit_worker_turn!(turn, runtime).map_err(StepError::from)
}
fn await_explicit_retry(
    receiver: &mpsc::Receiver<Command>,
    stopping: &AtomicBool,
    retry_requested: &AtomicBool,
) -> bool {
    // Never automatically repeat an uncertain publication. A fresh explicit
    // login/logout command permits reopening and inspecting the same provider.
    loop {
        if retry_requested.load(Ordering::Acquire) {
            return true;
        }
        match receiver.recv_timeout(Duration::from_millis(250)) {
            Ok(Command::Wake(_) | Command::Logout | Command::Configure)
            | Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return false,
        }
    }
    false
}
fn suspend(runtime: Runtime<'_>) {
    runtime.gate.store(true, Ordering::Release);
    if let Ok(state) = worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    ) && !state.locked
        && let Ok(mut turn) = runtime
            .owner
            .begin_suspend_authorization(runtime.operation, state.generation)
    {
        let _ = commit_worker_turn!(turn, runtime);
    }
}
fn storage(value: secrets::StorageState) -> LocalAuthStorage {
    match value {
        secrets::StorageState::Available => LocalAuthStorage::Available,
        secrets::StorageState::Locked => LocalAuthStorage::Locked,
        secrets::StorageState::Unconfigured => LocalAuthStorage::Unconfigured,
        secrets::StorageState::Unavailable => LocalAuthStorage::Unavailable,
    }
}
fn set_failed(state: &Mutex<View>, storage: LocalAuthStorage, gate: &AtomicBool) {
    gate.store(true, Ordering::Release);
    if let Ok(mut view) = state.lock() {
        view.status.storage = storage;
        view.status.phase = LocalAuthPhase::Unavailable;
        view.presentation = None;
    }
}
fn auth_failed(state: &Mutex<View>, error: lomi_host_auth::Error, gate: &AtomicBool) {
    set_failed(
        state,
        match error {
            lomi_host_auth::Error::Storage(e) => storage(e.state()),
            _ => LocalAuthStorage::Unavailable,
        },
        gate,
    );
}
fn current(runtime: Runtime<'_>, generation: u64) -> bool {
    worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    )
    .is_ok_and(|s| s.generation == generation && !s.pending_cloud_revoke)
}
// Internal injection boundary: production always uses the concrete HTTPS transport.
pub(super) trait AuthTransport {
    fn revoke(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevokeParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error>;

    /// Older injected transports deny the new proof-only operation by default.
    /// A denial is never an acknowledgement and keeps the prior recovery path
    /// available for implementations that do not support this endpoint.
    fn revocation_ack(
        &self,
        _host: lomi_remote_protocol::HostId,
        _request: &lomi_remote_protocol::HostRevocationAckParams,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired,
        ))
    }

    /// Older injected transports treat the historical enrollment proof route
    /// as absent, preserving the existing exchange/register fallback.
    fn enrollment_revocation_ack(
        &self,
        _host: lomi_remote_protocol::HostId,
        _request: &HostEnrollmentRevocationAckParams,
    ) -> Result<HostEnrollmentRevocationAckResult, lomi_host_http::Error> {
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::ResourceNotFound,
        ))
    }

    fn initiate(
        &self,
        request: &lomi_remote_protocol::EnrollmentInitiateParams,
    ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error>;
    fn poll(
        &self,
        device: &lomi_remote_protocol::DeviceCode,
    ) -> Result<PollOutcome, lomi_host_http::Error>;
    fn exchange(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error>;
    fn register(
        &self,
        request: &lomi_remote_protocol::HostRegisterParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error>;
    fn refresh(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error>;
}
impl AuthTransport for Transport {
    fn revoke(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevokeParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Transport::revoke(self, host, request, access)
    }

    fn revocation_ack(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &lomi_remote_protocol::HostRevocationAckParams,
    ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
        Transport::revocation_ack(self, host, request)
    }

    fn enrollment_revocation_ack(
        &self,
        host: lomi_remote_protocol::HostId,
        request: &HostEnrollmentRevocationAckParams,
    ) -> Result<HostEnrollmentRevocationAckResult, lomi_host_http::Error> {
        Transport::enrollment_revocation_ack(self, host, request)
    }

    fn initiate(
        &self,
        request: &lomi_remote_protocol::EnrollmentInitiateParams,
    ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
        Transport::initiate(self, request)
    }
    fn poll(
        &self,
        device: &lomi_remote_protocol::DeviceCode,
    ) -> Result<PollOutcome, lomi_host_http::Error> {
        Transport::poll(self, device)
    }
    fn exchange(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
        Transport::exchange(self, request)
    }
    fn register(
        &self,
        request: &lomi_remote_protocol::HostRegisterParams,
        access: &lomi_remote_protocol::HostAccessCredential,
    ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
        Transport::register(self, request, access)
    }
    fn refresh(
        &self,
        request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
    ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
        Transport::refresh(self, request)
    }
}
#[derive(Clone, Copy)]
pub(super) struct RuntimeWithOperation<'a, 'operation> {
    owner: &'a SharedOwner,
    operation: &'operation OwnerOperation<'a>,
    #[cfg(any(unix, windows))]
    public_io: &'a super::public_configuration::WorkerPublicIo<'a>,
    state: &'a Mutex<View>,
    stopping: &'a AtomicBool,
    receiver: &'a mpsc::Receiver<Command>,
    retry_requested: &'a AtomicBool,
    gate: &'a AtomicBool,
    paused: &'a AtomicBool,
    base: u64,
    anchor: Instant,
    aborted: &'operation std::cell::Cell<bool>,
}

type Runtime<'a> = RuntimeWithOperation<'a, 'a>;

impl<'a, 'operation> RuntimeWithOperation<'a, 'operation> {
    pub(super) fn with_operation<'next>(
        self,
        operation: &'next OwnerOperation<'a>,
        aborted: &'next std::cell::Cell<bool>,
    ) -> RuntimeWithOperation<'a, 'next> {
        self.with_operation_at(operation, aborted, self.base, self.anchor)
    }

    pub(super) fn with_operation_at<'next>(
        self,
        operation: &'next OwnerOperation<'a>,
        aborted: &'next std::cell::Cell<bool>,
        base: u64,
        anchor: Instant,
    ) -> RuntimeWithOperation<'a, 'next> {
        RuntimeWithOperation {
            owner: self.owner,
            operation,
            #[cfg(any(unix, windows))]
            public_io: self.public_io,
            state: self.state,
            stopping: self.stopping,
            receiver: self.receiver,
            retry_requested: self.retry_requested,
            gate: self.gate,
            paused: self.paused,
            base,
            anchor,
            aborted,
        }
    }

    pub(super) fn started_git_terminal_latches(
        self,
    ) -> owner_domain::StartedGitTerminalLatches<'a> {
        owner_domain::StartedGitTerminalLatches::from_runtime(
            self.gate,
            self.paused,
            self.stopping,
            &self.public_io.setup().pending,
        )
    }

    fn projected_time(self) -> u64 {
        self.base.saturating_add(self.anchor.elapsed().as_secs())
    }
    fn with_clock_floor(self, floor: u64) -> Self {
        if floor <= self.projected_time() {
            return self;
        }
        // This returns a fresh projection for the next handoff. It preserves
        // the same OwnerOperation and its monotonic deadline.
        Self {
            base: floor,
            anchor: Instant::now(),
            ..self
        }
    }
    fn check(self) -> Result<(), StepError> {
        if self.aborted.get() {
            return Err(StepError::Stale);
        }
        if self.operation.check().is_err() {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        if self.stopping.load(Ordering::Acquire) || self.paused.load(Ordering::Acquire) {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        #[cfg(any(unix, windows))]
        if self.public_io.setup().pending.load(Ordering::Acquire) {
            self.aborted.set(true);
            return Err(StepError::Stale);
        }
        Ok(())
    }
    /// Read-only check for whether queued ingress output can make progress on
    /// the next actor pass. The ingress stage still performs all authorization
    /// and per-fragment checks before disclosing data.
    fn ingress_can_advance(self) -> bool {
        !self.aborted.get()
            && !self.operation.cancellation_latch().load(Ordering::Acquire)
            && Instant::now() < self.operation.deadline()
            && !self.stopping.load(Ordering::Acquire)
            && !self.gate.load(Ordering::Acquire)
            && !self.paused.load(Ordering::Acquire)
            && !self.public_io.setup().pending.load(Ordering::Acquire)
    }
    fn busy(self) -> Result<(), StepError> {
        self.check()?;
        // Busy retains the same turn and original operation. Commands are left
        // queued so Configure/Logout dispatch follows dropping attempt and IO.
        std::thread::park_timeout(
            Duration::from_millis(10).min(
                self.operation
                    .deadline()
                    .saturating_duration_since(Instant::now()),
            ),
        );
        self.check()
    }
}
fn advance_clock_projection(
    runtime: Runtime<'_>,
    floor: u64,
    base: &mut u64,
    anchor: &mut Instant,
) {
    // Called only after a non-retained turn. Held continuations keep their
    // admission projection and fixed effect checkpoints.
    let fresh = runtime.with_clock_floor(floor);
    *base = fresh.base;
    *anchor = fresh.anchor;
}
#[cfg(any(unix, windows))]
fn ready_from_existing_worker(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    runtime: Runtime<'_>,
    transport: &dyn AuthTransport,
) -> Result<(), StepError> {
    use super::shared_owner::{ConfiguredWorkerAttempt, WorkerReadyError};
    let retained_rotation = auth.status() == Status::Rotating;
    let now = runtime.projected_time();
    let retained_enrollment =
        auth.status() == Status::Unconfirmed && auth.enrollment_revocation_ack_request(now).is_ok();
    let map = |error| match error {
        WorkerReadyError::Provider(lomi_host_auth::Error::Expired) if retained_rotation => {
            StepError::ExpiredRotation
        }
        WorkerReadyError::Provider(lomi_host_auth::Error::Expired) if retained_enrollment => {
            StepError::ExpiredEnrollment
        }
        WorkerReadyError::Provider(error) => StepError::Auth(error),
        WorkerReadyError::Http(error) => StepError::Http(error),
        WorkerReadyError::Domain(_) | WorkerReadyError::Stale => StepError::Stale,
        WorkerReadyError::Store(_) => StepError::Auth(lomi_host_auth::Error::Sealed),
    };
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    emit_auth_ready(
        runtime.state,
        AuthReadyStage::Factory,
        AuthReadyOutcome::Enter,
    );
    let attempt_result = ConfiguredWorkerAttempt::from_existing_worker(
        auth,
        runtime.public_io,
        runtime.gate,
        runtime.paused,
        runtime.base,
        runtime.anchor,
    );
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    match &attempt_result {
        Ok(_) => emit_auth_ready(runtime.state, AuthReadyStage::Factory, AuthReadyOutcome::Ok),
        Err(error) => emit_auth_ready_error(runtime.state, AuthReadyStage::Factory, error),
    }
    let mut attempt = attempt_result.map_err(map)?;
    #[cfg(test)]
    attempt.install_auth_api_for_test(transport);
    #[cfg(not(test))]
    let _ = transport;
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    emit_auth_ready(
        runtime.state,
        AuthReadyStage::Begin,
        AuthReadyOutcome::Enter,
    );
    let turn_result = attempt.begin_ready(runtime.owner, runtime.operation);
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    match &turn_result {
        Ok(_) => emit_auth_ready(runtime.state, AuthReadyStage::Begin, AuthReadyOutcome::Ok),
        Err(error) => emit_auth_ready_error(runtime.state, AuthReadyStage::Begin, error),
    }
    let mut turn = turn_result.map_err(map)?;
    let mut cleanup_until = None;
    loop {
        if runtime.check().is_err() {
            // Attenuation only. The retained turn must observe cancellation and
            // finish its own same-ticket preaccept abort, even after expiry.
            turn.notice_cancel();
            cleanup_until.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
        }
        #[cfg(all(unix, test, feature = "cloud-fixture"))]
        let source_stage = turn.diagnostic_stage();
        #[cfg(all(unix, test, feature = "cloud-fixture"))]
        emit_auth_ready(runtime.state, source_stage, AuthReadyOutcome::Enter);
        let step_result = turn.try_step();
        #[cfg(all(unix, test, feature = "cloud-fixture"))]
        match &step_result {
            Ok(true) => emit_auth_ready(
                runtime.state,
                AuthReadyStage::Done,
                AuthReadyOutcome::Complete,
            ),
            Ok(false) => {
                emit_auth_ready(runtime.state, turn.diagnostic_stage(), AuthReadyOutcome::Ok)
            }
            Err(WorkerReadyError::Domain(DomainError::Busy)) => {
                if let Some(pending_error) = turn.pending_abort_error() {
                    emit_auth_ready_error(runtime.state, source_stage, &pending_error);
                    emit_auth_ready(runtime.state, AuthReadyStage::Abort, AuthReadyOutcome::Busy);
                } else {
                    emit_auth_ready(
                        runtime.state,
                        turn.diagnostic_stage(),
                        AuthReadyOutcome::Busy,
                    );
                }
            }
            Err(error) => emit_auth_ready_error(runtime.state, source_stage, error),
        }
        match step_result {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(WorkerReadyError::Domain(DomainError::Busy)) => {
                // Runtime::busy would return before the typed abort can release
                // its original writer. This separate reserve authorizes only
                // failure cleanup; it never extends operation/HTTP authority.
                if turn.pending_abort_error().is_some() {
                    cleanup_until.get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
                }
                let until = cleanup_until.unwrap_or_else(|| runtime.operation.deadline());
                if cleanup_until.is_some_and(|until| Instant::now() >= until) {
                    // A permanently unavailable lock remains conservatively
                    // fenced by the turn's Drop, rather than minting recovery.
                    let pending_error = turn.pending_abort_error();
                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                    emit_auth_ready_error(
                        runtime.state,
                        AuthReadyStage::Abort,
                        pending_error.as_ref().unwrap_or(&WorkerReadyError::Stale),
                    );
                    return Err(pending_error.map(map).unwrap_or(StepError::Stale));
                }
                std::thread::park_timeout(
                    Duration::from_millis(10).min(until.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(map(error)),
        }
    }
}
impl From<OwnerError> for StepError {
    fn from(error: OwnerError) -> Self {
        match error {
            OwnerError::Store(StoreError::Fenced)
            | OwnerError::Domain(
                DomainError::Stale
                | DomainError::Cancelled
                | DomainError::Deadline
                | DomainError::Busy,
            ) => Self::Stale,
            _ => Self::Auth(lomi_host_auth::Error::Sealed),
        }
    }
}

#[cfg(test)]
fn run(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
) {
    run_with_data(auth, transport, config, runtime, None);
}
#[cfg(test)]
fn run_with_data(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    data: Option<&dyn cloud::DataApi>,
) {
    // Existing injected runtime tests cannot accidentally create peer transport.
    run_with_apis(
        auth,
        transport,
        config,
        runtime,
        InjectedApis {
            data,
            pairing: None,
            channel: None,
            enabled: data.is_none(),
            channels_enabled: data.is_none(),
        },
    );
}
struct InjectedApis<'a> {
    data: Option<&'a dyn cloud::DataApi>,
    pairing: Option<&'a dyn peer::PeerApi>,
    channel: Option<&'a dyn channel::ChannelApi>,
    enabled: bool,
    channels_enabled: bool,
}
#[derive(Default)]
struct IdleScheduler {
    channel_next: bool,
}
impl IdleScheduler {
    fn select_channel(&mut self, channels_enabled: bool) -> bool {
        if !channels_enabled {
            return false;
        }
        let selected = self.channel_next;
        self.channel_next = !self.channel_next;
        selected
    }
}
// Retain the former publication wait behavior only for its cancellation tests.
// Production publication scheduling is owned by the Cloud worker.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PublicationSchedule {
    Configure,
    Logout,
    Disconnected,
}

#[cfg(test)]
struct PublicationWait<'a, 'o> {
    operation: &'o super::owner_domain::Operation<'o>,
    receiver: &'a mpsc::Receiver<Command>,
    gate: &'a AtomicBool,
    paused: &'a AtomicBool,
    stopping: &'a AtomicBool,
    pending: &'a AtomicBool,
    poll: Duration,
    aborted: Option<super::shared_owner::PublicationError>,
}
#[cfg(test)]
impl PublicationWait<'_, '_> {
    fn check(&mut self) -> Result<(), super::shared_owner::PublicationError> {
        use super::shared_owner::PublicationError;
        if let Some(error) = self.aborted {
            return Err(error);
        }
        let result = self
            .operation
            .check()
            .map_err(PublicationError::Domain)
            .and_then(|()| {
                if self.gate.load(Ordering::Acquire)
                    || self.paused.load(Ordering::Acquire)
                    || self.stopping.load(Ordering::Acquire)
                    || self.pending.load(Ordering::Acquire)
                {
                    Err(PublicationError::Stale)
                } else {
                    Ok(())
                }
            });
        if let Err(error) = result {
            self.aborted = Some(error);
        }
        result
    }
    fn delay(&self) -> Duration {
        self.operation
            .deadline()
            .saturating_duration_since(Instant::now())
            .min(
                self.poll
                    .clamp(Duration::from_millis(1), Duration::from_millis(250)),
            )
    }
    // Only Busy calls this wait. All turn Store/domain guards have already
    // dropped; the same attempt, provider and operation remain borrowed.
    fn busy(
        &mut self,
    ) -> Result<Option<PublicationSchedule>, super::shared_owner::PublicationError> {
        self.check()?;
        let received = self.receiver.recv_timeout(self.delay());
        self.check()?;
        Ok(match received {
            Ok(Command::Configure) => Some(PublicationSchedule::Configure),
            Ok(Command::Logout) => Some(PublicationSchedule::Logout),
            Err(mpsc::RecvTimeoutError::Disconnected) => Some(PublicationSchedule::Disconnected),
            Ok(Command::Wake(_)) | Err(mpsc::RecvTimeoutError::Timeout) => None,
        })
    }
}

// Admission management only. This identity cannot mint Ready or transfer any
// existing effect continuation. Renewal occurs only after every class settled.
struct WorkerOperationUnits<'a> {
    initial: &'a OwnerOperation<'a>,
    initial_aborted: &'a std::cell::Cell<bool>,
    next: Option<OwnerOperation<'a>>,
    next_aborted: std::cell::Cell<bool>,
    started: bool,
}
impl<'a> WorkerOperationUnits<'a> {
    fn new(initial: &'a OwnerOperation<'a>, aborted: &'a std::cell::Cell<bool>) -> Self {
        Self {
            initial,
            initial_aborted: aborted,
            next: None,
            next_aborted: std::cell::Cell::new(false),
            started: false,
        }
    }
    fn operation(&self) -> &OwnerOperation<'a> {
        self.next.as_ref().unwrap_or(self.initial)
    }
    fn aborted(&self) -> &std::cell::Cell<bool> {
        if self.next.is_some() {
            &self.next_aborted
        } else {
            self.initial_aborted
        }
    }
    fn admit_after_settlement(&mut self, stopping: &'a AtomicBool) {
        self.next = Some(OwnerOperation::new(
            Instant::now() + Duration::from_secs(60),
            stopping,
        ));
        self.next_aborted.set(false);
    }
}

#[cfg(test)]
fn run_with_apis(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
) {
    // Runtime tests snapshot the exact selected configuration before any
    // provider or network attempt, matching production's held selection.
    let selected_configuration =
        worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))
            .ok()
            .and_then(|snapshot| snapshot.configuration);
    run_with_apis_and_coordinator(
        auth,
        transport,
        config,
        selected_configuration.as_ref(),
        runtime,
        apis,
        std::sync::Weak::new(),
    );
}
fn run_with_apis_and_coordinator(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    selected_configuration: Option<&LocalAuthConfiguration>,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
    coordinator: std::sync::Weak<super::Coordinator>,
) {
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    run_with_apis_inner(
        auth,
        transport,
        config,
        selected_configuration,
        runtime,
        apis,
        coordinator,
        None,
        None,
    );
    #[cfg(not(all(unix, test, feature = "cloud-fixture")))]
    run_with_apis_inner(
        auth,
        transport,
        config,
        selected_configuration,
        runtime,
        apis,
        coordinator,
    );
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn run_with_apis_and_coordinator_with_checkpoint(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    selected_configuration: Option<&LocalAuthConfiguration>,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
    coordinator: std::sync::Weak<super::Coordinator>,
    ack_checkpoint: &SyncSender<()>,
) {
    run_with_apis_inner(
        auth,
        transport,
        config,
        selected_configuration,
        runtime,
        apis,
        coordinator,
        Some(ack_checkpoint),
        None,
    );
}

fn run_with_apis_inner(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    selected_configuration: Option<&LocalAuthConfiguration>,
    runtime: Runtime<'_>,
    apis: InjectedApis<'_>,
    coordinator: std::sync::Weak<super::Coordinator>,
    #[cfg(all(unix, test, feature = "cloud-fixture"))] ack_checkpoint: Option<&SyncSender<()>>,
    #[cfg(all(unix, test, feature = "cloud-fixture"))] peer_eligible_observer: Option<&dyn Fn()>,
) {
    let mut ingress =
        remote_ingress::Registry::with_coordinator(runtime.stopping, coordinator.clone());
    #[cfg(all(unix, test, feature = "cloud-fixture"))]
    if let Some((remote_api_root, relay_root)) = runtime.public_io.cloud_fixture_ingress_roots() {
        if ingress
            .use_cloud_fixture_transport_for_test(remote_api_root, relay_root)
            .is_err()
        {
            set_failed(runtime.state, LocalAuthStorage::Unavailable, runtime.gate);
            return;
        }
    }
    let data = apis.data;
    let Runtime {
        owner,
        operation,
        #[cfg(any(unix, windows))]
            public_io: _,
        aborted: _,
        state,
        stopping,
        receiver,
        retry_requested,
        gate,
        paused,
        mut base,
        mut anchor,
    } = runtime;
    let mut was_active = match worker_read!(runtime, owner.auth_selection(operation)) {
        Ok(snapshot) => snapshot.verified_generation.is_some(),
        Err(_) => {
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        }
    };
    let mut verified_generation = None;
    let mut cloud = cloud::Worker::default();
    let mut peer = peer::Worker::default();
    let mut channel = channel::Worker::default();
    let mut idle = IdleScheduler::default();
    let initial_runtime = runtime;
    let mut units = WorkerOperationUnits::new(runtime.operation, runtime.aborted);
    let mut immediate_ingress_pass = false;
    while !stopping.load(Ordering::Acquire) || ingress.has_active_git_writer() {
        let retained = cloud.has_retained_operation()
            || peer.has_retained_operation()
            || channel.has_retained_operation()
            || ingress.has_retained_operation();
        if units.started && !retained {
            cloud.finish_operation();
            units.admit_after_settlement(stopping);
        }
        units.started = true;
        let mut runtime =
            initial_runtime.with_operation_at(units.operation(), units.aborted(), base, anchor);
        let operation = runtime.operation;
        let wait = remote_ingress::actor_wait_duration(std::mem::take(&mut immediate_ingress_pass));
        match receiver.recv_timeout(wait) {
            Ok(Command::Wake(id)) => {
                let _ = id;
            }
            Ok(Command::Logout | Command::Configure) | Err(_) => {}
        }
        if stopping.load(Ordering::Acquire) {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                let _ = ingress.advance_started_git(auth, runtime);
                continue;
            }
            break;
        }
        if paused.load(Ordering::Acquire) {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                let _ = ingress.advance_started_git(auth, runtime);
                continue;
            }
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        }
        // Consume earlier intent notifications before this attempt. A new
        // explicit request racing a failure remains visible even if try_send fails.
        retry_requested.store(false, Ordering::Release);
        let mut now = runtime.projected_time();
        if ingress.has_active_git_writer()
            && (operation.check().is_err() || runtime.check().is_err())
        {
            ingress.cancel_started_git();
            immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
            continue;
        }
        if matches!(operation.check(), Err(DomainError::Deadline))
            && !stopping.load(Ordering::Acquire)
            && !paused.load(Ordering::Acquire)
            && !runtime.public_io.setup().pending.load(Ordering::Acquire)
        {
            // End the old unit, preserving every durable original intent/ID.
            // Closing the volatile gate forces a real Ready resume if a writer
            // attenuation occurred. No old continuation reaches the new unit.
            cloud.finish_operation();
            peer.discard_retained_operation();
            channel.discard_retained_operation();
            ingress.discard();
            gate.store(true, Ordering::Release);
            continue;
        }
        if runtime.check().is_err() {
            if ingress.has_active_git_writer() {
                ingress.cancel_started_git();
                immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                continue;
            }
            return;
        }
        // Retained effect scopes have their OWN fixed clock checkpoints. A
        // standalone Mutation writer here would stale their original admission.
        let snapshot = if ingress.has_active_git_writer() {
            match ingress.started_git_auth_status(owner) {
                Ok(Some(snapshot)) => Ok(snapshot),
                Err(error) if owner_busy(&error) => {
                    if runtime.busy().is_err() {
                        ingress.cancel_started_git();
                        immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                    }
                    continue;
                }
                Ok(None) | Err(_) => {
                    ingress.cancel_started_git();
                    immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                    continue;
                }
            }
        } else {
            (if retained { Ok(now) } else { observed(runtime) }).and_then(|floor| {
                now = floor;
                if !retained {
                    runtime = runtime.with_clock_floor(floor);
                    base = runtime.base;
                    anchor = runtime.anchor;
                }
                worker_read!(runtime, owner.auth_status(operation))
            })
        };
        let Ok(snapshot) = snapshot else {
            if matches!(operation.check(), Err(DomainError::Deadline)) {
                cloud.finish_operation();
                peer.discard_retained_operation();
                channel.discard_retained_operation();
                ingress.discard();
                gate.store(true, Ordering::Release);
                continue;
            }
            if let Ok(mut turn) = owner.begin_seal_authorization(operation) {
                let _ = commit_worker_turn!(turn, runtime);
            }
            set_failed(state, LocalAuthStorage::Unavailable, gate);
            return;
        };
        let fence = snapshot.authorization;
        let intent = snapshot.intent;
        let deferred_intent = snapshot.deferred_intent;
        if ingress.has_active_git_writer() {
            let Some(continuation) = ingress.started_git_continuation() else {
                ingress.cancel_started_git();
                immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
                continue;
            };
            let deadlines = auth.credential_deadlines().ok();
            let active_valid = auth.status() == Status::Ready
                && !fence.locked
                && !fence.pending_cloud_revoke
                && fence.generation == continuation.runtime().scope.authorization_generation
                && intent.is_none()
                && !gate.load(Ordering::Acquire)
                && !runtime.public_io.setup().pending.load(Ordering::Acquire)
                && deadlines.is_some_and(|deadlines| {
                    now < deadlines.access_expires_at && now < deadlines.refresh_at
                });
            if !active_valid {
                ingress.cancel_started_git();
            }
            if fence.locked
                || fence.pending_cloud_revoke
                || fence.generation != continuation.runtime().scope.authorization_generation
            {
                ingress.discard_other_ingress_for_started_git();
            }
            immediate_ingress_pass = ingress.advance_started_git(auth, runtime);
            continue;
        }
        if verified_generation != Some(fence.generation) {
            if verified_generation.is_some() {
                was_active = false;
                cloud.finish_operation();
                peer.discard_retained_operation();
                channel.discard_retained_operation();
                ingress.discard();
            }
            verified_generation = Some(fence.generation);
        }
        if auth
            .credential_deadlines()
            .is_ok_and(|d| now >= d.access_expires_at)
            && !fence.locked
        {
            cloud.finish_operation();
            peer.discard_retained_operation();
            channel.discard_retained_operation();
            ingress.discard();
            gate.store(true, Ordering::Release);
            let outcome = owner
                .begin_suspend_authorization(operation, fence.generation)
                .and_then(|mut turn| commit_worker_turn!(turn, runtime));
            if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                set_failed(state, LocalAuthStorage::Unavailable, gate);
                return;
            }
        }

        let phase = match auth.status() {
            Status::Empty => LocalAuthPhase::Idle,
            Status::PendingInit => LocalAuthPhase::Initializing,
            Status::AwaitingApproval => LocalAuthPhase::AwaitingApproval,
            Status::Approved | Status::ExchangePrepared => LocalAuthPhase::Exchanging,
            Status::Unconfirmed => LocalAuthPhase::Registering,
            Status::Ready => LocalAuthPhase::Ready,
            Status::Rotating => LocalAuthPhase::Refreshing,
            Status::Revoked => LocalAuthPhase::Locked,
            Status::Sealed => LocalAuthPhase::Unavailable,
        };
        if let Ok(mut view) = state.lock() {
            view.status.phase = if fence.pending_cloud_revoke {
                LocalAuthPhase::PendingRevoke
            } else {
                phase
            };
            view.status.storage = LocalAuthStorage::Available;
            view.status.generation = DecimalU64(fence.generation);
            view.status.locked = fence.locked;
            view.status.pending_cloud_revoke = fence.pending_cloud_revoke;
            view.status.operation_id = if fence.pending_cloud_revoke {
                deferred_intent.map(|i| i.operation_id)
            } else {
                intent.map(|i| i.operation_id)
            };
            let deadlines = auth.credential_deadlines().ok();
            view.status.access_expires_at = deadlines.map(|d| DecimalU64(d.access_expires_at));
            view.status.refresh_at = deadlines.map(|d| DecimalU64(d.refresh_at));
            view.presentation = if fence.pending_cloud_revoke || intent.is_none() {
                None
            } else {
                auth.enrollment_presentation(now).ok().and_then(|p| {
                    Some(LocalLoginPresentation {
                        user_code: p.user_code,
                        verification_url: format!("{}/device", config.origin()).try_into().ok()?,
                        expires_at: DecimalU64(p.expires_at),
                        next_poll_at: DecimalU64(p.next_poll_at),
                    })
                })
            };
        }
        let diagnostic_status = state.lock().ok().map(|view| view.status.clone());
        if let (Some(coordinator), Some(status)) = (coordinator.upgrade(), diagnostic_status) {
            coordinator.observe_authentication(&status);
        }
        if !fence.pending_cloud_revoke && fence.locked && intent.is_none() && !was_active {
            continue;
        }
        let mut requested_immediate_ingress_pass = false;
        let result: Result<bool, StepError> = (|| {
            runtime.check()?;
            if fence.pending_cloud_revoke {
                ingress.discard();
                channel.discard_retained_operation();
                if cloud.logout_epoch_step(auth, config, runtime, fence.generation, data)? {
                    return Ok(false);
                }
                #[cfg(all(unix, test, feature = "cloud-fixture"))]
                if let Some(checkpoint) = ack_checkpoint {
                    return revoke_step_with_ack_checkpoint(
                        auth,
                        transport,
                        config,
                        runtime,
                        fence.generation,
                        checkpoint,
                    )
                    .map(|()| false);
                }
                return revoke_step(auth, transport, config, runtime, fence.generation)
                    .map(|()| false);
            }
            match auth.status() {
                Status::Revoked if intent.is_some() => auth.restart_after_revocation(now)?,
                Status::Empty if intent.is_some() => auth.initialize()?,
                Status::PendingInit if intent.is_some() => {
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let response = transport.initiate(&auth.init_request()?)?;
                    // Measure enrollment TTL conservatively from request start.
                    let floor = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, floor, &mut base, &mut anchor);
                    }
                    if current(runtime, fence.generation) {
                        runtime.check()?;
                        auth.accept_initiation(response, now)?;
                    }
                }
                Status::AwaitingApproval if intent.is_some() => {
                    if auth.enrollment_presentation(now).is_err() {
                        auth.reset_expired_enrollment(now)?;
                        return Ok(false);
                    }
                    let device = match auth.device_poll_credential(now) {
                        Ok(device) => device,
                        Err(lomi_host_auth::Error::PollTooEarly) => return Ok(false),
                        Err(e) => return Err(e.into()),
                    };
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let response = transport.poll(&device);
                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                    let trace = state
                        .lock()
                        .ok()
                        .and_then(|mut view| observe_auth_poll(&mut view, &response));
                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                    if let Some(trace) = trace {
                        trace.emit();
                    }
                    let response = response?;
                    now = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, now, &mut base, &mut anchor);
                    }
                    if !current(runtime, fence.generation) {
                        return Ok(false);
                    }
                    match response {
                        PollOutcome::Approved {
                            bootstrap, context, ..
                        } => {
                            let result =
                                auth.accept_tls_approval(config.origin(), context, bootstrap, now);
                            #[cfg(all(unix, test, feature = "cloud-fixture"))]
                            if let Err(error) = &result {
                                emit_auth_failure(state, AuthFailurePhase::Approve, error);
                            }
                            result?;
                        }
                        PollOutcome::Pending => {}
                        PollOutcome::SlowDown | PollOutcome::RateLimited => {
                            auth.accept_tls_slow_down(config.origin(), now)?
                        }
                        PollOutcome::Expired => { /* Local durable expiry remains authoritative. */
                        }
                        PollOutcome::Denied => {
                            auth.reset_tls_denied_enrollment(config.origin(), now)?
                        }
                        PollOutcome::InvalidRequest | PollOutcome::InvalidGrant => {
                            return Err(StepError::Rejected);
                        }
                    }
                }
                Status::Approved if intent.is_some() => {
                    let prepared = auth.prepare_exchange(now);
                    #[cfg(all(unix, test, feature = "cloud-fixture"))]
                    if let Err(error) = &prepared {
                        emit_auth_failure(state, AuthFailurePhase::PrepareExchange, error);
                    }
                    match prepared {
                        Err(lomi_host_auth::Error::Expired) => {
                            auth.reset_expired_enrollment(now)?
                        }
                        result => result?,
                    }
                }
                Status::ExchangePrepared if intent.is_some() => {
                    mark_cloud_possible(runtime, fence.generation)?;
                    network(state, LocalAuthNetwork::Working);
                    runtime.check()?;
                    let request = normal_exchange_request(auth, now)?;
                    let response = transport.exchange(&request)?;
                    now = observed(runtime)?;
                    if !retained {
                        advance_clock_projection(runtime, now, &mut base, &mut anchor);
                    }
                    if current(runtime, fence.generation) {
                        runtime.check()?;
                        auth.accept_exchange(response, now)?;
                    }
                }
                Status::Unconfirmed if intent.is_some() => {
                    now = trusted_now(runtime)?;
                    let handoff = runtime.with_clock_floor(now);
                    if !retained {
                        base = handoff.base;
                        anchor = handoff.anchor;
                    }
                    ready_from_existing_worker(auth, handoff, transport)?;
                    was_active = true;
                }
                Status::Ready => {
                    if intent.is_some()
                        || fence.locked
                        || gate.load(Ordering::Acquire)
                        || auth.credential_deadlines()?.refresh_at <= now
                    {
                        ingress.discard();
                    } else {
                        // Preparation never pauses normal cloud/peer/channel
                        // priority. A later writer may stale this candidate;
                        // the next poll discards it without renewing provenance.
                        let expected_scope = cloud
                            .cached_eligibility()
                            .map(|eligibility| &eligibility.binding.scope);
                        let observation = runtime.owner.cloud_publication_fence_observation(
                            runtime.operation,
                            fence.generation,
                            expected_scope,
                        )?;
                        match observation {
                            super::shared_owner::CloudPublicationFenceObservation::CloseIngress => {
                                // A durable publication intent or a proven
                                // binding invalidation fences every live remote
                                // connection. A clear observation grants no
                                // eligibility; ordinary request gates remain
                                // authoritative below.
                                ingress.discard();
                            }
                            super::shared_owner::CloudPublicationFenceObservation::Clear => {
                                ingress.poll(auth, runtime, cloud.cached_eligibility());
                            }
                            super::shared_owner::CloudPublicationFenceObservation::Defer => {
                                // Store contention is a bounded pause. In
                                // particular, do not run Cloud's strict Domain
                                // observer while an ingress writer owns it.
                                return Ok(false);
                            }
                        }
                        if ingress.has_active_git_writer() {
                            // The retained Git writer owns the Domain ticket.
                            // Advance its finalization but defer Cloud/peer/
                            // channel readers until that ticket is released.
                            requested_immediate_ingress_pass =
                                ingress.advance(auth, runtime, cloud.cached_eligibility());
                            return Ok(requested_immediate_ingress_pass);
                        }
                    }
                    if intent.is_some()
                        || (was_active && (fence.locked || gate.load(Ordering::Acquire)))
                    {
                        ingress.discard();
                        channel.discard_retained_operation();
                        now = trusted_now(runtime)?;
                        let handoff = runtime.with_clock_floor(now);
                        if !retained {
                            base = handoff.base;
                            anchor = handoff.anchor;
                        }
                        ready_from_existing_worker(auth, handoff, transport)?;
                        was_active = true;
                    } else if intent.is_some()
                        || fence.locked
                        || gate.load(Ordering::Acquire)
                        || auth.credential_deadlines()?.refresh_at <= now
                    {
                        cloud.finish_operation();
                        peer.discard_retained_operation();
                        channel.discard_retained_operation();
                        ingress.discard();
                        auth.prepare_rotation(now)?;
                    } else if peer.has_retained_operation() {
                        let eligibility = cloud.cached_eligibility().ok_or(StepError::Stale)?;
                        peer.step(auth, config, runtime, eligibility, apis.pairing)?;
                    } else if channel.has_retained_operation() {
                        let eligibility = cloud.cached_eligibility().ok_or(StepError::Stale)?;
                        channel.step(auth, config, runtime, eligibility, apis.channel)?;
                        ingress.after_channel_step(&mut channel, auth, runtime, eligibility);
                    } else {
                        let outcome = if let Some(data) = data {
                            cloud.step_using(auth, data, config, runtime, fence.generation)?
                        } else {
                            cloud.step(auth, config, runtime, fence.generation)?
                        };
                        if let cloud::StepOutcome::PeerEligible(eligibility) = outcome {
                            #[cfg(all(unix, test, feature = "cloud-fixture"))]
                            if let Some(observer) = peer_eligible_observer {
                                observer();
                            }
                            if apis.enabled {
                                // Exactly one class runs, even when its selected turn
                                // only prepares locally or waits for bounded backoff.
                                if idle.select_channel(apis.channels_enabled) {
                                    channel.step(
                                        auth,
                                        config,
                                        runtime,
                                        &eligibility,
                                        apis.channel,
                                    )?;
                                    ingress.after_channel_step(
                                        &mut channel,
                                        auth,
                                        runtime,
                                        &eligibility,
                                    );
                                } else {
                                    peer.step(auth, config, runtime, &eligibility, apis.pairing)?;
                                }
                            }
                        }
                    }
                    // Heartbeat/refresh/configuration work above keeps priority.
                    // The driver owns only socket/crypto/codecs and request state.
                    requested_immediate_ingress_pass =
                        ingress.advance(auth, runtime, cloud.cached_eligibility());
                }
                Status::Rotating => {
                    ingress.discard();
                    channel.discard_retained_operation();
                    now = trusted_now(runtime)?;
                    let handoff = runtime.with_clock_floor(now);
                    if !retained {
                        base = handoff.base;
                        anchor = handoff.anchor;
                    }
                    ready_from_existing_worker(auth, handoff, transport)?;
                    was_active = true;
                }
                _ => {}
            }
            Ok(requested_immediate_ingress_pass)
        })();
        match result {
            Err(StepError::Stale) => {
                immediate_ingress_pass = false;
                continue;
            }
            Ok(request_immediate) => {
                immediate_ingress_pass = request_immediate;
                network(state, LocalAuthNetwork::Available);
            }
            Err(error) if global_credential_auth_required(&error) => {
                immediate_ingress_pass = false;
                // A failure during logout is never a revoke acknowledgement and
                // must preserve the exact logout generation/recovery material.
                if fence.pending_cloud_revoke {
                    network(state, LocalAuthNetwork::Unavailable);
                    for _ in 0..4 {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        let _ = receiver.recv_timeout(Duration::from_millis(250));
                    }
                    continue;
                }
                // Sample the durable high-water mark for the exact proof
                // check. This read does not change a retained scope or its
                // operation deadline.
                let now = match trusted_now(runtime) {
                    Ok(now) => now,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                };
                let registered_credential =
                    matches!(auth.status(), Status::Ready | Status::Rotating);
                let retained_enrollment_proof = enrollment_retirement_available(auth, now);
                let eligible = (registered_credential || retained_enrollment_proof)
                    && selected_configuration.is_some();
                if !eligible {
                    // Preserve the prior generic authority-rejection behavior
                    // for phases where there is no retained host credential to
                    // bind to the exact selected configuration.
                    gate.store(true, Ordering::Release);
                    let outcome = owner
                        .begin_authority_rejection(operation, fence.generation)
                        .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                    if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                    if let Ok(mut view) = state.lock() {
                        view.presentation = None;
                    }
                    network(state, LocalAuthNetwork::Unavailable);
                    continue;
                }
                let selected_configuration =
                    selected_configuration.expect("eligible checked configuration");
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_credential_rejection(
                        operation,
                        fence.generation,
                        selected_configuration.clone(),
                    )
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                match outcome {
                    Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                        if let Ok(mut view) = state.lock() {
                            view.presentation = None;
                        }
                        network(state, LocalAuthNetwork::Unavailable);
                    }
                    Err(OwnerError::Domain(
                        DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                    )) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(
                StepError::Http(lomi_host_http::Error::DataRemote(
                    lomi_host_http::DataFailure::ScopeDenied,
                ))
                | StepError::Rejected,
            ) => {
                immediate_ingress_pass = false;
                // Workspace/contract rejection keeps the existing generic
                // fence semantics; it is not credential-specific proof.
                if fence.pending_cloud_revoke {
                    network(state, LocalAuthNetwork::Unavailable);
                    for _ in 0..4 {
                        if stopping.load(Ordering::Acquire) {
                            return;
                        }
                        let _ = receiver.recv_timeout(Duration::from_millis(250));
                    }
                    continue;
                }
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_authority_rejection(operation, fence.generation)
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                if !matches!(outcome, Ok(_) | Err(OwnerError::Store(StoreError::Fenced))) {
                    set_failed(state, LocalAuthStorage::Unavailable, gate);
                    return;
                }
                if let Ok(mut view) = state.lock() {
                    view.presentation = None;
                }
                network(state, LocalAuthNetwork::Unavailable);
            }
            Err(StepError::ExpiredEnrollment) => {
                let now = match trusted_now(runtime) {
                    Ok(now) => now,
                    Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                };
                let retained_enrollment_proof = enrollment_retirement_available(auth, now);
                if fence.pending_cloud_revoke && retained_enrollment_proof {
                    network(state, LocalAuthNetwork::Unavailable);
                    let Some(selected_configuration) = selected_configuration else {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    };
                    let retry_at = Instant::now() + Duration::from_secs(5);
                    match wait_pending_enrollment_reprobe(
                        runtime,
                        fence.generation,
                        selected_configuration,
                        deferred_intent,
                        retry_at,
                    ) {
                        Ok(_) | Err(StepError::Stale) => continue,
                        Err(_) => {
                            set_failed(state, LocalAuthStorage::Unavailable, gate);
                            return;
                        }
                    }
                }
                if !fence.pending_cloud_revoke
                    && intent.is_some()
                    && selected_configuration.is_some()
                    && retained_enrollment_proof
                {
                    let selected_configuration =
                        selected_configuration.expect("guard checked configuration");
                    gate.store(true, Ordering::Release);
                    let outcome = owner
                        .begin_credential_rejection(
                            operation,
                            fence.generation,
                            selected_configuration.clone(),
                        )
                        .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                    match outcome {
                        Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                            if let Ok(mut view) = state.lock() {
                                view.presentation = None;
                            }
                            network(state, LocalAuthNetwork::Unavailable);
                            continue;
                        }
                        Err(OwnerError::Domain(
                            DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                        )) => continue,
                        Err(_) => {
                            set_failed(state, LocalAuthStorage::Unavailable, gate);
                            return;
                        }
                    }
                }
                suspend(runtime);
                auth_failed(state, lomi_host_auth::Error::Expired, gate);
                return;
            }
            Err(StepError::ExpiredRotation)
                if fence.pending_cloud_revoke && auth.status() == Status::Rotating =>
            {
                network(state, LocalAuthNetwork::Unavailable);
                let Some(selected_configuration) = selected_configuration else {
                    set_failed(state, LocalAuthStorage::Unavailable, gate);
                    return;
                };
                let retry_at = Instant::now() + Duration::from_secs(5);
                match wait_pending_rotation_reprobe(
                    runtime,
                    fence.generation,
                    selected_configuration,
                    deferred_intent,
                    retry_at,
                ) {
                    Ok(_) | Err(StepError::Stale) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(StepError::ExpiredRotation)
                if !fence.pending_cloud_revoke
                    && intent.is_some()
                    && auth.status() == Status::Rotating
                    && selected_configuration.is_some() =>
            {
                let selected_configuration = selected_configuration.expect("guard checked config");
                gate.store(true, Ordering::Release);
                let outcome = owner
                    .begin_credential_rejection(
                        operation,
                        fence.generation,
                        selected_configuration.clone(),
                    )
                    .and_then(|mut turn| commit_worker_turn!(turn, runtime));
                match outcome {
                    Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => {
                        if let Ok(mut view) = state.lock() {
                            view.presentation = None;
                        }
                        network(state, LocalAuthNetwork::Unavailable);
                    }
                    Err(OwnerError::Domain(
                        DomainError::Stale | DomainError::Cancelled | DomainError::Deadline,
                    )) => continue,
                    Err(_) => {
                        set_failed(state, LocalAuthStorage::Unavailable, gate);
                        return;
                    }
                }
            }
            Err(StepError::ExpiredRotation) => {
                suspend(runtime);
                auth_failed(state, lomi_host_auth::Error::Expired, gate);
                return;
            }
            Err(StepError::Http(_)) => {
                network(state, LocalAuthNetwork::Unavailable);
                // Network outage keeps local terminals and durable operation intact.
                for _ in 0..4 {
                    if stopping.load(Ordering::Acquire) {
                        return;
                    }
                    let _ = receiver.recv_timeout(Duration::from_millis(250));
                }
            }
            Err(StepError::Auth(lomi_host_auth::Error::Expired))
                if matches!(auth.status(), Status::AwaitingApproval | Status::Approved) =>
            {
                // No exchange intent exists. Definite expiry may reset in place;
                // an expired server challenge before local enrollment expiry
                // leaves the reserved poll cadence intact until expiry/denial.
                match auth.reset_expired_enrollment(now) {
                    Ok(()) | Err(lomi_host_auth::Error::InvalidState) => {}
                    Err(error) => {
                        suspend(runtime);
                        auth_failed(state, error, gate);
                        return;
                    }
                }
            }
            Err(StepError::Auth(error)) => {
                suspend(runtime);
                auth_failed(state, error, gate);
                return;
            }
        }
    }
}
fn fresh_access(auth: &HostAuth<'_, dyn SecretStorage + '_>, now: u64) -> bool {
    auth.status() == Status::Ready
        && auth
            .credential_deadlines()
            .is_ok_and(|d| now < d.access_expires_at)
}
fn enrollment_retirement_available<S: SecretStorage + ?Sized>(
    auth: &HostAuth<'_, S>,
    now: u64,
) -> bool {
    matches!(
        auth.status(),
        Status::ExchangePrepared | Status::Unconfirmed
    ) && auth.enrollment_revocation_ack_request(now).is_ok()
}
fn normal_exchange_request(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    now: u64,
) -> Result<lomi_remote_protocol::HostAuthorizationExchangeParams, StepError> {
    match auth.exchange_request(now) {
        Ok(request) => Ok(request),
        Err(lomi_host_auth::Error::Expired) if enrollment_retirement_available(auth, now) => {
            Err(StepError::ExpiredEnrollment)
        }
        Err(error) => Err(error.into()),
    }
}
fn normal_registration_request(
    auth: &HostAuth<'_, dyn SecretStorage + '_>,
    now: u64,
) -> Result<
    (
        lomi_remote_protocol::HostAccessCredential,
        lomi_remote_protocol::HostRegisterParams,
    ),
    StepError,
> {
    match auth.registration_request(now) {
        Ok(request) => Ok(request),
        Err(lomi_host_auth::Error::Expired) if enrollment_retirement_available(auth, now) => {
            Err(StepError::ExpiredEnrollment)
        }
        Err(error) => Err(error.into()),
    }
}
fn global_credential_auth_required(error: &StepError) -> bool {
    matches!(
        error,
        StepError::Http(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired
        )) | StepError::Http(lomi_host_http::Error::DataRemote(
            lomi_host_http::DataFailure::AuthRequired
        ))
    )
}

/// A single absolute deadline bounds the retry wait. Wake storms may prompt
/// revalidation but cannot move the deadline or trigger another network probe.
fn wait_pending_proof_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    loop {
        runtime.check()?;
        let status = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
        if status.authorization.generation != generation
            || !status.authorization.pending_cloud_revoke
            || status.deferred_intent != deferred
        {
            return Ok(false);
        }
        let selection = worker_read!(runtime, runtime.owner.auth_selection(runtime.operation))?;
        if selection.configuration.as_ref() != Some(configuration) {
            return Ok(false);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(true);
        }
        let wait = remaining.min(Duration::from_millis(250));
        match runtime.receiver.recv_timeout(wait) {
            Ok(Command::Wake(_) | Command::Logout | Command::Configure) => {}
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(StepError::Stale),
        }
    }
}

fn wait_pending_rotation_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    wait_pending_proof_reprobe(runtime, generation, configuration, deferred, deadline)
}

fn wait_pending_enrollment_reprobe(
    runtime: Runtime<'_>,
    generation: u64,
    configuration: &LocalAuthConfiguration,
    deferred: Option<lomi_host_store::LoginIntent>,
    deadline: Instant,
) -> Result<bool, StepError> {
    wait_pending_proof_reprobe(runtime, generation, configuration, deferred, deadline)
}

fn pending_current(runtime: Runtime<'_>, generation: u64) -> bool {
    worker_read!(
        runtime,
        runtime.owner.authorization_state(runtime.operation)
    )
    .is_ok_and(|s| s.generation == generation && s.pending_cloud_revoke)
}
fn acknowledge_revoke(
    runtime: Runtime<'_>,
    generation: u64,
    verified_cloud: bool,
) -> Result<(), StepError> {
    let result = if verified_cloud {
        let mut turn = runtime
            .owner
            .begin_acknowledge_authorization_revoke(runtime.operation, generation)?;
        commit_worker_turn!(turn, runtime)
    } else {
        let mut turn = runtime
            .owner
            .begin_acknowledge_local_authorization_logout(runtime.operation, generation)?;
        commit_worker_turn!(turn, runtime)
    };
    match result {
        Ok(_) | Err(OwnerError::Store(StoreError::Fenced)) => Ok(()),
        Err(e) => Err(e.into()),
    }
}
fn probe_enrollment_retirement_ack(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
    host: lomi_remote_protocol::HostId,
    now: u64,
) -> Result<bool, StepError> {
    let request = auth.enrollment_revocation_ack_request(now)?;
    runtime.check()?;
    match transport.enrollment_revocation_ack(host, &request) {
        Ok(result) => {
            let now = observed(runtime)?;
            if pending_current(runtime, generation) && !runtime.stopping.load(Ordering::Acquire) {
                runtime.check()?;
                // Persist the authenticated terminal secret state first. The
                // following loop performs the exact-generation Store handoff.
                auth.accept_enrollment_revocation_ack(config.origin(), &request, result, now)?;
            }
            Ok(true)
        }
        Err(lomi_host_http::Error::Remote(
            lomi_host_http::HostFailure::AuthRequired
            | lomi_host_http::HostFailure::ResourceNotFound,
        )) => {
            // A typed denial is not an ACK. Let the caller use the exact
            // ordinary exchange/register request if its local deadline remains.
            observed(runtime)?;
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}
fn revoke_step(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
) -> Result<(), StepError> {
    revoke_step_after_ack(auth, transport, config, runtime, generation, || {})
}

#[cfg(all(unix, test, feature = "cloud-fixture"))]
fn revoke_step_with_ack_checkpoint(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
    checkpoint: &SyncSender<()>,
) -> Result<(), StepError> {
    let stopping = runtime.stopping;
    revoke_step_after_ack(auth, transport, config, runtime, generation, || {
        stopping.store(true, Ordering::Release);
        let _ = checkpoint.send(());
    })
}

fn revoke_step_after_ack(
    auth: &mut HostAuth<'_, dyn SecretStorage + '_>,
    transport: &dyn AuthTransport,
    config: &Config,
    runtime: Runtime<'_>,
    generation: u64,
    after_secret_ack: impl FnOnce(),
) -> Result<(), StepError> {
    let Runtime {
        owner,
        operation,
        state,
        stopping,
        ..
    } = runtime;
    let now = observed(runtime)?;
    if !pending_current(runtime, generation) {
        return Ok(());
    }
    match auth.status() {
        Status::Empty => {
            if worker_read!(runtime, owner.auth_history(operation))?.cloud_may_exist != Some(false)
            {
                return Err(lomi_host_auth::Error::InvalidState.into());
            }
            acknowledge_revoke(runtime, generation, false)?;
        }
        Status::PendingInit | Status::AwaitingApproval | Status::Approved => {
            let pristine = worker_read!(runtime, owner.auth_history(operation))?.cloud_may_exist
                == Some(false);
            if !pristine {
                return Err(lomi_host_auth::Error::InvalidState.into());
            }
            auth.cancel_pending_login(now)?;
            acknowledge_revoke(runtime, generation, false)?;
        }
        Status::ExchangePrepared => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            runtime.check()?;
            if !probe_enrollment_retirement_ack(
                auth, transport, config, runtime, generation, host, now,
            )? {
                let now = observed(runtime)?;
                if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                    return Ok(());
                }
                mark_cloud_possible(runtime, generation)?;
                network(state, LocalAuthNetwork::Working);
                runtime.check()?;
                let request = normal_exchange_request(auth, now)?;
                let result = transport.exchange(&request)?;
                let now = observed(runtime)?;
                if pending_current(runtime, generation) {
                    runtime.check()?;
                    auth.accept_exchange(result, now)?;
                }
            }
        }
        Status::Unconfirmed => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            runtime.check()?;
            if !probe_enrollment_retirement_ack(
                auth, transport, config, runtime, generation, host, now,
            )? {
                let now = observed(runtime)?;
                if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                    return Ok(());
                }
                let (access, request) = normal_registration_request(auth, now)?;
                network(state, LocalAuthNetwork::Working);
                runtime.check()?;
                let result = transport.register(&request, &access)?;
                observed(runtime)?;
                if pending_current(runtime, generation) {
                    runtime.check()?;
                    auth.confirm_registration(result)?;
                }
            }
        }
        Status::Ready | Status::Rotating => {
            runtime.check()?;
            let access = auth.revocation_credential()?;
            let request = lomi_remote_protocol::HostRevokeParams {
                expected_host_access_epoch: auth.verified_host_access_epoch()?,
            };
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            network(state, LocalAuthNetwork::Working);
            match transport.revoke(host, &request, &access) {
                Ok(result) => {
                    let now = observed(runtime)?;
                    if pending_current(runtime, generation) {
                        // Secret ACK is durable first; its Revoked state repairs a
                        // crash before the exact-generation SQLite acknowledgement.
                        runtime.check()?;
                        auth.accept_tls_revocation(config.origin(), result, now)?;
                    }
                }
                Err(lomi_host_http::Error::Remote(lomi_host_http::HostFailure::AuthRequired)) => {
                    let now = observed(runtime)?;
                    if !pending_current(runtime, generation) || stopping.load(Ordering::Acquire) {
                        return Ok(());
                    }
                    let acknowledgement = auth.revocation_ack_request(now)?;
                    runtime.check()?;
                    match transport.revocation_ack(host, &acknowledgement) {
                        Ok(result) => {
                            let now = observed(runtime)?;
                            if pending_current(runtime, generation)
                                && !stopping.load(Ordering::Acquire)
                            {
                                runtime.check()?;
                                // Secret ACK is durable first; its Revoked state
                                // repairs a crash before SQLite acknowledgement.
                                auth.accept_revocation_ack(
                                    config.origin(),
                                    &acknowledgement,
                                    result,
                                    now,
                                )?;
                                // The fixture callback stops at this durable
                                // secret-write / SQLite-write boundary.
                                after_secret_ack();
                            }
                        }
                        Err(lomi_host_http::Error::Remote(
                            lomi_host_http::HostFailure::AuthRequired
                            | lomi_host_http::HostFailure::ResourceNotFound,
                        )) => {
                            // Closed proof/route denial is not an ACK. Retain
                            // the exact historical rotation recovery behavior;
                            // its retry identity and original deadline remain
                            // in HostAuth. Generic HTTP status failures are not
                            // classified as endpoint absence.
                            let now = observed(runtime)?;
                            if !pending_current(runtime, generation)
                                || stopping.load(Ordering::Acquire)
                            {
                                return Ok(());
                            }
                            if auth.status() == Status::Ready {
                                auth.prepare_rotation(now)?;
                            } else {
                                runtime.check()?;
                                let request = match auth.rotation_request(now) {
                                    Ok(request) => request,
                                    Err(lomi_host_auth::Error::Expired)
                                        if auth.status() == Status::Rotating =>
                                    {
                                        // Keep the exact old rotation and wait
                                        // for another idempotent revoke/ACK
                                        // probe. Never refresh expired proof.
                                        return Err(StepError::ExpiredRotation);
                                    }
                                    Err(error) => return Err(error.into()),
                                };
                                let result = transport.refresh(&request)?;
                                let now = observed(runtime)?;
                                if pending_current(runtime, generation)
                                    && !stopping.load(Ordering::Acquire)
                                {
                                    runtime.check()?;
                                    auth.accept_rotation(result, now)?;
                                }
                            }
                        }
                        Err(error) => return Err(error.into()),
                    }
                }
                Err(error) => return Err(error.into()),
            }
        }
        Status::Revoked => {
            let host = worker_read!(runtime, owner.identity(operation))?.host_id;
            match auth.retained_revocation_acknowledgement()? {
                RetainedRevocationAcknowledgement::Host(acknowledgement)
                    if acknowledgement.host_id == host => {}
                RetainedRevocationAcknowledgement::NoFamily { host_id, .. } if host_id == host => {}
                _ => return Err(lomi_host_auth::Error::InvalidResponse.into()),
            }
            acknowledge_revoke(runtime, generation, true)?;
        }
        Status::Sealed => return Err(lomi_host_auth::Error::Sealed.into()),
    }
    Ok(())
}
fn observed(runtime: Runtime<'_>) -> Result<u64, StepError> {
    runtime.check()?;
    let now = runtime.projected_time();
    let mut turn = runtime
        .owner
        .begin_observe_authorization_clock(runtime.operation, now)?;
    commit_worker_turn!(turn, runtime).map_err(StepError::from)
}
fn trusted_now(runtime: Runtime<'_>) -> Result<u64, StepError> {
    let projected = runtime.projected_time();
    let snapshot = worker_read!(runtime, runtime.owner.auth_status(runtime.operation))?;
    Ok(projected.max(snapshot.authorization.clock_floor))
}
fn network(state: &Mutex<View>, network: LocalAuthNetwork) {
    if let Ok(mut view) = state.lock() {
        view.status.network = network;
    }
}
#[derive(Debug)]
enum StepError {
    Auth(lomi_host_auth::Error),
    Http(lomi_host_http::Error),
    ExpiredEnrollment,
    ExpiredRotation,
    Rejected,
    Stale,
}
impl From<lomi_host_auth::Error> for StepError {
    fn from(e: lomi_host_auth::Error) -> Self {
        Self::Auth(e)
    }
}
impl From<lomi_host_http::Error> for StepError {
    fn from(e: lomi_host_http::Error) -> Self {
        Self::Http(e)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::testsupport::BuilderExt as _;
    use lomi_remote_protocol::{LocalIpcVersion, rpc::Confirmed};
    use sha2::{Digest, Sha256};
    use std::cell::Cell;
    use std::collections::VecDeque;

    #[cfg(feature = "cloud-fixture")]
    fn fixture_ca_der() -> Vec<u8> {
        use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign];
        params
            .self_signed(&KeyPair::generate().unwrap())
            .unwrap()
            .der()
            .to_vec()
    }

    #[cfg(feature = "cloud-fixture")]
    #[test]
    fn cloud_fixture_mode_allows_only_cloud_scheduling_and_disables_peer_channels() {
        assert!(FixtureMode::AuthOnly.rejects_configured_remote_api());
        assert_eq!(FixtureMode::AuthOnly.api_scheduling(), (false, false));

        assert!(!FixtureMode::CloudOnly.rejects_configured_remote_api());
        assert_eq!(FixtureMode::CloudOnly.api_scheduling(), (false, false));

        assert!(!FixtureMode::JoinedCloud.rejects_configured_remote_api());
        assert_eq!(FixtureMode::JoinedCloud.api_scheduling(), (true, true));
        assert_eq!(
            fixture_api_scheduling(Some(FixtureMode::JoinedCloud)),
            (true, true)
        );
        assert_eq!(fixture_api_scheduling(None), (true, true));
    }

    #[cfg(feature = "cloud-fixture")]
    struct SchedulerCloudApi {
        binding: lomi_remote_protocol::http::RuntimeBinding,
        gets: Cell<usize>,
        claims: Cell<usize>,
        heartbeats: Cell<usize>,
        publications: Cell<usize>,
    }

    #[cfg(feature = "cloud-fixture")]
    impl SchedulerCloudApi {
        fn new(runtime_id: lomi_remote_protocol::RuntimeId) -> Self {
            Self {
                binding: lomi_remote_protocol::http::RuntimeBinding {
                    runtime_id,
                    runtime_generation: DecimalU64(18),
                    host_access_epoch: DecimalU64(13),
                },
                gets: Cell::new(0),
                claims: Cell::new(0),
                heartbeats: Cell::new(0),
                publications: Cell::new(0),
            }
        }

        fn snapshot(
            &self,
            host_id: lomi_remote_protocol::HostId,
            runtime: Option<lomi_remote_protocol::http::RuntimeBinding>,
            publication_seq: u64,
        ) -> lomi_remote_protocol::http::HostRuntimeGetResult {
            let online = runtime.is_some();
            lomi_remote_protocol::http::HostRuntimeGetResult {
                host_id,
                host_access_epoch: DecimalU64(if online { 13 } else { 12 }),
                runtime_generation: DecimalU64(if online { 18 } else { 17 }),
                runtime,
                publication_seq: DecimalU64(publication_seq),
                lease_ms: DecimalU64(if online { 30_000 } else { 0 }),
                freshness_ms: DecimalU64(if online { 5_000 } else { 0 }),
            }
        }
    }

    #[cfg(feature = "cloud-fixture")]
    impl CloudDataApi for SchedulerCloudApi {
        fn get(
            &self,
            host: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::HostRuntimeGetResult, lomi_host_http::Error>
        {
            let call = self.gets.get();
            self.gets.set(call + 1);
            if call == 0 {
                Ok(self.snapshot(host, None, 0))
            } else {
                Ok(self.snapshot(
                    host,
                    Some(self.binding.clone()),
                    u64::from(self.publications.get() > 0),
                ))
            }
        }

        fn claim(
            &self,
            _: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::http::RuntimeClaimParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::RuntimeClaimResult, lomi_host_http::Error> {
            assert_eq!(request.runtime_id, self.binding.runtime_id);
            self.claims.set(self.claims.get() + 1);
            Ok(lomi_remote_protocol::http::RuntimeClaimResult {
                runtime: self.binding.clone(),
                lease_ms: DecimalU64(30_000),
            })
        }

        fn heartbeat(
            &self,
            _: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::http::HeartbeatParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::HeartbeatResult, lomi_host_http::Error> {
            assert_eq!(request.runtime, self.binding);
            self.heartbeats.set(self.heartbeats.get() + 1);
            Ok(lomi_remote_protocol::http::HeartbeatResult {
                runtime: self.binding.clone(),
                lease_ms: DecimalU64(30_000),
                freshness_ms: DecimalU64(5_000),
            })
        }

        fn publish(
            &self,
            _: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::http::PublicationParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::PublicationResult, lomi_host_http::Error> {
            assert_eq!(request.runtime, self.binding);
            self.publications.set(self.publications.get() + 1);
            Ok(lomi_remote_protocol::http::PublicationResult {
                runtime: self.binding.clone(),
                publication_seq: request.publication_seq,
            })
        }
    }

    #[cfg(feature = "cloud-fixture")]
    struct SchedulerPairingApi {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(feature = "cloud-fixture")]
    impl peer::PeerApi for SchedulerPairingApi {
        fn pending(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::PairingPendingResult, lomi_host_http::Error>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(lomi_remote_protocol::http::PairingPendingResult {
                pairings: Vec::new().try_into().unwrap(),
            })
        }

        fn get(
            &self,
            _: lomi_remote_protocol::PairingId,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::PairingResult, lomi_host_http::Error> {
            unreachable!("scheduler fixture has no pairing proposals")
        }

        fn decide(
            &self,
            _: lomi_remote_protocol::PairingId,
            _: &lomi_remote_protocol::http::PairingDecisionParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::PairingResult, lomi_host_http::Error> {
            unreachable!("scheduler fixture has no pairing decisions")
        }
    }

    #[cfg(feature = "cloud-fixture")]
    struct SchedulerChannelApi {
        calls: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(feature = "cloud-fixture")]
    impl channel::ChannelApi for SchedulerChannelApi {
        fn pending(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::ChannelPendingResult, lomi_host_http::Error>
        {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(lomi_remote_protocol::http::ChannelPendingResult {
                channels: Vec::new().try_into().unwrap(),
            })
        }

        fn get(
            &self,
            _: lomi_remote_protocol::ChannelId,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::ChannelResult, lomi_host_http::Error> {
            unreachable!("scheduler fixture has no channel proposals")
        }

        fn admit(
            &self,
            _: lomi_remote_protocol::ChannelId,
            _: &lomi_remote_protocol::http::ChannelAdmissionParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::http::ChannelResult, lomi_host_http::Error> {
            unreachable!("scheduler fixture has no channel admissions")
        }
    }

    #[cfg(feature = "cloud-fixture")]
    #[derive(Debug)]
    struct SchedulerRunObservation {
        timed_out: bool,
        ready: bool,
        peer_eligible: usize,
        gets: usize,
        claims: usize,
        heartbeats: usize,
        publications: usize,
        pairings: usize,
        channels: usize,
    }

    #[cfg(feature = "cloud-fixture")]
    fn run_ready_scheduler_fixture(
        enabled: bool,
        channels_enabled: bool,
        stop_after_eligibility: Option<usize>,
    ) -> SchedulerRunObservation {
        let (_directory, owner, setup, runtime_id) = owned_fixture_with_remote_api();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let login = owned_login(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let _host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);
        let history = owner.auth_history(&operation).unwrap();
        assert_eq!(history.authorization.generation, login.generation);
        assert_eq!(history.cloud_may_exist, Some(true));
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();
        // The Ready handoff below is an ordinary provider-to-Store transition,
        // but this scheduler unit must not contact the configured auth origin.
        // Its test transport returns the same kind of successful rotation used
        // by the existing Ready lifecycle fixtures.
        let transport = SuccessfulRefreshTransport {
            refresh_calls: Cell::new(0),
        };

        // Mirror the managed actor's actual provider-to-Store Ready handoff;
        // a Ready provider alone is not an active verified Store generation.
        with_owned_runtime(&owner, &setup, 1005, |runtime| {
            ready_from_existing_worker(&mut auth, runtime, &transport).unwrap();
        });
        assert_eq!(transport.refresh_calls.get(), 1);
        let ready = owner.auth_status(&operation).unwrap();
        assert_eq!(ready.intent, None);
        assert_eq!(
            owner
                .auth_selection(&operation)
                .unwrap()
                .verified_generation,
            Some(login.generation)
        );

        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let state = Mutex::new(initial());
        let retry_requested = AtomicBool::new(false);
        let gate = AtomicBool::new(false);
        let aborted = Cell::new(false);
        let (wake, receiver) = mpsc::sync_channel(8);
        let anchor = Instant::now();

        // Ensure a broken Cloud fixture cannot loop under the worker's normal
        // explicit-retry behavior indefinitely.
        let watchdog_stop = stopping.clone();
        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog_timed_out = timed_out.clone();
        let (watchdog_done, watchdog_wait) = mpsc::channel();
        let watchdog = thread::spawn(move || {
            if watchdog_wait.recv_timeout(Duration::from_secs(5)).is_err() {
                watchdog_timed_out.store(true, Ordering::Release);
                watchdog_stop.store(true, Ordering::Release);
            }
        });

        let cloud_api = SchedulerCloudApi::new(runtime_id);
        let pairing_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let channel_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let peer_api = SchedulerPairingApi {
            calls: pairing_calls.clone(),
        };
        let channel_api = SchedulerChannelApi {
            calls: channel_calls.clone(),
        };
        let peer_eligible_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let observed = peer_eligible_calls.clone();
        let stop = stopping.clone();
        let observer = move || {
            let count = observed.fetch_add(1, Ordering::SeqCst) + 1;
            if stop_after_eligibility.is_some_and(|limit| count >= limit) {
                stop.store(true, Ordering::Release);
            }
        };

        let selected_configuration = owner.auth_selection(&operation).unwrap().configuration;
        run_with_apis_inner(
            &mut auth,
            &transport,
            &config,
            selected_configuration.as_ref(),
            Runtime {
                owner: &owner,
                operation: &operation,
                public_io: &io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: 1005,
                anchor,
                aborted: &aborted,
            },
            InjectedApis {
                data: Some(&cloud_api),
                pairing: Some(&peer_api),
                channel: Some(&channel_api),
                enabled,
                channels_enabled,
            },
            std::sync::Weak::new(),
            None,
            Some(&observer),
        );
        drop(wake);
        let _ = watchdog_done.send(());
        watchdog.join().unwrap();
        SchedulerRunObservation {
            timed_out: timed_out.load(Ordering::Acquire),
            ready: auth.status() == Status::Ready,
            peer_eligible: peer_eligible_calls.load(Ordering::SeqCst),
            gets: cloud_api.gets.get(),
            claims: cloud_api.claims.get(),
            heartbeats: cloud_api.heartbeats.get(),
            publications: cloud_api.publications.get(),
            pairings: pairing_calls.load(Ordering::SeqCst),
            channels: channel_calls.load(Ordering::SeqCst),
        }
    }

    #[cfg(feature = "cloud-fixture")]
    #[test]
    fn cloud_only_reaches_peer_eligible_but_never_schedules_pairing_or_channels() {
        assert!(!FixtureMode::CloudOnly.rejects_configured_remote_api());

        let (enabled, channels_enabled) = fixture_api_scheduling(Some(FixtureMode::CloudOnly));
        let cloud_only = run_ready_scheduler_fixture(enabled, channels_enabled, Some(2));
        assert!(
            !cloud_only.timed_out,
            "CloudOnly scheduler timed out: {cloud_only:?}"
        );
        assert!(cloud_only.ready, "CloudOnly lost Ready: {cloud_only:?}");
        assert!(
            cloud_only.peer_eligible >= 2,
            "Cloud never produced PeerEligible: {cloud_only:?}"
        );
        assert!(
            cloud_only.gets >= 2,
            "Cloud GET/claim reconciliation did not run: {cloud_only:?}"
        );
        assert_eq!(
            cloud_only.claims, 1,
            "Cloud claim count mismatch: {cloud_only:?}"
        );
        assert!(
            cloud_only.heartbeats >= 1,
            "Cloud heartbeat did not run: {cloud_only:?}"
        );
        assert!(
            cloud_only.publications >= 1,
            "Cloud publication did not run: {cloud_only:?}"
        );
        assert_eq!(
            cloud_only.pairings, 0,
            "CloudOnly called pairing: {cloud_only:?}"
        );
        assert_eq!(
            cloud_only.channels, 0,
            "CloudOnly called channel: {cloud_only:?}"
        );

        // Production's (true, true) scheduling flags are the positive control:
        // the same Ready loop reaches Cloud eligibility and both downstream APIs.
        let (enabled, channels_enabled) = fixture_api_scheduling(None);
        assert_eq!((enabled, channels_enabled), (true, true));
        let production = run_ready_scheduler_fixture(enabled, channels_enabled, Some(3));
        assert!(
            !production.timed_out,
            "production scheduler timed out: {production:?}"
        );
        assert!(
            production.ready,
            "production control lost Ready: {production:?}"
        );
        assert!(
            production.peer_eligible >= 2,
            "production control missed eligibility: {production:?}"
        );
        assert!(
            production.gets >= 2,
            "production control missed GET: {production:?}"
        );
        assert_eq!(
            production.claims, 1,
            "production claim count mismatch: {production:?}"
        );
        assert!(
            production.heartbeats >= 1,
            "production control missed heartbeat: {production:?}"
        );
        assert!(
            production.publications >= 1,
            "production control missed publication: {production:?}"
        );
        assert!(
            production.pairings >= 1,
            "production control skipped pairing scheduling: {production:?}"
        );
        assert!(
            production.channels >= 1,
            "production control skipped channel scheduling: {production:?}"
        );
    }

    #[cfg(feature = "cloud-fixture")]
    #[test]
    fn cloud_fixture_roots_are_bounded_and_der_validated_before_start() {
        let auth_root = fixture_ca_der();
        let remote_root = fixture_ca_der();
        let roots = validate_cloud_fixture_roots(auth_root.clone(), remote_root.clone()).unwrap();
        assert_eq!(roots.auth, auth_root);
        assert_eq!(roots.remote_api, remote_root);

        assert!(matches!(
            validate_cloud_fixture_roots(Vec::new(), remote_root.clone()),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            validate_cloud_fixture_roots(auth_root.clone(), Vec::new()),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            validate_cloud_fixture_roots(vec![0; FIXTURE_ROOT_LIMIT + 1], remote_root.clone()),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            validate_cloud_fixture_roots(auth_root.clone(), vec![0; FIXTURE_ROOT_LIMIT + 1]),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            validate_cloud_fixture_roots(vec![0x30, 0x01, 0x00], remote_root.clone()),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
        assert!(matches!(
            validate_cloud_fixture_roots(auth_root, vec![0x30, 0x01, 0x00]),
            Err(lomi_host_http::Error::InvalidConfig)
        ));
    }

    #[cfg(feature = "cloud-fixture")]
    #[test]
    fn joined_cloud_fixture_requires_three_validated_der_roots() {
        let auth_root = fixture_ca_der();
        let remote_api_root = fixture_ca_der();
        let relay_root = fixture_ca_der();
        let roots = validate_joined_cloud_fixture_roots(
            auth_root.clone(),
            remote_api_root.clone(),
            relay_root.clone(),
        )
        .unwrap();
        assert_eq!(roots.auth, auth_root);
        assert_eq!(roots.remote_api, remote_api_root);
        assert_eq!(roots.relay, relay_root);

        for invalid in [
            (
                vec![0x30, 0x01, 0x00],
                remote_api_root.clone(),
                relay_root.clone(),
            ),
            (
                auth_root.clone(),
                vec![0x30, 0x01, 0x00],
                relay_root.clone(),
            ),
            (auth_root, remote_api_root, vec![0x30, 0x01, 0x00]),
        ] {
            assert!(matches!(
                validate_joined_cloud_fixture_roots(invalid.0, invalid.1, invalid.2),
                Err(lomi_host_http::Error::InvalidConfig)
            ));
        }
    }

    #[test]
    fn credential_rejection_classifier_accepts_only_global_typed_auth_required() {
        for error in [
            StepError::Http(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            )),
            StepError::Http(lomi_host_http::Error::DataRemote(
                lomi_host_http::DataFailure::AuthRequired,
            )),
        ] {
            assert!(global_credential_auth_required(&error));
        }
        for error in [
            StepError::Http(lomi_host_http::Error::DataRemote(
                lomi_host_http::DataFailure::ScopeDenied,
            )),
            StepError::Http(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::ResourceNotFound,
            )),
            StepError::Http(lomi_host_http::Error::Timeout),
            StepError::Auth(lomi_host_auth::Error::Expired),
            StepError::Auth(lomi_host_auth::Error::Sealed),
            StepError::ExpiredRotation,
            StepError::Rejected,
            StepError::Stale,
        ] {
            assert!(!global_credential_auth_required(&error));
        }
    }

    fn with_publication_wait(
        run: impl FnOnce(&mut PublicationWait<'_, '_>, &mpsc::SyncSender<Command>, &AtomicBool),
    ) {
        let cancel = AtomicBool::new(false);
        let operation = super::super::owner_domain::Operation::new(
            Instant::now() + Duration::from_secs(5),
            &cancel,
        );
        let (sender, receiver) = mpsc::sync_channel(1);
        let gate = AtomicBool::new(false);
        let paused = AtomicBool::new(false);
        let stopping = AtomicBool::new(false);
        let pending = AtomicBool::new(false);
        let mut wait = PublicationWait {
            operation: &operation,
            receiver: &receiver,
            gate: &gate,
            paused: &paused,
            stopping: &stopping,
            pending: &pending,
            poll: Duration::from_secs(1),
            aborted: None,
        };
        run(&mut wait, &sender, &cancel);
    }
    #[test]
    fn publication_busy_wait_yields_commands_and_consumes_only_wake() {
        with_publication_wait(|wait, sender, _| {
            sender
                .send(Command::Wake(OperationId::from_bytes([1; 16]).unwrap()))
                .unwrap();
            assert_eq!(wait.busy(), Ok(None));
            sender.send(Command::Configure).unwrap();
            assert_eq!(wait.busy(), Ok(Some(PublicationSchedule::Configure)));
            sender.send(Command::Logout).unwrap();
            assert_eq!(wait.busy(), Ok(Some(PublicationSchedule::Logout)));
        });
    }
    #[test]
    fn publication_busy_wait_bounds_poll_by_original_deadline() {
        with_publication_wait(|wait, _, _| {
            assert!(wait.delay() <= Duration::from_millis(250));
            wait.poll = Duration::from_millis(3);
            assert!(wait.delay() <= Duration::from_millis(3));
            assert!(Instant::now() + wait.delay() <= wait.operation.deadline());
            wait.operation.expire_for_test();
            assert_eq!(
                wait.busy(),
                Err(super::super::shared_owner::PublicationError::Domain(
                    super::super::owner_domain::Error::Deadline
                ))
            );
        });
    }
    #[test]
    fn publication_busy_wait_abort_is_sticky_for_every_latch() {
        for latch in 0..4 {
            with_publication_wait(|wait, sender, _| {
                let flag = match latch {
                    0 => wait.gate,
                    1 => wait.paused,
                    2 => wait.stopping,
                    _ => wait.pending,
                };
                flag.store(true, Ordering::Release);
                assert_eq!(
                    wait.busy(),
                    Err(super::super::shared_owner::PublicationError::Stale)
                );
                flag.store(false, Ordering::Release);
                sender.send(Command::Configure).unwrap();
                assert_eq!(
                    wait.busy(),
                    Err(super::super::shared_owner::PublicationError::Stale)
                );
                assert!(matches!(wait.receiver.try_recv(), Ok(Command::Configure)));
                // These latches abort this schedule, without changing the
                // Operation's distinct real cancellation-latch semantics.
                assert_eq!(wait.operation.check(), Ok(()));
            });
        }
    }
    #[test]
    fn publication_busy_wait_preserves_original_sticky_cancellation() {
        with_publication_wait(|wait, _, cancel| {
            cancel.store(true, Ordering::Release);
            let expected = Err(super::super::shared_owner::PublicationError::Domain(
                super::super::owner_domain::Error::Cancelled,
            ));
            assert_eq!(wait.busy(), expected);
            cancel.store(false, Ordering::Release);
            assert_eq!(wait.busy(), expected);
        });
    }
    #[test]
    fn publication_busy_wait_disconnect_yields_without_cancelling() {
        with_publication_wait(|wait, _, _| {
            let (sender, receiver) = mpsc::sync_channel(1);
            drop(sender);
            // A separate wait keeps the original operation and all latches.
            let mut disconnected = PublicationWait {
                operation: wait.operation,
                receiver: &receiver,
                gate: wait.gate,
                paused: wait.paused,
                stopping: wait.stopping,
                pending: wait.pending,
                poll: wait.poll,
                aborted: None,
            };
            assert_eq!(
                disconnected.busy(),
                Ok(Some(PublicationSchedule::Disconnected))
            );
            assert_eq!(disconnected.operation.check(), Ok(()));
        });
    }
    pub(super) struct MemoryStorage(Option<Vec<u8>>);
    impl MemoryStorage {
        pub(super) fn from_fixture_bytes(bytes: Vec<u8>) -> Self {
            Self(Some(bytes))
        }
        #[cfg(feature = "cloud-fixture")]
        pub(super) fn fixture_bytes(&self) -> Option<&[u8]> {
            self.0.as_deref()
        }
    }
    impl SecretStorage for MemoryStorage {
        fn status(&self) -> secrets::ProviderStatus {
            secrets::ProviderStatus {
                kind: Some(crate::testsupport::provider_kind()),
                state: secrets::StorageState::Available,
            }
        }
        fn load(&self) -> Result<Option<secrets::SecretBundle>, secrets::Error> {
            self.0.clone().map(secrets::SecretBundle::new).transpose()
        }
        fn replace(&mut self, bundle: &secrets::SecretBundle) -> Result<(), secrets::Error> {
            self.0 = Some(bundle.expose().to_vec());
            Ok(())
        }
    }
    struct BlockedTransport {
        entered: mpsc::SyncSender<()>,
        release: mpsc::Receiver<()>,
    }
    impl AuthTransport for BlockedTransport {
        fn revoke(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }

        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            self.entered.send(()).unwrap();
            let _ = self.release.recv_timeout(Duration::from_secs(3));
            Err(lomi_host_http::Error::Timeout)
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
    }
    struct RevocationAckTransport<'a> {
        owner: Option<&'a SharedOwner>,
        host: lomi_remote_protocol::HostId,
        acknowledgement: Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error>,
        refresh_error: lomi_host_http::Error,
        revoke_calls: Cell<usize>,
        acknowledgement_calls: Cell<usize>,
        refresh_calls: Cell<usize>,
        revoke_requests: std::cell::RefCell<
            Vec<(
                lomi_remote_protocol::HostId,
                lomi_remote_protocol::HostRevokeParams,
                lomi_remote_protocol::HostAccessCredential,
            )>,
        >,
        acknowledgement_requests:
            std::cell::RefCell<Vec<lomi_remote_protocol::HostRevocationAckParams>>,
        refresh_requests:
            std::cell::RefCell<Vec<lomi_remote_protocol::HostAuthorizationRefreshParams>>,
    }
    impl AuthTransport for RevocationAckTransport<'_> {
        fn revoke(
            &self,
            host: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::HostRevokeParams,
            access: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            self.revoke_calls.set(self.revoke_calls.get() + 1);
            self.revoke_requests
                .borrow_mut()
                .push((host, request.clone(), access.clone()));
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            ))
        }
        fn revocation_ack(
            &self,
            host: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::HostRevocationAckParams,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            self.acknowledgement_calls
                .set(self.acknowledgement_calls.get() + 1);
            self.acknowledgement_requests
                .borrow_mut()
                .push(request.clone());
            if let Some(owner) = self.owner {
                let cancel = AtomicBool::new(false);
                let operation = test_operation(&cancel);
                owner
                    .begin_local_logout(&operation)
                    .unwrap()
                    .try_commit()
                    .unwrap();
            }
            self.acknowledgement.clone()
        }
        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            self.refresh_calls.set(self.refresh_calls.get() + 1);
            self.refresh_requests.borrow_mut().push(request.clone());
            Err(self.refresh_error)
        }
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ActorAuthEvent {
        Revoke,
        Acknowledgement {
            accepted: bool,
            proof_matches: bool,
            at: Instant,
        },
        EnrollmentAcknowledgement {
            accepted: bool,
            proof_matches: bool,
        },
        Exchange,
        Register,
        Initiate,
    }
    struct ActorRecoveryTransport {
        host: lomi_remote_protocol::HostId,
        expected_family: Option<lomi_remote_protocol::HostAuthorizationId>,
        expected_epoch: Option<DecimalU64>,
        expected_refresh_digest: Option<[u8; 32]>,
        accept_acknowledgement: Arc<AtomicBool>,
        acknowledgement_calls: Arc<std::sync::atomic::AtomicUsize>,
        refresh_calls: Arc<std::sync::atomic::AtomicUsize>,
        events: mpsc::Sender<ActorAuthEvent>,
        initiate_release: mpsc::Receiver<()>,
    }
    struct SuccessfulRefreshTransport {
        refresh_calls: Cell<usize>,
    }
    impl AuthTransport for SuccessfulRefreshTransport {
        fn revoke(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            request: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            self.refresh_calls.set(self.refresh_calls.get() + 1);
            Ok(lomi_remote_protocol::HostAuthorizationResult {
                account_id: lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap(),
                host_id: request.host_id,
                host_authorization_id: request.host_authorization_id,
                access: "synthetic_rotated_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_rotated_refresh".to_owned().try_into().unwrap(),
                rotation_id: request.rotation_id,
                expires_in_seconds: DecimalU64(300),
            })
        }
    }
    impl AuthTransport for ActorRecoveryTransport {
        fn revoke(
            &self,
            host: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            let _ = self.events.send(ActorAuthEvent::Revoke);
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            ))
        }
        fn revocation_ack(
            &self,
            host: lomi_remote_protocol::HostId,
            request: &lomi_remote_protocol::HostRevocationAckParams,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            let accepted = self.accept_acknowledgement.load(Ordering::Acquire);
            let proof_matches = self.expected_family == Some(request.host_authorization_id)
                && self.expected_epoch == Some(request.expected_host_access_epoch)
                && self.expected_refresh_digest
                    == Some(Sha256::digest(request.refresh.expose_wire().as_bytes()).into());
            self.acknowledgement_calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.events.send(ActorAuthEvent::Acknowledgement {
                accepted,
                proof_matches,
                at: Instant::now(),
            });
            if accepted {
                Ok(valid_revoke_ack(self.host))
            } else {
                Err(lomi_host_http::Error::Remote(
                    lomi_host_http::HostFailure::AuthRequired,
                ))
            }
        }
        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            let _ = self.events.send(ActorAuthEvent::Initiate);
            let _ = self.initiate_release.recv_timeout(Duration::from_secs(3));
            Err(lomi_host_http::Error::Timeout)
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            self.refresh_calls.fetch_add(1, Ordering::SeqCst);
            Err(lomi_host_http::Error::Timeout)
        }
    }

    #[derive(Clone, Copy)]
    enum EnrollmentAckReply {
        Deny,
        NotFound,
        NoFamily,
        Family,
        WrongHostFamily,
    }
    #[derive(Clone, Copy)]
    enum RegistrationReply {
        Timeout,
        AuthRequired,
    }
    #[derive(Clone, Copy)]
    enum ExchangeReply {
        Timeout,
        AuthRequired,
    }
    struct ActorEnrollmentTransport {
        host: lomi_remote_protocol::HostId,
        expected_request: HostEnrollmentRevocationAckParams,
        ack_replies: std::cell::RefCell<VecDeque<EnrollmentAckReply>>,
        exchange_replies: std::cell::RefCell<VecDeque<ExchangeReply>>,
        register_replies: std::cell::RefCell<VecDeque<RegistrationReply>>,
        acknowledgement_calls: Arc<std::sync::atomic::AtomicUsize>,
        exchange_calls: Arc<std::sync::atomic::AtomicUsize>,
        register_calls: Arc<std::sync::atomic::AtomicUsize>,
        events: mpsc::Sender<ActorAuthEvent>,
        initiate_release: mpsc::Receiver<()>,
    }
    impl ActorEnrollmentTransport {
        fn new(
            host: lomi_remote_protocol::HostId,
            expected_request: HostEnrollmentRevocationAckParams,
            ack_replies: impl IntoIterator<Item = EnrollmentAckReply>,
            exchange_replies: impl IntoIterator<Item = ExchangeReply>,
            register_replies: impl IntoIterator<Item = RegistrationReply>,
            events: mpsc::Sender<ActorAuthEvent>,
            initiate_release: mpsc::Receiver<()>,
        ) -> Self {
            Self {
                host,
                expected_request,
                ack_replies: std::cell::RefCell::new(ack_replies.into_iter().collect()),
                exchange_replies: std::cell::RefCell::new(exchange_replies.into_iter().collect()),
                register_replies: std::cell::RefCell::new(register_replies.into_iter().collect()),
                acknowledgement_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                exchange_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                register_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                events,
                initiate_release,
            }
        }

        fn wrong_host(&self) -> lomi_remote_protocol::HostId {
            let bytes = if self.host.to_bytes() == [0xee; 16] {
                [0xef; 16]
            } else {
                [0xee; 16]
            };
            lomi_remote_protocol::HostId::from_bytes(bytes).unwrap()
        }
    }
    impl AuthTransport for ActorEnrollmentTransport {
        fn revoke(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }

        fn revocation_ack(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevocationAckParams,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }

        fn enrollment_revocation_ack(
            &self,
            host: lomi_remote_protocol::HostId,
            request: &HostEnrollmentRevocationAckParams,
        ) -> Result<HostEnrollmentRevocationAckResult, lomi_host_http::Error> {
            assert_eq!(host, self.host);
            let proof_matches = request == &self.expected_request;
            assert!(
                proof_matches,
                "retirement probe must preserve original proof"
            );
            self.acknowledgement_calls.fetch_add(1, Ordering::SeqCst);
            let reply = self
                .ack_replies
                .borrow_mut()
                .pop_front()
                .expect("scripted enrollment ACK response");
            let accepted = !matches!(
                reply,
                EnrollmentAckReply::Deny | EnrollmentAckReply::NotFound
            );
            let _ = self.events.send(ActorAuthEvent::EnrollmentAcknowledgement {
                accepted,
                proof_matches,
            });
            let account_id = lomi_remote_protocol::AccountId::from_bytes([4; 16]).unwrap();
            Ok(match reply {
                EnrollmentAckReply::Deny => {
                    return Err(lomi_host_http::Error::Remote(
                        lomi_host_http::HostFailure::AuthRequired,
                    ));
                }
                EnrollmentAckReply::NotFound => {
                    return Err(lomi_host_http::Error::Remote(
                        lomi_host_http::HostFailure::ResourceNotFound,
                    ));
                }
                EnrollmentAckReply::NoFamily => HostEnrollmentRevocationAckResult::NoFamily {
                    host_id: self.host,
                    enrollment_id: request.enrollment_id,
                    operation_id: request.operation_id,
                    account_id,
                },
                EnrollmentAckReply::Family | EnrollmentAckReply::WrongHostFamily => {
                    HostEnrollmentRevocationAckResult::RevokedFamily {
                        host_id: if matches!(reply, EnrollmentAckReply::WrongHostFamily) {
                            self.wrong_host()
                        } else {
                            self.host
                        },
                        enrollment_id: request.enrollment_id,
                        operation_id: request.operation_id,
                        account_id,
                        host_authorization_id:
                            lomi_remote_protocol::HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                        family_host_access_epoch: DecimalU64(12),
                        host_access_epoch: DecimalU64(13),
                    }
                }
            })
        }

        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            let _ = self.events.send(ActorAuthEvent::Initiate);
            let _ = self.initiate_release.recv_timeout(Duration::from_secs(3));
            Err(lomi_host_http::Error::Timeout)
        }

        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }

        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            self.exchange_calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.events.send(ActorAuthEvent::Exchange);
            match self.exchange_replies.borrow_mut().pop_front() {
                Some(ExchangeReply::Timeout) => Err(lomi_host_http::Error::Timeout),
                Some(ExchangeReply::AuthRequired) => Err(lomi_host_http::Error::Remote(
                    lomi_host_http::HostFailure::AuthRequired,
                )),
                None => unreachable!(),
            }
        }

        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            self.register_calls.fetch_add(1, Ordering::SeqCst);
            let _ = self.events.send(ActorAuthEvent::Register);
            match self.register_replies.borrow_mut().pop_front() {
                Some(RegistrationReply::Timeout) => Err(lomi_host_http::Error::Timeout),
                Some(RegistrationReply::AuthRequired) => Err(lomi_host_http::Error::Remote(
                    lomi_host_http::HostFailure::AuthRequired,
                )),
                None => unreachable!(),
            }
        }

        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
    }

    fn spawn_auth_actor<T: AuthTransport + Send + 'static>(
        owner: Arc<SharedOwner>,
        setup: Arc<super::super::public_configuration::PublicSetup>,
        config: Config,
        mut provider: MemoryStorage,
        transport: T,
        stopping: Arc<AtomicBool>,
        base: u64,
    ) -> thread::JoinHandle<(MemoryStorage, Status, u64)> {
        thread::spawn(move || {
            let paused = AtomicBool::new(false);
            let io = setup.enter_owned(&paused).unwrap().unwrap();
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(30), &stopping);
            let aborted = std::cell::Cell::new(false);
            let state = Mutex::new(initial());
            let retry_requested = AtomicBool::new(false);
            let gate = AtomicBool::new(true);
            let (wake, receiver) = mpsc::sync_channel(1);
            let anchor = Instant::now();
            let mut auth = HostAuth::open(
                &mut provider as &mut dyn SecretStorage,
                config.clone(),
                base,
            )
            .unwrap();
            run_with_apis(
                &mut auth,
                &transport,
                &config,
                Runtime {
                    owner: &owner,
                    operation: &operation,
                    public_io: &io,
                    state: &state,
                    stopping: &stopping,
                    receiver: &receiver,
                    retry_requested: &retry_requested,
                    gate: &gate,
                    paused: &paused,
                    base,
                    anchor,
                    aborted: &aborted,
                },
                InjectedApis {
                    data: None,
                    pairing: None,
                    channel: None,
                    enabled: false,
                    channels_enabled: false,
                },
            );
            drop(wake);
            let final_status = auth.status();
            drop(auth);
            let final_projected_time = base.saturating_add(anchor.elapsed().as_secs());
            (provider, final_status, final_projected_time)
        })
    }

    fn ready_auth_for_revoke(
        owner: &SharedOwner,
        setup: &super::super::public_configuration::PublicSetup,
        operation: &OwnerOperation<'_>,
        config: &Config,
        provider: &mut MemoryStorage,
        base: u64,
    ) -> lomi_remote_protocol::HostId {
        let host = owner.identity(operation).unwrap().host_id;
        *provider = unconfirmed_storage(config, host);
        HostAuth::open(provider, config.clone(), 1003)
            .unwrap()
            .confirm_registration(lomi_remote_protocol::HostRegisterResult {
                host_id: host,
                host_access_epoch: DecimalU64(12),
            })
            .unwrap();
        with_owned_runtime(owner, setup, base, |runtime| {
            assert!(qualify_cloud_history(runtime, Status::Ready));
        });
        host
    }
    fn ack_transport<'a>(
        host: lomi_remote_protocol::HostId,
        acknowledgement: Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error>,
    ) -> RevocationAckTransport<'a> {
        RevocationAckTransport {
            owner: None,
            host,
            acknowledgement,
            refresh_error: lomi_host_http::Error::Timeout,
            revoke_calls: Cell::new(0),
            acknowledgement_calls: Cell::new(0),
            refresh_calls: Cell::new(0),
            revoke_requests: std::cell::RefCell::new(Vec::new()),
            acknowledgement_requests: std::cell::RefCell::new(Vec::new()),
            refresh_requests: std::cell::RefCell::new(Vec::new()),
        }
    }
    fn valid_revoke_ack(
        host: lomi_remote_protocol::HostId,
    ) -> lomi_remote_protocol::HostRevokeResult {
        lomi_remote_protocol::HostRevokeResult {
            host_id: host,
            host_access_epoch: DecimalU64(13),
        }
    }
    #[test]
    fn proof_only_ack_publishes_secret_state_before_replayable_sqlite_ack() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);
        let fence = owned_logout(&owner, &operation);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1500,
        )
        .unwrap();
        let transport = ack_transport(host, Ok(valid_revoke_ack(host)));

        // The first turn publishes only the protected secret ACK. A process
        // crash here leaves SQLite pending and the next turn repairs it.
        with_owned_runtime(&owner, &setup, 1500, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, fence.generation).unwrap();
            assert_eq!(auth.status(), Status::Revoked);
            assert!(
                owner
                    .auth_status(runtime.operation)
                    .unwrap()
                    .authorization
                    .pending_cloud_revoke
            );
        });
        assert_eq!(transport.revoke_calls.get(), 1);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
        assert_eq!(transport.refresh_calls.get(), 0);
        let sent = transport.acknowledgement_requests.borrow();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].host_authorization_id,
            lomi_remote_protocol::HostAuthorizationId::from_bytes([8; 16]).unwrap()
        );
        assert_eq!(sent[0].expected_host_access_epoch, DecimalU64(12));
        assert_eq!(sent[0].refresh.expose_wire(), "synthetic_refresh");
        drop(sent);

        with_owned_runtime(&owner, &setup, 1501, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, fence.generation).unwrap();
        });
        assert_eq!(auth.status(), Status::Revoked);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
        assert!(
            !owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }

    #[test]
    fn reopened_expired_rotation_uses_exact_retained_proof_ack_and_repairs_sqlite() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);

        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        auth.prepare_rotation(1100).unwrap();
        let original_rotation = auth.rotation_request(1100).unwrap();
        drop(auth);
        let original_bundle = provider.0.as_ref().unwrap().clone();
        let fence = owned_logout(&owner, &operation);

        // Reopen after the original rotation intent's fixed 300 second window.
        // Its old refresh proof remains available only to revocation ACK.
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1501,
        )
        .unwrap();
        assert_eq!(auth.status(), Status::Rotating);
        assert_eq!(
            auth.rotation_request(1501),
            Err(lomi_host_auth::Error::Expired)
        );
        let transport = ack_transport(host, Ok(valid_revoke_ack(host)));

        with_owned_runtime(&owner, &setup, 1501, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, fence.generation).unwrap();
            assert_eq!(auth.status(), Status::Revoked);
            assert!(
                owner
                    .auth_status(runtime.operation)
                    .unwrap()
                    .authorization
                    .pending_cloud_revoke
            );
        });
        assert_eq!(transport.revoke_calls.get(), 1);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
        assert_eq!(transport.refresh_calls.get(), 0);
        let revoke = transport.revoke_requests.borrow();
        assert_eq!(revoke.len(), 1);
        assert_eq!(revoke[0].0, host);
        assert_eq!(revoke[0].1.expected_host_access_epoch, DecimalU64(12));
        assert_eq!(revoke[0].2.expose_wire(), "synthetic_access");
        drop(revoke);
        let ack = transport.acknowledgement_requests.borrow();
        assert_eq!(ack.len(), 1);
        assert_eq!(
            ack[0].host_authorization_id,
            original_rotation.host_authorization_id
        );
        assert_eq!(ack[0].expected_host_access_epoch, DecimalU64(12));
        assert_eq!(
            ack[0].refresh.expose_wire(),
            original_rotation.refresh.expose_wire()
        );
        drop(ack);
        drop(auth);
        assert_ne!(provider.0.as_ref().unwrap(), &original_bundle);
        assert!(
            !provider
                .0
                .as_ref()
                .unwrap()
                .windows(b"synthetic_refresh".len())
                .any(|window| window == b"synthetic_refresh")
        );

        // A fresh turn sees the secret ACK and completes the exact-generation
        // SQLite handoff without repeating either HTTP request.
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1502,
        )
        .unwrap();
        with_owned_runtime(&owner, &setup, 1502, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, fence.generation).unwrap();
        });
        assert_eq!(auth.status(), Status::Revoked);
        assert_eq!(transport.revoke_calls.get(), 1);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
        assert_eq!(transport.refresh_calls.get(), 0);
        assert!(
            !owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }

    #[test]
    fn pending_expired_rotation_reprobes_without_refresh_then_ack_promotes_deferred_login() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let local_configuration = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let intent = owned_login(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);

        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        auth.prepare_rotation(1100).unwrap();
        let original_rotation = auth.rotation_request(1100).unwrap();
        let original_epoch = auth.verified_host_access_epoch().unwrap();
        drop(auth);
        let original_bundle = provider.0.as_ref().unwrap().clone();
        let rejected = owner
            .begin_credential_rejection(&operation, intent.generation, local_configuration.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        let deferred = lomi_host_store::LoginIntent {
            operation_id: intent.operation_id,
            generation: rejected.generation,
        };
        assert!(rejected.pending_cloud_revoke);
        assert_eq!(
            owner.auth_status(&operation).unwrap().deferred_intent,
            Some(deferred)
        );

        // The live-family proof is denied and the original local rotation
        // window has expired. This pass observes expiry without sending a new
        // refresh or mutating its retained rotation/proof.
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1501,
        )
        .unwrap();
        assert_eq!(auth.status(), Status::Rotating);
        let denied_transport = ack_transport(
            host,
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            )),
        );
        with_owned_runtime(&owner, &setup, 1501, |runtime| {
            assert!(matches!(
                revoke_step(
                    &mut auth,
                    &denied_transport,
                    &config,
                    runtime,
                    rejected.generation
                ),
                Err(StepError::ExpiredRotation)
            ));
            assert!(
                wait_pending_rotation_reprobe(
                    runtime,
                    rejected.generation,
                    &local_configuration,
                    Some(deferred),
                    Instant::now(),
                )
                .unwrap()
            );
        });
        drop(auth);
        assert_eq!(provider.0.as_ref().unwrap(), &original_bundle);
        assert_eq!(denied_transport.revoke_calls.get(), 1);
        assert_eq!(denied_transport.acknowledgement_calls.get(), 1);
        assert_eq!(denied_transport.refresh_calls.get(), 0);
        assert_eq!(denied_transport.refresh_requests.borrow().as_slice(), &[]);
        let pending = owner.auth_status(&operation).unwrap();
        assert_eq!(pending.authorization.generation, rejected.generation);
        assert!(pending.authorization.pending_cloud_revoke);
        assert_eq!(pending.intent, None);
        assert_eq!(pending.deferred_intent, Some(deferred));

        // A later central revoke result accepts the same historical proof;
        // only that typed ACK promotes the deferred operation, with no new
        // LoginStart command and no refresh replay.
        let recovery_transport = ack_transport(host, Ok(valid_revoke_ack(host)));
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1502,
        )
        .unwrap();
        with_owned_runtime(&owner, &setup, 1502, |runtime| {
            revoke_step(
                &mut auth,
                &recovery_transport,
                &config,
                runtime,
                rejected.generation,
            )
            .unwrap();
            assert_eq!(auth.status(), Status::Revoked);
            assert!(
                owner
                    .auth_status(runtime.operation)
                    .unwrap()
                    .authorization
                    .pending_cloud_revoke
            );
        });
        assert_eq!(recovery_transport.revoke_calls.get(), 1);
        assert_eq!(recovery_transport.acknowledgement_calls.get(), 1);
        assert_eq!(recovery_transport.refresh_calls.get(), 0);
        let acknowledged = recovery_transport.acknowledgement_requests.borrow();
        assert_eq!(acknowledged.len(), 1);
        assert_eq!(
            acknowledged[0].host_authorization_id,
            original_rotation.host_authorization_id
        );
        assert_eq!(acknowledged[0].expected_host_access_epoch, original_epoch);
        assert_eq!(
            acknowledged[0].refresh.expose_wire(),
            original_rotation.refresh.expose_wire()
        );
        drop(acknowledged);

        with_owned_runtime(&owner, &setup, 1503, |runtime| {
            revoke_step(
                &mut auth,
                &recovery_transport,
                &config,
                runtime,
                rejected.generation,
            )
            .unwrap();
        });
        let promoted = owner.auth_status(&operation).unwrap();
        assert_eq!(promoted.authorization.generation, rejected.generation);
        assert!(promoted.authorization.locked && !promoted.authorization.pending_cloud_revoke);
        assert_eq!(promoted.intent, Some(deferred));
        assert_eq!(promoted.deferred_intent, None);
        assert!(matches!(
            owner.remote_authorization(&operation),
            Err(OwnerError::Domain(DomainError::Denied))
        ));
    }

    #[test]
    fn actor_loop_defers_expired_rotation_through_denial_then_promotes_and_restarts_pending_init() {
        let (_directory, owner, setup) = owned_fixture();
        let setup_cancel = AtomicBool::new(false);
        let setup_operation = test_operation(&setup_cancel);
        let config = owned_config(&owner, &setup_operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(
            &owner,
            &setup,
            &setup_operation,
            &config,
            &mut provider,
            1003,
        );
        let active = owned_login(&owner, &setup_operation);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        auth.prepare_rotation(1100).unwrap();
        let retained = auth.rotation_request(1100).unwrap();
        let expected_family = retained.host_authorization_id;
        let expected_epoch = auth.verified_host_access_epoch().unwrap();
        let expected_refresh_digest: [u8; 32] =
            Sha256::digest(retained.refresh.expose_wire().as_bytes()).into();
        drop(retained);
        drop(auth);

        let expected_deferred = lomi_host_store::LoginIntent {
            operation_id: active.operation_id,
            generation: active.generation + 1,
        };
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let accept_acknowledgement = Arc::new(AtomicBool::new(false));
        let acknowledgement_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refresh_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config.clone(),
            provider,
            ActorRecoveryTransport {
                host,
                expected_family: Some(expected_family),
                expected_epoch: Some(expected_epoch),
                expected_refresh_digest: Some(expected_refresh_digest),
                accept_acknowledgement: accept_acknowledgement.clone(),
                acknowledgement_calls: acknowledgement_calls.clone(),
                refresh_calls: refresh_calls.clone(),
                events,
                initiate_release,
            },
            stopping.clone(),
            1501,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Revoke
        );
        let first_ack = event_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let ActorAuthEvent::Acknowledgement {
            accepted: false,
            proof_matches: true,
            at: first_ack_at,
        } = first_ack
        else {
            panic!("first proof acknowledgement must be denied");
        };
        let inspect_cancel = AtomicBool::new(false);
        let inspect_operation = test_operation(&inspect_cancel);
        let pending = retry_owner_busy(|| owner.auth_status(&inspect_operation)).unwrap();
        assert!(pending.authorization.pending_cloud_revoke);
        assert!(pending.authorization.locked);
        assert_eq!(pending.intent, None);
        assert_eq!(pending.deferred_intent, Some(expected_deferred));
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&inspect_operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));

        // The first denial enters the actual five-second actor-loop retry. This
        // flag is changed while it waits; no second probe is allowed early.
        accept_acknowledgement.store(true, Ordering::Release);
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(7)).unwrap(),
            ActorAuthEvent::Revoke
        );
        let second_ack = event_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let ActorAuthEvent::Acknowledgement {
            accepted: true,
            proof_matches: true,
            at: second_ack_at,
        } = second_ack
        else {
            panic!("second proof acknowledgement must use the accepted result");
        };
        assert!(
            second_ack_at.duration_since(first_ack_at) >= Duration::from_millis(4500),
            "retry escaped its fixed backoff"
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );

        let promoted = retry_owner_busy(|| owner.auth_status(&inspect_operation)).unwrap();
        assert!(promoted.authorization.locked);
        assert!(!promoted.authorization.pending_cloud_revoke);
        assert_eq!(promoted.intent, Some(expected_deferred));
        assert_eq!(promoted.deferred_intent, None);
        assert_eq!(
            owner
                .auth_selection(&inspect_operation)
                .unwrap()
                .verified_generation,
            None
        );
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&inspect_operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 2);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (provider, final_status, final_projected_time) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
        let mut reopened_storage = MemoryStorage(provider.0);
        let reopened = HostAuth::open(&mut reopened_storage, config, final_projected_time).unwrap();
        assert_eq!(reopened.status(), Status::PendingInit);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn actor_loop_acknowledges_exchange_prepared_no_family_before_new_login() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (provider, request) = exchange_prepared_storage(&config);
        let rejected = owner
            .begin_credential_rejection(&operation, active.generation, selected)
            .unwrap()
            .try_commit()
            .unwrap();
        let deferred = lomi_host_store::LoginIntent {
            operation_id: active.operation_id,
            generation: rejected.generation,
        };

        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::NoFamily],
            [],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config.clone(),
            provider,
            transport,
            stopping.clone(),
            1003,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert!(current.authorization.locked);
        assert_eq!(current.intent, Some(deferred));
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 0);
        assert_eq!(register_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (provider, final_status, final_projected_time) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
        let mut reopened_storage = MemoryStorage(provider.0);
        let reopened = HostAuth::open(&mut reopened_storage, config, final_projected_time).unwrap();
        assert_eq!(reopened.status(), Status::PendingInit);
    }

    #[test]
    fn actor_loop_denied_enrollment_ack_retries_then_promotes_only_typed_family_ack() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        let request = enrollment_ack_request(&mut provider, &config, 1003);
        let rejected = owner
            .begin_credential_rejection(&operation, active.generation, selected)
            .unwrap()
            .try_commit()
            .unwrap();
        let deferred = lomi_host_store::LoginIntent {
            operation_id: active.operation_id,
            generation: rejected.generation,
        };

        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::Deny, EnrollmentAckReply::Family],
            [],
            [RegistrationReply::Timeout],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1004,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: false,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Register
        );
        let denied = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(denied.authorization.pending_cloud_revoke && denied.authorization.locked);
        assert_eq!(denied.intent, None);
        assert_eq!(denied.deferred_intent, Some(deferred));
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(4)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert!(current.authorization.locked);
        assert_eq!(current.intent, Some(deferred));
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 2);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 0);
        assert_eq!(register_calls.load(Ordering::SeqCst), 1);

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
    }

    #[test]
    fn missing_enrollment_ack_route_falls_back_to_exact_exchange_then_reprobes() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (selected, rejected, deferred) =
            install_pending_credential_rejection(&owner, &operation);
        let (provider, request) = exchange_prepared_storage(&config);
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::NotFound, EnrollmentAckReply::NoFamily],
            [ExchangeReply::Timeout],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1003,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: false,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Exchange
        );
        let pending = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(pending.authorization.pending_cloud_revoke && pending.authorization.locked);
        assert_eq!(pending.intent, None);
        assert_eq!(pending.deferred_intent, Some(deferred));
        assert_eq!(pending.authorization.generation, rejected.generation);

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(4)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert_eq!(current.intent, Some(deferred));
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 2);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 1);
        assert_eq!(register_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
        assert_eq!(
            selected,
            owner
                .auth_selection(&operation)
                .unwrap()
                .configuration
                .unwrap()
        );
    }

    #[test]
    fn typed_exchange_auth_required_fences_active_intent_before_no_family_ack() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (provider, request) = exchange_prepared_storage(&config);
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::NoFamily],
            [ExchangeReply::AuthRequired],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1003,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Exchange
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        let fenced = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(fenced.authorization.pending_cloud_revoke && fenced.authorization.locked);
        assert_eq!(fenced.intent, None);
        assert_eq!(
            fenced.deferred_intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: active.operation_id,
                generation: fenced.authorization.generation,
            })
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert!(current.authorization.locked);
        assert_eq!(current.deferred_intent, None);
        assert_eq!(current.intent.unwrap().operation_id, active.operation_id);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 1);
        assert_eq!(register_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            retry_owner_busy(|| owner.remote_authorization(&operation)),
            Err(OwnerError::Domain(DomainError::Denied))
        ));

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
        let selected_after = retry_owner_busy(|| owner.auth_selection(&operation))
            .unwrap()
            .configuration
            .unwrap();
        assert_eq!(selected_after, selected);
    }

    #[test]
    fn typed_registration_auth_required_fences_active_unconfirmed_enrollment() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        let request = enrollment_ack_request(&mut provider, &config, 1003);
        let clock_floor = owner
            .begin_observe_authorization_clock(&operation, 1100)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(clock_floor, 1100);
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::Family],
            [],
            [RegistrationReply::AuthRequired],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1004,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Register
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        let fenced = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(fenced.authorization.pending_cloud_revoke && fenced.authorization.locked);
        assert_eq!(fenced.intent, None);
        assert_eq!(
            fenced.deferred_intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: active.operation_id,
                generation: fenced.authorization.generation,
            })
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert_eq!(current.intent.unwrap().operation_id, active.operation_id);
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(register_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            retry_owner_busy(|| owner.auth_selection(&operation))
                .unwrap()
                .configuration
                .unwrap(),
            selected
        );

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
    }

    #[test]
    fn active_expired_exchange_uses_historical_ack_without_sending_expired_exchange() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let _selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (provider, request) = exchange_prepared_storage(&config);
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::NoFamily],
            [],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1400,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert_eq!(current.authorization.generation, active.generation + 1);
        assert_eq!(
            current.intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: active.operation_id,
                generation: active.generation + 1,
            })
        );
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 0);

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
    }

    #[test]
    fn active_expired_unconfirmed_registration_uses_historical_ack_without_register_send() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let config = owned_config(&owner, &operation);
        let active = owned_login(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        let request = enrollment_ack_request(&mut provider, &config, 1003);
        let (events, event_rx) = mpsc::channel();
        let (release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::Family],
            [],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1400,
        );

        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::EnrollmentAcknowledgement {
                accepted: true,
                proof_matches: true,
            }
        );
        assert_eq!(
            event_rx.recv_timeout(Duration::from_secs(3)).unwrap(),
            ActorAuthEvent::Initiate
        );
        let current = retry_owner_busy(|| owner.auth_status(&operation)).unwrap();
        assert!(!current.authorization.pending_cloud_revoke);
        assert_eq!(current.authorization.generation, active.generation + 1);
        assert_eq!(
            current.intent,
            Some(lomi_host_store::LoginIntent {
                operation_id: active.operation_id,
                generation: active.generation + 1,
            })
        );
        assert_eq!(current.deferred_intent, None);
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert_eq!(register_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            retry_owner_busy(|| owner.auth_selection(&operation))
                .unwrap()
                .configuration
                .unwrap(),
            selected
        );

        stopping.store(true, Ordering::Release);
        release_initiate.send(()).unwrap();
        let (_, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::PendingInit);
    }

    #[test]
    fn passive_expired_exchange_stays_locked_without_retirement_probe() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (provider, request) = exchange_prepared_storage(&config);
        let original = provider.0.as_ref().unwrap().clone();
        let (events, event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let transport =
            ActorEnrollmentTransport::new(host, request, [], [], [], events, initiate_release);
        let acknowledgement_calls = transport.acknowledgement_calls.clone();
        let exchange_calls = transport.exchange_calls.clone();
        let register_calls = transport.register_calls.clone();
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config,
            provider,
            transport,
            stopping.clone(),
            1400,
        );
        assert!(matches!(
            event_rx.recv_timeout(Duration::from_millis(500)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        stopping.store(true, Ordering::Release);
        let (provider, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::ExchangePrepared);
        assert_eq!(provider.0.as_deref(), Some(original.as_slice()));
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 0);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 0);
        assert_eq!(register_calls.load(Ordering::SeqCst), 0);
        let snapshot = owner.auth_status(&operation).unwrap();
        assert!(snapshot.authorization.locked);
        assert!(!snapshot.authorization.pending_cloud_revoke);
        assert_eq!(snapshot.intent, None);
        assert_eq!(snapshot.deferred_intent, None);
    }

    #[test]
    fn no_family_secret_ack_reopen_repairs_only_the_exact_pending_store_generation() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let (selected, rejected, deferred) =
            install_pending_credential_rejection(&owner, &operation);
        let (mut provider, request) = exchange_prepared_storage(&config);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1003,
        )
        .unwrap();
        let (events, _event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let transport = ActorEnrollmentTransport::new(
            host,
            request,
            [EnrollmentAckReply::NoFamily],
            [],
            [],
            events,
            initiate_release,
        );
        let acknowledgement_calls = transport.acknowledgement_calls.clone();

        with_owned_runtime(&owner, &setup, 1003, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, rejected.generation).unwrap();
        });
        assert_eq!(auth.status(), Status::Revoked);
        let before_reopen = owner.auth_status(&operation).unwrap();
        assert!(before_reopen.authorization.pending_cloud_revoke);
        assert_eq!(before_reopen.intent, None);
        assert_eq!(before_reopen.deferred_intent, Some(deferred));
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        drop(auth);

        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1004,
        )
        .unwrap();
        assert!(matches!(
            auth.retained_revocation_acknowledgement(),
            Ok(RetainedRevocationAcknowledgement::NoFamily { host_id, .. }) if host_id == host
        ));
        with_owned_runtime(&owner, &setup, 1004, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, rejected.generation).unwrap();
        });
        let repaired = owner.auth_status(&operation).unwrap();
        assert!(!repaired.authorization.pending_cloud_revoke);
        assert!(repaired.authorization.locked);
        assert_eq!(repaired.authorization.generation, rejected.generation);
        assert_eq!(repaired.intent, Some(deferred));
        assert_eq!(repaired.deferred_intent, None);
        assert_eq!(
            owner.auth_history(&operation).unwrap().cloud_may_exist,
            Some(false)
        );
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 1);
        assert!(matches!(
            owner.remote_authorization(&operation),
            Err(OwnerError::Domain(DomainError::Denied))
        ));
        assert_eq!(
            selected,
            owner
                .auth_selection(&operation)
                .unwrap()
                .configuration
                .unwrap()
        );
    }

    #[test]
    fn enrollment_ack_wrong_host_origin_and_generation_cannot_clear_pending_fence() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let identity = owner.identity(&operation).unwrap();
        let (_selected, rejected, deferred) =
            install_pending_credential_rejection(&owner, &operation);
        let mut provider = unconfirmed_storage(&config, host);
        let request = enrollment_ack_request(&mut provider, &config, 1003);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1003,
        )
        .unwrap();

        let (events, _event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let wrong_host_transport = ActorEnrollmentTransport::new(
            host,
            request.clone(),
            [EnrollmentAckReply::WrongHostFamily],
            [],
            [],
            events,
            initiate_release,
        );
        let wrong_host_calls = wrong_host_transport.acknowledgement_calls.clone();
        with_owned_runtime(&owner, &setup, 1004, |runtime| {
            assert!(matches!(
                revoke_step(
                    &mut auth,
                    &wrong_host_transport,
                    &config,
                    runtime,
                    rejected.generation,
                ),
                Err(StepError::Auth(lomi_host_auth::Error::InvalidResponse))
            ));
        });
        assert_eq!(auth.status(), Status::Unconfirmed);
        assert_eq!(wrong_host_calls.load(Ordering::SeqCst), 1);

        let (events, _event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let wrong_origin_transport = ActorEnrollmentTransport::new(
            host,
            request.clone(),
            [EnrollmentAckReply::Family],
            [],
            [],
            events,
            initiate_release,
        );
        let wrong_origin_calls = wrong_origin_transport.acknowledgement_calls.clone();
        let wrong_origin = Config::new(
            host,
            identity.profile_id,
            "https://alternate.example".to_owned(),
            config.public_client_id().to_owned().try_into().unwrap(),
        )
        .unwrap();
        with_owned_runtime(&owner, &setup, 1005, |runtime| {
            assert!(matches!(
                revoke_step(
                    &mut auth,
                    &wrong_origin_transport,
                    &wrong_origin,
                    runtime,
                    rejected.generation,
                ),
                Err(StepError::Auth(lomi_host_auth::Error::InvalidResponse))
            ));
        });
        assert_eq!(auth.status(), Status::Unconfirmed);
        assert_eq!(wrong_origin_calls.load(Ordering::SeqCst), 1);

        let (events, _event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let stale_transport =
            ActorEnrollmentTransport::new(host, request, [], [], [], events, initiate_release);
        let stale_calls = stale_transport.acknowledgement_calls.clone();
        with_owned_runtime(&owner, &setup, 1006, |runtime| {
            revoke_step(
                &mut auth,
                &stale_transport,
                &config,
                runtime,
                rejected.generation - 1,
            )
            .unwrap();
        });
        assert_eq!(stale_calls.load(Ordering::SeqCst), 0);
        let current = owner.auth_status(&operation).unwrap();
        assert!(current.authorization.pending_cloud_revoke);
        assert_eq!(current.authorization.generation, rejected.generation);
        assert_eq!(current.intent, None);
        assert_eq!(current.deferred_intent, Some(deferred));
        assert!(matches!(
            owner.remote_authorization(&operation),
            Err(OwnerError::Domain(DomainError::Denied))
        ));
    }

    #[test]
    fn passive_expired_rotation_stays_locked_without_automatic_retirement() {
        let (_directory, owner, setup) = owned_fixture();
        let setup_cancel = AtomicBool::new(false);
        let setup_operation = test_operation(&setup_cancel);
        let config = owned_config(&owner, &setup_operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(
            &owner,
            &setup,
            &setup_operation,
            &config,
            &mut provider,
            1003,
        );
        let intent = owned_login(&owner, &setup_operation);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        let verified_refresh = SuccessfulRefreshTransport {
            refresh_calls: Cell::new(0),
        };
        with_owned_runtime(&owner, &setup, 1100, |runtime| {
            ready_from_existing_worker(&mut auth, runtime, &verified_refresh).unwrap();
        });
        assert_eq!(verified_refresh.refresh_calls.get(), 1);
        assert_eq!(auth.status(), Status::Ready);
        let verified = owner.auth_status(&setup_operation).unwrap();
        assert_eq!(intent.generation, verified.authorization.generation);
        assert_eq!(verified.intent, None);
        assert_eq!(verified.deferred_intent, None);
        assert!(!verified.authorization.locked);
        assert_eq!(
            owner
                .auth_selection(&setup_operation)
                .unwrap()
                .verified_generation,
            Some(verified.authorization.generation)
        );
        auth.prepare_rotation(1100).unwrap();
        drop(auth);
        let original_bundle = provider.0.as_ref().unwrap().clone();

        let before = owner.auth_status(&setup_operation).unwrap();
        assert_eq!(before.intent, None);
        assert_eq!(before.deferred_intent, None);
        let (events, event_rx) = mpsc::channel();
        let (_release_initiate, initiate_release) = mpsc::channel();
        let acknowledgement_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let refresh_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let stopping = Arc::new(AtomicBool::new(false));
        let worker = spawn_auth_actor(
            owner.clone(),
            setup,
            config.clone(),
            provider,
            ActorRecoveryTransport {
                host,
                expected_family: None,
                expected_epoch: None,
                expected_refresh_digest: None,
                accept_acknowledgement: Arc::new(AtomicBool::new(false)),
                acknowledgement_calls: acknowledgement_calls.clone(),
                refresh_calls: refresh_calls.clone(),
                events,
                initiate_release,
            },
            stopping.clone(),
            1501,
        );

        let finished_by = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() && Instant::now() < finished_by {
            thread::sleep(Duration::from_millis(5));
        }
        assert!(worker.is_finished(), "passive expiry actor should settle");
        let (provider, final_status, _) = worker.join().unwrap();
        assert_eq!(final_status, Status::Rotating);
        assert!(event_rx.try_iter().next().is_none());
        assert_eq!(acknowledgement_calls.load(Ordering::SeqCst), 0);
        assert_eq!(refresh_calls.load(Ordering::SeqCst), 0);
        assert!(provider.0.as_deref() == Some(original_bundle.as_slice()));

        let inspect_cancel = AtomicBool::new(false);
        let inspect_operation = test_operation(&inspect_cancel);
        let after = owner.auth_status(&inspect_operation).unwrap();
        assert_eq!(
            after.authorization.generation,
            before.authorization.generation
        );
        assert!(after.authorization.locked);
        assert!(!after.authorization.pending_cloud_revoke);
        assert_eq!(after.intent, None);
        assert_eq!(after.deferred_intent, None);
        assert!(matches!(
            owner.remote_authorization(&inspect_operation),
            Err(OwnerError::Domain(DomainError::Denied))
        ));
    }

    #[test]
    fn proof_ack_transport_failures_preserve_exact_rotation_and_pending_generation() {
        let failures = [
            lomi_host_http::Error::HttpStatus,
            lomi_host_http::Error::Timeout,
            lomi_host_http::Error::Network,
            // The HTTPS decoder maps a malformed ACK body to InvalidResponse.
            lomi_host_http::Error::InvalidResponse,
            lomi_host_http::Error::Remote(lomi_host_http::HostFailure::OutcomeUnknown),
        ];
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        auth.prepare_rotation(1100).unwrap();
        let original_rotation = auth.rotation_request(1100).unwrap();
        drop(auth);
        let original_bundle = provider.0.as_ref().unwrap().clone();
        let fence = owned_logout(&owner, &operation);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1200,
        )
        .unwrap();

        for (step, failure) in failures.into_iter().enumerate() {
            let now = 1200 + step as u64 * 10;
            let transport = ack_transport(host, Err(failure));
            with_owned_runtime(&owner, &setup, now, |runtime| {
                assert!(matches!(
                    revoke_step(&mut auth, &transport, &config, runtime, fence.generation),
                    Err(StepError::Http(actual)) if actual == failure
                ));
            });
            assert_eq!(auth.status(), Status::Rotating);
            assert_eq!(auth.rotation_request(now + 9).unwrap(), original_rotation);
            assert_eq!(transport.revoke_calls.get(), 1);
            assert_eq!(transport.acknowledgement_calls.get(), 1);
            assert_eq!(transport.refresh_calls.get(), 0);
            let sent = transport.acknowledgement_requests.borrow();
            assert_eq!(sent.len(), 1);
            assert_eq!(
                sent[0].host_authorization_id,
                original_rotation.host_authorization_id
            );
            assert_eq!(
                sent[0].refresh.expose_wire(),
                original_rotation.refresh.expose_wire()
            );
            drop(sent);
            let state = owner.auth_status(&operation).unwrap().authorization;
            assert_eq!(state.generation, fence.generation);
            assert!(state.pending_cloud_revoke);
        }

        drop(auth);
        assert_eq!(provider.0.as_ref().unwrap(), &original_bundle);
        let auth = HostAuth::open(&mut provider as &mut dyn SecretStorage, config, 1255).unwrap();
        assert_eq!(auth.status(), Status::Rotating);
        assert_eq!(auth.rotation_request(1255).unwrap(), original_rotation);
    }

    #[test]
    fn generation_change_during_ack_does_not_apply_the_response() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);
        let fence = owned_logout(&owner, &operation);
        let original = provider.0.as_ref().unwrap().clone();
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1500,
        )
        .unwrap();
        let mut transport = ack_transport(host, Ok(valid_revoke_ack(host)));
        transport.owner = Some(&owner);

        with_owned_runtime(&owner, &setup, 1500, |runtime| {
            revoke_step(&mut auth, &transport, &config, runtime, fence.generation).unwrap();
        });
        assert_eq!(auth.status(), Status::Ready);
        drop(auth);
        assert_eq!(provider.0.as_ref().unwrap(), &original);
        let state = owner.auth_status(&operation).unwrap().authorization;
        assert!(state.pending_cloud_revoke);
        assert_ne!(state.generation, fence.generation);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
    }

    #[test]
    fn denied_ack_retries_only_the_exact_prepared_rotation_and_preserves_it_on_failure() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let mut provider = MemoryStorage(None);
        let host = ready_auth_for_revoke(&owner, &setup, &operation, &config, &mut provider, 1003);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        auth.prepare_rotation(1100).unwrap();
        let original_rotation = auth.rotation_request(1100).unwrap();
        drop(auth);
        let original_bundle = provider.0.as_ref().unwrap().clone();
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1100,
        )
        .unwrap();
        let fence = owned_logout(&owner, &operation);
        let transport = ack_transport(
            host,
            Err(lomi_host_http::Error::Remote(
                lomi_host_http::HostFailure::AuthRequired,
            )),
        );

        with_owned_runtime(&owner, &setup, 1200, |runtime| {
            assert!(matches!(
                revoke_step(&mut auth, &transport, &config, runtime, fence.generation),
                Err(StepError::Http(lomi_host_http::Error::Timeout))
            ));
        });
        assert_eq!(auth.status(), Status::Rotating);
        drop(auth);
        assert_eq!(provider.0.as_ref().unwrap(), &original_bundle);
        assert_eq!(transport.acknowledgement_calls.get(), 1);
        assert_eq!(transport.refresh_calls.get(), 1);
        assert_eq!(&*transport.refresh_requests.borrow(), &[original_rotation]);
        assert!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }
    fn configuration_value() -> LocalAuthConfiguration {
        LocalAuthConfiguration {
            version: 1,
            origin: "https://identity.example".to_owned().try_into().unwrap(),
            remote_api_origin: None,
            relay_endpoint: None,
            client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
            provider: crate::testsupport::provider(),
            keychain_path: None,
            protected_file_acknowledgement: crate::testsupport::file_acknowledgement(),
        }
    }

    // Insert into auth::tests after configuration_value. Uses the actual owner,
    // actual PublicSetup IO lease and actual typed Store turns; no Store aliases.
    fn owned_fixture() -> (
        tempfile::TempDir,
        Arc<SharedOwner>,
        Arc<super::super::public_configuration::PublicSetup>,
    ) {
        let directory = tempfile::Builder::new()
            .prefix("lomi-auth-owner-scheduler-")
            .private_tempdir()
            .unwrap();
        let profile = directory.path().canonicalize().unwrap();
        let lock = OwnerLock::acquire(&profile).unwrap();
        let mut store =
            HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        store.configure_auth(&configuration_value()).unwrap();
        let discovery = LocalDiscovery {
            version: LocalIpcVersion::CURRENT,
            profile_id: store.identity().profile_id,
            host_id: store.identity().host_id,
            runtime_id: store.runtime_id(),
            build_id: "test".to_owned(),
        };
        let endpoint = Arc::new(OwnerEndpoint::bind(lock, discovery).unwrap());
        super::super::public_configuration::startup(&mut store, endpoint.profile()).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        (directory, owner, setup)
    }

    #[cfg(feature = "cloud-fixture")]
    fn owned_fixture_with_remote_api() -> (
        tempfile::TempDir,
        Arc<SharedOwner>,
        Arc<super::super::public_configuration::PublicSetup>,
        lomi_remote_protocol::RuntimeId,
    ) {
        let directory = tempfile::Builder::new()
            .prefix("lomi-auth-cloud-scheduler-")
            .private_tempdir()
            .unwrap();
        let profile = directory.path().canonicalize().unwrap();
        let lock = OwnerLock::acquire(&profile).unwrap();
        let mut store =
            HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        let mut configured = configuration_value();
        configured.remote_api_origin =
            Some("https://remote.example".to_owned().try_into().unwrap());
        store.configure_auth(&configured).unwrap();
        let runtime_id = store.runtime_id();
        let discovery = LocalDiscovery {
            version: LocalIpcVersion::CURRENT,
            profile_id: store.identity().profile_id,
            host_id: store.identity().host_id,
            runtime_id,
            build_id: "test".to_owned(),
        };
        let endpoint = Arc::new(OwnerEndpoint::bind(lock, discovery).unwrap());
        super::super::public_configuration::startup(&mut store, endpoint.profile()).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint,
        ));
        (directory, owner, setup, runtime_id)
    }

    fn test_operation(cancel: &AtomicBool) -> OwnerOperation<'_> {
        OwnerOperation::new(Instant::now() + Duration::from_secs(10), cancel)
    }
    fn owned_config(owner: &SharedOwner, operation: &OwnerOperation<'_>) -> Config {
        let selected = owner.auth_selection(operation).unwrap();
        configuration(&selected.identity, &selected.configuration.unwrap()).unwrap()
    }
    fn owned_login(
        owner: &SharedOwner,
        operation: &OwnerOperation<'_>,
    ) -> lomi_host_store::LoginIntent {
        let selected = owner.auth_selection(operation).unwrap();
        let generation = owner
            .auth_status(operation)
            .unwrap()
            .authorization
            .generation;
        owner
            .begin_login(
                operation,
                OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes()).unwrap(),
                selected.configuration.unwrap(),
                generation,
            )
            .unwrap()
            .try_commit()
            .unwrap()
    }

    #[test]
    fn pending_revoke_status_surfaces_deferred_operation_without_presentation() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let selected = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        let generation = owner
            .auth_status(&operation)
            .unwrap()
            .authorization
            .generation;
        let operation_id = OperationId::from_bytes([95; 16]).unwrap();
        owner
            .begin_login(&operation, operation_id, selected.clone(), generation)
            .unwrap()
            .try_commit()
            .unwrap();
        let rejected = owner
            .begin_credential_rejection(&operation, generation, selected)
            .unwrap()
            .try_commit()
            .unwrap();
        assert!(rejected.pending_cloud_revoke);

        let (wake, _receiver) = mpsc::sync_channel(1);
        let handle = owned_handle(owner, setup, wake);
        let status = match handle
            .dispatch(&operation, LocalCall::LoginStatus {})
            .unwrap()
        {
            LocalResult::LoginStatus(status) => status,
            _ => panic!("login status response expected"),
        };
        assert_eq!(status.phase, LocalAuthPhase::PendingRevoke);
        assert!(status.pending_cloud_revoke && status.locked);
        assert_eq!(status.generation, DecimalU64(rejected.generation));
        assert_eq!(status.operation_id, Some(operation_id));
        assert!(matches!(
            handle.dispatch(&operation, LocalCall::LoginPresentation {}),
            Err(LocalError::Conflict)
        ));
    }

    fn owned_logout(
        owner: &SharedOwner,
        operation: &OwnerOperation<'_>,
    ) -> lomi_host_store::AuthorizationState {
        owner
            .begin_local_logout(operation)
            .unwrap()
            .try_commit()
            .unwrap()
    }
    fn with_owned_runtime(
        owner: &SharedOwner,
        setup: &super::super::public_configuration::PublicSetup,
        base: u64,
        run: impl FnOnce(Runtime<'_>),
    ) {
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let (_wake, receiver) = mpsc::sync_channel(8);
        let aborted = std::cell::Cell::new(false);
        run(Runtime {
            owner,
            operation: &operation,
            public_io: &io,
            state: &Mutex::new(initial()),
            stopping: &AtomicBool::new(false),
            receiver: &receiver,
            retry_requested: &AtomicBool::new(false),
            gate: &AtomicBool::new(true),
            paused: &paused,
            base,
            anchor: Instant::now(),
            aborted: &aborted,
        });
    }

    fn install_pending_credential_rejection(
        owner: &SharedOwner,
        operation: &OwnerOperation<'_>,
    ) -> (
        LocalAuthConfiguration,
        lomi_host_store::AuthorizationState,
        lomi_host_store::LoginIntent,
    ) {
        let selected = owner
            .auth_selection(operation)
            .unwrap()
            .configuration
            .unwrap();
        let active = owned_login(owner, operation);
        let rejected = owner
            .begin_credential_rejection(operation, active.generation, selected.clone())
            .unwrap()
            .try_commit()
            .unwrap();
        let deferred = lomi_host_store::LoginIntent {
            operation_id: active.operation_id,
            generation: rejected.generation,
        };
        assert!(rejected.pending_cloud_revoke);
        let snapshot = owner.auth_status(operation).unwrap();
        assert_eq!(snapshot.intent, None);
        assert_eq!(snapshot.deferred_intent, Some(deferred));
        (selected, rejected, deferred)
    }

    fn run_pending_rotation_wait(
        owner: &SharedOwner,
        setup: &super::super::public_configuration::PublicSetup,
        operation: &OwnerOperation<'_>,
        stopping: &AtomicBool,
        receiver: &mpsc::Receiver<Command>,
        generation: u64,
        configuration: &LocalAuthConfiguration,
        deferred: Option<lomi_host_store::LoginIntent>,
        deadline: Instant,
    ) -> Result<bool, StepError> {
        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let state = Mutex::new(initial());
        let retry_requested = AtomicBool::new(false);
        let gate = AtomicBool::new(true);
        let aborted = std::cell::Cell::new(false);
        wait_pending_rotation_reprobe(
            Runtime {
                owner,
                operation,
                public_io: &io,
                state: &state,
                stopping,
                receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: 1501,
                anchor: Instant::now(),
                aborted: &aborted,
            },
            generation,
            configuration,
            deferred,
            deadline,
        )
    }

    fn retry_owner_busy<T>(
        mut read: impl FnMut() -> Result<T, OwnerError>,
    ) -> Result<T, OwnerError> {
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            match read() {
                Ok(value) => return Ok(value),
                Err(error) if owner_busy(&error) && Instant::now() < deadline => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => return Err(error),
            }
        }
    }

    #[test]
    fn pending_rotation_wait_keeps_one_deadline_under_wake_storm() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let (configuration, rejected, deferred) =
            install_pending_credential_rejection(&owner, &operation);
        let (wake, receiver) = mpsc::sync_channel(8);
        let producer_wake = wake.clone();
        let storm_stop = Arc::new(AtomicBool::new(false));
        let producer_stop = storm_stop.clone();
        let operation_id = deferred.operation_id;
        let producer = thread::spawn(move || {
            while !producer_stop.load(Ordering::Acquire) {
                let _ = producer_wake.try_send(Command::Wake(operation_id));
                thread::sleep(Duration::from_millis(5));
            }
        });
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let deadline = start + Duration::from_millis(450);
        let result = run_pending_rotation_wait(
            &owner,
            &setup,
            &operation,
            &stopping,
            &receiver,
            rejected.generation,
            &configuration,
            Some(deferred),
            deadline,
        );
        let elapsed = start.elapsed();
        storm_stop.store(true, Ordering::Release);
        producer.join().unwrap();

        assert!(matches!(result, Ok(true)));
        assert!(elapsed >= Duration::from_millis(450));
        assert!(elapsed < Duration::from_secs(2));
    }

    #[test]
    fn pending_rotation_wait_interrupts_on_stop_cancel_and_logout() {
        let (_directory, owner, setup) = owned_fixture();
        let seed_cancel = AtomicBool::new(false);
        let seed_operation = test_operation(&seed_cancel);
        let (configuration, rejected, deferred) =
            install_pending_credential_rejection(&owner, &seed_operation);
        let (wake, receiver) = mpsc::sync_channel(8);

        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = Arc::new(AtomicBool::new(false));
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let stop_latch = stopping.clone();
        let stop_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            stop_latch.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let stopped = run_pending_rotation_wait(
            &owner,
            &setup,
            &operation,
            &stopping,
            &receiver,
            rejected.generation,
            &configuration,
            Some(deferred),
            Instant::now() + Duration::from_secs(5),
        );
        let stop_elapsed = start.elapsed();
        stop_thread.join().unwrap();
        assert!(matches!(stopped, Err(StepError::Stale)));
        assert!(stop_elapsed < Duration::from_millis(500));

        let cancel = Arc::new(AtomicBool::new(false));
        let stopping = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(5), &cancel);
        let cancel_latch = cancel.clone();
        let cancel_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            cancel_latch.store(true, Ordering::Release);
        });
        let start = Instant::now();
        let cancelled = run_pending_rotation_wait(
            &owner,
            &setup,
            &operation,
            &stopping,
            &receiver,
            rejected.generation,
            &configuration,
            Some(deferred),
            Instant::now() + Duration::from_secs(5),
        );
        let cancel_elapsed = start.elapsed();
        cancel_thread.join().unwrap();
        assert!(matches!(cancelled, Err(StepError::Stale)));
        assert!(cancel_elapsed < Duration::from_millis(500));

        let logout_handle = owned_handle(owner.clone(), setup, wake);
        let logout_handle_thread = logout_handle.clone();
        let logout_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            let cancel = AtomicBool::new(false);
            let operation = test_operation(&cancel);
            logout_handle_thread
                .dispatch(
                    &operation,
                    LocalCall::Logout(LocalOperatorIntent {
                        operator_intent: Confirmed::Confirmed,
                    }),
                )
                .unwrap()
        });
        let operation_cancel = AtomicBool::new(false);
        let operation = test_operation(&operation_cancel);
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let logged_out = run_pending_rotation_wait(
            &owner,
            logout_handle.public_setup.as_ref().unwrap(),
            &operation,
            &stopping,
            &receiver,
            rejected.generation,
            &configuration,
            Some(deferred),
            Instant::now() + Duration::from_secs(5),
        );
        let logout_elapsed = start.elapsed();
        let _logout_result = logout_thread.join().unwrap();
        assert!(matches!(logged_out, Ok(false)));
        assert!(logout_elapsed < Duration::from_millis(500));
    }

    #[test]
    fn actual_public_configuration_pending_interrupts_rotation_wait() {
        let (_directory, owner, setup) = owned_fixture();
        let seed_cancel = AtomicBool::new(false);
        let seed_operation = test_operation(&seed_cancel);
        let (configuration, rejected, deferred) =
            install_pending_credential_rejection(&owner, &seed_operation);
        let (wake, receiver) = mpsc::sync_channel(8);
        let handle = owned_handle(owner.clone(), setup.clone(), wake);
        let configuring = handle.clone();
        let configure_thread = thread::spawn(move || {
            thread::sleep(Duration::from_millis(40));
            let cancel = AtomicBool::new(false);
            let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(5), &cancel);
            let mut selected = configuration_value();
            selected.remote_api_origin =
                Some("https://remote.example".to_owned().try_into().unwrap());
            configuring.dispatch(
                &operation,
                LocalCall::AuthConfigure(LocalAuthConfigure {
                    configuration: selected,
                    operator_intent: Confirmed::Confirmed,
                }),
            )
        });

        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let stopping = AtomicBool::new(false);
        let start = Instant::now();
        let result = run_pending_rotation_wait(
            &owner,
            &setup,
            &operation,
            &stopping,
            &receiver,
            rejected.generation,
            &configuration,
            Some(deferred),
            Instant::now() + Duration::from_secs(5),
        );
        let elapsed = start.elapsed();
        let _configuration_result = configure_thread.join().unwrap();

        assert!(matches!(result, Err(StepError::Stale)));
        assert!(elapsed < Duration::from_millis(500));
    }

    #[test]
    fn contended_worker_selection_and_status_resume_without_another_command() {
        let (_directory, owner, setup) = owned_fixture();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let held_owner = owner.clone();
        let holder = thread::spawn(move || {
            let cancel = AtomicBool::new(false);
            let operation = test_operation(&cancel);
            held_owner
                .hold_store_for_test(&operation, entered_tx, release_rx)
                .unwrap();
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let reading_owner = owner.clone();
        let reader = thread::spawn(move || {
            with_owned_runtime(&reading_owner, &setup, 1000, |runtime| {
                let identity = runtime.operation.retained_identity();
                runtime.state.lock().unwrap().status.storage = LocalAuthStorage::Available;
                assert!(
                    matches!(reading_owner.auth_status(runtime.operation), Err(error) if owner_busy(&error))
                );
                waiting_tx.send(()).unwrap();
                let selection =
                    worker_read!(runtime, reading_owner.auth_selection(runtime.operation)).unwrap();
                let snapshot =
                    worker_read!(runtime, reading_owner.auth_status(runtime.operation)).unwrap();
                assert!(runtime.operation.is_same_admission(&identity));
                assert!(!runtime.aborted.get());
                assert!(!runtime.retry_requested.load(Ordering::Acquire));
                assert_eq!(
                    runtime.state.lock().unwrap().status.storage,
                    LocalAuthStorage::Available
                );
                assert!(!snapshot.authorization.pending_cloud_revoke);
                done_tx.send(selection.identity.host_id).unwrap();
            });
        });
        waiting_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(matches!(
            done_rx.recv_timeout(Duration::from_millis(20)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        release_tx.send(()).unwrap();
        done_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        holder.join().unwrap();
        reader.join().unwrap();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        assert!(
            !owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }

    fn owned_handle(
        owner: Arc<SharedOwner>,
        setup: Arc<super::super::public_configuration::PublicSetup>,
        wake: SyncSender<Command>,
    ) -> Handle {
        Handle {
            owner,
            wake,
            state: Arc::new(Mutex::new(initial())),
            retry_requested: Arc::new(AtomicBool::new(false)),
            gate: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
            public_setup: Some(setup),
        }
    }
    #[test]
    fn login_start_snapshot_retries_owner_contention_before_dispatch_admits_once() {
        let (_directory, owner, setup) = owned_fixture();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (released_tx, released_rx) = mpsc::channel();
        let held_owner = owner.clone();
        let holder = thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(5), &cancelled);
            held_owner
                .hold_store_for_test(&operation, entered_tx, release_rx)
                .unwrap();
            released_tx.send(()).unwrap();
        });
        entered_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("test lock holder entered");

        let (busy_tx, busy_rx) = mpsc::sync_channel(1);
        let reading_owner = owner.clone();
        let (wake, wake_rx) = mpsc::sync_channel(1);
        let handle = owned_handle(owner.clone(), setup, wake);
        let operation_id = OperationId::from_bytes([74; 16]).unwrap();
        let reader = thread::spawn(move || {
            let cancelled = AtomicBool::new(false);
            let operation = test_operation(&cancelled);
            let identity = operation.retained_identity();
            let mut attempts = 0;
            let mut first_attempt = true;
            let (selected, status) = login_start_snapshot(&operation, || {
                attempts += 1;
                assert!(operation.is_same_admission(&identity));
                if !first_attempt {
                    released_rx
                        .recv_timeout(Duration::from_secs(2))
                        .expect("held owner locks were released");
                }
                let selected = match reading_owner.auth_selection(&operation) {
                    Err(error) if owner_busy(&error) => {
                        first_attempt = false;
                        busy_tx.send(()).unwrap();
                        return Err(error);
                    }
                    result => result?,
                };
                let status = reading_owner.auth_status(&operation)?;
                Ok((selected, status))
            })
            .unwrap();
            assert_eq!(attempts, 2);
            assert!(operation.is_same_admission(&identity));
            assert_eq!(
                selected.configuration,
                reading_owner
                    .auth_selection(&operation)
                    .unwrap()
                    .configuration
            );

            let accepted = handle
                .dispatch(
                    &operation,
                    LocalCall::LoginStart(LocalLoginStart { operation_id }),
                )
                .unwrap();
            let accepted = match accepted {
                LocalResult::LoginAccepted(accepted) => accepted,
                _ => panic!("LoginStart must be accepted once after snapshot retry"),
            };
            assert_eq!(accepted.operation_id, operation_id);
            assert_eq!(
                accepted.generation,
                DecimalU64(status.authorization.generation)
            );
            assert!(handle.retry_requested.load(Ordering::Acquire));
            assert!(matches!(wake_rx.try_recv(), Ok(Command::Wake(id)) if id == operation_id));
            assert!(matches!(wake_rx.try_recv(), Err(mpsc::TryRecvError::Empty)));
            let persisted = reading_owner.auth_status(&operation).unwrap();
            let intent = persisted.intent.expect("one durable LoginIntent");
            assert_eq!(intent.operation_id, operation_id);
            assert_eq!(intent.generation, status.authorization.generation);
            intent
        });

        busy_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("first snapshot read observed typed lock contention");
        release_tx.send(()).unwrap();
        holder.join().unwrap();
        let intent = reader.join().unwrap();
        assert_eq!(intent.operation_id, operation_id);
    }

    #[test]
    fn login_start_snapshot_stops_on_cancellation_deadline_and_other_errors() {
        let cancelled = AtomicBool::new(false);
        let operation = test_operation(&cancelled);
        let attempts = Cell::new(0);
        let error = login_start_snapshot(&operation, || {
            attempts.set(attempts.get() + 1);
            cancelled.store(true, Ordering::SeqCst);
            Err(OwnerError::Domain(DomainError::Busy))
        })
        .unwrap_err();
        assert_eq!(error, LocalError::Unavailable);
        assert_eq!(attempts.get(), 1);

        let cancelled = AtomicBool::new(false);
        let operation = test_operation(&cancelled);
        let attempts = Cell::new(0);
        let error = login_start_snapshot(&operation, || {
            attempts.set(attempts.get() + 1);
            operation.expire_for_test();
            Err(OwnerError::Domain(DomainError::Busy))
        })
        .unwrap_err();
        assert_eq!(error, LocalError::Unavailable);
        assert_eq!(attempts.get(), 1);

        let cancelled = AtomicBool::new(false);
        let operation = test_operation(&cancelled);
        let attempts = Cell::new(0);
        let error = login_start_snapshot(&operation, || {
            attempts.set(attempts.get() + 1);
            Err(OwnerError::Store(StoreError::Invalid))
        })
        .unwrap_err();
        assert_eq!(error, LocalError::InvalidArgument);
        assert_eq!(attempts.get(), 1);
    }

    #[test]
    fn login_start_snapshot_restarts_pair_after_second_read_busy() {
        let (_directory, owner, _setup) = owned_fixture();
        let cancelled = AtomicBool::new(false);
        let operation = test_operation(&cancelled);
        let selection_reads = Cell::new(0);
        let status_reads = Cell::new(0);
        let (selected, status) = login_start_snapshot(&operation, || {
            selection_reads.set(selection_reads.get() + 1);
            let selected = owner.auth_selection(&operation)?;
            status_reads.set(status_reads.get() + 1);
            if status_reads.get() == 1 {
                // Model auth_status reporting typed Busy after selection
                // succeeded; the whole pair must be acquired again.
                return Err(OwnerError::Domain(DomainError::Busy));
            }
            Ok((selected, owner.auth_status(&operation)?))
        })
        .unwrap();
        assert_eq!(selection_reads.get(), 2);
        assert_eq!(status_reads.get(), 2);
        assert_eq!(
            selected.configuration,
            owner.auth_selection(&operation).unwrap().configuration
        );
        assert_eq!(
            status.authorization.generation,
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .generation
        );
    }

    #[test]
    fn owned_login_intent_survives_a_full_wake_queue() {
        let (_directory, owner, setup) = owned_fixture();
        let (wake, receiver) = mpsc::sync_channel(1);
        wake.try_send(Command::Configure).unwrap();
        let handle = owned_handle(owner.clone(), setup, wake);
        let cancel = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(2), &cancel);
        let journal_operation_id = OperationId::from_bytes([31; 16]).unwrap();
        assert!(matches!(
            handle.dispatch(
                &operation,
                LocalCall::LoginStart(LocalLoginStart {
                    operation_id: journal_operation_id,
                })
            ),
            Ok(LocalResult::LoginAccepted(_))
        ));
        let snapshot = owner.auth_status(&operation).unwrap();
        assert_eq!(snapshot.intent.unwrap().operation_id, journal_operation_id);
        assert!(handle.retry_requested.load(Ordering::Acquire));
        assert!(matches!(receiver.try_recv(), Ok(Command::Configure)));
    }
    #[test]
    fn owned_runtime_abort_remains_sticky_after_pending_clears_and_leaves_commands_queued() {
        let (_directory, owner, setup) = owned_fixture();
        let paused = AtomicBool::new(false);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let cancel = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(2), &cancel);
        let (wake, receiver) = mpsc::sync_channel(1);
        wake.try_send(Command::Logout).unwrap();
        let aborted = std::cell::Cell::new(false);
        let runtime = Runtime {
            owner: &owner,
            operation: &operation,
            public_io: &io,
            state: &Mutex::new(initial()),
            stopping: &AtomicBool::new(false),
            receiver: &receiver,
            retry_requested: &AtomicBool::new(false),
            gate: &AtomicBool::new(true),
            paused: &paused,
            base: 1000,
            anchor: Instant::now(),
            aborted: &aborted,
        };
        // A closed volatile auth gate permits enrollment/recovery. Pending config
        // cancels this specific action even if that pending flag later clears.
        assert!(runtime.check().is_ok());
        setup.pending.store(true, Ordering::Release);
        assert!(matches!(runtime.busy(), Err(StepError::Stale)));
        setup.pending.store(false, Ordering::Release);
        assert!(matches!(runtime.check(), Err(StepError::Stale)));
        assert!(matches!(receiver.try_recv(), Ok(Command::Logout)));
    }
    #[test]
    fn owned_logout_persists_while_configuration_waits_for_the_actual_worker_io() {
        let (_directory, owner, setup) = owned_fixture();
        let (wake, _receiver) = mpsc::sync_channel(1);
        let handle = owned_handle(owner.clone(), setup.clone(), wake);
        let io = setup.enter_owned(&handle.paused).unwrap().unwrap();
        let configuring = handle.clone();
        let worker = thread::spawn(move || {
            let cancel = AtomicBool::new(false);
            let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(3), &cancel);
            let mut config = configuration_value();
            config.remote_api_origin =
                Some("https://remote.example".to_owned().try_into().unwrap());
            configuring.dispatch(
                &operation,
                LocalCall::AuthConfigure(LocalAuthConfigure {
                    configuration: config,
                    operator_intent: Confirmed::Confirmed,
                }),
            )
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !setup.pending.load(Ordering::Acquire) {
            assert!(Instant::now() < deadline);
            thread::sleep(Duration::from_millis(1));
        }
        let cancel = AtomicBool::new(false);
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(1), &cancel);
        let result = handle
            .dispatch(
                &operation,
                LocalCall::Logout(LocalOperatorIntent {
                    operator_intent: Confirmed::Confirmed,
                }),
            )
            .unwrap();
        let LocalResult::LoginStatus(status) = result else {
            panic!("logout must return its committed authorization state");
        };
        assert!(handle.gate.load(Ordering::Acquire));
        assert!(status.locked);
        assert!(status.pending_cloud_revoke);
        // The announced configuration writer denies new local snapshots while
        // waiting for IO. Logout's committed response remains available.
        assert!(matches!(
            owner.auth_status(&operation),
            Err(shared_owner::Error::Domain(DomainError::Denied))
        ));
        // Configuration cannot complete before this exact read lease is dropped.
        assert!(!worker.is_finished());
        drop(io);
        assert!(matches!(
            worker.join().unwrap(),
            Ok(LocalResult::AuthConfigured {})
        ));
        let verification = test_operation(&cancel);
        let persisted = owner.auth_status(&verification).unwrap().authorization;
        assert!(persisted.locked);
        assert!(persisted.pending_cloud_revoke);
        assert_eq!(DecimalU64(persisted.generation), status.generation);
    }

    #[test]
    fn settled_worker_unit_admits_a_successor_but_old_identity_cannot_transfer() {
        let stopping = AtomicBool::new(false);
        let initial = test_operation(&stopping);
        let aborted = std::cell::Cell::new(false);
        let old_identity = initial.retained_identity();
        let mut units = WorkerOperationUnits::new(&initial, &aborted);
        assert!(units.operation().is_same_admission(&old_identity));
        // A retained class keeps this exact admission even after its expiry.
        initial.expire_for_test();
        assert_eq!(units.operation().check(), Err(DomainError::Deadline));
        assert!(units.operation().is_same_admission(&old_identity));
        // Only the scheduler's all-classes-settled branch calls this method.
        units.admit_after_settlement(&stopping);
        assert_eq!(units.operation().check(), Ok(()));
        assert!(!units.operation().is_same_admission(&old_identity));
        assert!(!units.aborted().get());
    }
    #[test]
    fn blocked_transport_keeps_two_actual_ipc_clients_and_offline_logout_responsive() {
        crate::testsupport::initialize_child_ownership();
        let directory = tempfile::Builder::new()
            .prefix("lomi-auth-ipc-")
            .private_tempdir()
            .unwrap();
        let profile = directory.path().canonicalize().unwrap().join("profile");
        crate::testsupport::create_private_dir(&profile).unwrap();
        let lock = OwnerLock::acquire(&profile).unwrap();
        let mut store =
            HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        store.configure_auth(&configuration_value()).unwrap();
        super::super::public_configuration::startup(&mut store, lock.profile()).unwrap();
        let project = store
            .add_project(directory.path(), "Project".to_owned().try_into().unwrap())
            .unwrap();
        store.share(project.state.context.workspace_id, 0).unwrap();
        let intent = store
            .begin_login(OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes()).unwrap())
            .unwrap();
        let endpoint = Arc::new(
            OwnerEndpoint::bind(
                lock,
                LocalDiscovery {
                    version: LocalIpcVersion::CURRENT,
                    profile_id: store.identity().profile_id,
                    host_id: store.identity().host_id,
                    runtime_id: store.runtime_id(),
                    build_id: "test".to_owned(),
                },
            )
            .unwrap(),
        );
        let stopping = Arc::new(AtomicBool::new(false));
        let trusted = configuration(store.identity(), &configuration_value()).unwrap();
        let owner = SharedOwner::new(store).unwrap();
        let setup = Arc::new(super::super::public_configuration::PublicSetup::new(
            endpoint.clone(),
        ));
        let (sender, receiver) = mpsc::sync_channel(1);
        let view = Arc::new(Mutex::new(initial()));
        let retry_requested = Arc::new(AtomicBool::new(false));
        let handle = Handle {
            owner: owner.clone(),
            wake: sender.clone(),
            state: view.clone(),
            retry_requested: retry_requested.clone(),
            gate: Arc::new(AtomicBool::new(true)),
            paused: Arc::new(AtomicBool::new(false)),
            #[cfg(any(unix, windows))]
            public_setup: Some(setup.clone()),
        };
        let coordinator = Arc::new(Coordinator {
            owner: owner.clone(),
            deferred_completions: Mutex::new(rpc::CompletionQueue::new()),
            auth: Mutex::new(Some(handle.clone())),
            terminals: TerminalService::new(),
            stopping: stopping.clone(),
            workspace_locks: Mutex::new(std::collections::BTreeMap::new()),
            files: super::remote_files::Roots::default(),
            git_reads: super::remote_git::Reads::default(),
            git_mutations: super::remote_git_mutations::Mutations::default(),
        });
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let worker_owner = owner.clone();
        let worker_setup = setup.clone();
        let worker_handle = handle.clone();
        let worker_stop = stopping.clone();
        let worker_endpoint = endpoint.clone();
        let worker = thread::spawn(move || {
            let _retained_endpoint = worker_endpoint;
            let io = worker_setup
                .enter_owned(&worker_handle.paused)
                .unwrap()
                .unwrap();
            let operation = test_operation(&worker_stop);
            let aborted = std::cell::Cell::new(false);
            let mut provider = MemoryStorage(None);
            let mut auth = HostAuth::open(
                &mut provider as &mut dyn SecretStorage,
                trusted.clone(),
                1000,
            )
            .unwrap();
            run(
                &mut auth,
                &BlockedTransport {
                    entered: entered_tx,
                    release: release_rx,
                },
                &trusted,
                Runtime {
                    owner: &worker_owner,
                    operation: &operation,
                    public_io: &io,
                    aborted: &aborted,
                    state: &view,
                    stopping: &worker_stop,
                    receiver: &receiver,
                    retry_requested: &retry_requested,
                    gate: &worker_handle.gate,
                    paused: &worker_handle.paused,
                    base: 1000,
                    anchor: Instant::now(),
                },
            );
        });
        entered_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // The network worker is blocked; its wake queue is deliberately full.
        sender.try_send(Command::Configure).unwrap();
        let serving = coordinator.clone();
        let ipc_owner = endpoint.clone();
        let server = thread::spawn(move || {
            for _ in 0..2 {
                // Request operation is admitted before frame IO and passed
                // unchanged through auth dispatch.
                let cancel = AtomicBool::new(false);
                let operation = test_operation(&cancel);
                assert!(ipc_owner.wait(Duration::from_secs(3)).unwrap());
                let stream = ipc_owner.accept().unwrap().unwrap();
                let mut connection = ipc_owner.handshake(stream).unwrap();
                let request = connection.read_request().unwrap();
                connection
                    .write(&LocalResponse {
                        version: connection.version(),
                        request_id: request.request_id,
                        result: serving.dispatch(&operation, request.call),
                    })
                    .unwrap();
            }
        });
        let began = Instant::now();
        let mut first = LocalClient::connect(&profile).unwrap();
        assert!(matches!(
            first.request(LocalCall::LoginStatus {}).unwrap().result,
            Ok(LocalResult::LoginStatus(_))
        ));
        let mut second = LocalClient::connect(&profile).unwrap();
        assert!(matches!(
            second
                .request(LocalCall::Logout(LocalOperatorIntent {
                    operator_intent: Confirmed::Confirmed
                }))
                .unwrap()
                .result,
            Ok(LocalResult::LoginStatus(_))
        ));
        assert!(began.elapsed() < Duration::from_secs(2));
        server.join().unwrap();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let status = owner.auth_status(&operation).unwrap();
        assert!(status.authorization.pending_cloud_revoke);
        assert!(status.authorization.generation > intent.generation);
        assert_eq!(status.intent, None);
        assert!(
            !owner
                .workspace(&operation, project.state.context.workspace_id)
                .unwrap()
                .consent
        );
        // A delayed pre-logout intent cannot begin work against the old fence.
        let result = owner
            .begin_login(
                &operation,
                intent.operation_id,
                configuration_value(),
                intent.generation,
            )
            .unwrap()
            .try_commit();
        assert_eq!(result, Err(OwnerError::Store(StoreError::Fenced)));
        stopping.store(true, Ordering::Release);
        release_tx.send(()).unwrap();
        worker.join().unwrap();
    }
    #[test]
    fn second_logout_between_snapshot_and_ack_keeps_new_pending_work_alive() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let first = owned_logout(&owner, &operation);
        let before_ack = Arc::new(std::sync::Barrier::new(2));
        let release_ack = Arc::new(std::sync::Barrier::new(2));
        let worker_owner = owner.clone();
        let entered = before_ack.clone();
        let release = release_ack.clone();
        let worker = thread::spawn(move || {
            with_owned_runtime(&worker_owner, &setup, 1000, |runtime| {
                assert!(pending_current(runtime, first.generation));
                entered.wait();
                release.wait();
                assert!(acknowledge_revoke(runtime, first.generation, true).is_ok());
            });
        });
        before_ack.wait();
        let second = owned_logout(&owner, &operation);
        release_ack.wait();
        worker.join().unwrap();
        let current = owner.auth_status(&operation).unwrap().authorization;
        assert_eq!(current.generation, second.generation);
        assert!(current.pending_cloud_revoke);
    }
    pub(super) fn test_store() -> (tempfile::TempDir, Arc<Mutex<HostStore>>, Config) {
        let dir = tempfile::Builder::new()
            .prefix("lomi-owner-auth-")
            .private_tempdir()
            .unwrap();
        let mut store =
            HostStore::open(&dir.path().join("host.sqlite"), Limits::default()).unwrap();
        store.configure_auth(&configuration_value()).unwrap();
        let config = configuration(store.identity(), &configuration_value()).unwrap();
        (dir, Arc::new(Mutex::new(store)), config)
    }
    fn approved_storage(config: &Config) -> MemoryStorage {
        use lomi_remote_crypto::{
            HostEnrollmentChallengeContext, prepare_host_enrollment_challenge,
            verify_host_key_initiation,
        };
        use lomi_remote_protocol::*;
        let mut storage = MemoryStorage(None);
        let mut auth = HostAuth::open(&mut storage, config.clone(), 1000).unwrap();
        auth.initialize().unwrap();
        let initiation = auth.init_request().unwrap();
        let committed = verify_host_key_initiation(&initiation).unwrap();
        let pin = committed.descriptor.commitment().unwrap();
        auth.accept_initiation(
            EnrollmentInitiateResult {
                enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                device_code: "synthetic_device".to_owned().try_into().unwrap(),
                user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
                expires_in_seconds: DecimalU64(600),
                poll_interval_seconds: DecimalU64(5),
            },
            1000,
        )
        .unwrap();
        let challenge = prepare_host_enrollment_challenge(
            &committed,
            &pin,
            [4; 16],
            &HostEnrollmentChallengeContext {
                enrollment_id: [3; 16],
                bootstrap_session_id: [5; 16],
                operation_id: [6; 16],
                nonce: [7; 32],
                audience: config.exchange_audience(),
                expires_at: DecimalU64(1500),
            },
        )
        .unwrap();
        let encoded: String = challenge
            .canonical()
            .unwrap()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        auth.accept_tls_approval(
            config.origin(),
            HostEnrollmentTokenContext {
                account_id: AccountId::from_bytes([4; 16]).unwrap(),
                challenge: encoded.try_into().unwrap(),
            },
            "synthetic_bootstrap".to_owned().try_into().unwrap(),
            1001,
        )
        .unwrap();
        drop(auth);
        storage
    }
    fn awaiting_approval_storage(config: &Config) -> (MemoryStorage, PollOutcome) {
        use lomi_remote_crypto::{
            HostEnrollmentChallengeContext, prepare_host_enrollment_challenge,
            verify_host_key_initiation,
        };
        use lomi_remote_protocol::*;
        let mut storage = MemoryStorage(None);
        let mut auth = HostAuth::open(&mut storage, config.clone(), 1000).unwrap();
        auth.initialize().unwrap();
        let initiation_request = auth.init_request().unwrap();
        let committed = verify_host_key_initiation(&initiation_request).unwrap();
        let pin = committed.descriptor.commitment().unwrap();
        auth.accept_initiation(
            EnrollmentInitiateResult {
                enrollment_id: EnrollmentId::from_bytes([3; 16]).unwrap(),
                device_code: "synthetic_device".to_owned().try_into().unwrap(),
                user_code: "SYNTHETIC-CODE".to_owned().try_into().unwrap(),
                expires_in_seconds: DecimalU64(600),
                poll_interval_seconds: DecimalU64(5),
            },
            1000,
        )
        .unwrap();
        let challenge = prepare_host_enrollment_challenge(
            &committed,
            &pin,
            [4; 16],
            &HostEnrollmentChallengeContext {
                enrollment_id: [3; 16],
                bootstrap_session_id: [5; 16],
                operation_id: [6; 16],
                nonce: [7; 32],
                audience: config.exchange_audience(),
                expires_at: DecimalU64(1500),
            },
        )
        .unwrap();
        let context = HostEnrollmentTokenContext {
            account_id: AccountId::from_bytes([4; 16]).unwrap(),
            challenge: challenge
                .canonical()
                .unwrap()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
                .try_into()
                .unwrap(),
        };
        drop(auth);
        (
            storage,
            PollOutcome::Approved {
                bootstrap: "synthetic_bootstrap".to_owned().try_into().unwrap(),
                context,
                expires_in_seconds: 300,
            },
        )
    }

    struct ClockFloorStorage {
        bytes: Option<Vec<u8>>,
        writes: usize,
    }
    impl SecretStorage for ClockFloorStorage {
        fn status(&self) -> secrets::ProviderStatus {
            secrets::ProviderStatus {
                kind: Some(crate::testsupport::provider_kind()),
                state: secrets::StorageState::Available,
            }
        }

        fn load(&self) -> Result<Option<secrets::SecretBundle>, secrets::Error> {
            self.bytes
                .clone()
                .map(secrets::SecretBundle::new)
                .transpose()
        }

        fn replace(&mut self, bundle: &secrets::SecretBundle) -> Result<(), secrets::Error> {
            self.bytes = Some(bundle.expose().to_vec());
            self.writes += 1;
            Ok(())
        }
    }

    struct ClockFloorTransport {
        approval: std::sync::Mutex<Option<PollOutcome>>,
        host: lomi_remote_protocol::HostId,
        exchange_delay: Duration,
        poll_calls: Arc<std::sync::atomic::AtomicUsize>,
        exchange_calls: Arc<std::sync::atomic::AtomicUsize>,
        register_calls: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl AuthTransport for ClockFloorTransport {
        fn revoke(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }

        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            unreachable!()
        }

        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            self.poll_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .approval
                .lock()
                .unwrap()
                .take()
                .expect("one scripted approval"))
        }

        fn exchange(
            &self,
            request: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            use lomi_remote_protocol::*;
            self.exchange_calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.exchange_delay);
            Ok(HostAuthorizationResult {
                account_id: AccountId::from_bytes([4; 16]).unwrap(),
                host_id: request.host_id,
                host_authorization_id: HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                access: "synthetic_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
                rotation_id: request.operation_id,
                expires_in_seconds: DecimalU64(300),
            })
        }

        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            self.register_calls.fetch_add(1, Ordering::SeqCst);
            Ok(lomi_remote_protocol::HostRegisterResult {
                host_id: self.host,
                host_access_epoch: DecimalU64(12),
            })
        }

        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
    }

    #[test]
    fn actor_carries_persisted_clock_floor_through_verified_ready_handoff() {
        let (_directory, owner, setup) = owned_fixture();
        let setup_cancel = AtomicBool::new(false);
        let setup_operation = test_operation(&setup_cancel);
        let config = owned_config(&owner, &setup_operation);
        let login = owned_login(&owner, &setup_operation);
        let floor = owner
            .begin_observe_authorization_clock(&setup_operation, 1100)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(floor, 1100);

        let (initial_storage, approval) = awaiting_approval_storage(&config);
        let mut provider = ClockFloorStorage {
            bytes: initial_storage.0,
            writes: 0,
        };
        let stopping = Arc::new(AtomicBool::new(false));
        let poll_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let exchange_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let register_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let host = owner.identity(&setup_operation).unwrap().host_id;
        assert_eq!(
            owner.auth_status(&setup_operation).unwrap().intent,
            Some(login)
        );
        let transport = ClockFloorTransport {
            approval: std::sync::Mutex::new(Some(approval)),
            host,
            exchange_delay: Duration::from_millis(1100),
            poll_calls: poll_calls.clone(),
            exchange_calls: exchange_calls.clone(),
            register_calls: register_calls.clone(),
        };

        let paused = AtomicBool::new(false);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(30), &stopping);
        let aborted = std::cell::Cell::new(false);
        let state = Mutex::new(initial());
        let retry_requested = AtomicBool::new(false);
        let gate = Arc::new(AtomicBool::new(true));
        let (wake, receiver) = mpsc::sync_channel(1);
        let anchor = Instant::now();
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();

        let watch_owner = owner.clone();
        let watch_stopping = stopping.clone();
        let watch_gate = gate.clone();
        let expected_generation = owner
            .auth_status(&setup_operation)
            .unwrap()
            .authorization
            .generation;
        let watcher = std::thread::spawn(move || {
            let watch_cancel = AtomicBool::new(false);
            let watch_operation =
                OwnerOperation::new(Instant::now() + Duration::from_secs(20), &watch_cancel);
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                let verified = watch_owner
                    .auth_selection(&watch_operation)
                    .is_ok_and(|snapshot| {
                        snapshot.verified_generation == Some(expected_generation)
                    });
                if verified && !watch_gate.load(Ordering::Acquire) {
                    watch_stopping.store(true, Ordering::Release);
                    return true;
                }
                if Instant::now() >= deadline {
                    watch_stopping.store(true, Ordering::Release);
                    return false;
                }
                std::thread::park_timeout(Duration::from_millis(2));
            }
        });

        run_with_apis(
            &mut auth,
            &transport,
            &config,
            Runtime {
                owner: &owner,
                operation: &operation,
                public_io: &public_io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: 1005,
                anchor,
                aborted: &aborted,
            },
            InjectedApis {
                data: None,
                pairing: None,
                channel: None,
                enabled: false,
                channels_enabled: false,
            },
        );
        drop(wake);
        let reached_ready = watcher.join().unwrap();

        assert_eq!(poll_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 1);
        assert_eq!(register_calls.load(Ordering::SeqCst), 1);
        assert!(reached_ready, "worker did not publish verified Ready");
        assert!(stopping.load(Ordering::Acquire));
        assert_eq!(auth.status(), Status::Ready);
        assert!(!gate.load(Ordering::Acquire));
        assert_eq!(
            state.lock().unwrap().status.storage,
            LocalAuthStorage::Available
        );
        assert_eq!(owner.auth_status(&setup_operation).unwrap().intent, None);
        assert_eq!(
            owner
                .auth_selection(&setup_operation)
                .unwrap()
                .verified_generation,
            Some(expected_generation)
        );

        let clock_floor = owner
            .auth_status(&setup_operation)
            .unwrap()
            .authorization
            .clock_floor;
        assert!(
            clock_floor >= 1101,
            "clock floor did not advance after its forward jump"
        );
        drop(auth);
        assert_eq!(provider.writes, 5);
        assert!(matches!(
            HostAuth::open(&mut provider, config.clone(), clock_floor - 1),
            Err(lomi_host_auth::Error::ClockRollback)
        ));
        assert_eq!(
            HostAuth::open(&mut provider, config, clock_floor)
                .unwrap()
                .status(),
            Status::Ready
        );
    }

    #[cfg(all(unix, feature = "cloud-fixture"))]
    #[test]
    fn expired_approval_with_ahead_floor_keeps_original_deadline_without_sealing() {
        let (_directory, owner, setup) = owned_fixture();
        let setup_cancel = AtomicBool::new(false);
        let setup_operation = test_operation(&setup_cancel);
        let config = owned_config(&owner, &setup_operation);
        let _login = owned_login(&owner, &setup_operation);
        let floor = owner
            .begin_observe_authorization_clock(&setup_operation, 1550)
            .unwrap()
            .try_commit()
            .unwrap();
        assert_eq!(floor, 1550);

        let (initial_storage, approval) = awaiting_approval_storage(&config);
        let mut provider = ClockFloorStorage {
            bytes: initial_storage.0,
            writes: 0,
        };
        let stopping = Arc::new(AtomicBool::new(false));
        let poll_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let exchange_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let register_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let host = owner.identity(&setup_operation).unwrap().host_id;
        let transport = ClockFloorTransport {
            approval: std::sync::Mutex::new(Some(approval)),
            host,
            exchange_delay: Duration::ZERO,
            poll_calls: poll_calls.clone(),
            exchange_calls: exchange_calls.clone(),
            register_calls,
        };

        let paused = AtomicBool::new(false);
        let public_io = setup.enter_owned(&paused).unwrap().unwrap();
        let operation = OwnerOperation::new(Instant::now() + Duration::from_secs(20), &stopping);
        let aborted = std::cell::Cell::new(false);
        let mut view = initial();
        view.auth_poll_observation = Some(AuthPollObservation::default());
        let state = Arc::new(Mutex::new(view));
        let retry_requested = AtomicBool::new(false);
        let gate = Arc::new(AtomicBool::new(true));
        let (wake, receiver) = mpsc::sync_channel(1);
        let anchor = Instant::now();
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();

        let watch_state = state.clone();
        let watch_stopping = stopping.clone();
        let watcher = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let failed_approval = watch_state
                    .lock()
                    .ok()
                    .and_then(|view| {
                        view.auth_poll_observation
                            .as_ref()
                            .map(|trace| trace.failure_emitted)
                    })
                    .unwrap_or(false);
                if failed_approval {
                    watch_stopping.store(true, Ordering::Release);
                    return true;
                }
                if Instant::now() >= deadline {
                    watch_stopping.store(true, Ordering::Release);
                    return false;
                }
                std::thread::park_timeout(Duration::from_millis(1));
            }
        });

        run_with_apis(
            &mut auth,
            &transport,
            &config,
            Runtime {
                owner: &owner,
                operation: &operation,
                public_io: &public_io,
                state: &state,
                stopping: &stopping,
                receiver: &receiver,
                retry_requested: &retry_requested,
                gate: &gate,
                paused: &paused,
                base: 1005,
                anchor,
                aborted: &aborted,
            },
            InjectedApis {
                data: None,
                pairing: None,
                channel: None,
                enabled: false,
                channels_enabled: false,
            },
        );
        drop(wake);
        let saw_approval_error = watcher.join().unwrap();

        assert!(saw_approval_error, "approval error path was not reached");
        assert_eq!(poll_calls.load(Ordering::SeqCst), 1);
        assert_eq!(exchange_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            provider.writes, 1,
            "only the poll reservation should persist"
        );
        let status = state.lock().unwrap().status.clone();
        assert_eq!(status.phase, LocalAuthPhase::AwaitingApproval);
        assert_eq!(status.storage, LocalAuthStorage::Available);
        assert_eq!(
            owner
                .auth_status(&setup_operation)
                .unwrap()
                .authorization
                .clock_floor,
            floor
        );

        let auth = HostAuth::open(&mut provider, config, floor).unwrap();
        assert_eq!(auth.status(), Status::AwaitingApproval);
        assert_eq!(
            auth.enrollment_presentation(floor).unwrap().expires_at,
            1600
        );
    }

    fn exchange_prepared_storage(
        config: &Config,
    ) -> (MemoryStorage, HostEnrollmentRevocationAckParams) {
        let mut storage = approved_storage(config);
        let mut auth = HostAuth::open(&mut storage, config.clone(), 1001).unwrap();
        auth.prepare_exchange(1002).unwrap();
        let request = auth.enrollment_revocation_ack_request(1002).unwrap();
        drop(auth);
        (storage, request)
    }
    fn enrollment_ack_request(
        storage: &mut MemoryStorage,
        config: &Config,
        now: u64,
    ) -> HostEnrollmentRevocationAckParams {
        let auth = HostAuth::open(storage, config.clone(), now).unwrap();
        auth.enrollment_revocation_ack_request(now).unwrap()
    }
    pub(super) fn unconfirmed_storage(
        config: &Config,
        host: lomi_remote_protocol::HostId,
    ) -> MemoryStorage {
        use lomi_remote_protocol::*;
        let mut storage = approved_storage(config);
        let mut auth = HostAuth::open(&mut storage, config.clone(), 1001).unwrap();
        auth.prepare_exchange(1002).unwrap();
        let operation = auth.exchange_request(1002).unwrap().operation_id;
        auth.accept_exchange(
            HostAuthorizationResult {
                account_id: AccountId::from_bytes([4; 16]).unwrap(),
                host_id: host,
                host_authorization_id: HostAuthorizationId::from_bytes([8; 16]).unwrap(),
                access: "synthetic_access".to_owned().try_into().unwrap(),
                refresh: "synthetic_refresh".to_owned().try_into().unwrap(),
                rotation_id: operation,
                expires_in_seconds: DecimalU64(300),
            },
            1003,
        )
        .unwrap();
        drop(auth);
        storage
    }
    struct WrapperRegistration<'a> {
        host: lomi_remote_protocol::HostId,
        paused: &'a AtomicBool,
        cancelled: &'a AtomicBool,
        cancel: bool,
        rendezvous: Option<(mpsc::SyncSender<()>, mpsc::Receiver<()>)>,
        sends: std::cell::Cell<usize>,
    }
    impl AuthTransport for WrapperRegistration<'_> {
        fn revoke(
            &self,
            _: lomi_remote_protocol::HostId,
            _: &lomi_remote_protocol::HostRevokeParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRevokeResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn initiate(
            &self,
            _: &lomi_remote_protocol::EnrollmentInitiateParams,
        ) -> Result<lomi_remote_protocol::EnrollmentInitiateResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn poll(
            &self,
            _: &lomi_remote_protocol::DeviceCode,
        ) -> Result<PollOutcome, lomi_host_http::Error> {
            unreachable!()
        }
        fn exchange(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationExchangeParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn refresh(
            &self,
            _: &lomi_remote_protocol::HostAuthorizationRefreshParams,
        ) -> Result<lomi_remote_protocol::HostAuthorizationResult, lomi_host_http::Error> {
            unreachable!()
        }
        fn register(
            &self,
            _: &lomi_remote_protocol::HostRegisterParams,
            _: &lomi_remote_protocol::HostAccessCredential,
        ) -> Result<lomi_remote_protocol::HostRegisterResult, lomi_host_http::Error> {
            self.sends.set(self.sends.get() + 1);
            if let Some((entered, release)) = &self.rendezvous {
                if self.cancel {
                    self.cancelled.store(true, Ordering::Release);
                } else {
                    self.paused.store(true, Ordering::Release);
                }
                entered.send(()).unwrap();
                release.recv_timeout(Duration::from_secs(3)).unwrap();
            }
            Ok(lomi_remote_protocol::HostRegisterResult {
                host_id: self.host,
                host_access_epoch: DecimalU64(12),
            })
        }
    }
    #[test]
    fn actual_ready_wrapper_retains_cancelled_abort_while_busy_then_retries_same_owner() {
        for cancel in [false, true] {
            let (_directory, owner, setup) = owned_fixture();
            let control_cancel = AtomicBool::new(false);
            let control_operation = test_operation(&control_cancel);
            let config = owned_config(&owner, &control_operation);
            let host = owner.identity(&control_operation).unwrap().host_id;
            let intent = owned_login(&owner, &control_operation);
            let mut provider = unconfirmed_storage(&config, host);
            let (network_tx, network_rx) = mpsc::sync_channel(1);
            let (network_release_tx, network_release_rx) = mpsc::channel();
            let (aborted_tx, aborted_rx) = mpsc::channel();
            let (retry_tx, retry_rx) = mpsc::channel();
            let worker_owner = owner.clone();
            let worker = thread::spawn(move || {
                let cancelled = AtomicBool::new(false);
                let operation = test_operation(&cancelled);
                let paused = AtomicBool::new(false);
                let gate = AtomicBool::new(true);
                let stopping = AtomicBool::new(false);
                let aborted = std::cell::Cell::new(false);
                let io = setup.enter_owned(&paused).unwrap().unwrap();
                let (_wake, receiver) = mpsc::sync_channel(1);
                let retry_requested = AtomicBool::new(false);
                let state = Mutex::new(initial());
                let runtime = Runtime {
                    owner: &worker_owner,
                    operation: &operation,
                    public_io: &io,
                    state: &state,
                    stopping: &stopping,
                    receiver: &receiver,
                    retry_requested: &retry_requested,
                    gate: &gate,
                    paused: &paused,
                    base: 1005,
                    anchor: Instant::now(),
                    aborted: &aborted,
                };
                let mut auth =
                    HostAuth::open(&mut provider as &mut dyn SecretStorage, config, 1005).unwrap();
                let transport = WrapperRegistration {
                    host,
                    paused: &paused,
                    cancelled: &cancelled,
                    cancel,
                    rendezvous: Some((network_tx, network_release_rx)),
                    sends: std::cell::Cell::new(0),
                };
                assert!(matches!(
                    ready_from_existing_worker(&mut auth, runtime, &transport),
                    Err(StepError::Stale)
                ));
                assert_eq!(transport.sends.get(), 1);
                assert_eq!(auth.status(), Status::Unconfirmed);
                assert!(gate.load(Ordering::Acquire));
                assert!(!retry_requested.load(Ordering::Acquire));
                aborted_tx.send(()).unwrap();
                retry_rx.recv_timeout(Duration::from_secs(3)).unwrap();
                paused.store(false, Ordering::Release);
                cancelled.store(false, Ordering::Release);
                let retry_operation = test_operation(&cancelled);
                let retry_aborted = std::cell::Cell::new(false);
                let transport = WrapperRegistration {
                    host,
                    paused: &paused,
                    cancelled: &cancelled,
                    cancel: false,
                    rendezvous: None,
                    sends: std::cell::Cell::new(0),
                };
                ready_from_existing_worker(
                    &mut auth,
                    Runtime {
                        operation: &retry_operation,
                        aborted: &retry_aborted,
                        ..runtime
                    },
                    &transport,
                )
                .unwrap();
                assert_eq!(transport.sends.get(), 1);
                assert_eq!(auth.status(), Status::Ready);
                assert!(!gate.load(Ordering::Acquire));
            });
            network_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            let (held_tx, held_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let held_owner = owner.clone();
            let holder = thread::spawn(move || {
                let cancel = AtomicBool::new(false);
                let operation = test_operation(&cancel);
                held_owner
                    .hold_store_for_test(&operation, held_tx, release_rx)
                    .unwrap();
            });
            held_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            network_release_tx.send(()).unwrap();
            // The wrapper has received the actual response and noticed pause or
            // cancellation, but cannot drop its writer while abort is Busy.
            assert!(matches!(
                aborted_rx.recv_timeout(Duration::from_millis(30)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ));
            release_tx.send(()).unwrap();
            aborted_rx.recv_timeout(Duration::from_secs(3)).unwrap();
            holder.join().unwrap();
            let before_retry = owner.auth_status(&control_operation).unwrap();
            assert_eq!(before_retry.intent, Some(intent));
            assert!(before_retry.authorization.locked);
            assert_eq!(
                owner
                    .auth_selection(&control_operation)
                    .unwrap()
                    .verified_generation,
                None
            );
            retry_tx.send(()).unwrap();
            worker.join().unwrap();
            assert!(
                !owner
                    .auth_status(&control_operation)
                    .unwrap()
                    .authorization
                    .locked
            );
        }
    }

    #[test]
    fn registration_response_after_original_access_deadline_never_unlocks() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        owner
            .begin_mark_cloud_authorization_possible(&operation, 0)
            .unwrap()
            .try_commit()
            .unwrap();
        let intent = owned_login(&owner, &operation);
        let paused = AtomicBool::new(false);
        let gate = AtomicBool::new(true);
        let io = setup.enter_owned(&paused).unwrap().unwrap();
        let mut auth =
            HostAuth::open(&mut provider as &mut dyn SecretStorage, config, 1301).unwrap();
        assert_eq!(auth.status(), Status::Unconfirmed);
        assert!(auth.registration_request(1301).is_ok());
        let sends = std::rc::Rc::new(std::cell::Cell::new(0));
        let exact_request = std::rc::Rc::new(std::cell::RefCell::new(None));
        {
            // Real constructor validates the actual borrowed provider/configuration/IO
            // BEFORE a cfg(test)-only closed network script is installed.
            let mut attempt =
                super::super::shared_owner::ConfiguredWorkerAttempt::from_existing_worker(
                    &mut auth,
                    &io,
                    &gate,
                    &paused,
                    1301,
                    Instant::now(),
                )
                .unwrap();
            attempt.install_ready_http_script_for_test(sends.clone(), exact_request.clone(), 1301);
            let mut turn = attempt.begin_ready(&owner, &operation).unwrap();
            assert_eq!(turn.try_step(), Ok(false)); // Prepare exact original Register.
            assert_eq!(turn.try_step(), Ok(false)); // Send once and retain typed response.
            assert_eq!(sends.get(), 1);
            assert!(exact_request.borrow().is_some());
            // The response is already retained. Advance the same attempt's trusted
            // projected clock to its ORIGINAL access expiry before response acceptance.
            turn.advance_retained_response_time_for_test(1302).unwrap();
            assert_eq!(turn.try_step(), Ok(false)); // Persist the post-response clock.
            let expired = Err(super::super::shared_owner::WorkerReadyError::Provider(
                lomi_host_auth::Error::Expired,
            ));
            assert_eq!(turn.try_step(), expired); // Actually process/reject the response.
            assert_eq!(turn.try_step(), expired); // Terminal: never resend or publish.
        }
        assert_eq!(sends.get(), 1);
        assert_eq!(auth.status(), Status::Unconfirmed);
        assert!(gate.load(Ordering::Acquire));
        let snapshot = owner.auth_status(&operation).unwrap();
        assert!(snapshot.authorization.locked);
        assert_eq!(snapshot.authorization.clock_floor, 1302);
        assert_eq!(snapshot.intent, Some(intent));
        assert_eq!(
            owner
                .auth_selection(&operation)
                .unwrap()
                .verified_generation,
            None
        );
    }
    #[test]
    fn lost_confirmed_bundle_keeps_logout_pending_and_blocks_new_keys() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        HostAuth::open(&mut provider, config.clone(), 1003)
            .unwrap()
            .confirm_registration(lomi_remote_protocol::HostRegisterResult {
                host_id: host,
                host_access_epoch: DecimalU64(12),
            })
            .unwrap();
        with_owned_runtime(&owner, &setup, 1003, |runtime| {
            assert!(qualify_cloud_history(runtime, Status::Ready))
        });
        provider.0 = None;
        let fence = owned_logout(&owner, &operation);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1004,
        )
        .unwrap();
        assert_eq!(auth.status(), Status::Empty);
        with_owned_runtime(&owner, &setup, 1004, |runtime| {
            assert!(!qualify_cloud_history(runtime, auth.status()));
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::sync_channel(1);
            assert!(
                revoke_step(
                    &mut auth,
                    &BlockedTransport { entered, release },
                    &config,
                    runtime,
                    fence.generation
                )
                .is_err()
            );
        });
        drop(auth);
        assert!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
        assert!(provider.0.is_none());
    }
    #[test]
    fn durable_revoked_secret_ack_repairs_crash_before_sql_ack() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let host = owner.identity(&operation).unwrap().host_id;
        let mut provider = unconfirmed_storage(&config, host);
        let mut auth = HostAuth::open(&mut provider, config.clone(), 1003).unwrap();
        auth.confirm_registration(lomi_remote_protocol::HostRegisterResult {
            host_id: host,
            host_access_epoch: DecimalU64(12),
        })
        .unwrap();
        with_owned_runtime(&owner, &setup, 1003, |runtime| {
            assert!(qualify_cloud_history(runtime, Status::Ready))
        });
        let fence = owned_logout(&owner, &operation);
        auth.accept_tls_revocation(
            config.origin(),
            lomi_remote_protocol::HostRevokeResult {
                host_id: host,
                host_access_epoch: DecimalU64(13),
            },
            1004,
        )
        .unwrap();
        drop(auth);
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1005,
        )
        .unwrap();
        assert_eq!(auth.status(), Status::Revoked);
        with_owned_runtime(&owner, &setup, 1005, |runtime| {
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::sync_channel(1);
            assert!(
                revoke_step(
                    &mut auth,
                    &BlockedTransport { entered, release },
                    &config,
                    runtime,
                    fence.generation
                )
                .is_ok()
            );
        });
        let history = owner.auth_history(&operation).unwrap();
        assert!(!history.authorization.pending_cloud_revoke);
        assert!(history.authorization.locked);
        assert_eq!(history.cloud_may_exist, Some(false));
        assert_eq!(auth.status(), Status::Revoked);
    }
    struct StopOnResetStorage {
        inner: MemoryStorage,
        stopping: Arc<AtomicBool>,
    }
    impl SecretStorage for StopOnResetStorage {
        fn status(&self) -> secrets::ProviderStatus {
            self.inner.status()
        }
        fn load(&self) -> Result<Option<secrets::SecretBundle>, secrets::Error> {
            self.inner.load()
        }
        fn replace(&mut self, bundle: &secrets::SecretBundle) -> Result<(), secrets::Error> {
            self.inner.replace(bundle)?;
            if bundle
                .expose()
                .windows(b"\"state\":\"PendingInit\"".len())
                .any(|bytes| bytes == b"\"state\":\"PendingInit\"")
            {
                self.stopping.store(true, Ordering::Release);
            }
            Ok(())
        }
    }
    #[test]
    fn expired_approved_enrollment_can_reset_and_logout_without_cloud_history() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        owned_login(&owner, &operation);
        let stopping = Arc::new(AtomicBool::new(false));
        let mut provider = StopOnResetStorage {
            inner: approved_storage(&config),
            stopping: stopping.clone(),
        };
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1500,
        )
        .unwrap();
        with_owned_runtime(&owner, &setup, 1500, |runtime| {
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::sync_channel(1);
            run(
                &mut auth,
                &BlockedTransport { entered, release },
                &config,
                Runtime {
                    stopping: &stopping,
                    ..runtime
                },
            );
        });
        assert_eq!(auth.status(), Status::PendingInit);
        assert_eq!(
            owner.auth_history(&operation).unwrap().cloud_may_exist,
            Some(false)
        );
        let fence = owned_logout(&owner, &operation);
        with_owned_runtime(&owner, &setup, 1501, |runtime| {
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::sync_channel(1);
            assert!(
                revoke_step(
                    &mut auth,
                    &BlockedTransport { entered, release },
                    &config,
                    runtime,
                    fence.generation
                )
                .is_ok()
            );
        });
        assert!(
            !owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }
    struct UncertainStorage {
        inner: MemoryStorage,
        fail: bool,
        loads: std::cell::Cell<usize>,
    }
    impl SecretStorage for UncertainStorage {
        fn status(&self) -> secrets::ProviderStatus {
            self.inner.status()
        }
        fn load(&self) -> Result<Option<secrets::SecretBundle>, secrets::Error> {
            self.loads.set(self.loads.get() + 1);
            self.inner.load()
        }
        fn replace(&mut self, bundle: &secrets::SecretBundle) -> Result<(), secrets::Error> {
            self.inner.replace(bundle)?;
            if self.fail {
                self.fail = false;
                Err(secrets::Error::CommitUncertain)
            } else {
                Ok(())
            }
        }
    }
    #[test]
    fn uncertain_publication_waits_for_fresh_login_then_reopens_and_inspects() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let config = owned_config(&owner, &operation);
        let (wake, receiver) = mpsc::sync_channel(1);
        let handle = owned_handle(owner.clone(), setup.clone(), wake.clone());
        handle
            .dispatch(
                &operation,
                LocalCall::LoginStart(LocalLoginStart {
                    operation_id: OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes())
                        .unwrap(),
                }),
            )
            .unwrap();
        let mut provider = UncertainStorage {
            inner: MemoryStorage(None),
            fail: true,
            loads: std::cell::Cell::new(0),
        };
        let mut auth = HostAuth::open(
            &mut provider as &mut dyn SecretStorage,
            config.clone(),
            1000,
        )
        .unwrap();
        with_owned_runtime(&owner, &setup, 1000, |runtime| {
            let (entered, _) = mpsc::sync_channel(1);
            let (_, release) = mpsc::sync_channel(1);
            run(
                &mut auth,
                &BlockedTransport { entered, release },
                &config,
                Runtime {
                    state: &handle.state,
                    receiver: &receiver,
                    retry_requested: &handle.retry_requested,
                    gate: &handle.gate,
                    paused: &handle.paused,
                    ..runtime
                },
            );
        });
        drop(auth);
        assert!(provider.inner.0.is_some());
        let inspected_before_retry = provider.loads.get();
        assert!(inspected_before_retry >= 1);
        assert_eq!(
            handle.state.lock().unwrap().status.storage,
            LocalAuthStorage::Unavailable
        );
        wake.try_send(Command::Configure).unwrap();
        let wait_retry = handle.retry_requested.clone();
        let (done_tx, done_rx) = mpsc::sync_channel(1);
        let waiter = thread::spawn(move || {
            done_tx
                .send(await_explicit_retry(
                    &receiver,
                    &AtomicBool::new(false),
                    &wait_retry,
                ))
                .unwrap();
        });
        assert!(done_rx.recv_timeout(Duration::from_millis(100)).is_err());
        handle
            .dispatch(
                &operation,
                LocalCall::LoginStart(LocalLoginStart {
                    operation_id: OperationId::from_bytes(uuid::Uuid::new_v4().into_bytes())
                        .unwrap(),
                }),
            )
            .unwrap();
        assert!(done_rx.recv_timeout(Duration::from_secs(1)).unwrap());
        waiter.join().unwrap();
        let auth = HostAuth::open(&mut provider, config, 1001).unwrap();
        assert_eq!(auth.status(), Status::PendingInit);
        assert!(auth.init_request().is_ok());
        drop(auth);
        assert_eq!(provider.loads.get(), inspected_before_retry + 1);
    }
    #[test]
    fn full_configure_queue_cannot_lose_explicit_logout_retry_after_failure() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let (wake, receiver) = mpsc::sync_channel(1);
        wake.try_send(Command::Configure).unwrap();
        let handle = owned_handle(owner.clone(), setup, wake);
        handle
            .dispatch(
                &operation,
                LocalCall::Logout(LocalOperatorIntent {
                    operator_intent: Confirmed::Confirmed,
                }),
            )
            .unwrap();
        assert!(await_explicit_retry(
            &receiver,
            &AtomicBool::new(false),
            &handle.retry_requested
        ));
        assert!(
            owner
                .auth_status(&operation)
                .unwrap()
                .authorization
                .pending_cloud_revoke
        );
    }
    #[test]
    fn setup_rejects_invalid_or_identity_remote_api_pins_before_save() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let (wake, _receiver) = mpsc::sync_channel(1);
        let handle = owned_handle(owner.clone(), setup, wake);
        for origin in [
            "https://identity.example",
            "http://remote.example",
            "https://remote.example/path",
            "https://remote.example?token=x",
            "https://user@remote.example",
            "https://REMOTE.example",
            "https://remote.example/",
        ] {
            let mut config = configuration_value();
            config.remote_api_origin = Some(origin.to_owned().try_into().unwrap());
            assert_eq!(
                handle.dispatch(
                    &operation,
                    LocalCall::AuthConfigure(LocalAuthConfigure {
                        configuration: config,
                        operator_intent: Confirmed::Confirmed,
                    })
                ),
                Err(LocalError::InvalidArgument)
            );
            assert_eq!(
                owner.auth_selection(&operation).unwrap().configuration,
                Some(configuration_value())
            );
        }
        let mut config = configuration_value();
        config.remote_api_origin = Some("https://remote.example".to_owned().try_into().unwrap());
        handle
            .dispatch(
                &operation,
                LocalCall::AuthConfigure(LocalAuthConfigure {
                    configuration: config.clone(),
                    operator_intent: Confirmed::Confirmed,
                }),
            )
            .unwrap();
        assert_eq!(
            owner.auth_selection(&operation).unwrap().configuration,
            Some(config)
        );
    }

    #[test]
    fn relay_configuration_is_typed_before_write_and_round_trips_without_runtime_transport() {
        let (_directory, owner, setup) = owned_fixture();
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        let baseline = owner
            .auth_selection(&operation)
            .unwrap()
            .configuration
            .unwrap();
        for endpoint in [
            serde_json::json!("wss://RELAY.example/v2/relay"),
            serde_json::json!("wss://relay.example:443/v2/relay"),
            serde_json::json!("wss://relay.example/v2/relay?token=x"),
            serde_json::json!(42),
        ] {
            let mut config = serde_json::to_value(&baseline).unwrap();
            config["relayEndpoint"] = endpoint;
            assert!(serde_json::from_value::<LocalAuthConfiguration>(config).is_err());
            assert_eq!(
                owner.auth_selection(&operation).unwrap().configuration,
                Some(baseline.clone())
            );
        }
        let (wake, _receiver) = mpsc::sync_channel(1);
        let handle = owned_handle(owner.clone(), setup, wake);
        let mut pinned = baseline;
        pinned.relay_endpoint = Some(
            "wss://relay.example:8443/v2/relay"
                .to_owned()
                .try_into()
                .unwrap(),
        );
        handle
            .dispatch(
                &operation,
                LocalCall::AuthConfigure(LocalAuthConfigure {
                    configuration: pinned.clone(),
                    operator_intent: Confirmed::Confirmed,
                }),
            )
            .unwrap();
        let selected = owner.auth_selection(&operation).unwrap();
        let saved = selected.configuration.unwrap();
        assert_eq!(saved, pinned);
        assert!(saved.remote_api_origin.is_none());
        assert!(configuration(&selected.identity, &saved).is_ok());
    }

    #[test]
    fn worker_reread_of_invalid_remote_api_pin_fails_closed_before_provider_open() {
        let directory = tempfile::Builder::new()
            .prefix("lomi-auth-pin-reread-")
            .private_tempdir()
            .unwrap();
        let profile = directory.path().canonicalize().unwrap();
        let lock = OwnerLock::acquire(&profile).unwrap();
        let mut store =
            HostStore::open(&lock.prepare_database().unwrap(), Limits::default()).unwrap();
        let mut config = configuration_value();
        // Bypass the host validator to model persisted configuration tampering.
        config.remote_api_origin = Some("https://identity.example".to_owned().try_into().unwrap());
        store.configure_auth(&config).unwrap();
        let intent = store
            .begin_login(OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes()).unwrap())
            .unwrap();
        store.complete_login(intent).unwrap();
        let endpoint = Arc::new(
            OwnerEndpoint::bind(
                lock,
                LocalDiscovery {
                    version: LocalIpcVersion::CURRENT,
                    profile_id: store.identity().profile_id,
                    host_id: store.identity().host_id,
                    runtime_id: store.runtime_id(),
                    build_id: "test".to_owned(),
                },
            )
            .unwrap(),
        );
        let owner = SharedOwner::new(store).unwrap();
        let stopping = Arc::new(AtomicBool::new(false));
        let (handle, worker) = start(
            endpoint.clone(),
            owner.clone(),
            stopping.clone(),
            std::sync::Weak::new(),
        );
        let deadline = Instant::now() + Duration::from_secs(3);
        let failed = loop {
            if handle.state.lock().unwrap().status.storage == LocalAuthStorage::Unavailable {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            thread::sleep(Duration::from_millis(10));
        };
        stopping.store(true, Ordering::Release);
        worker.join().unwrap();
        assert!(failed);
        assert!(handle.gate.load(Ordering::Acquire));
        assert!(!profile.join("host-secrets.lock").exists());
        assert!(!profile.join("host-secrets.bundle").exists());
        let cancel = AtomicBool::new(false);
        let operation = test_operation(&cancel);
        assert!(owner.auth_status(&operation).unwrap().authorization.locked);
        assert!(!handle.is_authorized(&operation));
        assert_eq!(
            owner.auth_selection(&operation).unwrap().configuration,
            Some(config)
        );
        drop(endpoint);
    }

    #[test]
    fn setup_rejects_untrusted_origins_and_provider_fallbacks_before_save() {
        let directory = tempfile::Builder::new()
            .prefix("lomi-auth-config-")
            .tempdir()
            .unwrap();
        crate::testsupport::make_private(directory.path()).unwrap();
        let store =
            HostStore::open(&directory.path().join("host.sqlite"), Limits::default()).unwrap();
        for origin in [
            "http://identity.example",
            "https://identity.example/device",
            "https://identity.example?token=x",
            "https://user@identity.example",
            "https://IDENTITY.example",
        ] {
            let mut config = configuration_value();
            config.origin = origin.to_owned().try_into().unwrap();
            assert!(configuration(store.identity(), &config).is_err());
        }
        let mut config = configuration_value();
        // The other platform's provider is a fallback this platform never accepts.
        #[cfg(unix)]
        {
            config.provider = LocalAuthProvider::WindowsDpapi;
            config.protected_file_acknowledgement = None;
        }
        #[cfg(windows)]
        {
            config.provider = LocalAuthProvider::ProtectedFile;
            config.protected_file_acknowledgement =
                Some(lomi_remote_protocol::ipc::LocalFileAcknowledgement::OsPermissionsOnly);
        }
        assert!(configuration(store.identity(), &config).is_err());
        assert!(store.auth_configuration().unwrap().is_none());
    }
}

#[cfg(test)]
#[path = "auth_public_configuration_tests.rs"]
mod public_configuration_tests;

// Immutable evidence captured only by the actual selected auth worker.
pub(super) struct RemoteWorkerEvidence<'w, 'p, 's, 'r> {
    // The actual borrow excludes credential/provider mutation for the whole turn.
    _auth: &'w HostAuth<'p, dyn SecretStorage + 's>,
    runtime: Runtime<'r>,
    eligibility: &'r cloud::PeerEligibility,
    provider: peer::ProviderCapture,
    trusted: Config,
    origin: lomi_host_auth::peer_policy::RemoteOrigin,
    io_identity: super::public_configuration::WorkerPublicIoIdentity,
    operation_identity: owner_domain::OperationIdentity,
}
impl<'a, 'operation> RuntimeWithOperation<'a, 'operation> {
    // Private Runtime is constructed only by the selected actual auth worker.
    // No factory accepting caller booleans, public identity or replacement IO.
    pub(in crate::unix::auth) fn remote_worker_evidence<'w, 'p, 's>(
        self,
        auth: &'w HostAuth<'p, dyn SecretStorage + 's>,
        eligibility: &'operation cloud::PeerEligibility,
    ) -> peer::ResultPeer<RemoteWorkerEvidence<'w, 'p, 's, 'operation>>
    where
        'a: 'operation,
    {
        let runtime: Runtime<'operation> = RuntimeWithOperation {
            owner: self.owner,
            operation: self.operation,
            public_io: self.public_io,
            state: self.state,
            stopping: self.stopping,
            receiver: self.receiver,
            retry_requested: self.retry_requested,
            gate: self.gate,
            paused: self.paused,
            base: self.base,
            anchor: self.anchor,
            aborted: self.aborted,
        };
        peer::check_peer_runtime(runtime)?;
        let provider = peer::ProviderCapture::read(auth, runtime, eligibility)?;
        let trusted = auth.trusted_configuration().clone();
        let origin = peer::policy(lomi_host_auth::peer_policy::RemoteOrigin::new(
            &trusted,
            eligibility.binding.scope.remote_api_origin.clone(),
        ))?;
        let evidence = RemoteWorkerEvidence {
            _auth: auth,
            runtime,
            eligibility,
            provider,
            trusted,
            origin,
            io_identity: runtime.public_io.retained_identity(),
            operation_identity: runtime.operation.retained_identity(),
        };
        if !evidence.current() {
            return Err(peer::PeerError::Invalid);
        }
        Ok(evidence)
    }
}
impl<'w, 'p, 's, 'r> RemoteWorkerEvidence<'w, 'p, 's, 'r> {
    pub(super) fn auth(&self) -> &HostAuth<'p, dyn SecretStorage + 's> {
        self._auth
    }
    pub(super) fn owner(&self) -> &'r SharedOwner {
        self.runtime.owner
    }
    pub(super) fn operation(&self) -> &'r OwnerOperation<'r> {
        self.runtime.operation
    }
    pub(super) fn eligibility(&self) -> &'r cloud::PeerEligibility {
        self.eligibility
    }
    pub(super) fn provider(&self) -> &peer::ProviderCapture {
        &self.provider
    }
    pub(super) fn trusted(&self) -> &Config {
        &self.trusted
    }
    pub(super) fn origin(&self) -> &lomi_host_auth::peer_policy::RemoteOrigin {
        &self.origin
    }
    pub(super) fn now(&self) -> Option<self::remote_connection::TrustedNow> {
        let monotonic = Instant::now();
        let elapsed = monotonic.checked_duration_since(self.runtime.anchor)?;
        let wall = Duration::from_secs(self.runtime.base).checked_add(elapsed)?;
        if wall.is_zero() || wall.as_secs() > i64::MAX as u64 {
            return None;
        }
        Some(self::remote_connection::TrustedNow { wall, monotonic })
    }
    /// No Domain, Store, provider IO or lock acquisition. The actual immutable
    /// HostAuth and public IO lease remain borrowed even during a Core wait.
    pub(super) fn current(&self) -> bool {
        if self.runtime.check().is_err()
            || self.runtime.gate.load(Ordering::Acquire)
            || !self.runtime.public_io.is_same_lease(&self.io_identity)
            || !self
                .runtime
                .operation
                .is_same_admission(&self.operation_identity)
        {
            return false;
        }
        self.now().is_some_and(|now| {
            self.provider
                .valid_for_owner(now.wall.as_secs(), self.eligibility)
        })
    }
    pub(super) fn gate_denied(&self) -> &'r AtomicBool {
        self.runtime.gate
    }
    /// Actual public setup fence; never a point-in-time copied permission.
    pub(super) fn public_setup_pending(&self) -> &'r AtomicBool {
        &self.runtime.public_io.setup().pending
    }
    pub(super) fn paused(&self) -> &'r AtomicBool {
        self.runtime.paused
    }
    pub(super) fn stopping(&self) -> &'r AtomicBool {
        self.runtime.stopping
    }
}
