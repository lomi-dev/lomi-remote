//! Bounded observations of actual HTTPS attempts. No probe, endpoint, account,
//! library error, proxy environment, request body or credential is retained.
//! Observations never participate in authorization, retry, or mutation policy.
use lomi_remote_protocol::ipc::{DiagnosticCode, DoctorHealth};
use std::{
    sync::{Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy)]
pub struct FailureObservation {
    pub code: DiagnosticCode,
    pub unix_time_ms: Option<u64>,
}

#[derive(Clone, Copy)]
pub struct Snapshot {
    pub dns: DoctorHealth,
    pub tls: DoctorHealth,
    /// Host transports explicitly disable proxies, including environment ones.
    pub proxy: DoctorHealth,
    pub last_error: Option<FailureObservation>,
}

struct Observation {
    updated: Instant,
    dns: DoctorHealth,
    tls: DoctorHealth,
    last_error: Option<FailureObservation>,
}

fn state() -> &'static Mutex<Observation> {
    static STATE: OnceLock<Mutex<Observation>> = OnceLock::new();
    STATE.get_or_init(|| {
        Mutex::new(Observation {
            updated: Instant::now(),
            dns: DoctorHealth::Unknown,
            tls: DoctorHealth::Unknown,
            last_error: None,
        })
    })
}

pub fn snapshot() -> Snapshot {
    let mut snapshot = Snapshot {
        dns: DoctorHealth::Unknown,
        tls: DoctorHealth::Unknown,
        proxy: DoctorHealth::DisabledByPolicy,
        last_error: None,
    };
    if let Ok(observation) = state().lock() {
        // Healthy is evidence of a recent actual request, not a live probe.
        if observation.updated.elapsed() <= Duration::from_secs(60) {
            snapshot.dns = observation.dns;
            snapshot.tls = observation.tls;
        }
        snapshot.last_error = observation.last_error;
    }
    snapshot
}

pub(super) fn response_received() {
    if let Ok(mut observation) = state().lock() {
        observation.updated = Instant::now();
        // The HTTPS-only agent uses no idle connection pool. A received HTTP
        // response therefore follows resolution and an authenticated TLS path.
        observation.dns = DoctorHealth::Healthy;
        observation.tls = DoctorHealth::Healthy;
    }
}

pub(super) fn failure(code: DiagnosticCode, dns: DoctorHealth, tls: DoctorHealth) {
    if let Ok(mut observation) = state().lock() {
        observation.updated = Instant::now();
        observation.dns = dns;
        observation.tls = tls;
        observation.last_error = Some(FailureObservation {
            code,
            unix_time_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|time| u64::try_from(time.as_millis()).ok()),
        });
    }
}

pub(super) fn transport_error(error: &ureq::Error) {
    use DoctorHealth::{TransportUnavailable, Unknown};
    let (code, dns, tls) = match error {
        ureq::Error::HostNotFound => (
            DiagnosticCode::DnsUnavailable,
            TransportUnavailable,
            Unknown,
        ),
        ureq::Error::Tls(_) | ureq::Error::Rustls(_) => (
            DiagnosticCode::TlsUnavailable,
            Unknown,
            TransportUnavailable,
        ),
        ureq::Error::Timeout(_) => (DiagnosticCode::NetworkTimeout, Unknown, Unknown),
        _ => (DiagnosticCode::NetworkUnavailable, Unknown, Unknown),
    };
    failure(code, dns, tls);
}
