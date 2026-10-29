//! Redacted, typed doctor reports from the authenticated Host and read-only
//! native state. Collection never starts or repairs services, launches
//! shells/Git, reads credentials, or makes network requests.

use lomi_remote_protocol::ipc::{
    DiagnosticCode, DoctorCheck, DoctorDiagnostic, DoctorHealth, LocalCall, LocalResult,
};
use std::path::Path;

pub const MAX_DIAGNOSTIC_FINDINGS: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticRunMode {
    Online,
    Offline,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostAvailability {
    Available,
    Unavailable,
    PermissionDenied,
    Incompatible,
    InvalidProfile,
    NotAttempted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticCheck {
    IpcVersion,
    ProfileOwner,
    Service,
    Autostart,
    Clock,
    Network,
    Dns,
    Tls,
    Proxy,
    Authorization,
    Storage,
    Shell,
    RemoteGit,
    NativeGit,
    RootPermissions,
    Limits,
    ActivationJournal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutableCheck {
    Shell,
    NativeGit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticState {
    Healthy,
    Unavailable,
    PermissionDenied,
    Incompatible,
    Unknown,
    NotObserved,
    ConfigurationInvalid,
    TransportUnavailable,
    AuthorizationRejected,
    Invalid,
    DisabledByPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSource {
    LocalHost,
    LocalMachine,
    LocalTransport,
    ServiceManager,
}

/// Classification for a future bounded request against a configured trusted
/// endpoint. No endpoint or credential is carried into the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkObservation {
    Available,
    ConfigurationInvalid,
    TransportUnavailable,
    AuthorizationRejected,
    NotObserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairGuidance {
    None,
    CollectMoreEvidence,
    StartOrReconnectHost,
    RepairProfilePermissions,
    ReviewProfileSetup,
    UpdateLomiRemote,
    CompleteOrRecoverUpdate,
    ReviewServiceRegistration,
    EnableAutostart,
    VerifySystemClock,
    ConfigureTrustedEndpoint,
    CheckNetworkTransport,
    Reauthenticate,
    CheckStorage,
    ReviewShellSetup,
    ReviewBuiltInGit,
    InstallOrConfigureNativeGit,
    ReviewResourceLimits,
    UseDirectNetworkConnection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiagnosticFinding {
    pub check: DiagnosticCheck,
    pub state: DiagnosticState,
    pub source: DiagnosticSource,
    pub guidance: RepairGuidance,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticReport {
    pub mode: DiagnosticRunMode,
    pub findings: Vec<DiagnosticFinding>,
    /// Set when more observations existed than this bounded report retained.
    pub truncated: bool,
    /// A closed code from the current Host; never raw OS/library error text.
    pub last_error: Option<DiagnosticCode>,
    pub logs_available: bool,
}

pub struct DiagnosticReportBuilder {
    mode: DiagnosticRunMode,
    findings: Vec<DiagnosticFinding>,
    truncated: bool,
    last_error: Option<DiagnosticCode>,
    logs_available: bool,
}

impl DiagnosticReportBuilder {
    pub fn new(mode: DiagnosticRunMode) -> Self {
        Self {
            mode,
            findings: Vec::with_capacity(MAX_DIAGNOSTIC_FINDINGS),
            truncated: false,
            last_error: None,
            logs_available: false,
        }
    }

    pub fn add_wire_diagnostics(&mut self, diagnostics: &[DoctorDiagnostic]) {
        if diagnostics.len() > MAX_DIAGNOSTIC_FINDINGS {
            self.truncated = true;
        }
        for diagnostic in diagnostics.iter().take(MAX_DIAGNOSTIC_FINDINGS) {
            let check = match diagnostic.check {
                DoctorCheck::IpcVersion => DiagnosticCheck::IpcVersion,
                DoctorCheck::ProfileOwner => DiagnosticCheck::ProfileOwner,
                DoctorCheck::Service => DiagnosticCheck::Service,
                DoctorCheck::Autostart => DiagnosticCheck::Autostart,
                DoctorCheck::Clock => DiagnosticCheck::Clock,
                DoctorCheck::Network => DiagnosticCheck::Network,
                DoctorCheck::Dns => DiagnosticCheck::Dns,
                DoctorCheck::Tls => DiagnosticCheck::Tls,
                DoctorCheck::Proxy => DiagnosticCheck::Proxy,
                DoctorCheck::Authorization => DiagnosticCheck::Authorization,
                DoctorCheck::Storage => DiagnosticCheck::Storage,
                DoctorCheck::Shell => DiagnosticCheck::Shell,
                DoctorCheck::Git => DiagnosticCheck::RemoteGit,
                DoctorCheck::RootPermissions => DiagnosticCheck::RootPermissions,
                DoctorCheck::Limits => DiagnosticCheck::Limits,
            };
            let state = match diagnostic.health {
                DoctorHealth::Healthy => DiagnosticState::Healthy,
                DoctorHealth::Unavailable => DiagnosticState::Unavailable,
                DoctorHealth::PermissionDenied => DiagnosticState::PermissionDenied,
                DoctorHealth::Incompatible => DiagnosticState::Incompatible,
                DoctorHealth::Unknown => DiagnosticState::Unknown,
                DoctorHealth::ConfigurationInvalid => DiagnosticState::ConfigurationInvalid,
                DoctorHealth::TransportUnavailable => DiagnosticState::TransportUnavailable,
                DoctorHealth::AuthorizationRejected => DiagnosticState::AuthorizationRejected,
                DoctorHealth::DisabledByPolicy => DiagnosticState::DisabledByPolicy,
            };
            self.add(check, state, DiagnosticSource::LocalHost);
        }
    }

    pub fn add_wire_report(&mut self, report: &lomi_remote_protocol::ipc::LocalDoctorReport) {
        self.add_wire_diagnostics(&report.checks.0);
        self.last_error = report.last_error;
        self.logs_available = report.logs_available;
    }

    pub fn add(
        &mut self,
        check: DiagnosticCheck,
        state: DiagnosticState,
        source: DiagnosticSource,
    ) {
        if self.findings.len() == MAX_DIAGNOSTIC_FINDINGS {
            self.truncated = true;
            return;
        }
        self.findings.push(DiagnosticFinding {
            check,
            state,
            source,
            guidance: guidance(check, state),
        });
    }

    pub fn add_missing_observations(
        &mut self,
        checks: &[DiagnosticCheck],
        source: DiagnosticSource,
    ) {
        if checks.len() > MAX_DIAGNOSTIC_FINDINGS {
            self.truncated = true;
        }
        for &check in checks.iter().take(MAX_DIAGNOSTIC_FINDINGS) {
            self.add(check, DiagnosticState::NotObserved, source);
        }
    }

    pub fn add_network_observation(
        &mut self,
        observation: NetworkObservation,
        source: DiagnosticSource,
    ) {
        let state = match observation {
            NetworkObservation::Available => DiagnosticState::Healthy,
            NetworkObservation::ConfigurationInvalid => DiagnosticState::ConfigurationInvalid,
            NetworkObservation::TransportUnavailable => DiagnosticState::TransportUnavailable,
            NetworkObservation::AuthorizationRejected => DiagnosticState::AuthorizationRejected,
            NetworkObservation::NotObserved => DiagnosticState::NotObserved,
        };
        self.add(DiagnosticCheck::Network, state, source);
    }

    /// Inspect a configured executable without launching it. Call only with a
    /// path obtained from trusted local configuration or an installed product
    /// resolver; the path is never copied into the finding.
    pub fn add_executable_observation(
        &mut self,
        check: ExecutableCheck,
        path: &Path,
        source: DiagnosticSource,
    ) {
        let check = match check {
            ExecutableCheck::Shell => DiagnosticCheck::Shell,
            ExecutableCheck::NativeGit => DiagnosticCheck::NativeGit,
        };
        let state = match lomi_platform::diagnostics::inspect_executable(path) {
            lomi_platform::diagnostics::ExecutableObservation::ProtectedFile => {
                DiagnosticState::Healthy
            }
            lomi_platform::diagnostics::ExecutableObservation::Missing => {
                DiagnosticState::Unavailable
            }
            lomi_platform::diagnostics::ExecutableObservation::PermissionDenied => {
                DiagnosticState::PermissionDenied
            }
            lomi_platform::diagnostics::ExecutableObservation::Invalid => DiagnosticState::Invalid,
            lomi_platform::diagnostics::ExecutableObservation::Unavailable => {
                DiagnosticState::Unknown
            }
        };
        self.add(check, state, source);
    }

    pub fn add_host_availability(&mut self, availability: HostAvailability) {
        let state = match availability {
            HostAvailability::Available => DiagnosticState::Healthy,
            HostAvailability::Unavailable => DiagnosticState::Unavailable,
            HostAvailability::PermissionDenied => DiagnosticState::PermissionDenied,
            HostAvailability::Incompatible => DiagnosticState::Incompatible,
            HostAvailability::InvalidProfile => DiagnosticState::Invalid,
            HostAvailability::NotAttempted => DiagnosticState::NotObserved,
        };
        self.add(
            DiagnosticCheck::IpcVersion,
            state,
            DiagnosticSource::LocalTransport,
        );
    }

    pub fn add_offline_observations(&mut self, profile: Option<&Path>) {
        match profile {
            Some(path) => {
                let state = match lomi_platform::diagnostics::inspect_profile(path) {
                    lomi_platform::diagnostics::ProfileObservation::Private => {
                        DiagnosticState::Healthy
                    }
                    lomi_platform::diagnostics::ProfileObservation::Missing => {
                        DiagnosticState::ConfigurationInvalid
                    }
                    lomi_platform::diagnostics::ProfileObservation::PermissionDenied => {
                        DiagnosticState::PermissionDenied
                    }
                    lomi_platform::diagnostics::ProfileObservation::Invalid => {
                        DiagnosticState::Invalid
                    }
                    lomi_platform::diagnostics::ProfileObservation::Unavailable => {
                        DiagnosticState::Unknown
                    }
                };
                self.add(
                    DiagnosticCheck::ProfileOwner,
                    state,
                    DiagnosticSource::LocalMachine,
                );
            }
            None => self.add(
                DiagnosticCheck::ProfileOwner,
                DiagnosticState::NotObserved,
                DiagnosticSource::LocalMachine,
            ),
        }

        let activation = match lomi_platform::installation::check_current_executable() {
            Ok(()) => DiagnosticState::Healthy,
            Err(lomi_platform::installation::ActivationError::Incomplete) => {
                DiagnosticState::Incompatible
            }
            Err(lomi_platform::installation::ActivationError::Unavailable) => {
                DiagnosticState::Unknown
            }
        };
        self.add(
            DiagnosticCheck::ActivationJournal,
            activation,
            DiagnosticSource::LocalMachine,
        );
        let root = lomi_platform::setup_context::current_account()
            .map(|account| {
                if account.is_root() {
                    DiagnosticState::PermissionDenied
                } else {
                    DiagnosticState::Healthy
                }
            })
            .unwrap_or(DiagnosticState::Unknown);
        self.add(
            DiagnosticCheck::RootPermissions,
            root,
            DiagnosticSource::LocalMachine,
        );

        use lomi_platform::service_observation as native;
        let service = profile.and_then(|profile| {
            let executable = std::env::current_exe().ok()?;
            let binding =
                native::current_binding(profile, &executable, native::ServiceMode::Manual).ok()?;
            Some((binding.mode, native::inspect(&binding)))
        });
        let service_state = service
            .as_ref()
            .map_or(DiagnosticState::Unknown, |(_, state)| {
                if state.binding == native::BindingState::Mismatch
                    || state.registration == native::RegistrationState::Invalid
                {
                    DiagnosticState::Incompatible
                } else {
                    match state.runtime {
                        native::RuntimeState::Running
                            if state.ipc == native::IpcReadiness::Ready =>
                        {
                            DiagnosticState::Healthy
                        }
                        native::RuntimeState::Stopped | native::RuntimeState::Failed => {
                            DiagnosticState::Unavailable
                        }
                        _ => DiagnosticState::Unknown,
                    }
                }
            });
        self.add(
            DiagnosticCheck::Service,
            service_state,
            DiagnosticSource::ServiceManager,
        );
        let autostart = service
            .as_ref()
            .map_or(DiagnosticState::Unknown, |(mode, state)| {
                match (mode, state.autostart) {
                    (_, native::AutostartState::Enabled)
                    | (native::ServiceMode::Manual, native::AutostartState::Disabled) => {
                        DiagnosticState::Healthy
                    }
                    (_, native::AutostartState::Disabled) => DiagnosticState::Unavailable,
                    (_, native::AutostartState::Unknown) => DiagnosticState::Unknown,
                }
            });
        self.add(
            DiagnosticCheck::Autostart,
            autostart,
            DiagnosticSource::ServiceManager,
        );
        self.add(
            DiagnosticCheck::Proxy,
            DiagnosticState::DisabledByPolicy,
            DiagnosticSource::LocalMachine,
        );
        self.add_missing_observations(
            &[
                DiagnosticCheck::Clock,
                DiagnosticCheck::Network,
                DiagnosticCheck::Dns,
                DiagnosticCheck::Tls,
                DiagnosticCheck::Authorization,
                DiagnosticCheck::Storage,
                DiagnosticCheck::Shell,
                DiagnosticCheck::RemoteGit,
                DiagnosticCheck::Limits,
            ],
            DiagnosticSource::LocalHost,
        );
    }

    pub fn finish(self) -> DiagnosticReport {
        DiagnosticReport {
            mode: self.mode,
            findings: self.findings,
            truncated: self.truncated,
            last_error: self.last_error,
            logs_available: self.logs_available,
        }
    }
}

/// Query the current authenticated Host without starting or repairing it.
/// Failed transport checks remain classified in a read-only offline report.
pub fn collect(
    profile: Option<&Path>,
    mut request: impl FnMut(LocalCall) -> Result<LocalResult, &'static str>,
) -> DiagnosticReport {
    let availability = match request(LocalCall::DoctorReport {}) {
        Ok(LocalResult::DoctorReport(report)) => {
            let mut builder = DiagnosticReportBuilder::new(DiagnosticRunMode::Online);
            builder.add_wire_report(&report);
            return builder.finish();
        }
        Ok(_) => HostAvailability::Incompatible,
        Err("LOCAL_PERMISSION_DENIED") => HostAvailability::PermissionDenied,
        Err("INVALID_LOCAL_PROFILE" | "LOCAL_HOST_IDENTITY_CHANGED") => {
            HostAvailability::InvalidProfile
        }
        Err("UPDATE_REQUIRED" | "DOCTOR_RESPONSE_INVALID") => HostAvailability::Incompatible,
        Err(_) => HostAvailability::Unavailable,
    };
    let mut builder = DiagnosticReportBuilder::new(DiagnosticRunMode::Offline);
    builder.add_host_availability(availability);
    builder.add_offline_observations(profile);
    builder.finish()
}

impl DiagnosticReport {
    /// The export contains closed vocabulary only, never paths or raw errors.
    pub fn redacted_json(&self) -> serde_json::Value {
        serde_json::json!({
            "version": lomi_remote_protocol::LocalIpcVersion::CURRENT,
            "report": {
                "mode": match self.mode { DiagnosticRunMode::Online => "online", DiagnosticRunMode::Offline => "offline" },
                "findings": self.findings.iter().map(|finding| serde_json::json!({
                    "check": format!("{:?}", finding.check),
                    "state": format!("{:?}", finding.state),
                    "source": format!("{:?}", finding.source),
                    "guidance": format!("{:?}", finding.guidance),
                })).collect::<Vec<_>>(),
                "lastError": self.last_error,
                "logsAvailable": self.logs_available,
                "truncated": self.truncated,
            }
        })
    }
}

fn guidance(check: DiagnosticCheck, state: DiagnosticState) -> RepairGuidance {
    match state {
        DiagnosticState::Healthy => RepairGuidance::None,
        DiagnosticState::DisabledByPolicy => RepairGuidance::UseDirectNetworkConnection,
        DiagnosticState::NotObserved | DiagnosticState::Unknown => {
            RepairGuidance::CollectMoreEvidence
        }
        DiagnosticState::PermissionDenied => match check {
            DiagnosticCheck::ProfileOwner | DiagnosticCheck::RootPermissions => {
                RepairGuidance::RepairProfilePermissions
            }
            _ => RepairGuidance::CollectMoreEvidence,
        },
        DiagnosticState::Incompatible => match check {
            DiagnosticCheck::ActivationJournal => RepairGuidance::CompleteOrRecoverUpdate,
            _ => RepairGuidance::UpdateLomiRemote,
        },
        DiagnosticState::Invalid => match check {
            DiagnosticCheck::ProfileOwner => RepairGuidance::ReviewProfileSetup,
            DiagnosticCheck::ActivationJournal => RepairGuidance::CompleteOrRecoverUpdate,
            _ => RepairGuidance::CollectMoreEvidence,
        },
        DiagnosticState::ConfigurationInvalid => match check {
            DiagnosticCheck::Network | DiagnosticCheck::Authorization => {
                RepairGuidance::ConfigureTrustedEndpoint
            }
            DiagnosticCheck::Shell => RepairGuidance::ReviewShellSetup,
            DiagnosticCheck::ProfileOwner => RepairGuidance::ReviewProfileSetup,
            _ => RepairGuidance::CollectMoreEvidence,
        },
        DiagnosticState::TransportUnavailable => match check {
            DiagnosticCheck::Network
            | DiagnosticCheck::Dns
            | DiagnosticCheck::Tls
            | DiagnosticCheck::Proxy => RepairGuidance::CheckNetworkTransport,
            DiagnosticCheck::Service | DiagnosticCheck::Autostart => {
                RepairGuidance::ReviewServiceRegistration
            }
            _ => RepairGuidance::CollectMoreEvidence,
        },
        DiagnosticState::AuthorizationRejected => RepairGuidance::Reauthenticate,
        DiagnosticState::Unavailable => match check {
            DiagnosticCheck::IpcVersion => RepairGuidance::StartOrReconnectHost,
            DiagnosticCheck::Service => RepairGuidance::ReviewServiceRegistration,
            DiagnosticCheck::Autostart => RepairGuidance::EnableAutostart,
            DiagnosticCheck::Clock => RepairGuidance::VerifySystemClock,
            DiagnosticCheck::Network => RepairGuidance::CheckNetworkTransport,
            DiagnosticCheck::Storage => RepairGuidance::CheckStorage,
            DiagnosticCheck::Shell => RepairGuidance::ReviewShellSetup,
            DiagnosticCheck::RemoteGit => RepairGuidance::ReviewBuiltInGit,
            DiagnosticCheck::NativeGit => RepairGuidance::InstallOrConfigureNativeGit,
            DiagnosticCheck::Limits => RepairGuidance::ReviewResourceLimits,
            _ => RepairGuidance::CollectMoreEvidence,
        },
    }
}
