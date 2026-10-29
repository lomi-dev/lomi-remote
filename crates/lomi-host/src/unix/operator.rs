//! Owner-local operational observations. No observation grants authority or
//! relaxes the Cloud fail-closed gate.
use super::*;
use lomi_remote_protocol::DecimalU64;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct ClientObservation {
    count: u32,
    valid_until: Instant,
}

impl Coordinator {
    /// Retain the original diagnostic vocabulary for Local IPC 1.0 clients.
    /// New detail is available only through the additive doctor.report call.
    pub(super) fn doctor_legacy(
        &self,
        operation: &owner_domain::Operation<'_>,
    ) -> Result<BoundedList<DoctorDiagnostic, 32>, LocalError> {
        let report = self.doctor(operation)?;
        Ok(BoundedList(
            report
                .0
                .into_iter()
                .filter_map(|mut check| {
                    if matches!(
                        check.check,
                        DoctorCheck::Dns
                            | DoctorCheck::Tls
                            | DoctorCheck::Proxy
                            | DoctorCheck::Authorization
                    ) {
                        return None;
                    }
                    check.health = match check.health {
                        DoctorHealth::ConfigurationInvalid => DoctorHealth::Incompatible,
                        DoctorHealth::TransportUnavailable => DoctorHealth::Unavailable,
                        DoctorHealth::AuthorizationRejected => DoctorHealth::PermissionDenied,
                        DoctorHealth::DisabledByPolicy => DoctorHealth::Unknown,
                        health => health,
                    };
                    Some(check)
                })
                .collect(),
        ))
    }
    pub(super) fn doctor_report(
        &self,
        operation: &owner_domain::Operation<'_>,
    ) -> Result<LocalDoctorReport, LocalError> {
        let checks = self.doctor(operation)?;
        let logs = self.logs.last_error();
        let network = lomi_host_http::diagnostics::snapshot().last_error;
        let local = logs.as_ref().and_then(|entry| entry.as_ref());
        let last_error = match (local, network) {
            (Some(local), Some(network)) => {
                if local.code == DiagnosticCode::NetworkUnavailable
                    || network
                        .unix_time_ms
                        .zip(local.unix_time_ms)
                        .is_some_and(|(network, local)| network >= local.0)
                {
                    Some(network.code)
                } else {
                    Some(local.code)
                }
            }
            (Some(local), None) => Some(local.code),
            (None, Some(network)) => Some(network.code),
            (None, None) => None,
        };
        operation.check().map_err(|_| LocalError::Unavailable)?;
        Ok(LocalDoctorReport {
            checks,
            last_error,
            logs_available: logs.is_some(),
        })
    }
    pub(super) fn observe_clients(&self, count: u32, valid_until: Instant) {
        if let Ok(mut observation) = self.clients.lock() {
            *observation = Some(ClientObservation { count, valid_until });
        }
    }

    fn connected_clients(&self) -> Option<u32> {
        self.clients
            .lock()
            .ok()?
            .as_ref()
            .filter(|observation| Instant::now() < observation.valid_until)
            .map(|observation| observation.count)
    }

    pub(super) fn login_observation(
        &self,
        operation: &owner_domain::Operation<'_>,
    ) -> Result<LocalLoginStatus, LocalError> {
        let handle = self
            .auth
            .lock()
            .map_err(|_| LocalError::Unavailable)?
            .clone()
            .ok_or(LocalError::Unavailable)?;
        let LocalResult::LoginStatus(status) =
            handle.dispatch(operation, LocalCall::LoginStatus {})?
        else {
            return Err(LocalError::Unavailable);
        };
        self.observe_authentication(&status);
        Ok(status)
    }

    pub(super) fn observe_authentication(&self, status: &LocalLoginStatus) {
        let next = (status.phase, status.storage, status.network);
        let Ok(mut previous) = self.diagnostic_auth.lock() else {
            return;
        };
        if previous.as_ref() == Some(&next) {
            return;
        }
        *previous = Some(next);
        let event = if status.storage == LocalAuthStorage::Unavailable {
            Some((
                DiagnosticComponent::Storage,
                DiagnosticCode::StorageUnavailable,
            ))
        } else if status.phase == LocalAuthPhase::Unconfigured {
            Some((
                DiagnosticComponent::Authentication,
                DiagnosticCode::AuthenticationConfigurationMissing,
            ))
        } else if status.network == LocalAuthNetwork::Unavailable {
            Some((
                DiagnosticComponent::Network,
                DiagnosticCode::NetworkUnavailable,
            ))
        } else if matches!(
            status.phase,
            LocalAuthPhase::Locked | LocalAuthPhase::PendingRevoke
        ) {
            Some((
                DiagnosticComponent::Authentication,
                DiagnosticCode::AuthenticationRejected,
            ))
        } else {
            None
        };
        if let Some((component, code)) = event {
            self.logs
                .record(DiagnosticSeverity::Warning, component, code);
        }
    }

    pub(super) fn operator_snapshot(
        &self,
        operation: &owner_domain::Operation<'_>,
    ) -> Result<LocalOperatorSnapshot, LocalError> {
        let login = self.login_observation(operation)?;
        let maintenance = rpc::owner_call(operation, || self.owner.maintenance_status(operation))
            .map_err(owner_error)?;
        let status = rpc::owner_call(operation, || self.owner.local_status(operation))
            .map_err(owner_error)?;
        // All are observations. Refuse a torn local identity rather than
        // publishing counts for a different owner runtime.
        if status.host_id != maintenance.host_id || status.runtime_id != maintenance.runtime_id {
            return Err(LocalError::Conflict);
        }
        Ok(LocalOperatorSnapshot {
            status,
            login,
            uptime_seconds: DecimalU64(self.started.elapsed().as_secs()),
            active_terminals: maintenance.active_terminals,
            connected_clients: self.connected_clients(),
        })
    }

    pub(super) fn workspace_details(
        &self,
        operation: &owner_domain::Operation<'_>,
        workspace_id: WorkspaceId,
    ) -> Result<LocalWorkspaceDetails, LocalError> {
        let project = rpc::owner_call(operation, || self.owner.workspace(operation, workspace_id))
            .map_err(owner_error)?;
        let identity =
            rpc::owner_call(operation, || self.owner.identity(operation)).map_err(owner_error)?;
        let root_path = project
            .local_root
            .to_str()
            .ok_or(LocalError::Unavailable)?
            .to_owned()
            .try_into()
            .map_err(|_| LocalError::Unavailable)?;
        // The WWW origin is an independent compile-time release pin. Never
        // derive it from an API response, the identity origin, or a relay URL.
        let remote_web_url = option_env!("LOMI_HOST_REMOTE_WEB_ORIGIN").and_then(|origin| {
            let client = "lomi-local-link".to_owned().try_into().ok()?;
            lomi_host_auth::Config::new(
                identity.host_id,
                identity.profile_id,
                origin.to_owned(),
                client,
            )
            .ok()?;
            format!(
                "{origin}/?view=remote-v2&host={}&workspace={}",
                String::from(identity.host_id),
                String::from(workspace_id)
            )
            .try_into()
            .ok()
        });
        Ok(LocalWorkspaceDetails {
            workspace: summary(&project)?,
            root_path,
            remote_web_url,
        })
    }

    pub(super) fn doctor(
        &self,
        operation: &owner_domain::Operation<'_>,
    ) -> Result<BoundedList<DoctorDiagnostic, 32>, LocalError> {
        use DoctorHealth as H;
        use lomi_platform::diagnostics::{ExecutableObservation as E, ProfileObservation as P};
        let mut checks = Vec::with_capacity(11);
        let mut add = |check, health| checks.push(DoctorDiagnostic { check, health });
        // Reaching this handler required canonical decoding and OS-authenticated
        // IPC. Other checks use their own observations below.
        add(DoctorCheck::IpcVersion, H::Healthy);
        let profile = self
            .profile
            .as_deref()
            .map(lomi_platform::diagnostics::inspect_profile);
        add(
            DoctorCheck::ProfileOwner,
            match profile {
                Some(P::Private) => H::Healthy,
                Some(P::PermissionDenied) => H::PermissionDenied,
                Some(P::Invalid) => H::Incompatible,
                Some(P::Missing | P::Unavailable) => H::Unavailable,
                None => H::Unknown,
            },
        );
        let authorization = rpc::owner_call(operation, || self.owner.auth_status(operation))
            .map_err(owner_error)?
            .authorization;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .map(|time| time.as_secs());
        add(
            DoctorCheck::Clock,
            if now.is_some_and(|now| now >= 1_704_067_200 && now >= authorization.clock_floor) {
                H::Healthy
            } else {
                H::Incompatible
            },
        );
        let transport = lomi_host_http::diagnostics::snapshot();
        add(DoctorCheck::Dns, transport.dns);
        add(DoctorCheck::Tls, transport.tls);
        add(DoctorCheck::Proxy, transport.proxy);
        match self.login_observation(operation) {
            Ok(login) => {
                add(
                    DoctorCheck::Network,
                    match (login.phase, login.network) {
                        (LocalAuthPhase::Unconfigured, _) => H::ConfigurationInvalid,
                        (_, LocalAuthNetwork::Available) => H::Healthy,
                        (_, LocalAuthNetwork::Unavailable) => H::TransportUnavailable,
                        (_, LocalAuthNetwork::Idle | LocalAuthNetwork::Working) => H::Unknown,
                    },
                );
                add(
                    DoctorCheck::Authorization,
                    if matches!(
                        login.phase,
                        LocalAuthPhase::Locked | LocalAuthPhase::PendingRevoke
                    ) {
                        H::AuthorizationRejected
                    } else if login.phase == LocalAuthPhase::Unconfigured {
                        H::ConfigurationInvalid
                    } else if login.phase == LocalAuthPhase::Ready && !login.locked {
                        H::Healthy
                    } else {
                        H::Unknown
                    },
                );
                add(
                    DoctorCheck::Storage,
                    match login.storage {
                        LocalAuthStorage::Available => H::Healthy,
                        LocalAuthStorage::Locked => H::PermissionDenied,
                        LocalAuthStorage::Unavailable => H::Unavailable,
                        LocalAuthStorage::Unconfigured => H::Unknown,
                    },
                );
            }
            Err(_) => {
                add(DoctorCheck::Network, H::Unknown);
                add(DoctorCheck::Authorization, H::Unknown);
                add(DoctorCheck::Storage, H::Unavailable);
            }
        }
        let shell = rpc::owner_call(operation, || self.owner.default_shell(operation))
            .map_err(owner_error)?;
        add(
            DoctorCheck::Shell,
            match shell {
                None => H::Unavailable,
                Some(shell) => {
                    match lomi_platform::diagnostics::inspect_executable(&shell.executable) {
                        E::ProtectedFile
                            if lomi_platform::diagnostics::can_execute_as_current_account(
                                &shell.executable,
                            ) =>
                        {
                            H::Healthy
                        }
                        E::ProtectedFile => H::PermissionDenied,
                        E::PermissionDenied => H::PermissionDenied,
                        E::Invalid => H::Incompatible,
                        E::Missing | E::Unavailable => H::Unavailable,
                    }
                }
            },
        );
        add(
            DoctorCheck::Git,
            if lomi_git::embedded_read_worker_integrity() {
                H::Healthy
            } else {
                H::Unavailable
            },
        );
        add(DoctorCheck::RootPermissions, root_permissions());
        add(DoctorCheck::Limits, resource_limits());
        let preferred = rpc::owner_call(operation, || self.owner.local_start_mode(operation))
            .map_err(owner_error)?;
        let mode = match preferred {
            LocalStartMode::Manual => lomi_platform::service_observation::ServiceMode::Manual,
            LocalStartMode::Login => lomi_platform::service_observation::ServiceMode::Login,
            LocalStartMode::Boot => lomi_platform::service_observation::ServiceMode::Boot,
        };
        // Native queries run after owned Store snapshots have released all
        // owner guards. A manager error cannot become a healthy observation.
        let service = self.profile.as_deref().and_then(|profile| {
            let executable = std::env::current_exe().ok()?;
            let binding =
                lomi_platform::service_observation::current_binding(profile, &executable, mode)
                    .ok()?;
            Some((
                binding.mode,
                lomi_platform::service_observation::inspect(&binding),
            ))
        });
        use lomi_platform::service_observation::{
            AutostartState, BindingState, IpcReadiness, RuntimeState,
        };
        add(
            DoctorCheck::Service,
            service.as_ref().map_or(H::Unknown, |(_, service)| {
                if service.binding == BindingState::Mismatch {
                    H::Incompatible
                } else if service.runtime == RuntimeState::Running
                    && service.ipc == IpcReadiness::Ready
                {
                    H::Healthy
                } else if service.runtime == RuntimeState::Unknown {
                    H::Unknown
                } else {
                    H::Unavailable
                }
            }),
        );
        add(
            DoctorCheck::Autostart,
            service
                .as_ref()
                .map_or(H::Unknown, |(mode, service)| match service.autostart {
                    AutostartState::Enabled => H::Healthy,
                    AutostartState::Disabled
                        if *mode == lomi_platform::service_observation::ServiceMode::Manual =>
                    {
                        H::Healthy
                    }
                    AutostartState::Disabled => H::Unavailable,
                    AutostartState::Unknown => H::Unknown,
                }),
        );
        operation.check().map_err(|_| LocalError::Unavailable)?;
        Ok(BoundedList(checks))
    }
}

fn root_permissions() -> DoctorHealth {
    #[cfg(target_os = "linux")]
    {
        let (mut real, mut effective, mut saved) = (0, 0, 0);
        if unsafe { libc::getresuid(&mut real, &mut effective, &mut saved) } != 0 {
            return DoctorHealth::Unknown;
        }
        if real == 0 || effective == 0 || saved == 0 {
            DoctorHealth::PermissionDenied
        } else {
            DoctorHealth::Healthy
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        match lomi_platform::setup_context::current_account() {
            Ok(account) if !account.is_root() => DoctorHealth::Healthy,
            Ok(_) => DoctorHealth::PermissionDenied,
            Err(_) => DoctorHealth::Unknown,
        }
    }
}

fn resource_limits() -> DoctorHealth {
    #[cfg(unix)]
    {
        let mut limits = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limits.as_mut_ptr()) } != 0 {
            return DoctorHealth::Unknown;
        }
        let limits = unsafe { limits.assume_init() };
        if limits.rlim_cur >= 256 {
            DoctorHealth::Healthy
        } else {
            DoctorHealth::Unavailable
        }
    }
    #[cfg(not(unix))]
    {
        DoctorHealth::Unknown
    }
}
