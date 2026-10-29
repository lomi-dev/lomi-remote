//! Native service controls for the operator UI. Read paths never install,
//! repair, or create profiles. Every action follows an explicit UI confirmation.
use crate::ui::operations::{
    ServiceAccountKind, ServiceAction, ServiceAutostartState, ServiceMode, ServiceRuntimeState,
    ServiceSnapshot,
};
use lomi_platform::service_observation as native;
use lomi_remote_protocol::ipc::{LocalOperatorSnapshot, LocalStartMode};
use std::path::Path;

pub fn native_mode(mode: LocalStartMode) -> native::ServiceMode {
    match mode {
        LocalStartMode::Manual => native::ServiceMode::Manual,
        LocalStartMode::Login => native::ServiceMode::Login,
        LocalStartMode::Boot => native::ServiceMode::Boot,
    }
}

pub fn binding(
    profile: &Path,
    preferred: LocalStartMode,
) -> Result<native::ServiceBinding, &'static str> {
    let executable = std::env::current_exe().map_err(|_| "SERVICE_EXECUTABLE_UNAVAILABLE")?;
    native::current_binding(profile, &executable, native_mode(preferred)).map_err(service_error)
}

pub fn snapshot(
    profile: &Path,
    preferred: LocalStartMode,
    operator: Option<&LocalOperatorSnapshot>,
) -> Result<ServiceSnapshot, &'static str> {
    let binding = binding(profile, preferred)?;
    let observation = native::inspect(&binding);
    if observation.binding == native::BindingState::Mismatch {
        return Err("SERVICE_OWNERSHIP_CONFLICT");
    }
    let mode = match binding.mode {
        native::ServiceMode::Manual => ServiceMode::Manual,
        native::ServiceMode::Login => ServiceMode::Login,
        native::ServiceMode::Boot => ServiceMode::Boot,
    };
    Ok(ServiceSnapshot {
        mode: (observation.binding == native::BindingState::Matches).then_some(mode),
        runtime: match observation.runtime {
            native::RuntimeState::Running => ServiceRuntimeState::Running,
            native::RuntimeState::Starting => ServiceRuntimeState::Starting,
            native::RuntimeState::Stopped => ServiceRuntimeState::Stopped,
            native::RuntimeState::Failed => ServiceRuntimeState::Failed,
            native::RuntimeState::Unknown => ServiceRuntimeState::Unknown,
        },
        autostart: match observation.autostart {
            native::AutostartState::Enabled => ServiceAutostartState::Enabled,
            native::AutostartState::Disabled => ServiceAutostartState::Disabled,
            native::AutostartState::Unknown => ServiceAutostartState::Unknown,
        },
        // This adapter runs in the current account's ordinary context. An
        // administrator acting for another account uses the explicit installer.
        account: ServiceAccountKind::CurrentUser,
        host_uptime_seconds: operator.map(|snapshot| snapshot.uptime_seconds.0),
        connected_clients: operator.and_then(|snapshot| snapshot.connected_clients),
        active_terminals: operator
            .and_then(|snapshot| u32::try_from(snapshot.active_terminals.0).ok()),
    })
}

pub fn action(
    profile: &Path,
    preferred: LocalStartMode,
    action: ServiceAction,
    expected_host_id: lomi_remote_protocol::HostId,
) -> Result<(), &'static str> {
    let desired = match action {
        ServiceAction::InstallLogin => LocalStartMode::Login,
        ServiceAction::InstallBoot => LocalStartMode::Boot,
        _ => preferred,
    };
    let binding = binding(profile, desired)?;
    let install = matches!(
        action,
        ServiceAction::InstallLogin | ServiceAction::InstallBoot
    );
    if install && binding.mode != native_mode(desired) {
        return Err("SERVICE_MODE_CHANGE_REQUIRES_EXPLICIT_UNINSTALL");
    }
    if binding.mode == native::ServiceMode::Manual {
        match action {
            ServiceAction::Start => {
                lomi_host::start_bound(&binding.executable, profile, expected_host_id)
            }
            ServiceAction::Stop => lomi_host::stop_bound(profile, expected_host_id),
            ServiceAction::Restart => {
                lomi_host::stop_bound(profile, expected_host_id)
                    .map_err(|_| "SERVICE_STOP_NOT_CONFIRMED")?;
                lomi_host::start_bound(&binding.executable, profile, expected_host_id)
            }
            _ => return Err("SERVICE_MANUAL_MODE_HAS_NO_AUTOSTART_REGISTRATION"),
        }
        .map_err(|_| "SERVICE_OPERATION_NOT_CONFIRMED")?;
        return Ok(());
    }
    let action = match action {
        ServiceAction::InstallLogin | ServiceAction::InstallBoot => native::ServiceAction::Install,
        ServiceAction::Start => native::ServiceAction::Start,
        ServiceAction::Stop => native::ServiceAction::Stop,
        ServiceAction::Restart => native::ServiceAction::Restart,
        ServiceAction::Uninstall => native::ServiceAction::Uninstall,
    };
    native::control(&binding, action).map_err(service_error)?;
    Ok(())
}

pub fn service_error(error: native::ServiceError) -> &'static str {
    match error {
        native::ServiceError::InvalidBinding => "SERVICE_INVALID_CONFIGURATION",
        native::ServiceError::Conflict => "SERVICE_OWNERSHIP_CONFLICT",
        native::ServiceError::ManagerUnavailable => "SERVICE_MANAGER_UNAVAILABLE",
        native::ServiceError::OperationUncertain => "SERVICE_OPERATION_UNCERTAIN",
        native::ServiceError::NotReady => "SERVICE_NOT_READY",
        native::ServiceError::CredentialsRequired => "SERVICE_OS_CREDENTIALS_REQUIRED",
        native::ServiceError::AdministratorRequired => "SERVICE_ADMINISTRATOR_INSTALL_REQUIRED",
        native::ServiceError::Unsupported => "SERVICE_MODE_UNAVAILABLE",
    }
}
