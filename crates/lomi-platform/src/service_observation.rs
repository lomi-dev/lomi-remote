//! Read-only, typed observation of the selected account's Host service.
//!
//! This module deliberately does not route through the text status commands:
//! those commands may acquire service locks or perform recovery. Native
//! backends below inspect only existing registration and manager state.

use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceMode {
    Manual,
    Login,
    Boot,
}

impl ServiceMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Manual => "manual",
            Self::Login => "login",
            Self::Boot => "boot",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ServiceAccount {
    Unix { uid: u32, gid: u32, name: String },
    Windows { sid: String, name: String },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceBinding {
    pub account: ServiceAccount,
    pub mode: ServiceMode,
    pub profile: PathBuf,
    /// The exact program used by the OS service/task adapter.
    pub executable: PathBuf,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingState {
    Matches,
    Mismatch,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistrationState {
    Missing,
    Present,
    Invalid,
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeState {
    Running,
    Starting,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AutostartState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcReadiness {
    Ready,
    NotReady,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServiceObservation {
    pub binding: BindingState,
    pub registration: RegistrationState,
    pub runtime: RuntimeState,
    pub autostart: AutostartState,
    pub ipc: IpcReadiness,
}

impl ServiceObservation {
    fn unavailable() -> Self {
        Self {
            binding: BindingState::Unknown,
            registration: RegistrationState::Unavailable,
            runtime: RuntimeState::Unknown,
            autostart: AutostartState::Unknown,
            ipc: IpcReadiness::Unknown,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceAction {
    Install,
    Start,
    Stop,
    Restart,
    Uninstall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ServiceError {
    InvalidBinding,
    Conflict,
    ManagerUnavailable,
    OperationUncertain,
    NotReady,
    CredentialsRequired,
    AdministratorRequired,
    Unsupported,
}

impl std::fmt::Display for ServiceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidBinding => "SERVICE_INVALID_CONFIGURATION",
            Self::Conflict => "SERVICE_OWNERSHIP_CONFLICT",
            Self::ManagerUnavailable => "SERVICE_MANAGER_UNAVAILABLE",
            Self::OperationUncertain => "SERVICE_OPERATION_UNCERTAIN",
            Self::NotReady => "SERVICE_NOT_READY",
            Self::CredentialsRequired => "SERVICE_OS_CREDENTIALS_REQUIRED",
            Self::AdministratorRequired => "SERVICE_ADMINISTRATOR_REQUIRED",
            Self::Unsupported => "SERVICE_ADAPTER_UNAVAILABLE_FOR_MODE_OR_ACCOUNT",
        })
    }
}

impl std::error::Error for ServiceError {}

/// Return the native process account identity. Environment variables are never
/// used as authority for the selected account.
pub fn current_account() -> Result<ServiceAccount, ServiceError> {
    #[cfg(target_os = "linux")]
    {
        return crate::service_linux::current_service_account();
    }
    #[cfg(target_os = "macos")]
    {
        return crate::service_macos::current_service_account();
    }
    #[cfg(windows)]
    {
        let selected = crate::setup_context::select_current_account()
            .map_err(|_| ServiceError::AdministratorRequired)?;
        let account = selected.windows().ok_or(ServiceError::InvalidBinding)?;
        return Ok(ServiceAccount::Windows {
            sid: account.sid().to_owned(),
            name: account.name().to_owned(),
        });
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(ServiceError::Unsupported)
    }
}

/// Build the current account's service binding without creating a profile or
/// registration. Existing native registration takes precedence over the
/// caller's preferred mode and executable hint.
pub fn current_binding(
    profile: &std::path::Path,
    _executable_hint: &std::path::Path,
    preferred_mode: ServiceMode,
) -> Result<ServiceBinding, ServiceError> {
    if !profile.is_absolute() || profile == std::path::Path::new("/") {
        return Err(ServiceError::InvalidBinding);
    }
    let account = current_account()?;
    #[cfg(target_os = "linux")]
    let (mode, executable) = {
        let (mode, executable) = match crate::service_linux::discover_service_binding(profile)? {
            Some((mode, path)) => (mode, path),
            None => (
                preferred_mode,
                std::env::current_exe()
                    .and_then(|path| path.canonicalize())
                    .map_err(|_| ServiceError::InvalidBinding)?,
            ),
        };
        let ServiceAccount::Unix { .. } = &account else {
            return Err(ServiceError::InvalidBinding);
        };
        (mode, executable)
    };
    #[cfg(target_os = "macos")]
    let (mode, executable) = {
        use crate::service_observation::ServiceAccount;
        let ServiceAccount::Unix { uid, .. } = &account else {
            return Err(ServiceError::InvalidBinding);
        };
        if *uid == 0 {
            return Err(ServiceError::Unsupported);
        }
        let executable =
            crate::service_macos::custody::installed_privileged_host_executable(profile)
                .map_err(|_| ServiceError::InvalidBinding)?;
        let mode = crate::service_macos::discover_service_mode(profile, &executable)?
            .unwrap_or(preferred_mode);
        (mode, executable)
    };
    #[cfg(windows)]
    let (mode, executable) = {
        let ServiceAccount::Windows { name, .. } = &account else {
            return Err(ServiceError::InvalidBinding);
        };
        let admin =
            crate::windows::service_admin::inspect(name).map_err(map_windows_admin_error)?;
        let login = crate::windows::task::registered_helper(profile)?;
        match (admin, login) {
            (Some(_), Some(_)) => return Err(ServiceError::Conflict),
            (Some(status), None) => {
                if status.profile != profile || status.mode != "boot" {
                    return Err(ServiceError::Conflict);
                }
                (ServiceMode::Boot, status.executable)
            }
            (None, Some(helper)) => (ServiceMode::Login, helper),
            (None, None) => match preferred_mode {
                ServiceMode::Boot => return Err(ServiceError::AdministratorRequired),
                ServiceMode::Login => (
                    ServiceMode::Login,
                    _executable_hint.with_file_name("lomiremote-host.exe"),
                ),
                ServiceMode::Manual => (ServiceMode::Manual, _executable_hint.to_path_buf()),
            },
        }
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    let (mode, executable) = {
        let _ = (account, _executable_hint, preferred_mode);
        return Err(ServiceError::Unsupported);
    };
    let binding = ServiceBinding {
        account,
        mode,
        profile: profile.to_path_buf(),
        executable,
    };
    validate_binding_shape(&binding)?;
    let observed = inspect(&binding);
    if observed.binding != BindingState::Matches
        || observed.registration == RegistrationState::Invalid
        || observed.registration == RegistrationState::Unavailable
    {
        return Err(ServiceError::Conflict);
    }
    Ok(binding)
}

/// Inspect native registration and manager state without creating a profile,
/// lock, registration, or service-manager entry.
pub fn inspect(binding: &ServiceBinding) -> ServiceObservation {
    if validate_binding_shape(binding).is_err() {
        return ServiceObservation {
            binding: BindingState::Mismatch,
            registration: RegistrationState::Invalid,
            runtime: RuntimeState::Unknown,
            autostart: AutostartState::Unknown,
            ipc: IpcReadiness::Unknown,
        };
    }
    match inspect_native(binding) {
        Ok(observation) => observation,
        Err(ServiceError::Conflict | ServiceError::InvalidBinding) => ServiceObservation {
            binding: BindingState::Mismatch,
            registration: RegistrationState::Invalid,
            runtime: RuntimeState::Unknown,
            autostart: AutostartState::Unknown,
            ipc: IpcReadiness::Unknown,
        },
        Err(_) => ServiceObservation::unavailable(),
    }
}

/// Invoke an exact-bound native service operation and return a fresh typed
/// observation. Manual-mode install is an intentional no-op: it confirms that
/// no managed service registration has been created.
pub fn control(
    binding: &ServiceBinding,
    action: ServiceAction,
) -> Result<ServiceObservation, ServiceError> {
    validate_binding_shape(binding)?;
    if action == ServiceAction::Install && binding.mode == ServiceMode::Manual {
        return Ok(inspect(binding));
    }
    if binding.mode == ServiceMode::Manual {
        return Err(ServiceError::Unsupported);
    }
    control_native(binding, action)?;
    let observed = inspect(binding);
    if observed.registration == RegistrationState::Invalid
        || observed.registration == RegistrationState::Unavailable
    {
        return Err(ServiceError::Conflict);
    }
    Ok(observed)
}

fn validate_binding_shape(binding: &ServiceBinding) -> Result<(), ServiceError> {
    if !binding.profile.is_absolute()
        || !binding.executable.is_absolute()
        || binding.profile == std::path::Path::new("/")
        || binding.profile.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        || binding.executable.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
    {
        return Err(ServiceError::InvalidBinding);
    }
    match &binding.account {
        ServiceAccount::Unix { uid, gid: _, name }
            if *uid != 0
                && !name.is_empty()
                && name.len() <= 256
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)) =>
        {
            Ok(())
        }
        ServiceAccount::Windows { sid, name }
            if sid.starts_with("S-1-")
                && sid.len() <= 184
                && sid
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b == b'-' || b == b'S')
                && !name.is_empty()
                && name.len() <= 512
                && !name.chars().any(char::is_control) =>
        {
            Ok(())
        }
        _ => Err(ServiceError::InvalidBinding),
    }
}

#[cfg(target_os = "linux")]
fn inspect_native(binding: &ServiceBinding) -> Result<ServiceObservation, ServiceError> {
    crate::service_linux::inspect_read_only(binding)
}

#[cfg(target_os = "macos")]
fn inspect_native(binding: &ServiceBinding) -> Result<ServiceObservation, ServiceError> {
    crate::service_macos::inspect_read_only(binding)
}

#[cfg(windows)]
fn inspect_native(binding: &ServiceBinding) -> Result<ServiceObservation, ServiceError> {
    use crate::windows::{service_admin, task};
    if binding.mode != ServiceMode::Boot {
        let ServiceAccount::Windows { name, .. } = &binding.account else {
            return Err(ServiceError::InvalidBinding);
        };
        if service_admin::inspect(name)
            .map_err(map_windows_admin_error)?
            .is_some()
        {
            return Err(ServiceError::Conflict);
        }
        return task::inspect_read_only(binding);
    }
    let ServiceAccount::Windows { sid, name } = &binding.account else {
        return Err(ServiceError::InvalidBinding);
    };
    let status = service_admin::inspect(name).map_err(map_windows_admin_error)?;
    let Some(status) = status else {
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: RegistrationState::Missing,
            runtime: RuntimeState::Stopped,
            autostart: AutostartState::Disabled,
            ipc: IpcReadiness::NotReady,
        });
    };
    if status.account_sid != *sid
        || status.profile != binding.profile
        || status.executable != binding.executable
        || status.mode != "boot"
    {
        return Err(ServiceError::Conflict);
    }
    let runtime = if status.running {
        RuntimeState::Running
    } else if status.phase == "starting" {
        RuntimeState::Starting
    } else if matches!(
        status.phase,
        "updating" | "deleting" | "intent" | "credentials_required"
    ) {
        RuntimeState::Unknown
    } else {
        RuntimeState::Stopped
    };
    let ipc_ready = status.running
        && status
            .process_id
            .is_some_and(|pid| service_admin::authenticated_host_status(&binding.profile, pid));
    Ok(ServiceObservation {
        binding: BindingState::Matches,
        registration: RegistrationState::Present,
        runtime,
        autostart: if status.autostart {
            AutostartState::Enabled
        } else {
            AutostartState::Disabled
        },
        ipc: if ipc_ready {
            IpcReadiness::Ready
        } else if status.running {
            IpcReadiness::NotReady
        } else {
            IpcReadiness::NotReady
        },
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn inspect_native(_binding: &ServiceBinding) -> Result<ServiceObservation, ServiceError> {
    Err(ServiceError::Unsupported)
}

#[cfg(target_os = "linux")]
fn control_native(binding: &ServiceBinding, action: ServiceAction) -> Result<(), ServiceError> {
    crate::service_linux::control_exact(binding, action)
}

#[cfg(target_os = "macos")]
fn control_native(binding: &ServiceBinding, action: ServiceAction) -> Result<(), ServiceError> {
    crate::service_macos::control_exact(binding, action)
}

#[cfg(windows)]
fn control_native(binding: &ServiceBinding, action: ServiceAction) -> Result<(), ServiceError> {
    windows_control_exact(binding, action)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn control_native(_binding: &ServiceBinding, _action: ServiceAction) -> Result<(), ServiceError> {
    Err(ServiceError::Unsupported)
}

#[cfg(windows)]
fn map_windows_admin_error(error: crate::windows::service_admin::Error) -> ServiceError {
    use crate::windows::service_admin::Error as NativeError;
    match error {
        NativeError::Invalid => ServiceError::InvalidBinding,
        NativeError::Conflict | NativeError::ProtectedImageRequired => ServiceError::Conflict,
        NativeError::AdministratorRequired => ServiceError::AdministratorRequired,
        NativeError::AccountNotOrdinary => ServiceError::Unsupported,
        NativeError::CredentialsRequired => ServiceError::CredentialsRequired,
        NativeError::NotInstalled => ServiceError::NotReady,
        NativeError::Manager => ServiceError::ManagerUnavailable,
        NativeError::NotReady => ServiceError::NotReady,
        NativeError::Deadline => ServiceError::OperationUncertain,
    }
}

#[cfg(windows)]
fn map_windows_login_error(error: crate::windows::task::Error) -> ServiceError {
    use crate::windows::task::Error as NativeError;
    match error {
        NativeError::Invalid | NativeError::HelperMissing => ServiceError::InvalidBinding,
        NativeError::Conflict => ServiceError::Conflict,
        NativeError::Manager => ServiceError::ManagerUnavailable,
        NativeError::Deadline => ServiceError::OperationUncertain,
        NativeError::NotReady => ServiceError::NotReady,
        NativeError::PrivilegedAccount | NativeError::SessionRequired => ServiceError::Unsupported,
        NativeError::NotInstalled => ServiceError::NotReady,
    }
}

#[cfg(windows)]
fn windows_control_exact(
    binding: &ServiceBinding,
    action: ServiceAction,
) -> Result<(), ServiceError> {
    use crate::windows::{service_admin, task};
    let ServiceAccount::Windows { name, .. } = &binding.account else {
        return Err(ServiceError::InvalidBinding);
    };
    let operation = match action {
        ServiceAction::Install => "install",
        ServiceAction::Start => "start",
        ServiceAction::Stop => "stop",
        ServiceAction::Restart => "restart",
        ServiceAction::Uninstall => "uninstall",
    };
    match binding.mode {
        ServiceMode::Manual => Err(ServiceError::Unsupported),
        ServiceMode::Login => {
            task::run(&binding.profile, &binding.executable, operation, Some(name))
                .map(|_| ())
                .map_err(map_windows_login_error)
        }
        ServiceMode::Boot if action == ServiceAction::Install => {
            Err(ServiceError::CredentialsRequired)
        }
        ServiceMode::Boot => {
            let current = inspect_native(binding)?;
            if current.binding != BindingState::Matches
                || current.registration != RegistrationState::Present
            {
                return Err(ServiceError::Conflict);
            }
            service_admin::run(operation, name, None, None)
                .map(|_| ())
                .map_err(map_windows_admin_error)
        }
    }
}

/// Install a Windows Boot registration after the caller obtains the explicit
/// OS credential and verified release-image capabilities. General `control`
/// intentionally cannot prompt for or invent either capability.
#[cfg(windows)]
pub fn install_windows_boot(
    binding: &ServiceBinding,
    password: crate::windows::service_admin::ServicePassword,
    image: &crate::windows::service_admin::VerifiedHostServiceImage,
) -> Result<ServiceObservation, ServiceError> {
    use crate::windows::service_admin;
    validate_binding_shape(binding)?;
    if binding.mode != ServiceMode::Boot {
        return Err(ServiceError::InvalidBinding);
    }
    let ServiceAccount::Windows { name, .. } = &binding.account else {
        return Err(ServiceError::InvalidBinding);
    };
    service_admin::run("install", name, Some(password), Some(image))
        .map_err(map_windows_admin_error)?;
    let observed = inspect(binding);
    if observed.binding != BindingState::Matches
        || observed.registration != RegistrationState::Present
    {
        return Err(ServiceError::NotReady);
    }
    Ok(observed)
}
