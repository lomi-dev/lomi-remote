//! Concrete first-run adapters for the selected ordinary account. Native
//! account selection and fresh-process privilege dropping precede this module.
use crate::setup::*;
use lomi_platform::{diagnostics as native_diagnostics, service_observation as native};
use lomi_remote_protocol::{HostId, WorkspaceId, ipc::*};
use std::{io::IsTerminal, path::Path};

pub struct LocalSetupHost {
    binding: ServiceBinding,
    expected_host_id: Option<HostId>,
    requires_existing_profile: bool,
}

impl LocalSetupHost {
    pub fn new(binding: ServiceBinding) -> Self {
        Self {
            binding,
            expected_host_id: None,
            requires_existing_profile: false,
        }
    }
}

#[cfg(unix)]
type Client = lomi_platform::unix::LocalClient;
#[cfg(windows)]
type Client = lomi_platform::windows::LocalClient;

fn connect(binding: &ServiceBinding) -> Result<Client, SetupError> {
    #[cfg(target_os = "macos")]
    {
        crate::terminal_commands::connect_installed_macos_host(&binding.profile_path)
            .map_err(|_| SetupError::HostUnavailable)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Client::connect(&binding.profile_path).map_err(|_| SetupError::HostUnavailable)
    }
}

fn selected_account(binding: &ServiceBinding) -> Result<native::ServiceAccount, SetupError> {
    let account = native::current_account().map_err(|_| SetupError::BindingMismatch)?;
    let matches = match (&binding.account, &account) {
        (
            SetupAccount::Unix { uid, gid },
            native::ServiceAccount::Unix {
                uid: current_uid,
                gid: current_gid,
                name,
            },
        ) => uid == current_uid && gid == current_gid && name == &binding.account_name,
        (
            SetupAccount::Windows { sid },
            native::ServiceAccount::Windows {
                sid: current_sid, ..
            },
        ) => sid == current_sid,
        _ => false,
    };
    if !matches {
        return Err(SetupError::BindingMismatch);
    }
    Ok(account)
}

fn native_binding(binding: &ServiceBinding) -> Result<native::ServiceBinding, SetupError> {
    Ok(native::ServiceBinding {
        account: selected_account(binding)?,
        mode: crate::operator::native_mode(binding.mode),
        profile: binding.profile_path.clone(),
        executable: binding.executable_path.clone(),
    })
}

impl SetupHost for LocalSetupHost {
    fn preflight(&mut self, binding: &ServiceBinding) -> Result<HostPreflight, SetupError> {
        selected_account(binding)?;
        if binding != &self.binding {
            return Err(SetupError::BindingMismatch);
        }
        let mut network = SetupNetworkState::Unknown;
        let (
            existing_configuration,
            existing_host_id,
            identity_pending_recovery,
            existing_host_name,
        ) = if let Ok(mut client) = connect(binding) {
            let discovery = client.discovery().clone();
            let status = match client.request(LocalCall::Status {}) {
                Ok(response) => match response.result {
                    Ok(LocalResult::Status(status)) => status,
                    _ => return Err(SetupError::HostUnavailable),
                },
                Err(_) => return Err(SetupError::HostUnavailable),
            };
            let workspaces = match client.request(LocalCall::Workspaces {}) {
                Ok(response) => match response.result {
                    Ok(LocalResult::Workspaces(workspaces)) => workspaces,
                    _ => return Err(SetupError::HostUnavailable),
                },
                Err(_) => return Err(SetupError::HostUnavailable),
            };
            let login = match client.request(LocalCall::LoginStatus {}) {
                Ok(response) => match response.result {
                    Ok(LocalResult::LoginStatus(login)) => login,
                    _ => return Err(SetupError::HostUnavailable),
                },
                Err(_) => return Err(SetupError::HostUnavailable),
            };
            network = match login.network {
                LocalAuthNetwork::Available => SetupNetworkState::Available,
                LocalAuthNetwork::Unavailable => SetupNetworkState::Offline,
                _ => SetupNetworkState::Unknown,
            };
            (
                !workspaces.0.is_empty() || login.phase != LocalAuthPhase::Unconfigured,
                Some(discovery.host_id),
                false,
                Some(status.host_name),
            )
        } else {
            match lomi_host::inspect_setup(&binding.profile_path) {
                lomi_host::SetupInspection::Ready(observation) => (
                    observation.auth_configuration.is_some() || observation.workspace_present,
                    Some(observation.identity.host_id),
                    false,
                    None,
                ),
                lomi_host::SetupInspection::MissingDatabase => (false, None, false, None),
                lomi_host::SetupInspection::NeedsRecovery => (true, None, true, None),
                _ => return Err(SetupError::ProfileRejected),
            }
        };
        if let Some(id) = existing_host_id {
            if self.expected_host_id.is_some_and(|expected| expected != id) {
                return Err(SetupError::BindingMismatch);
            }
            self.expected_host_id = Some(id);
        }
        self.requires_existing_profile =
            existing_host_id.is_some() || identity_pending_recovery || existing_configuration;
        Ok(HostPreflight {
            existing_configuration,
            existing_host_id,
            identity_pending_recovery,
            suggested_host_name: existing_host_name
                .unwrap_or_else(|| lomi_host::suggested_host_display_name(existing_host_id)),
            current_directory: std::env::current_dir().map_err(|_| SetupError::InvalidOptions)?,
            release_version: env!("CARGO_PKG_VERSION").to_owned(),
            network,
            interactive_terminal: std::io::stdin().is_terminal() && std::io::stdout().is_terminal(),
        })
    }

    fn start_local(
        &mut self,
        binding: &ServiceBinding,
        expected_host_id: Option<HostId>,
    ) -> Result<(), SetupError> {
        selected_account(binding)?;
        if binding != &self.binding {
            return Err(SetupError::BindingMismatch);
        }
        if let Some(id) = expected_host_id {
            if self.expected_host_id.is_some_and(|expected| expected != id) {
                return Err(SetupError::BindingMismatch);
            }
            self.expected_host_id = Some(id);
        }
        let expected_host_id = expected_host_id.or(self.expected_host_id);
        match self.observe(binding) {
            Ok(observed) => {
                if expected_host_id.is_some_and(|expected| expected != observed.status.host_id) {
                    return Err(SetupError::BindingMismatch);
                }
                return Ok(());
            }
            Err(SetupError::HostUnavailable) => {}
            Err(error) => return Err(error),
        }
        let native = native_binding(binding)?;
        let observation = native::inspect(&native);
        if observation.binding != native::BindingState::Matches {
            return Err(SetupError::BindingMismatch);
        }
        if matches!(
            observation.registration,
            native::RegistrationState::Invalid | native::RegistrationState::Unavailable
        ) {
            return Err(SetupError::ServiceUnavailable);
        }
        if binding.mode != LocalStartMode::Manual
            && observation.registration == native::RegistrationState::Present
        {
            native::control(&native, native::ServiceAction::Start)
                .map_err(|_| SetupError::ServiceUnavailable)?;
        } else {
            let executable = initial_host_executable(binding)?;
            match expected_host_id {
                Some(id) => lomi_host::start_bound(&executable, &binding.profile_path, id),
                None if self.requires_existing_profile => {
                    lomi_host::start_existing(&executable, &binding.profile_path)
                }
                None => lomi_host::start(&executable, &binding.profile_path),
            }
            .map_err(|_| SetupError::HostUnavailable)?;
        }
        let observed = self.observe(binding)?;
        if expected_host_id.is_some_and(|expected| expected != observed.status.host_id) {
            return Err(SetupError::BindingMismatch);
        }
        Ok(())
    }

    fn observe(&mut self, binding: &ServiceBinding) -> Result<HostObservation, SetupError> {
        selected_account(binding)?;
        if binding != &self.binding {
            return Err(SetupError::BindingMismatch);
        }
        let mut client = connect(binding)?;
        let discovery = client.discovery().clone();
        if self
            .expected_host_id
            .is_some_and(|expected| expected != discovery.host_id)
        {
            return Err(SetupError::BindingMismatch);
        }
        let response = client
            .request(LocalCall::Status {})
            .map_err(|_| SetupError::HostUnavailable)?;
        let Ok(LocalResult::Status(status)) = response.result else {
            return Err(SetupError::ProtocolMismatch);
        };
        if discovery.host_id != status.host_id || discovery.runtime_id != status.runtime_id {
            return Err(SetupError::BindingMismatch);
        }
        self.expected_host_id = Some(status.host_id);
        Ok(HostObservation {
            status,
            profile_path: binding.profile_path.clone(),
            account: binding.account.clone(),
        })
    }

    fn request(&mut self, call: LocalCall) -> Result<LocalResult, SetupCallError> {
        selected_account(&self.binding).map_err(|_| SetupCallError::Rejected)?;
        let mut client = connect(&self.binding).map_err(|_| SetupCallError::Unavailable)?;
        if self
            .expected_host_id
            .is_none_or(|expected| expected != client.discovery().host_id)
        {
            return Err(SetupCallError::Rejected);
        }
        // Once request dispatch begins, a transport failure is uncertain. The
        // coordinator decides which exact idempotent operations can reconcile.
        let response = client
            .request(call)
            .map_err(|_| SetupCallError::OutcomeUnknown)?;
        response.result.map_err(|_| SetupCallError::Rejected)
    }

    fn publication_status(
        &mut self,
        workspace_id: WorkspaceId,
    ) -> Result<WorkspacePublication, SetupError> {
        match self.request(LocalCall::WorkspacePublication(LocalWorkspaceRead {
            workspace_id,
        })) {
            Ok(LocalResult::WorkspacePublication(publication)) => Ok(WorkspacePublication {
                host_id: publication.host_id,
                workspace_id: publication.workspace_id,
                auth_generation: publication.auth_generation,
                consent: publication.consent,
                publication: match publication.publication {
                    LocalPublicationState::Pending => PublicationState::Pending,
                    LocalPublicationState::Acknowledged => PublicationState::Acknowledged,
                    LocalPublicationState::Unknown => PublicationState::Unknown,
                },
            }),
            _ => Err(SetupError::HostUnavailable),
        }
    }
}

fn initial_host_executable(binding: &ServiceBinding) -> Result<std::path::PathBuf, SetupError> {
    #[cfg(windows)]
    if binding.mode == LocalStartMode::Login {
        // The logon task action is the GUI-subsystem helper. The temporary
        // local-first daemon must be the CLI from that exact installed pair.
        let expected = binding.executable_path.with_file_name("lomiremote.exe");
        let current = std::env::current_exe().map_err(|_| SetupError::BindingMismatch)?;
        if current
            .canonicalize()
            .map_err(|_| SetupError::BindingMismatch)?
            != expected
                .canonicalize()
                .map_err(|_| SetupError::BindingMismatch)?
        {
            return Err(SetupError::BindingMismatch);
        }
        return Ok(expected);
    }
    Ok(binding.executable_path.clone())
}

#[derive(Default)]
pub struct NativeSetupService;

impl SetupServiceControl for NativeSetupService {
    fn validate_binding(&mut self, binding: &ServiceBinding) -> Result<(), SetupError> {
        selected_account(binding)?;
        if !binding.profile_path.is_absolute() || !binding.executable_path.is_absolute() {
            return Err(SetupError::InvalidOptions);
        }
        use native_diagnostics::{ExecutableObservation as E, ProfileObservation as P};
        match native_diagnostics::inspect_profile(&binding.profile_path) {
            P::Private | P::Missing => {}
            _ => return Err(SetupError::ProfileRejected),
        }
        if native_diagnostics::inspect_executable(&binding.executable_path) != E::ProtectedFile {
            return Err(SetupError::BindingMismatch);
        }
        Ok(())
    }

    fn detect_shells(
        &mut self,
        binding: &ServiceBinding,
    ) -> Result<Vec<ShellCandidate>, SetupError> {
        selected_account(binding)?;
        let paths = native_diagnostics::standard_shell_candidates();
        Ok(paths
            .into_iter()
            .filter(|path| {
                native_diagnostics::inspect_executable(path)
                    == native_diagnostics::ExecutableObservation::ProtectedFile
            })
            .map(|executable| ShellCandidate {
                label: executable
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                executable,
            })
            .collect())
    }

    fn detect_git_repository(&mut self, root: &Path) -> Result<bool, SetupError> {
        Ok(root.join(".git").symlink_metadata().is_ok())
    }

    fn verify_workspace_access(
        &mut self,
        binding: &ServiceBinding,
        root: &Path,
    ) -> Result<(), SetupError> {
        selected_account(binding)?;
        if !root.is_absolute()
            || root
                .canonicalize()
                .map_err(|_| SetupError::InvalidOptions)?
                != root
        {
            return Err(SetupError::InvalidOptions);
        }
        std::fs::read_dir(root).map_err(|_| SetupError::ServiceUnavailable)?;
        Ok(())
    }

    fn verify_shell_profile(
        &mut self,
        binding: &ServiceBinding,
        root: &Path,
        profile: &LocalShellProfileRegister,
    ) -> Result<(), SetupError> {
        self.verify_workspace_access(binding, root)?;
        if profile.profile_id
            != profile
                .derived_profile_id()
                .map_err(|_| SetupError::InvalidOptions)?
            || Path::new(profile.cwd.as_str()) != root
            || native_diagnostics::inspect_executable(Path::new(profile.executable.as_str()))
                != native_diagnostics::ExecutableObservation::ProtectedFile
            || !native_diagnostics::can_execute_as_current_account(Path::new(
                profile.executable.as_str(),
            ))
        {
            return Err(SetupError::InvalidOptions);
        }
        Ok(())
    }

    fn inspect(&mut self, binding: &ServiceBinding) -> Result<ServiceObservation, SetupError> {
        let observation = native::inspect(&native_binding(binding)?);
        Ok(ServiceObservation {
            binding_matches: observation.binding == native::BindingState::Matches,
            registration_present: observation.registration == native::RegistrationState::Present,
            autostart_enabled: observation.autostart == native::AutostartState::Enabled,
            active: observation.runtime == native::RuntimeState::Running,
            ipc_ready: observation.ipc == native::IpcReadiness::Ready,
        })
    }

    fn install(&mut self, binding: &ServiceBinding) -> Result<(), SetupError> {
        native::control(&native_binding(binding)?, native::ServiceAction::Install)
            .map(|_| ())
            .map_err(|_| SetupError::ServiceUnavailable)
    }

    fn start(&mut self, binding: &ServiceBinding) -> Result<(), SetupError> {
        if binding.mode == LocalStartMode::Manual {
            if self.inspect(binding)?.ipc_ready {
                Ok(())
            } else {
                Err(SetupError::ServiceUnavailable)
            }
        } else {
            native::control(&native_binding(binding)?, native::ServiceAction::Start)
                .map(|_| ())
                .map_err(|_| SetupError::ServiceUnavailable)
        }
    }
}
