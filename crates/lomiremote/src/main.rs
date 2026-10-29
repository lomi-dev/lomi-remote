use clap::ArgMatches;
use lomi_remote_protocol::{
    LocalIpcVersion, WorkspaceId,
    ipc::{
        LocalAuthConfiguration, LocalAuthConfigure, LocalAuthProvider, LocalCall, LocalError,
        LocalFileAcknowledgement, LocalLoginStart, LocalOperatorIntent, LocalProjectName,
        LocalResponse, LocalResult, LocalRootPath, LocalWorkspaceAdd, LocalWorkspaceTarget,
    },
    rpc::Confirmed,
};
use lomiremote::{cli, ui};
use std::{
    env,
    io::{self, IsTerminal},
    path::{Path, PathBuf},
    process::ExitCode,
};

#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    exit: u8,
}
impl Failure {
    fn unavailable() -> Self {
        Self {
            code: "DAEMON_UNAVAILABLE",
            exit: 4,
        }
    }
    fn macos_admin_install_required() -> Self {
        Self {
            code: "MACOS_ADMIN_INSTALL_REQUIRED",
            exit: 4,
        }
    }
    fn update_required() -> Self {
        Self {
            code: "UPDATE_REQUIRED",
            exit: 6,
        }
    }
    fn arguments() -> Self {
        Self {
            code: "INVALID_ARGUMENT",
            exit: 2,
        }
    }
    fn unsupported() -> Self {
        Self {
            code: "UNSUPPORTED_LOCAL_OPERATION",
            exit: 3,
        }
    }
    fn nonroot_account_required() -> Self {
        Self {
            code: "NONROOT_HOST_ACCOUNT_REQUIRED",
            exit: 3,
        }
    }
}
#[cfg(any(unix, windows))]
fn request(profile: &Path, call: LocalCall) -> Result<LocalResponse, Failure> {
    request_with_host(profile, None, call)
}
#[cfg(any(unix, windows))]
fn request_with_host(
    profile: &Path,
    expected_host_id: Option<lomi_remote_protocol::HostId>,
    call: LocalCall,
) -> Result<LocalResponse, Failure> {
    #[cfg(unix)]
    use lomi_platform::unix::{Error, LocalClient};
    #[cfg(windows)]
    use lomi_platform::windows::{Error, LocalClient};
    let is_doctor = matches!(&call, LocalCall::Doctor {} | LocalCall::DoctorReport {});
    let map = |error: Error| match error {
        Error::PermissionDenied => Failure {
            code: "LOCAL_PERMISSION_DENIED",
            exit: 5,
        },
        Error::Io(error) if error.kind() == io::ErrorKind::PermissionDenied => Failure {
            code: "LOCAL_PERMISSION_DENIED",
            exit: 5,
        },
        Error::Incompatible => Failure {
            code: "UPDATE_REQUIRED",
            exit: 6,
        },
        Error::InvalidFrame if is_doctor => Failure {
            code: "DOCTOR_RESPONSE_INVALID",
            exit: 6,
        },
        Error::InvalidProfile | Error::InvalidEndpoint | Error::InvalidFrame => Failure {
            code: "INVALID_LOCAL_PROFILE",
            exit: 5,
        },
        _ => Failure::unavailable(),
    };
    let mut client = {
        #[cfg(target_os = "macos")]
        {
            if matches!(
                &call,
                LocalCall::Status {} | LocalCall::DaemonStop(_) | LocalCall::Logout(_)
            ) {
                LocalClient::connect(profile).map_err(map)?
            } else {
                lomiremote::terminal_commands::connect_installed_macos_host(profile)
                    .map_err(macos_identity_failure)?
            }
        }
        #[cfg(not(target_os = "macos"))]
        {
            LocalClient::connect(profile).map_err(map)?
        }
    };
    if expected_host_id.is_some_and(|expected| expected != client.discovery().host_id) {
        return Err(Failure {
            code: "LOCAL_HOST_IDENTITY_CHANGED",
            exit: 5,
        });
    }
    let removing = matches!(&call, LocalCall::WorkspaceRemove(_));
    client.request(call).map_err(|error| {
        if removing {
            // After handing the mutation to the transport, failure does not
            // prove whether its durable fence or cleanup was committed.
            Failure {
                code: "WORKSPACE_REMOVAL_OUTCOME_UNCERTAIN",
                exit: 7,
            }
        } else {
            map(error)
        }
    })
}
#[cfg(not(any(unix, windows)))]
fn request(_profile: &Path, _call: LocalCall) -> Result<LocalResponse, Failure> {
    Err(Failure::unsupported())
}

#[cfg(target_os = "macos")]
fn macos_identity_failure(code: &'static str) -> Failure {
    match code {
        "MACOS_ADMIN_INSTALL_REQUIRED" => Failure::macos_admin_install_required(),
        "UPDATE_REQUIRED" => Failure::update_required(),
        "LOCAL_PERMISSION_DENIED" => Failure { code, exit: 5 },
        "INVALID_LOCAL_PROFILE" => Failure { code, exit: 5 },
        _ => Failure::unavailable(),
    }
}

struct IpcBackend<'a>(&'a Path, lomi_remote_protocol::HostId);
impl ui::Backend for IpcBackend<'_> {
    fn doctor_report(&mut self) -> Result<lomiremote::diagnostics::DiagnosticReport, &'static str> {
        let profile = self.0;
        Ok(lomiremote::diagnostics::collect(Some(profile), |call| {
            self.request(call)
        }))
    }
    fn diagnostic_profile_path(&self) -> Option<PathBuf> {
        Some(self.0.to_path_buf())
    }
    fn service_status(&mut self) -> Result<ui::operations::ServiceSnapshot, &'static str> {
        let mode = match self.request(LocalCall::SetupStartModeRead {}) {
            Ok(LocalResult::SetupStartMode(preference)) => preference.start_mode,
            _ => lomi_remote_protocol::ipc::LocalStartMode::Manual,
        };
        let operator = match self.request(LocalCall::OperatorSnapshot {}) {
            Ok(LocalResult::OperatorSnapshot(snapshot)) => Some(snapshot),
            _ => None,
        };
        lomiremote::operator::snapshot(self.0, mode, operator.as_ref())
    }
    fn service_action(
        &mut self,
        action: ui::operations::ServiceAction,
    ) -> Result<ui::operations::ServiceSnapshot, &'static str> {
        let mode = match self.request(LocalCall::SetupStartModeRead {}) {
            Ok(LocalResult::SetupStartMode(preference)) => preference.start_mode,
            _ => lomi_remote_protocol::ipc::LocalStartMode::Manual,
        };
        if let Err("LOCAL_HOST_IDENTITY_CHANGED") = self.request(LocalCall::Status {}) {
            return Err("LOCAL_HOST_IDENTITY_CHANGED");
        }
        lomiremote::operator::action(self.0, mode, action, self.1)?;
        self.service_status()
    }
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        request_with_host(self.0, Some(self.1), call)
            .map_err(|failure| failure.code)?
            .result
            .map_err(|_| "LOCAL_REQUEST_REJECTED")
    }
}
fn default_profile() -> Option<PathBuf> {
    lomi_platform::default_profile()
}

fn run_setup_flow(profile: &Path, args: Option<&ArgMatches>) -> u8 {
    use lomiremote::setup::{SetupError, SetupOutcome, SetupProblem};
    let (binding, result) = match lomiremote::setup_entry::run(profile, args) {
        Ok(entry) => (Some(entry.binding), Ok(entry.outcome)),
        Err(error) => (None, Err(error)),
    };
    let interactive = !(args.is_some_and(|args| args.get_flag("non-interactive")))
        && io::stdin().is_terminal()
        && io::stdout().is_terminal();
    match result {
        Ok(SetupOutcome::ExistingConfiguration { host_id }) => {
            let Some(binding) = binding else {
                return 4;
            };
            let host_id = match prepare_dashboard_host(&binding, host_id) {
                Ok(id) => id,
                Err(failure) => return print_failure(failure, false),
            };
            if interactive {
                ui::run(&mut IpcBackend(profile, host_id)).map_or(4, |_| 0)
            } else {
                0
            }
        }
        Ok(SetupOutcome::Complete {
            host_id,
            workspace_id,
            sharing,
        }) => {
            println!(
                "Setup complete.\nHost: {}\nWorkspace: {}\nSharing: {:?}",
                String::from(host_id),
                String::from(workspace_id),
                sharing
            );
            if interactive {
                ui::run(&mut IpcBackend(profile, host_id)).map_or(4, |_| 0)
            } else {
                0
            }
        }
        Ok(SetupOutcome::PendingLogin { .. }) => {
            eprintln!(
                "SETUP_LOGIN_PENDING: the Host continues the device login. Resume with `lomiremote setup`; `lomiremote login code` explicitly reveals the current code."
            );
            3
        }
        Ok(SetupOutcome::Incomplete { stage, problem, .. }) => {
            eprintln!("SETUP_INCOMPLETE: {stage:?}: {problem:?}. Resume with `lomiremote setup`.");
            if matches!(
                problem,
                SetupProblem::ServiceInstallFailed | SetupProblem::ServiceNotReady
            ) {
                eprintln!(
                    "The selected autostart mode is not ready. Check `lomiremote service status` and `lomiremote doctor`; administrator-managed modes require the OS installer for the selected account."
                );
                eprintln!(
                    "For a temporary foreground Host, run `lomiremote daemon run` as the same ordinary account, retaining your --profile-dir selection. Keep that terminal open, then resume setup after repairing the service. Autostart and sharing still require their own setup confirmation."
                );
                #[cfg(target_os = "macos")]
                eprintln!(
                    "Foreground mode also requires the signed administrator Host components for this account. Install those components first if they are unavailable."
                );
            }
            if matches!(
                problem,
                SetupProblem::ShareOutcomeUnknown | SetupProblem::UnshareOutcomeUnknown
            ) {
                7
            } else {
                3
            }
        }
        Err(error) => {
            eprintln!("{error}");
            match error {
                SetupError::InvalidOptions | SetupError::ChoicesRequired => 2,
                SetupError::BindingMismatch
                | SetupError::ProfileRejected
                | SetupError::ChoiceMismatch => 5,
                SetupError::ProtocolMismatch => 6,
                SetupError::InteractionUnavailable => 3,
                _ => 4,
            }
        }
    }
}

fn prepare_dashboard_host(
    binding: &lomiremote::setup::ServiceBinding,
    expected: Option<lomi_remote_protocol::HostId>,
) -> Result<lomi_remote_protocol::HostId, Failure> {
    use lomiremote::setup::SetupHost;
    let mut host = lomiremote::setup_runtime::LocalSetupHost::new(binding.clone());
    let preflight = host
        .preflight(binding)
        .map_err(|_| Failure::unavailable())?;
    if expected
        .zip(preflight.existing_host_id)
        .is_some_and(|(expected, current)| expected != current)
    {
        return Err(Failure {
            code: "LOCAL_HOST_IDENTITY_CHANGED",
            exit: 5,
        });
    }
    host.start_local(binding, expected.or(preflight.existing_host_id))
        .map_err(|error| {
            if error == lomiremote::setup::SetupError::BindingMismatch {
                Failure {
                    code: "LOCAL_HOST_IDENTITY_CHANGED",
                    exit: 5,
                }
            } else {
                Failure::unavailable()
            }
        })?;
    let observation = host.observe(binding).map_err(|_| Failure::unavailable())?;
    Ok(observation.status.host_id)
}
fn print_failure(failure: Failure, json: bool) -> u8 {
    if json {
        let value =
            serde_json::json!({"version":LocalIpcVersion::CURRENT,"error":{"code":failure.code}});
        if serde_json::to_writer(io::stdout().lock(), &value).is_err() {
            return 4;
        }
        println!();
    }
    match failure.code {
        "MACOS_ADMIN_INSTALL_REQUIRED" => eprintln!(
            "{}: install the signed Lomi Remote administrator Host for this account",
            failure.code
        ),
        "UPDATE_REQUIRED" => eprintln!(
            "{}: the running local Host is not the installed signed Lomi Remote Host; run `daemon stop --confirm` with the installed CLI, then retry. This ends Host terminal sessions; private editor drafts remain on this device",
            failure.code
        ),
        "NONROOT_HOST_ACCOUNT_REQUIRED" => eprintln!(
            "{}: select a dedicated non-root operating-system account and run setup as that account; project directories and ownership are preserved",
            failure.code
        ),
        _ => eprintln!("{}", failure.code),
    }
    failure.exit
}
fn local_exit(error: LocalError) -> u8 {
    match error {
        LocalError::InvalidArgument => 2,
        LocalError::PermissionDenied => 5,
        LocalError::VersionMismatch => 6,
        LocalError::Conflict | LocalError::Quarantine | LocalError::NativeBindRejected => 7,
        LocalError::Unavailable => 4,
    }
}
fn run_doctor(profile: &Path, json: bool) -> u8 {
    use lomiremote::diagnostics::{self, DiagnosticRunMode};
    let report = diagnostics::collect(Some(profile), |call| {
        request(profile, call)
            .map_err(|failure| failure.code)?
            .result
            .map_err(|error| match error {
                LocalError::PermissionDenied => "LOCAL_PERMISSION_DENIED",
                LocalError::VersionMismatch => "UPDATE_REQUIRED",
                _ => "DOCTOR_REQUEST_UNAVAILABLE",
            })
    });
    if json {
        if serde_json::to_writer(io::stdout().lock(), &report.redacted_json()).is_err() {
            return 4;
        }
        println!();
    } else {
        println!("Doctor: {:?} observations", report.mode);
        for finding in &report.findings {
            println!(
                "{:?}: {:?} ({:?}) — {:?}",
                finding.check, finding.state, finding.source, finding.guidance
            );
        }
        if let Some(code) = report.last_error {
            println!("Last retained error: {code:?}");
        } else if !report.logs_available {
            println!("Host error log is unavailable.");
        }
        println!(
            "DNS/TLS checks describe recent Host requests. Proxy use is disabled by Host policy. No network probe or repair was run."
        );
    }
    if report.mode == DiagnosticRunMode::Offline {
        4
    } else {
        0
    }
}

fn print_response(response: LocalResponse, json: bool) -> u8 {
    let mut exit = response
        .result
        .as_ref()
        .err()
        .copied()
        .map_or(0, local_exit);
    if matches!(&response.result, Ok(LocalResult::WorkspaceRemovalStatus(status))
        if matches!(status.phase, lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Stopping
            | lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain))
    {
        exit = 7;
    }
    if json {
        if serde_json::to_writer(io::stdout().lock(), &response).is_err() {
            return 4;
        }
        println!();
    } else {
        match response.result {
            Ok(LocalResult::Status(status)) => println!(
                "Host: {}\nHost ID: {}\nRuntime: {}\nSharing: {:?}",
                ui::safe_label(status.host_name.as_str()),
                String::from(status.host_id),
                String::from(status.runtime_id),
                status.sharing
            ),
            Ok(LocalResult::MaintenanceStatus(status)) => println!(
                "Profile schema: {}\nActive terminals: {}\nStop the host before activating an update.",
                status.profile_schema.0, status.active_terminals.0,
            ),
            Ok(LocalResult::Workspaces(workspaces)) => {
                if workspaces.0.is_empty() {
                    println!("No workspaces registered.");
                }
                for workspace in workspaces.0 {
                    println!(
                        "{}  {}  {:?}",
                        String::from(workspace.workspace_id),
                        ui::safe_label(workspace.name.as_str()),
                        workspace.sharing
                    );
                }
            }
            Ok(LocalResult::Workspace(workspace)) => println!(
                "{}  {}  {:?}",
                String::from(workspace.workspace_id),
                ui::safe_label(workspace.name.as_str()),
                workspace.sharing
            ),
            Ok(LocalResult::Removed(id)) => {
                println!("Removed workspace registration: {}", String::from(id))
            }
            Ok(LocalResult::WorkspaceRemovalStatus(status)) => {
                println!(
                    "Workspace: {}\nRemoval: {:?}\nConfirmed session cleanup: {}/{}",
                    String::from(status.workspace_id),
                    status.phase,
                    status.confirmed_sessions.0,
                    status.total_sessions.0
                );
                if matches!(
                    status.phase,
                    lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Stopping
                        | lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain
                ) {
                    println!(
                        "Project files are preserved. Cleanup is not repeated. Query with `lomiremote workspace removal-status {}` using the same --profile-dir, if selected.",
                        String::from(status.workspace_id)
                    );
                }
            }
            Ok(LocalResult::AuthConfigured {}) => println!("Host authentication configured."),
            Ok(LocalResult::LoginAccepted(result)) => println!(
                "Login started: {}\nUse `lomiremote login code` to display the user code.",
                String::from(result.operation_id)
            ),
            Ok(LocalResult::LoginStatus(status)) => println!(
                "Authentication: {:?}\nStorage: {:?}\nNetwork: {:?}\nLocked: {}\nPending cloud revoke: {}",
                status.phase,
                status.storage,
                status.network,
                status.locked,
                status.pending_cloud_revoke
            ),
            Ok(LocalResult::LoginPresentation(presentation)) => println!(
                "Open: {}\nCode: {}\nExpires at: {}",
                presentation.verification_url.as_str(),
                presentation.user_code.expose_wire(),
                presentation.expires_at.0
            ),
            Ok(LocalResult::Doctor(checks)) => {
                for check in checks.0 {
                    println!("{:?}: {:?}", check.check, check.health);
                }
            }
            Ok(_) => {
                eprintln!("UNEXPECTED_LOCAL_RESPONSE");
                return 6;
            }
            Err(error) => eprintln!("{error:?}"),
        }
    }
    exit
}
fn workspace_target(arguments: &ArgMatches) -> Result<LocalWorkspaceTarget, Failure> {
    if !arguments.get_flag("confirm") {
        return Err(Failure {
            code: "CONFIRMATION_REQUIRED",
            exit: 2,
        });
    }
    let id = arguments
        .get_one::<String>("workspace-id")
        .ok_or_else(Failure::arguments)?;
    Ok(LocalWorkspaceTarget {
        workspace_id: WorkspaceId::try_from(id.clone()).map_err(|_| Failure::arguments())?,
        operator_intent: Confirmed::Confirmed,
    })
}
fn call_for(arguments: &ArgMatches) -> Result<(LocalCall, bool), Failure> {
    match arguments.subcommand() {
        Some(("status", args)) => Ok((LocalCall::Status {}, args.get_flag("json"))),
        Some(("doctor", args)) => Ok((LocalCall::Doctor {}, args.get_flag("json"))),
        Some(("maintenance", args)) => match args.subcommand() {
            Some(("prepare", args)) => Ok((
                LocalCall::MaintenancePrepare(LocalOperatorIntent {
                    operator_intent: Confirmed::Confirmed,
                }),
                args.get_flag("json"),
            )),
            _ => Err(Failure::arguments()),
        },
        Some(("auth", auth)) => match auth.subcommand() {
            Some(("configure", args)) => {
                if !args.get_flag("confirm") {
                    return Err(Failure {
                        code: "CONFIRMATION_REQUIRED",
                        exit: 2,
                    });
                }
                if ["origin", "remote-api-origin", "relay-endpoint", "client-id"]
                    .iter()
                    .all(|name| args.get_one::<String>(name).is_none())
                {
                    let configuration = lomiremote::bootstrap::default_auth_configuration(
                        args.get_one::<PathBuf>("keychain-path")
                            .map(PathBuf::as_path),
                        args.get_flag("ack-os-permissions-only"),
                    )
                    .map_err(|_| Failure {
                        code: "HOST_BOOTSTRAP_CONFIGURATION_REQUIRED",
                        exit: 2,
                    })?;
                    if let Some(provider) = args.get_one::<String>("provider") {
                        let expected = match configuration.provider {
                            LocalAuthProvider::ProtectedFile => "protected-file",
                            LocalAuthProvider::MacOsKeychain => "macos-keychain",
                            LocalAuthProvider::WindowsDpapi => "windows-dpapi",
                            LocalAuthProvider::LinuxSecretService => "linux-secret-service",
                        };
                        if provider != expected {
                            return Err(Failure::arguments());
                        }
                    }
                    return Ok((
                        LocalCall::AuthConfigure(LocalAuthConfigure {
                            configuration,
                            operator_intent: Confirmed::Confirmed,
                        }),
                        args.get_flag("json"),
                    ));
                }
                let text = |name| {
                    args.get_one::<String>(name)
                        .cloned()
                        .ok_or_else(Failure::arguments)
                };
                let provider = match text("provider")?.as_str() {
                    "protected-file" => LocalAuthProvider::ProtectedFile,
                    "macos-keychain" => LocalAuthProvider::MacOsKeychain,
                    "windows-dpapi" => LocalAuthProvider::WindowsDpapi,
                    "linux-secret-service" => LocalAuthProvider::LinuxSecretService,
                    _ => return Err(Failure::arguments()),
                };
                let keychain_path = args
                    .get_one::<PathBuf>("keychain-path")
                    .map(|p| {
                        p.to_str()
                            .ok_or_else(Failure::arguments)
                            .and_then(|p| p.to_owned().try_into().map_err(|_| Failure::arguments()))
                    })
                    .transpose()?;
                let configuration = LocalAuthConfiguration {
                    version: 1,
                    origin: text("origin")?
                        .try_into()
                        .map_err(|_| Failure::arguments())?,
                    remote_api_origin: args
                        .get_one::<String>("remote-api-origin")
                        .cloned()
                        .map(TryInto::try_into)
                        .transpose()
                        .map_err(|_| Failure::arguments())?,
                    relay_endpoint: args
                        .get_one::<String>("relay-endpoint")
                        .cloned()
                        .map(TryInto::try_into)
                        .transpose()
                        .map_err(|_| Failure::arguments())?,
                    client_id: text("client-id")?
                        .try_into()
                        .map_err(|_| Failure::arguments())?,
                    provider,
                    keychain_path,
                    protected_file_acknowledgement: args
                        .get_flag("ack-os-permissions-only")
                        .then_some(LocalFileAcknowledgement::OsPermissionsOnly),
                };
                configuration.validate().map_err(|_| Failure::arguments())?;
                Ok((
                    LocalCall::AuthConfigure(LocalAuthConfigure {
                        configuration,
                        operator_intent: Confirmed::Confirmed,
                    }),
                    args.get_flag("json"),
                ))
            }
            _ => Err(Failure::arguments()),
        },
        Some(("login", args)) => match args.subcommand() {
            Some(("status", status)) => Ok((LocalCall::LoginStatus {}, status.get_flag("json"))),
            Some(("code", code)) => Ok((LocalCall::LoginPresentation {}, code.get_flag("json"))),
            None => Ok((
                LocalCall::LoginStart(LocalLoginStart {
                    operation_id: lomi_remote_protocol::OperationId::from_bytes(
                        *uuid::Uuid::new_v4().as_bytes(),
                    )
                    .map_err(|_| Failure::arguments())?,
                }),
                args.get_flag("json"),
            )),
            _ => Err(Failure::arguments()),
        },
        Some(("logout", args)) => {
            if !args.get_flag("confirm") {
                return Err(Failure {
                    code: "CONFIRMATION_REQUIRED",
                    exit: 2,
                });
            }
            Ok((
                LocalCall::Logout(LocalOperatorIntent {
                    operator_intent: Confirmed::Confirmed,
                }),
                args.get_flag("json"),
            ))
        }
        Some(("workspace", workspace)) => match workspace.subcommand() {
            Some(("list", args)) => Ok((LocalCall::Workspaces {}, args.get_flag("json"))),
            Some(("rename", args)) => {
                let target = workspace_target(args)?;
                let text = |name| {
                    args.get_one::<String>(name)
                        .cloned()
                        .ok_or_else(Failure::arguments)?
                        .try_into()
                        .map_err(|_| Failure::arguments())
                };
                Ok((
                    LocalCall::WorkspaceRename(lomi_remote_protocol::ipc::LocalWorkspaceRename {
                        workspace_id: target.workspace_id,
                        expected_name: text("expected-name")?,
                        name: text("name")?,
                        operator_intent: Confirmed::Confirmed,
                    }),
                    args.get_flag("json"),
                ))
            }
            Some(("add", args)) => {
                let name = args
                    .get_one::<String>("name")
                    .ok_or_else(Failure::arguments)?
                    .clone();
                // Relative paths refer to this CLI's working directory, not
                // the independently running daemon's working directory.
                let path = std::path::absolute(
                    args.get_one::<PathBuf>("path")
                        .ok_or_else(Failure::arguments)?,
                )
                .map_err(|_| Failure::arguments())?;
                let path = path.to_str().ok_or_else(Failure::arguments)?.to_owned();
                Ok((
                    LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
                        name: LocalProjectName::try_from(name).map_err(|_| Failure::arguments())?,
                        root_path: LocalRootPath::try_from(path)
                            .map_err(|_| Failure::arguments())?,
                        operator_intent: Confirmed::Confirmed,
                    }),
                    false,
                ))
            }
            Some(("remove", args)) => {
                Ok((LocalCall::WorkspaceRemove(workspace_target(args)?), false))
            }
            Some(("removal-status", args)) => {
                let id = args
                    .get_one::<String>("workspace-id")
                    .ok_or_else(Failure::arguments)?;
                Ok((
                    LocalCall::WorkspaceRemovalStatus(
                        lomi_remote_protocol::ipc::LocalWorkspaceRead {
                            workspace_id: WorkspaceId::try_from(id.clone())
                                .map_err(|_| Failure::arguments())?,
                        },
                    ),
                    args.get_flag("json"),
                ))
            }
            Some(("share", args)) => Ok((LocalCall::Share(workspace_target(args)?), false)),
            Some(("unshare", args)) => Ok((LocalCall::Unshare(workspace_target(args)?), false)),
            _ => Err(Failure::arguments()),
        },
        _ => Err(Failure::unsupported()),
    }
}
fn requested_json(arguments: &ArgMatches) -> bool {
    arguments
        .try_get_one::<bool>("json")
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
        || arguments
            .subcommand()
            .is_some_and(|(_, nested)| requested_json(nested))
}

/// Account selection precedes even resolving the default profile. A root
/// parent never opens a journal/database or becomes the long-lived Host.
fn prepare_setup_account(arguments: &ArgMatches) -> Result<Option<u8>, Failure> {
    use lomi_platform::setup_context as context;
    if arguments
        .subcommand()
        .is_some_and(|(name, _)| name != "setup")
    {
        return Ok(None);
    }
    let options = arguments.subcommand().map(|(_, options)| options);
    let account_name = options.and_then(|options| options.get_one::<String>("account"));
    let current = context::current_account().map_err(|_| Failure::nonroot_account_required())?;
    #[cfg(windows)]
    {
        if options.is_some_and(|options| options.get_flag("create-account")) {
            return Err(Failure::unsupported());
        }
        let requested = account_name
            .map(|name| context::select_windows_account(name))
            .transpose()
            .map_err(|_| Failure::arguments())?;
        let current_sid = current
            .selected()
            .and_then(|account| account.windows())
            .map(|account| account.sid());
        let different = requested
            .as_ref()
            .and_then(|account| account.windows())
            .is_some_and(|account| Some(account.sid()) != current_sid);
        if current.is_root() || different {
            let interactive = io::stdin().is_terminal()
                && io::stdout().is_terminal()
                && !options.is_some_and(|options| options.get_flag("non-interactive"));
            if !interactive {
                return Err(Failure::nonroot_account_required());
            }
            let mut view = lomiremote::setup_view::SetupView::new();
            let mode = match options
                .and_then(|options| options.get_one::<String>("mode"))
                .map(String::as_str)
            {
                Some("manual") => lomi_remote_protocol::ipc::LocalStartMode::Manual,
                Some("login") => lomi_remote_protocol::ipc::LocalStartMode::Login,
                Some("boot") => lomi_remote_protocol::ipc::LocalStartMode::Boot,
                None => view
                    .select_start_mode(lomi_remote_protocol::ipc::LocalStartMode::Manual)
                    .map_err(|_| Failure::arguments())?,
                _ => return Err(Failure::arguments()),
            };
            let selected = match requested {
                Some(account) => account,
                None => {
                    let name = view
                        .select_existing_account_name(None)
                        .map_err(|_| Failure::arguments())?;
                    context::select_windows_account(&name).map_err(|_| Failure {
                        code: "SETUP_ACCOUNT_PROFILE_REQUIRED",
                        exit: 3,
                    })?
                }
            };
            let credential = lomi_platform::windows_password::prompt_logon_credential(
                selected.name(),
            )
            .map_err(|_| Failure {
                code: "SETUP_NATIVE_ACCOUNT_CREDENTIAL_REQUIRED",
                exit: 3,
            })?;
            let mut child_arguments: Vec<_> = env::args_os().skip(1).collect();
            if arguments.subcommand().is_none() {
                child_arguments.push("setup".into());
            }
            if options
                .and_then(|options| options.get_one::<String>("mode"))
                .is_none()
            {
                child_arguments.extend([
                    "--mode".into(),
                    match mode {
                        lomi_remote_protocol::ipc::LocalStartMode::Manual => "manual",
                        lomi_remote_protocol::ipc::LocalStartMode::Login => "login",
                        lomi_remote_protocol::ipc::LocalStartMode::Boot => "boot",
                    }
                    .into(),
                ]);
            }
            if account_name.is_none() {
                child_arguments.extend(["--account".into(), selected.name().into()]);
            }
            let executable = env::current_exe().map_err(|_| Failure::unavailable())?;
            let status = context::reexec_windows_as_selected(
                &selected,
                &credential,
                &executable,
                &child_arguments,
            )
            .map_err(|_| Failure {
                code: "SETUP_SELECTED_ACCOUNT_PROCESS_FAILED",
                exit: 5,
            })?;
            return Ok(Some(
                status
                    .code()
                    .and_then(|code| u8::try_from(code).ok())
                    .unwrap_or(4),
            ));
        }
    }
    if !current.is_root() {
        let selected = current
            .selected()
            .ok_or_else(Failure::nonroot_account_required)?;
        if let Some(name) = account_name {
            #[cfg(unix)]
            {
                let requested =
                    context::select_unix_account(name).map_err(|_| Failure::arguments())?;
                context::validate_selection(&requested)
                    .map_err(|_| Failure::nonroot_account_required())?;
            }
            #[cfg(windows)]
            {
                let requested =
                    context::select_windows_account(name).map_err(|_| Failure::arguments())?;
                if requested.windows().map(|account| account.sid())
                    != selected.windows().map(|account| account.sid())
                {
                    return Err(Failure::nonroot_account_required());
                }
            }
        }
        context::validate_selection(selected).map_err(|_| Failure::nonroot_account_required())?;
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use lomi_remote_protocol::ipc::LocalStartMode;
        let non_interactive = options.is_some_and(|options| options.get_flag("non-interactive"));
        let interactive =
            io::stdin().is_terminal() && io::stdout().is_terminal() && !non_interactive;
        let mut view = lomiremote::setup_view::SetupView::new();
        let mode = match options
            .and_then(|options| options.get_one::<String>("mode"))
            .map(String::as_str)
        {
            Some("manual") => LocalStartMode::Manual,
            Some("login") => LocalStartMode::Login,
            Some("boot") => LocalStartMode::Boot,
            None if interactive => view
                .select_start_mode(LocalStartMode::Manual)
                .map_err(|_| Failure::arguments())?,
            _ => return Err(Failure::nonroot_account_required()),
        };
        let account_name = match account_name {
            Some(name) => name.clone(),
            None if interactive => view
                .select_existing_account_name(None)
                .map_err(|_| Failure::arguments())?,
            None => return Err(Failure::nonroot_account_required()),
        };
        let selected = match context::select_unix_account(&account_name) {
            Ok(selected) => selected,
            #[cfg(target_os = "linux")]
            Err(context::Error::AccountNotFound) => {
                let confirmed = if options.is_some_and(|options| options.get_flag("create-account"))
                {
                    options.is_some_and(|options| options.get_flag("confirm"))
                } else if interactive {
                    view.ask_create_dedicated_account(&account_name)
                        .map_err(|_| Failure::arguments())?
                } else {
                    false
                };
                if !confirmed {
                    return Err(Failure::nonroot_account_required());
                }
                context::create_dedicated_account(
                    &account_name,
                    context::AccountCreationConsent::Confirmed,
                )
                .map_err(|_| Failure {
                    code: "SETUP_ACCOUNT_CREATION_NOT_CONFIRMED",
                    exit: 7,
                })?
            }
            Err(_) => return Err(Failure::nonroot_account_required()),
        };
        context::validate_selection(&selected).map_err(|_| Failure::nonroot_account_required())?;
        let mut child_arguments: Vec<_> = env::args_os()
            .skip(1)
            .filter(|value| value != "--create-account")
            .collect();
        if arguments.subcommand().is_none() {
            child_arguments.push("setup".into());
        }
        if options
            .and_then(|options| options.get_one::<String>("mode"))
            .is_none()
        {
            child_arguments.extend([
                "--mode".into(),
                match mode {
                    LocalStartMode::Manual => "manual",
                    LocalStartMode::Login => "login",
                    LocalStartMode::Boot => "boot",
                }
                .into(),
            ]);
        }
        if options
            .and_then(|options| options.get_one::<String>("account"))
            .is_none()
        {
            child_arguments.extend(["--account".into(), selected.name().into()]);
        }
        let selected_process_failure = |error| match error {
            context::Error::OperationUncertain => Failure {
                code: "SETUP_SELECTED_ACCOUNT_OPERATION_UNCERTAIN",
                exit: 7,
            },
            _ => Failure {
                code: "SETUP_SELECTED_ACCOUNT_PROCESS_FAILED",
                exit: 5,
            },
        };
        #[cfg(not(all(target_os = "linux", feature = "linux-setup-handoff")))]
        let executable = env::current_exe().map_err(|_| Failure::unavailable())?;
        #[cfg(all(target_os = "linux", feature = "linux-setup-handoff"))]
        let status = {
            let install = selected.home().join(".local/lib/lomiremote");
            let stable = install.join("lomiremote");
            let pending = install.join("activation.pending");
            let pending_exists = match std::fs::symlink_metadata(&pending) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => true,
            };
            let stable_exists = match std::fs::symlink_metadata(&stable) {
                Ok(_) => true,
                Err(error) if error.kind() == io::ErrorKind::NotFound => false,
                Err(_) => return Err(Failure::unavailable()),
            };
            if stable_exists && !pending_exists {
                // Execute existing user-owned application code only after the
                // platform helper has dropped every privilege. A live Host's
                // OwnerLock is therefore never disturbed by setup bootstrap.
                context::reexec_as_selected(&selected, &stable, &child_arguments)
            } else {
                context::reexec_sealed_current_as_selected(&selected, &child_arguments)
            }
        }
        .map_err(selected_process_failure)?;
        #[cfg(not(all(target_os = "linux", feature = "linux-setup-handoff")))]
        let status = context::reexec_as_selected(&selected, &executable, &child_arguments)
            .map_err(selected_process_failure)?;
        let code = status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .ok_or(Failure {
                code: "SETUP_SELECTED_ACCOUNT_OPERATION_UNCERTAIN",
                exit: 7,
            })?;
        return Ok(Some(code));
    }
    #[cfg(not(unix))]
    {
        Err(Failure::nonroot_account_required())
    }
}
fn main() -> ExitCode {
    if let Some(code) = lomiremote::maintenance_commands::dispatch_internal() {
        return ExitCode::from(code);
    }
    #[cfg(all(target_os = "linux", feature = "linux-setup-handoff"))]
    if let Some(code) = lomiremote::linux_selected_install::dispatch() {
        return code;
    }
    let maintenance_entry = is_maintenance_entry();
    if !maintenance_entry
        && let Err(error) = lomi_platform::installation::check_current_executable()
    {
        eprintln!("{error}");
        return ExitCode::from(4);
    }
    if let Some(code) = lomi_host::internal_native_entry() {
        return ExitCode::from(code as u8);
    }
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-git-worker")) {
        return ExitCode::from(if env::args_os().nth(2).is_none() {
            lomi_host::internal_git_worker() as u8
        } else {
            2
        });
    }
    #[cfg(target_os = "macos")]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-host-status")) {
        let mut args = env::args_os().skip(2);
        let (Some(profile), Some(pid), None) = (args.next(), args.next(), args.next()) else {
            return ExitCode::from(2);
        };
        let Some(pid) = pid
            .to_str()
            .and_then(|value| value.parse::<u32>().ok())
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u32)
        else {
            return ExitCode::from(2);
        };
        return ExitCode::from(lomi_platform::service_macos::internal_host_status(
            Path::new(&profile),
            pid,
        ) as u8);
    }
    #[cfg(target_os = "macos")]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-keychain-helper"))
    {
        return ExitCode::from(if env::args_os().nth(2).is_none() {
            lomi_platform::unix::keychain::internal_helper() as u8
        } else {
            2
        });
    }
    #[cfg(windows)]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-scm")) {
        let mut args = env::args_os().skip(2);
        let (Some(name), Some(profile), None) = (args.next(), args.next(), args.next()) else {
            return ExitCode::from(2);
        };
        return ExitCode::from(
            if lomi_host::windows_service::dispatch(name, PathBuf::from(profile)).is_ok() {
                0
            } else {
                4
            },
        );
    }
    #[cfg(windows)]
    if env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--internal-file-security-broker"))
    {
        let mut args = env::args_os().skip(2);
        let (Some(owner_sid), Some(installation_id), None) =
            (args.next(), args.next(), args.next())
        else {
            return ExitCode::from(2);
        };
        let (Some(owner_sid), Some(installation_id)) =
            (owner_sid.to_str(), installation_id.to_str())
        else {
            return ExitCode::from(2);
        };
        return ExitCode::from(
            if lomi_platform::windows::file_security_service::dispatch(
                owner_sid.to_owned(),
                installation_id.to_owned(),
            )
            .is_ok()
            {
                0
            } else {
                4
            },
        );
    }
    #[cfg(unix)]
    if lomi_platform::process::initialize_child_ownership().is_err() {
        eprintln!("CHILD_OWNERSHIP_UNAVAILABLE");
        return ExitCode::from(4);
    }
    #[cfg(target_os = "macos")]
    if let Some(mode) = env::args_os().nth(1)
        && matches!(
            mode.to_str(),
            Some(
                "--internal-privileged-pty-broker"
                    | "--internal-privileged-pty-controller"
                    | "--internal-privileged-pty-child"
                    | "--internal-privileged-pty-admin-status"
                    | "--internal-privileged-pty-admin-drain"
            )
        )
    {
        let mut args = env::args_os().skip(2);
        if mode == "--internal-privileged-pty-child" {
            if args.next().as_deref() != Some(std::ffi::OsStr::new("3")) || args.next().is_some() {
                return ExitCode::from(2);
            }
            return ExitCode::from(lomi_terminal::run_internal_privileged_pty_child(3) as u8);
        }
        let Some(registration) = args.next() else {
            return ExitCode::from(2);
        };
        let registration = std::path::Path::new(&registration);
        if mode == "--internal-privileged-pty-controller" {
            let Some(generation) = args.next() else {
                return ExitCode::from(2);
            };
            if args.next().is_some() {
                return ExitCode::from(2);
            }
            return ExitCode::from(lomi_terminal::run_internal_privileged_pty_controller(
                registration,
                std::path::Path::new(&generation),
            ) as u8);
        }
        if args.next().is_some() {
            return ExitCode::from(2);
        }
        return ExitCode::from(if mode == "--internal-privileged-pty-broker" {
            lomi_terminal::run_internal_privileged_pty_broker(registration)
        } else {
            lomi_terminal::run_internal_privileged_pty_admin(
                registration,
                mode == "--internal-privileged-pty-admin-drain",
            )
        } as u8);
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    if env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--internal-pty-coalition-protocol"))
    {
        let mut args = env::args_os().skip(2);
        if args.next().as_deref() != Some(std::ffi::OsStr::new("3")) || args.next().is_some() {
            return ExitCode::from(2);
        }
        return ExitCode::from(lomi_terminal::internal_pty_coalition_protocol(3) as u8);
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    if let Some(mode) = env::args_os().nth(1)
        && (mode == "--internal-pty-coalition" || mode == "--internal-pty-coalition-recover")
    {
        let Some(directory) = env::args_os().nth(2) else {
            return ExitCode::from(2);
        };
        if env::args_os().nth(3).is_some() {
            return ExitCode::from(2);
        }
        let directory = std::path::Path::new(&directory);
        return if mode == "--internal-pty-coalition" {
            ExitCode::from(lomi_terminal::internal_pty_coalition(directory) as u8)
        } else {
            ExitCode::from(
                if lomi_terminal::internal_pty_coalition_recover(directory).is_ok() {
                    0
                } else {
                    4
                },
            )
        };
    }
    #[cfg(unix)]
    if env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-pty-worker")) {
        return ExitCode::from(lomi_terminal::internal_pty_worker() as u8);
    }
    #[cfg(windows)]
    if env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--internal-public-update-root"))
    {
        if env::args_os().nth(2).is_some() {
            return ExitCode::from(2);
        }
        return match lomi_update_trust::embedded_root_sha256() {
            Ok(pin) => {
                println!("{pin}");
                ExitCode::SUCCESS
            }
            Err(_) => ExitCode::from(4),
        };
    }
    if env::args_os().nth(1).as_deref()
        == Some(std::ffi::OsStr::new("--internal-initialize-profile"))
    {
        let mut arguments = env::args_os().skip(2);
        let (Some(profile), None) = (arguments.next(), arguments.next()) else {
            return ExitCode::from(2);
        };
        return ExitCode::from(match lomi_host::initialize_profile(Path::new(&profile)) {
            Ok(_) => 0,
            Err(lomi_host::HostError::NonRootAccountRequired) => 3,
            Err(_) => 4,
        });
    }
    ExitCode::from(run())
}

fn is_maintenance_entry() -> bool {
    let mut args = env::args_os().skip(1);
    while let Some(argument) = args.next() {
        if argument == "--profile-dir" {
            let _ = args.next();
            continue;
        }
        if argument.to_string_lossy().starts_with("--profile-dir=") {
            continue;
        }
        if argument.to_string_lossy().starts_with('-') {
            continue;
        }
        if matches!(argument.to_str(), Some("update" | "uninstall")) {
            return true;
        }
        if argument == "maintenance" {
            return args.next().is_some_and(|subcommand| subcommand == "status");
        }
        return false;
    }
    false
}
fn run() -> u8 {
    let arguments = match cli::command().try_get_matches() {
        Ok(args) => args,
        Err(error) => {
            let exit = if error.use_stderr() { 2 } else { 0 };
            let _ = error.print();
            return exit;
        }
    };
    if arguments.subcommand_name() == Some("version") {
        if arguments
            .subcommand()
            .is_some_and(|(_, args)| args.get_flag("json"))
        {
            let metadata = serde_json::json!({
                "programVersion": env!("CARGO_PKG_VERSION"),
                "profileSchema": lomi_host::PROFILE_SCHEMA_VERSION,
            });
            if serde_json::to_writer(io::stdout().lock(), &metadata).is_err() {
                return 4;
            }
            println!();
            return 0;
        }
        println!("lomiremote {}", env!("CARGO_PKG_VERSION"));
        return 0;
    }
    if arguments.subcommand().is_none()
        && !(io::stdin().is_terminal() && io::stdout().is_terminal())
    {
        let _ = cli::command().write_long_help(&mut io::stderr().lock());
        eprintln!();
        return 2;
    }
    match prepare_setup_account(&arguments) {
        Ok(Some(exit)) => return exit,
        Ok(None) => {}
        Err(failure) => return print_failure(failure, false),
    }
    let json = requested_json(&arguments);
    let explicit_profile = arguments.get_one::<PathBuf>("profile-dir").cloned();
    #[cfg(target_os = "macos")]
    let selected_service_profile = if explicit_profile.is_none() {
        match arguments
            .subcommand()
            .filter(|(name, _)| *name == "service")
            .and_then(|(_, service)| service.subcommand())
            .filter(|(name, _)| *name != "file-security")
            .and_then(|(_, options)| {
                let mode = options.try_get_one::<String>("mode").ok().flatten()?;
                let account = options.try_get_one::<String>("account").ok().flatten()?;
                (mode == "boot"
                    || (lomi_platform::service_macos::is_administrator()
                        && matches!(mode.as_str(), "manual" | "login")))
                .then_some(account)
            }) {
            Some(account) => {
                match lomi_platform::service_macos::boot_profile_path_for_account(account) {
                    Ok(profile) => Some(profile),
                    Err(_) => {
                        return print_failure(
                            Failure {
                                code: "SERVICE_INVALID_CONFIGURATION",
                                exit: 2,
                            },
                            json,
                        );
                    }
                }
            }
            None => None,
        }
    } else {
        None
    };
    #[cfg(not(target_os = "macos"))]
    let selected_service_profile = None;
    let profile = match explicit_profile
        .or(selected_service_profile)
        .or_else(default_profile)
    {
        Some(path) => path,
        None => {
            return print_failure(
                Failure {
                    code: "PROFILE_DIRECTORY_REQUIRED",
                    exit: 3,
                },
                json,
            );
        }
    };
    if arguments.subcommand().is_none() {
        return run_setup_flow(&profile, None);
    }
    if let Some(("setup", args)) = arguments.subcommand() {
        return run_setup_flow(&profile, Some(args));
    }
    if let Some((name, args)) = arguments.subcommand()
        && (matches!(name, "update" | "uninstall")
            || (name == "maintenance" && args.subcommand_name() == Some("status")))
    {
        return lomiremote::maintenance_commands::run(&profile, name, args);
    }
    if let Some(("daemon", args)) = arguments.subcommand() {
        let result = match args.subcommand_name() {
            Some("run") => {
                #[cfg(target_os = "macos")]
                if let Err(error) = verify_macos_daemon_executable(&profile) {
                    return print_failure(error, false);
                }
                match args
                    .subcommand()
                    .unwrap()
                    .1
                    .get_one::<String>("expected-host-id")
                {
                    Some(id) => match lomi_remote_protocol::HostId::try_from(id.clone()) {
                        Ok(id) => lomi_host::run_bound(&profile, id),
                        Err(_) => return print_failure(Failure::arguments(), false),
                    },
                    None if args.subcommand().unwrap().1.get_flag("existing-profile") => {
                        lomi_host::run_existing(&profile)
                    }
                    None => lomi_host::run(&profile),
                }
            }
            Some("start") => {
                #[cfg(target_os = "macos")]
                {
                    return match ensure_host(&profile) {
                        Ok(()) => {
                            println!("Host ready.");
                            0
                        }
                        Err(error) => print_failure(error, false),
                    };
                }
                #[cfg(not(target_os = "macos"))]
                {
                    match env::current_exe() {
                        Ok(executable) => lomi_host::start(&executable, &profile),
                        Err(_) => return print_failure(Failure::unavailable(), false),
                    }
                }
            }
            Some("stop") => {
                if !args.subcommand().unwrap().1.get_flag("confirm") {
                    return print_failure(
                        Failure {
                            code: "CONFIRMATION_REQUIRED",
                            exit: 2,
                        },
                        false,
                    );
                }
                lomi_host::stop(&profile)
            }
            _ => return print_failure(Failure::arguments(), false),
        };
        return match result {
            Ok(()) => {
                if args.subcommand_name() != Some("run") {
                    println!(
                        "Host {}.",
                        if args.subcommand_name() == Some("stop") {
                            "stopped"
                        } else {
                            "ready"
                        }
                    );
                }
                0
            }
            Err(error) => {
                if error == lomi_host::HostError::NonRootAccountRequired {
                    return print_failure(Failure::nonroot_account_required(), false);
                }
                eprintln!("{error}");
                match error {
                    lomi_host::HostError::InvalidProfile => 5,
                    lomi_host::HostError::Unsupported => 3,
                    lomi_host::HostError::Cleanup => 7,
                    _ => 4,
                }
            }
        };
    }
    if let Some(("service", args)) = arguments.subcommand() {
        return lomiremote::service::run(&profile, args);
    }
    if let Some(("git-credentials", args)) = arguments.subcommand() {
        return lomiremote::git_credentials::run(&profile, args);
    }
    if let Some(("terminal", args)) = arguments.subcommand() {
        return lomiremote::terminal_commands::run(&profile, args);
    }
    if let Some(("doctor", args)) = arguments.subcommand() {
        return run_doctor(&profile, args.get_flag("json"));
    }
    if let Some(("logs", args)) = arguments.subcommand() {
        return lomiremote::logs::run(&profile, args.get_flag("follow"), args.get_flag("json"));
    }
    let (call, json) = match call_for(&arguments) {
        Ok(value) => value,
        Err(error) => return print_failure(error, json),
    };
    if matches!(
        &call,
        LocalCall::AuthConfigure(_) | LocalCall::LoginStart(_)
    ) {
        if let Err(error) = ensure_host(&profile) {
            return print_failure(error, json);
        }
    }
    let removal_target = match &call {
        LocalCall::WorkspaceRemove(target) => Some(target.workspace_id),
        _ => None,
    };
    match request(&profile, call) {
        Ok(response) => print_response(response, json),
        Err(error) => {
            if error.exit == 7 {
                if let Some(workspace_id) = removal_target {
                    eprintln!(
                        "Cleanup was not repeated. Check `lomiremote workspace removal-status {}` using the same --profile-dir, if selected.",
                        String::from(workspace_id)
                    );
                }
            }
            print_failure(error, json)
        }
    }
}

#[cfg(target_os = "macos")]
fn ensure_host(profile: &Path) -> Result<(), Failure> {
    lomi_platform::service_macos::custody::prepare_current_user_host_profile(profile)
        .map_err(|_| Failure::macos_admin_install_required())?;
    let executable =
        lomi_platform::service_macos::custody::installed_privileged_host_executable(profile)
            .map_err(|_| Failure::macos_admin_install_required())?;
    match lomiremote::terminal_commands::connect_installed_macos_host(profile)
        .map_err(macos_identity_failure)
    {
        Ok(_) => Ok(()),
        Err(failure) if failure.code == "DAEMON_UNAVAILABLE" => {
            lomi_host::start(&executable, profile).map_err(|_| Failure::unavailable())?;
            lomiremote::terminal_commands::connect_installed_macos_host(profile)
                .map(|_| ())
                .map_err(macos_identity_failure)
        }
        Err(failure) => Err(failure),
    }
}

#[cfg(not(target_os = "macos"))]
fn ensure_host(profile: &Path) -> Result<(), Failure> {
    let executable = env::current_exe().map_err(|_| Failure::unavailable())?;
    lomi_host::start(&executable, profile).map_err(|error| {
        if error == lomi_host::HostError::NonRootAccountRequired {
            Failure::nonroot_account_required()
        } else {
            Failure::unavailable()
        }
    })
}

#[cfg(target_os = "macos")]
fn verify_macos_daemon_executable(profile: &Path) -> Result<(), Failure> {
    let installed =
        lomi_platform::service_macos::custody::installed_privileged_host_executable(profile)
            .map_err(|_| Failure::macos_admin_install_required())?;
    let current = env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| Failure::macos_admin_install_required())?;
    if current != installed {
        return Err(Failure::macos_admin_install_required());
    }
    Ok(())
}
