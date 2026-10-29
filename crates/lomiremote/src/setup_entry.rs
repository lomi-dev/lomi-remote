//! Selected-account entrypoint for the resumable first-run setup flow.
//!
//! Account selection and any privileged account transition happen before this
//! module is called. This adapter resolves the exact native binding, prepares
//! only that account's private profile, then delegates all setup effects and
//! recovery ordering to [`crate::setup`].

use crate::{bootstrap, setup, setup_runtime, setup_view::SetupView};
use clap::ArgMatches;
use lomi_platform::{
    diagnostics as native_diagnostics, service_observation as native,
    setup_journal::SetupJournalStore,
};
use lomi_remote_protocol::{
    WorkspaceId,
    ipc::{
        LocalAuthConfiguration, LocalAuthPhase, LocalCall, LocalHostName, LocalLoginPresentation,
        LocalProcessArgument, LocalProjectName, LocalResult, LocalRootPath, LocalStartMode,
    },
    rpc::BoundedList,
};
use std::{
    io,
    path::{Component, Path, PathBuf},
};

const PATH_LIMIT: usize = 4096;
const SHELL_ARGUMENT_COUNT_LIMIT: usize = 32;
const SHELL_ARGUMENT_BYTES_LIMIT: usize = 8192;

/// Result returned to the CLI/dashboard after one bounded setup turn.
pub struct EntryOutcome {
    /// Exact selected-account service binding for any follow-up Host startup.
    pub binding: setup::ServiceBinding,
    pub outcome: setup::SetupOutcome,
}

/// Run the setup wizard or a fully specified headless setup turn in the
/// already-selected ordinary account.
pub fn run(profile: &Path, args: Option<&ArgMatches>) -> Result<EntryOutcome, setup::SetupError> {
    let account = native::current_account().map_err(map_service_error)?;
    reject_root_account(&account)?;
    validate_profile_input(profile)?;
    validate_optional_account_arg(args, &account)?;

    let non_interactive = args.is_some_and(|matches| matches.get_flag("non-interactive"));
    let requested_mode = parse_optional_mode(args)?;
    let executable_hint = current_executable_hint()?;
    let mut view = SetupView::new();
    let host_name_override = optional_host_name(args)?;
    if !non_interactive {
        view.set_host_name_override(host_name_override.clone());
    }
    let profile_exists = profile_exists_as_directory(profile)?;
    if non_interactive && requested_mode.is_none() && !profile_exists {
        return Err(setup::SetupError::InvalidOptions);
    }

    // Existing registrations are authoritative. Route completed/configured
    // profiles before opening mode or first-run choice prompts.
    let (selected_mode, existing_native_binding) = if profile_exists {
        let canonical = canonical_profile(profile)?;
        let discovered =
            resolve_native_binding(&canonical, &executable_hint, LocalStartMode::Manual)?;
        let observed = native::inspect(&discovered);
        if observed.binding != native::BindingState::Matches {
            return Err(setup::SetupError::BindingMismatch);
        }
        match observed.registration {
            native::RegistrationState::Present => {
                let actual_mode = local_mode(discovered.mode);
                if requested_mode.is_some_and(|requested| requested != actual_mode) {
                    return Err(setup::SetupError::BindingMismatch);
                }
                if let Some(routed) =
                    route_existing_dashboard(setup_binding(discovered.clone()), requested_mode)?
                {
                    return Ok(routed);
                }
                (actual_mode, Some(discovered))
            }
            native::RegistrationState::Missing => {
                if let Some(routed) =
                    route_existing_dashboard(setup_binding(discovered.clone()), requested_mode)?
                {
                    return Ok(routed);
                }
                let selected = select_mode(requested_mode, non_interactive, &mut view)?;
                (selected, None)
            }
            native::RegistrationState::Invalid | native::RegistrationState::Unavailable => {
                return Err(setup::SetupError::BindingMismatch);
            }
        }
    } else {
        let selected = select_mode(requested_mode, non_interactive, &mut view)?;
        (selected, None)
    };

    if non_interactive {
        let args = args.ok_or(setup::SetupError::InvalidOptions)?;
        if !args.get_flag("confirm") || requested_mode.is_none() {
            return Err(setup::SetupError::InvalidOptions);
        }
        required_text(args, "account")?;
    }

    prepare_profile(profile)?;
    let canonical_profile = canonical_profile(profile)?;

    // Re-resolve after profile preparation. The native resolver returns the
    // protected installed CLI/helper when a registration exists; it is never
    // replaced by a GUI or arbitrary current executable on macOS.
    let native_binding =
        resolve_native_binding(&canonical_profile, &executable_hint, selected_mode)?;
    if local_mode(native_binding.mode) != selected_mode
        || !same_native_account(&native_binding.account, &account)
        || native_binding.profile != canonical_profile
    {
        return Err(setup::SetupError::BindingMismatch);
    }

    let final_observation = native::inspect(&native_binding);
    if final_observation.binding != native::BindingState::Matches
        || final_observation.registration
            != if existing_native_binding.is_some() {
                native::RegistrationState::Present
            } else {
                native::RegistrationState::Missing
            }
    {
        // Do not adopt a service registration that appeared during profile
        // preparation, or continue after one disappeared.
        return Err(setup::SetupError::BindingMismatch);
    }

    if let Some(previous) = existing_native_binding.as_ref() {
        if previous.mode != native_binding.mode
            || previous.executable != native_binding.executable
            || previous.account != native_binding.account
        {
            return Err(setup::SetupError::BindingMismatch);
        }
    }

    let binding = setup_binding(native_binding);
    if let Some(routed) = route_existing_dashboard(binding.clone(), requested_mode)? {
        return Ok(routed);
    }
    let mut host = setup_runtime::LocalSetupHost::new(binding.clone());
    let mut service = setup_runtime::NativeSetupService;
    let choices = if non_interactive {
        Some(non_interactive_choices(
            args.ok_or(setup::SetupError::InvalidOptions)?,
            &binding,
            host_name_override,
        )?)
    } else {
        None
    };

    let mut interaction = if non_interactive {
        // The headless implementation never exposes a one-time device code
        // and never treats a pending login as success.
        SetupInteractionAdapter::Headless(HeadlessInteraction::new(
            args.ok_or(setup::SetupError::InvalidOptions)?,
        ))
    } else {
        SetupInteractionAdapter::Interactive(&mut view)
    };

    let outcome = setup::run(
        setup::SetupOptions {
            binding: binding.clone(),
            choices,
            non_interactive,
        },
        &mut host,
        &mut service,
        &mut interaction,
    )?;
    Ok(EntryOutcome { binding, outcome })
}

fn route_existing_dashboard(
    binding: setup::ServiceBinding,
    requested_mode: Option<LocalStartMode>,
) -> Result<Option<EntryOutcome>, setup::SetupError> {
    let requested_mode_mismatch = requested_mode.is_some_and(|mode| mode != binding.mode);
    let mut service = setup_runtime::NativeSetupService;
    setup::SetupServiceControl::validate_binding(&mut service, &binding)?;
    let mut host = setup_runtime::LocalSetupHost::new(binding.clone());
    let preflight = setup::SetupHost::preflight(&mut host, &binding)?;

    if let Some(host_id) = setup::completed_configuration(&binding)? {
        if requested_mode_mismatch
            || preflight
                .existing_host_id
                .is_some_and(|actual| actual != host_id)
        {
            return Err(setup::SetupError::BindingMismatch);
        }
        return Ok(Some(EntryOutcome {
            binding,
            outcome: setup::SetupOutcome::ExistingConfiguration {
                host_id: Some(host_id),
            },
        }));
    }

    let has_journal = SetupJournalStore::read_existing(&binding.profile_path)
        .map_err(|_| setup::SetupError::JournalUnavailable)?
        .is_some();
    if !has_journal && preflight.existing_configuration {
        if requested_mode_mismatch {
            return Err(setup::SetupError::BindingMismatch);
        }
        return Ok(Some(EntryOutcome {
            binding,
            outcome: setup::SetupOutcome::ExistingConfiguration {
                host_id: preflight.existing_host_id,
            },
        }));
    }
    Ok(None)
}

enum SetupInteractionAdapter<'a> {
    Interactive(&'a mut SetupView),
    Headless(HeadlessInteraction),
}

impl setup::SetupInteraction for SetupInteractionAdapter<'_> {
    fn wait_for_login_update(&mut self) -> Result<bool, setup::SetupError> {
        match self {
            Self::Interactive(view) => view.wait_for_login_update(),
            Self::Headless(_) => Ok(false),
        }
    }

    fn wait_for_publication_update(&mut self) -> Result<bool, setup::SetupError> {
        match self {
            Self::Interactive(view) => view.wait_for_publication_update(),
            Self::Headless(_) => Ok(false),
        }
    }

    fn collect_choices(
        &mut self,
        binding: &setup::ServiceBinding,
        preflight: &setup::HostPreflight,
        progress: Option<&setup::SetupProgress>,
        shells: &[setup::ShellCandidate],
    ) -> Result<setup::SetupChoices, setup::SetupError> {
        match self {
            Self::Interactive(view) => setup::SetupInteraction::collect_choices(
                &mut **view,
                binding,
                preflight,
                progress,
                shells,
            ),
            Self::Headless(_) => Err(setup::SetupError::ChoicesRequired),
        }
    }

    fn confirm_review(&mut self, review: &setup::SetupReview) -> Result<bool, setup::SetupError> {
        match self {
            Self::Interactive(view) => setup::SetupInteraction::confirm_review(&mut **view, review),
            Self::Headless(_) => Ok(true),
        }
    }

    fn confirm_authorization_context_change(&mut self) -> Result<bool, setup::SetupError> {
        match self {
            Self::Interactive(view) => {
                setup::SetupInteraction::confirm_authorization_context_change(&mut **view)
            }
            Self::Headless(interaction) => Ok(interaction.confirm_authorization_context_change),
        }
    }

    fn reveal_login_presentation(&mut self) -> bool {
        match self {
            Self::Interactive(view) => {
                setup::SetupInteraction::reveal_login_presentation(&mut **view)
            }
            Self::Headless(_) => false,
        }
    }

    fn show_login_presentation(&mut self, presentation: &LocalLoginPresentation) {
        if let Self::Interactive(view) = self {
            setup::SetupInteraction::show_login_presentation(&mut **view, presentation);
        }
    }

    fn confirm_renewed_share(
        &mut self,
        workspace_name: &LocalProjectName,
        workspace_id: WorkspaceId,
    ) -> Result<bool, setup::SetupError> {
        match self {
            Self::Interactive(view) => setup::SetupInteraction::confirm_renewed_share(
                &mut **view,
                workspace_name,
                workspace_id,
            ),
            Self::Headless(interaction) => Ok(interaction.renew_share_consent),
        }
    }
}

struct HeadlessInteraction {
    confirm_authorization_context_change: bool,
    renew_share_consent: bool,
}

impl HeadlessInteraction {
    fn new(args: &ArgMatches) -> Self {
        Self {
            confirm_authorization_context_change: args.get_flag("confirm-authorization-change"),
            renew_share_consent: args.get_flag("renew-share-consent"),
        }
    }
}

fn select_mode(
    requested: Option<LocalStartMode>,
    non_interactive: bool,
    view: &mut SetupView,
) -> Result<LocalStartMode, setup::SetupError> {
    if let Some(mode) = requested {
        return Ok(mode);
    }
    if non_interactive {
        // This provisional mode permits a configured, journal-free profile to
        // return to the dashboard. New or resumed setup is rejected before
        // setup::run unless the caller supplied its exact mode.
        return Ok(LocalStartMode::Manual);
    }
    view.select_start_mode(LocalStartMode::Manual)
}

fn parse_optional_mode(
    args: Option<&ArgMatches>,
) -> Result<Option<LocalStartMode>, setup::SetupError> {
    let Some(value) = args.and_then(|matches| matches.get_one::<String>("mode")) else {
        return Ok(None);
    };
    match value.as_str() {
        "manual" => Ok(Some(LocalStartMode::Manual)),
        "login" => Ok(Some(LocalStartMode::Login)),
        "boot" => Ok(Some(LocalStartMode::Boot)),
        _ => Err(setup::SetupError::InvalidOptions),
    }
}

fn validate_optional_account_arg(
    args: Option<&ArgMatches>,
    account: &native::ServiceAccount,
) -> Result<(), setup::SetupError> {
    let Some(requested) = args.and_then(|matches| matches.get_one::<String>("account")) else {
        return Ok(());
    };
    let matches = match account {
        native::ServiceAccount::Unix { uid, name, .. } => {
            requested == name || requested.parse::<u32>().ok() == Some(*uid)
        }
        #[cfg(windows)]
        native::ServiceAccount::Windows { sid, .. } => {
            if requested == sid {
                true
            } else {
                let selected = lomi_platform::setup_context::select_windows_account(requested)
                    .map_err(|_| setup::SetupError::BindingMismatch)?;
                selected
                    .windows()
                    .is_some_and(|selected| selected.sid() == sid)
            }
        }
        #[cfg(not(windows))]
        native::ServiceAccount::Windows { .. } => false,
    };
    if matches {
        Ok(())
    } else {
        Err(setup::SetupError::BindingMismatch)
    }
}

fn reject_root_account(account: &native::ServiceAccount) -> Result<(), setup::SetupError> {
    if matches!(account, native::ServiceAccount::Unix { uid: 0, .. }) {
        return Err(setup::SetupError::BindingMismatch);
    }
    Ok(())
}

fn same_native_account(left: &native::ServiceAccount, right: &native::ServiceAccount) -> bool {
    match (left, right) {
        (
            native::ServiceAccount::Unix {
                uid: left_uid,
                gid: left_gid,
                name: left_name,
            },
            native::ServiceAccount::Unix {
                uid: right_uid,
                gid: right_gid,
                name: right_name,
            },
        ) => left_uid == right_uid && left_gid == right_gid && left_name == right_name,
        (
            native::ServiceAccount::Windows {
                sid: left_sid,
                name: left_name,
            },
            native::ServiceAccount::Windows {
                sid: right_sid,
                name: right_name,
            },
        ) => left_sid == right_sid && left_name == right_name,
        _ => false,
    }
}

fn validate_profile_input(profile: &Path) -> Result<(), setup::SetupError> {
    if !profile.is_absolute()
        || profile == Path::new("/")
        || profile
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
        || profile
            .to_str()
            .is_none_or(|value| value.len() > PATH_LIMIT)
    {
        return Err(setup::SetupError::ProfileRejected);
    }
    Ok(())
}

fn profile_exists_as_directory(profile: &Path) -> Result<bool, setup::SetupError> {
    match profile.symlink_metadata() {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_dir() => {
            Err(setup::SetupError::ProfileRejected)
        }
        Ok(_) => match native_diagnostics::inspect_profile(profile) {
            native_diagnostics::ProfileObservation::Private => Ok(true),
            _ => Err(setup::SetupError::ProfileRejected),
        },
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(setup::SetupError::ProfileRejected),
    }
}

fn canonical_profile(profile: &Path) -> Result<PathBuf, setup::SetupError> {
    let canonical = native_diagnostics::canonical_profile_path(profile)
        .ok_or(setup::SetupError::ProfileRejected)?;
    validate_profile_input(&canonical)?;
    if native_diagnostics::inspect_profile(&canonical)
        != native_diagnostics::ProfileObservation::Private
    {
        return Err(setup::SetupError::ProfileRejected);
    }
    Ok(canonical)
}

fn prepare_profile(profile: &Path) -> Result<(), setup::SetupError> {
    #[cfg(target_os = "macos")]
    lomi_platform::service_macos::custody::prepare_current_user_host_profile(profile)
        .map_err(|_| setup::SetupError::ProfileRejected)?;

    // Opening and dropping the private journal store creates only the selected
    // account's private profile. The coordinator acquires its own journal lock
    // after Host/service preflight and no Host/auth/share state is created here.
    drop(SetupJournalStore::open(profile).map_err(|_| setup::SetupError::JournalUnavailable)?);
    Ok(())
}

fn current_executable_hint() -> Result<PathBuf, setup::SetupError> {
    std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| setup::SetupError::BindingMismatch)
}

fn resolve_native_binding(
    profile: &Path,
    executable_hint: &Path,
    preferred_mode: LocalStartMode,
) -> Result<native::ServiceBinding, setup::SetupError> {
    native::current_binding(profile, executable_hint, native_mode(preferred_mode))
        .map_err(map_service_error)
}

fn map_service_error(error: native::ServiceError) -> setup::SetupError {
    match error {
        native::ServiceError::InvalidBinding => setup::SetupError::ProfileRejected,
        native::ServiceError::Conflict => setup::SetupError::BindingMismatch,
        native::ServiceError::AdministratorRequired | native::ServiceError::Unsupported => {
            setup::SetupError::ServiceUnavailable
        }
        native::ServiceError::ManagerUnavailable
        | native::ServiceError::OperationUncertain
        | native::ServiceError::NotReady
        | native::ServiceError::CredentialsRequired => setup::SetupError::ServiceUnavailable,
    }
}

fn native_mode(mode: LocalStartMode) -> native::ServiceMode {
    match mode {
        LocalStartMode::Manual => native::ServiceMode::Manual,
        LocalStartMode::Login => native::ServiceMode::Login,
        LocalStartMode::Boot => native::ServiceMode::Boot,
    }
}

fn local_mode(mode: native::ServiceMode) -> LocalStartMode {
    match mode {
        native::ServiceMode::Manual => LocalStartMode::Manual,
        native::ServiceMode::Login => LocalStartMode::Login,
        native::ServiceMode::Boot => LocalStartMode::Boot,
    }
}

fn setup_binding(binding: native::ServiceBinding) -> setup::ServiceBinding {
    let (account_name, account) = match binding.account {
        native::ServiceAccount::Unix { uid, gid, name } => {
            (name, setup::SetupAccount::Unix { uid, gid })
        }
        native::ServiceAccount::Windows { sid, name } => {
            (name, setup::SetupAccount::Windows { sid })
        }
    };
    setup::ServiceBinding {
        mode: local_mode(binding.mode),
        account_name,
        account,
        profile_path: binding.profile,
        executable_path: binding.executable,
    }
}

fn non_interactive_choices(
    args: &ArgMatches,
    binding: &setup::ServiceBinding,
    host_name: Option<LocalHostName>,
) -> Result<setup::SetupChoices, setup::SetupError> {
    let workspace_name = required_text(args, "workspace-name")?
        .to_owned()
        .try_into()
        .map_err(|_| setup::SetupError::InvalidOptions)?;
    let workspace_root = args
        .get_one::<PathBuf>("workspace-root")
        .cloned()
        .filter(|path| !path.as_os_str().is_empty())
        .ok_or(setup::SetupError::InvalidOptions)?;
    if !workspace_root.is_absolute()
        || workspace_root
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        || workspace_root
            .to_str()
            .is_none_or(|value| value.len() > PATH_LIMIT)
    {
        return Err(setup::SetupError::InvalidOptions);
    }
    let create_missing_workspace = args.get_flag("create-workspace");
    if !workspace_root.exists() && !create_missing_workspace {
        return Err(setup::SetupError::InvalidOptions);
    }

    let shell_path = args
        .get_one::<PathBuf>("shell")
        .cloned()
        .ok_or(setup::SetupError::InvalidOptions)?;
    if !shell_path.is_absolute()
        || shell_path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
    {
        return Err(setup::SetupError::InvalidOptions);
    }
    let shell_executable: LocalRootPath = shell_path
        .to_str()
        .ok_or(setup::SetupError::InvalidOptions)?
        .to_owned()
        .try_into()
        .map_err(|_| setup::SetupError::InvalidOptions)?;
    let shell_name = args
        .get_one::<String>("shell-name")
        .map(String::as_str)
        .unwrap_or("Shell")
        .to_owned()
        .try_into()
        .map_err(|_| setup::SetupError::InvalidOptions)?;

    let mut shell_args = Vec::new();
    let mut shell_args_bytes = 0usize;
    if let Some(values) = args.get_many::<String>("shell-arg") {
        for value in values {
            if shell_args.len() == SHELL_ARGUMENT_COUNT_LIMIT
                || value.len() > 4096
                || value.chars().any(char::is_control)
            {
                return Err(setup::SetupError::InvalidOptions);
            }
            shell_args_bytes = shell_args_bytes.saturating_add(value.len());
            if shell_args_bytes > SHELL_ARGUMENT_BYTES_LIMIT {
                return Err(setup::SetupError::InvalidOptions);
            }
            shell_args.push(
                LocalProcessArgument::try_from(value.clone())
                    .map_err(|_| setup::SetupError::InvalidOptions)?,
            );
        }
    }

    let share = args.get_flag("share");
    let local_only = args.get_flag("local-only");
    if share == local_only {
        return Err(setup::SetupError::InvalidOptions);
    }
    let renew_share_consent = args.get_flag("renew-share-consent");
    let disable_existing_share = args.get_flag("disable-existing-share");
    if (renew_share_consent && !share) || (disable_existing_share && !local_only) {
        return Err(setup::SetupError::InvalidOptions);
    }

    let auth_configuration = headless_auth_configuration(args, binding)?;
    Ok(setup::SetupChoices {
        host_name,
        auth_configuration,
        workspace_name,
        workspace_root,
        create_missing_workspace,
        shell: setup::SetupShellChoice {
            name: shell_name,
            executable: shell_executable,
            args: BoundedList(shell_args),
            // Headless setup deliberately does not copy or infer environment
            // variables. Interactive setup can collect only its fixed allowlist.
            environment: BoundedList(Vec::new()),
        },
        share_remote: share,
        renew_share_consent,
        disable_existing_share,
    })
}

fn optional_host_name(
    args: Option<&ArgMatches>,
) -> Result<Option<LocalHostName>, setup::SetupError> {
    args.and_then(|args| args.get_one::<String>("host-name"))
        .map(|value| LocalHostName::try_from(value.trim().to_owned()))
        .transpose()
        .map_err(|_| setup::SetupError::InvalidOptions)
}

fn required_text<'a>(args: &'a ArgMatches, name: &str) -> Result<&'a str, setup::SetupError> {
    args.get_one::<String>(name)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(setup::SetupError::InvalidOptions)
}

fn headless_auth_configuration(
    args: &ArgMatches,
    binding: &setup::ServiceBinding,
) -> Result<Option<LocalAuthConfiguration>, setup::SetupError> {
    let existing = auth_configuration_exists(binding)?;
    let keychain_path = args.get_one::<PathBuf>("keychain-path");
    let protected_file_acknowledged = args.get_flag("ack-os-permissions-only");
    if existing == Some(true) {
        if keychain_path.is_some() || protected_file_acknowledged {
            return Err(setup::SetupError::InvalidOptions);
        }
        return Ok(None);
    }

    let Some(_pins) = bootstrap::public_release_pins() else {
        if keychain_path.is_some() || protected_file_acknowledged {
            return Err(setup::SetupError::InvalidOptions);
        }
        return Ok(None);
    };

    let configuration = bootstrap::default_auth_configuration(
        keychain_path.map(PathBuf::as_path),
        protected_file_acknowledged,
    )
    .map_err(|_| setup::SetupError::InvalidOptions)?;
    Ok(Some(configuration))
}

/// `Some(true/false)` is based on the stopped Store or authenticated live IPC.
/// `None` means setup is fenced on recovery and deliberately leaves the choice
/// to the Host's current post-start login status.
fn auth_configuration_exists(
    binding: &setup::ServiceBinding,
) -> Result<Option<bool>, setup::SetupError> {
    match lomi_host::inspect_setup(&binding.profile_path) {
        lomi_host::SetupInspection::Ready(observation) => {
            Ok(Some(observation.auth_configuration.is_some()))
        }
        lomi_host::SetupInspection::MissingDatabase => Ok(Some(false)),
        lomi_host::SetupInspection::OwnerRunning => {
            let mut host = setup_runtime::LocalSetupHost::new(binding.clone());
            let preflight = setup::SetupHost::preflight(&mut host, binding)?;
            if preflight.existing_host_id.is_none() {
                return Err(setup::SetupError::HostUnavailable);
            }
            match setup::SetupHost::request(&mut host, LocalCall::LoginStatus {}) {
                Ok(LocalResult::LoginStatus(status)) => {
                    Ok(Some(status.phase != LocalAuthPhase::Unconfigured))
                }
                _ => Err(setup::SetupError::HostUnavailable),
            }
        }
        lomi_host::SetupInspection::NeedsRecovery => Ok(None),
        lomi_host::SetupInspection::InvalidSchema
        | lomi_host::SetupInspection::MissingIdentity
        | lomi_host::SetupInspection::InvalidIdentity
        | lomi_host::SetupInspection::InvalidConfiguration
        | lomi_host::SetupInspection::Unavailable => Err(setup::SetupError::ProfileRejected),
    }
}
