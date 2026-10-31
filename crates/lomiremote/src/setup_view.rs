//! Full-screen first-run setup prompts.
//!
//! The setup driver owns ordering and persistence. This module only gathers
//! explicit operator choices and always restores the caller's terminal on exit.

use crate::ui::{
    interaction::{Action, Controls},
    pointer::PointerTracker,
    theme,
};
use crate::{bootstrap, setup};
use crossterm::{
    cursor::{Hide, Show},
    event::{
        self, DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
        EnableFocusChange, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyEventKind,
        KeyModifiers, MouseEvent, MouseEventKind,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use lomi_remote_protocol::{
    WorkspaceId,
    ipc::{
        LocalAuthConfiguration, LocalAuthProvider, LocalHostName, LocalProcessArgument,
        LocalProjectName, LocalRootPath, LocalShellEnvironment, LocalShellEnvironmentName,
        LocalStartMode,
    },
    rpc::BoundedList,
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
    layout::{Constraint, Layout, Rect},
    widgets::{Paragraph, Wrap},
};
use std::{
    io::{self, Stdout},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const MIN_COLUMNS: u16 = 80;
const MIN_ROWS: u16 = 24;
const PATH_LIMIT: usize = 4096;
const NAME_LIMIT: usize = 255;
const ARGUMENT_LIMIT: usize = 4096;
const ARGUMENTS_TOTAL_LIMIT: usize = 8192;
const ENVIRONMENT_VALUE_LIMIT: usize = 256;
const SHELL_CANDIDATE_LIMIT: usize = 64;
const INPUT_FIELD_ACTION: usize = usize::MAX;

/// A small, synchronous UI adapter for the resumable setup driver.
///
/// No state in this object is persisted. The setup journal intentionally omits
/// shell arguments and environment values, so they are collected again when a
/// setup is resumed.
#[derive(Default)]
pub struct SetupView {
    login_reveal_handled: bool,
    login_reveal_authorized: bool,
    host_name_override: Option<LocalHostName>,
}

impl SetupView {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_host_name_override(&mut self, name: Option<LocalHostName>) {
        self.host_name_override = name;
    }

    fn collect_host_name(
        &mut self,
        preflight: &setup::HostPreflight,
        progress: Option<&setup::SetupProgress>,
    ) -> Result<LocalHostName, setup::SetupError> {
        let default = self
            .host_name_override
            .take()
            .map(String::from)
            .or_else(|| progress.and_then(|progress| progress.host_name.clone()))
            .unwrap_or_else(|| preflight.suggested_host_name.as_str().to_owned());
        loop {
            let Some(value) = input_line(
                "Name this Host",
                "Choose a local display name for this Host. This label stays in the local profile and is not sent to Remote.",
                &default,
                NAME_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            match LocalHostName::try_from(value.trim().to_owned()) {
                Ok(name) => return Ok(name),
                Err(_) => {
                    notice("Host name is required, control-free, and at most 255 UTF-8 bytes.")?
                }
            }
        }
    }

    /// Choose a service mode before setup opens the profile or starts a Host.
    /// This prompt records no preference and performs no service operation.
    pub fn select_start_mode(
        &mut self,
        current_preference: LocalStartMode,
    ) -> Result<LocalStartMode, setup::SetupError> {
        #[cfg(target_os = "linux")]
        let mechanism = "Manual has no autostart. Login uses systemd --user and can stop at logout. Boot uses the same user manager and requires an administrator to enable lingering first; setup does not enable it.";
        #[cfg(target_os = "macos")]
        let mechanism = "All modes require the signed administrator-installed Host and terminal custodian. Login uses a LaunchAgent; Boot uses a LaunchDaemon. FileVault-protected files remain unavailable until the disk is unlocked.";
        #[cfg(windows)]
        let mechanism = "Manual has no autostart. Login uses Task Scheduler while the account is logged in. Boot uses an administrator-installed SCM service with explicit account credentials and does not need an interactive logon.";
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        let mechanism =
            "Autostart must be supported by this operating system before setup can enable it.";
        let account = match lomi_platform::service_observation::current_account() {
            Ok(lomi_platform::service_observation::ServiceAccount::Unix { uid, name, .. })
                if uid != 0 =>
            {
                format!("The Host runs as {name}.")
            }
            Ok(lomi_platform::service_observation::ServiceAccount::Windows { name, .. }) => {
                format!("The Host runs as {name}.")
            }
            _ => "Select an ordinary operating-system account in the next step.".to_owned(),
        };
        let explanation =
            format!("{account} {mechanism} This choice does not install or start a service.");
        let modes = [
            (
                "Manual — start the Host only when requested",
                LocalStartMode::Manual,
            ),
            (
                "Login — start after this account logs in",
                LocalStartMode::Login,
            ),
            (
                "Boot — start before interactive login when supported",
                LocalStartMode::Boot,
            ),
        ];
        let selected = modes
            .iter()
            .position(|(_, mode)| *mode == current_preference)
            .unwrap_or(0);
        let Some(index) = choose_index(
            "Choose Host start mode",
            &explanation,
            &modes.iter().map(|(label, _)| *label).collect::<Vec<_>>(),
            selected,
        )?
        else {
            return Ok(current_preference);
        };
        modes
            .get(index)
            .map(|(_, mode)| *mode)
            .ok_or(setup::SetupError::InteractionUnavailable)
    }

    /// Ask for the name of an already-existing operating-system account.
    /// This only gathers text; account creation, switching, and filesystem
    /// ownership changes are deliberately outside this UI.
    pub fn select_existing_account_name(
        &mut self,
        suggested: Option<&str>,
    ) -> Result<String, setup::SetupError> {
        loop {
            let Some(name) = input_line(
                "Select an existing service account",
                "Enter the exact name of an account that already exists. This prompt does not create or modify accounts.",
                suggested.unwrap_or_default(),
                NAME_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            let name = name.trim();
            if !name.is_empty() && name.len() <= NAME_LIMIT && !has_terminal_controls(name) {
                return Ok(name.to_owned());
            }
            notice("Account name is required and must be at most 255 UTF-8 bytes.")?;
        }
    }

    /// Confirm the requested dedicated-account creation intent. This UI only
    /// asks; OS account and filesystem changes belong to the native adapter.
    pub fn ask_create_dedicated_account(&mut self, name: &str) -> Result<bool, setup::SetupError> {
        if name.is_empty() || name.len() > NAME_LIMIT || has_terminal_controls(name) {
            return Err(setup::SetupError::InvalidOptions);
        }
        Ok(confirm(
            "Confirm dedicated service account",
            &format!(
                "Request creation of the dedicated non-root account {}? This prompt does not create the account. Project directories will not be moved and existing ownership will not be changed.",
                display(name, NAME_LIMIT),
            ),
            false,
        )?
        .unwrap_or(false))
    }

    fn collect_auth_configuration(
        &mut self,
        progress: Option<&setup::SetupProgress>,
    ) -> Result<Option<LocalAuthConfiguration>, setup::SetupError> {
        if progress.is_some_and(|progress| progress.auth_generation.is_some()) {
            return Ok(None);
        }
        let Some(pins) = bootstrap::public_release_pins() else {
            let Some(choice) = choose_index(
                "Authentication is not configured in this build",
                "No public release endpoints are embedded. Setup can preserve a local draft, but Remote login and sharing remain unavailable until a trusted configuration is provided.",
                &["Continue with a local setup draft", "Cancel setup"],
                1,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            return if choice == 0 {
                Ok(None)
            } else {
                Err(setup::SetupError::InteractionUnavailable)
            };
        };

        let provider = bootstrap::native_provider();
        if provider == bootstrap::NativeProvider::Unsupported {
            notice(
                "No native credential-storage provider is available for this operating system.",
            )?;
            return Ok(None);
        }
        let keychain_path = if provider == bootstrap::NativeProvider::MacOsKeychainPathRequired {
            loop {
                let Some(path) = input_line(
                    "Choose authentication storage",
                    "Enter an existing canonical macOS file Keychain path. Lomi will not create or unlock it. Public endpoint pins are shown on the next confirmation screen.",
                    "",
                    PATH_LIMIT,
                    false,
                )?
                else {
                    return Err(setup::SetupError::InteractionUnavailable);
                };
                let path = PathBuf::from(path.trim());
                if path.is_absolute()
                    && path.to_str().is_some()
                    && path.to_str().is_some_and(|text| text.len() <= PATH_LIMIT)
                    && !has_terminal_controls(path.to_str().unwrap_or_default())
                    && path.canonicalize().ok().as_deref() == Some(path.as_path())
                    && path.is_file()
                {
                    break Some(path);
                }
                notice("Enter an existing canonical absolute Keychain file path.")?;
            }
        } else {
            None
        };

        let mut protected_file_acknowledged = false;
        if provider == bootstrap::NativeProvider::LinuxStorageChoiceRequired {
            let Some(choice) = choose_index(
                "Choose Linux authentication storage",
                "Secret Service requires an already available and unlocked OS keyring. Lomi will not unlock it or switch providers automatically.",
                &[
                    "Secret Service — use this account's unlocked OS keyring",
                    "Protected file — store credentials with OS permissions only",
                ],
                0,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            if choice == 1 {
                let Some(accepted) = confirm(
                    "Confirm protected-file authentication storage",
                    "This provider stores credentials in a file protected by OS permissions only. Administrators and disk backups can read it. Lomi will not fall back to this provider automatically.",
                    false,
                )?
                else {
                    return Err(setup::SetupError::InteractionUnavailable);
                };
                if !accepted {
                    return Ok(None);
                }
                protected_file_acknowledged = true;
            }
        }

        let configuration = bootstrap::default_auth_configuration(
            keychain_path.as_deref(),
            protected_file_acknowledged,
        )
        .map_err(|_| setup::SetupError::InvalidOptions)?;
        let provider_name = match configuration.provider {
            LocalAuthProvider::ProtectedFile => "Linux protected file (OS permissions only)",
            LocalAuthProvider::MacOsKeychain => "macOS Keychain",
            LocalAuthProvider::WindowsDpapi => "Windows DPAPI for this account",
            LocalAuthProvider::LinuxSecretService => {
                "Linux Secret Service (unlocked keyring for this account)"
            }
        };
        let keychain_display = configuration
            .keychain_path
            .as_ref()
            .map(|path| format!("\nKeychain file: {}", display(path.as_str(), PATH_LIMIT)))
            .unwrap_or_default();
        let Some(accepted) = confirm_scrolled(
            "Confirm public authentication configuration",
            &format!(
                "Provider: {provider_name}{keychain_display}\nIdentity origin: {}\nRemote API: {}\nRelay: {}\nPublic client ID: {}\n\nThese are public endpoint pins. Access and refresh credentials are not part of this configuration.",
                display(pins.identity_origin, 1024),
                display(pins.remote_api_origin, 1024),
                display(pins.relay_endpoint, 1024),
                display(pins.client_id, 1024),
            ),
            true,
        )?
        else {
            return Err(setup::SetupError::InteractionUnavailable);
        };
        if accepted {
            Ok(Some(configuration))
        } else {
            Ok(None)
        }
    }

    fn collect_workspace(
        &mut self,
        binding: &setup::ServiceBinding,
        preflight: &setup::HostPreflight,
        progress: Option<&setup::SetupProgress>,
    ) -> Result<(LocalProjectName, PathBuf, bool), setup::SetupError> {
        let initial_path = progress
            .map(|progress| progress.workspace_root.clone())
            .filter(|path| !path.is_empty())
            .unwrap_or_else(|| {
                if is_filesystem_root(&preflight.current_directory) {
                    String::new()
                } else {
                    preflight.current_directory.to_string_lossy().into_owned()
                }
            });
        let workspace_root = loop {
            let Some(value) = input_line(
                "Choose the first workspace location",
                &format!(
                    "Selected account: {}\nStart mode: {}\nProfile: {}\n\nThe default is the current directory, never the whole home directory. Enter an absolute path. No files are moved.",
                    display(&binding.account_name, NAME_LIMIT),
                    start_mode_label(binding.mode),
                    display(&binding.profile_path.to_string_lossy(), 160),
                ),
                &initial_path,
                PATH_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            let value = if value.trim().is_empty() {
                preflight.current_directory.to_string_lossy().into_owned()
            } else {
                value.trim().to_owned()
            };
            let path = PathBuf::from(&value);
            if value.len() > PATH_LIMIT
                || !path.is_absolute()
                || is_filesystem_root(&path)
                || path
                    .components()
                    .any(|component| matches!(component, Component::ParentDir))
                || has_terminal_controls(&value)
            {
                notice("Workspace path must be absolute, control-free, and at most 4096 bytes.")?;
                continue;
            }
            match std::fs::metadata(&path) {
                Ok(metadata) if metadata.is_dir() => break path,
                Ok(_) => {
                    notice("The selected path exists but is not a directory.")?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => break path,
                Err(_) => {
                    notice("The selected path cannot be inspected. Check its permissions.")?;
                }
            }
        };

        let create_missing_workspace = if workspace_root.exists() {
            false
        } else {
            let Some(create) = confirm_scrolled(
                "Workspace directory does not exist",
                &format!(
                    "Create this directory only after the final review?\n\nExact path:\n{}",
                    display(&workspace_root.to_string_lossy(), PATH_LIMIT)
                ),
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            create
        };

        let default_name = progress
            .map(|progress| progress.workspace_name.clone())
            .filter(|name| !name.is_empty())
            .or_else(|| {
                workspace_root
                    .file_name()
                    .and_then(|name| name.to_str())
                    .filter(|name| !name.is_empty())
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "workspace".to_owned());
        let workspace_name = loop {
            let Some(value) = input_line(
                "Name the workspace",
                "This is a display name. The directory path remains local to this Host.",
                &default_name,
                NAME_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            match LocalProjectName::try_from(value.trim().to_owned()) {
                Ok(name) => break name,
                Err(_) => notice("Name is required, control-free, and at most 255 UTF-8 bytes.")?,
            }
        };
        Ok((workspace_name, workspace_root, create_missing_workspace))
    }

    fn collect_shell(
        &mut self,
        workspace_root: &Path,
        shells: &[setup::ShellCandidate],
    ) -> Result<setup::SetupShellChoice, setup::SetupError> {
        let candidates: Vec<&setup::ShellCandidate> = shells
            .iter()
            .take(SHELL_CANDIDATE_LIMIT)
            .filter(|candidate| {
                candidate.executable.is_absolute()
                    && candidate.executable.to_str().is_some_and(|text| {
                        !text.is_empty() && text.len() <= PATH_LIMIT && !has_terminal_controls(text)
                    })
            })
            .collect();
        let mut labels: Vec<String> = candidates
            .iter()
            .map(|candidate| {
                format!(
                    "{} — {}",
                    display(&candidate.label, 120),
                    display(&candidate.executable.to_string_lossy(), PATH_LIMIT)
                )
            })
            .collect();
        labels.push("Custom absolute executable…".to_owned());
        let Some(index) = choose_index(
            "Choose a shell profile",
            "Selecting a profile does not start it. Custom paths are checked by the service account before registration.",
            &labels.iter().map(String::as_str).collect::<Vec<_>>(),
            0,
        )?
        else {
            return Err(setup::SetupError::InteractionUnavailable);
        };
        let (default_name, executable) = if let Some(candidate) = candidates.get(index) {
            (candidate.label.clone(), candidate.executable.clone())
        } else {
            let executable = loop {
                let Some(text) = input_line(
                    "Enter a custom shell executable",
                    "Use an absolute path to an existing executable. Lomi will not invoke it during setup.",
                    "",
                    PATH_LIMIT,
                    false,
                )?
                else {
                    return Err(setup::SetupError::InteractionUnavailable);
                };
                let path = PathBuf::from(text.trim());
                if path.is_absolute()
                    && text.trim().len() <= PATH_LIMIT
                    && !has_terminal_controls(text.trim())
                    && std::fs::metadata(&path).is_ok_and(|metadata| metadata.is_file())
                {
                    break path;
                }
                notice(
                    "Shell executable must be an existing regular file at an absolute path of at most 4096 bytes.",
                )?;
            };
            ("custom shell".to_owned(), executable)
        };
        let executable_text = executable
            .to_str()
            .filter(|text| !text.is_empty() && text.len() <= PATH_LIMIT)
            .filter(|text| !has_terminal_controls(text))
            .ok_or(setup::SetupError::InvalidOptions)?;
        let executable = LocalRootPath::try_from(executable_text.to_owned())
            .map_err(|_| setup::SetupError::InvalidOptions)?;

        let name = loop {
            let Some(text) = input_line(
                "Name this shell profile",
                "The profile is registered for the selected workspace. It is not started during setup.",
                &default_name,
                NAME_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            match LocalProjectName::try_from(text.trim().to_owned()) {
                Ok(name) => break name,
                Err(_) => notice("Profile name is required and at most 255 UTF-8 bytes.")?,
            }
        };

        let mut args = Vec::new();
        let mut args_bytes = 0usize;
        while args.len() < 32 {
            let Some(text) = input_line(
                "Shell arguments",
                &format!(
                    "Enter one argument per line; spaces remain inside that argument. Press Enter on an empty line to finish. Up to 32 arguments, 4096 bytes each. Do not include credentials or secrets.\n\nWorkspace: {}\nShell: {}\nArguments collected: {}",
                    display(&workspace_root.to_string_lossy(), 160),
                    display(executable.as_str(), 160),
                    args.len()
                ),
                "",
                ARGUMENT_LIMIT,
                false,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            if text.is_empty() {
                break;
            }
            if has_terminal_controls(&text) || text.len() > ARGUMENT_LIMIT {
                notice("Argument contains control characters or exceeds 4096 UTF-8 bytes.")?;
                continue;
            }
            if args_bytes.saturating_add(text.len()) > ARGUMENTS_TOTAL_LIMIT {
                notice("The combined shell arguments are limited to 8192 UTF-8 bytes.")?;
                continue;
            }
            args_bytes += text.len();
            args.push(
                LocalProcessArgument::try_from(text)
                    .map_err(|_| setup::SetupError::InvalidOptions)?,
            );
        }

        let environment = self.collect_shell_environment()?;
        Ok(setup::SetupShellChoice {
            name,
            executable,
            args: BoundedList(args),
            environment: BoundedList(environment),
        })
    }

    fn collect_shell_environment(
        &mut self,
    ) -> Result<Vec<LocalShellEnvironment>, setup::SetupError> {
        const ALLOWED: [&str; 6] = [
            "TERM",
            "COLORTERM",
            "TERM_PROGRAM",
            "ZDOTDIR",
            "LOMI_ZDOTDIR",
            "PROMPT",
        ];
        let mut values = Vec::new();
        loop {
            if values.len() >= 8 {
                return Ok(values);
            }
            let mut names: Vec<&str> = ALLOWED
                .iter()
                .copied()
                .filter(|name| {
                    !values
                        .iter()
                        .any(|entry: &LocalShellEnvironment| entry.name.as_str() == *name)
                })
                .collect();
            names.push("Finish without adding another variable");
            let Some(index) = choose_index(
                "Optional shell environment",
                "Only this explicit allowlist is available; the installer environment is never copied. Values are saved in this Host's shell profile, not the setup journal. Do not enter secrets.",
                &names,
                names.len() - 1,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            if index >= ALLOWED.len() {
                return Ok(values);
            }
            let name = names[index];
            let Some(value) = input_line(
                &format!("Set {name}"),
                "This value is persisted with the local shell profile. Secret-like variables are not available here.",
                "",
                ENVIRONMENT_VALUE_LIMIT,
                true,
            )?
            else {
                return Err(setup::SetupError::InteractionUnavailable);
            };
            if has_terminal_controls(&value) || value.len() > ENVIRONMENT_VALUE_LIMIT {
                notice("Environment value contains controls or exceeds 256 UTF-8 bytes.")?;
                continue;
            }
            let name = LocalShellEnvironmentName::try_from(name.to_owned())
                .map_err(|_| setup::SetupError::InvalidOptions)?;
            let value = LocalProcessArgument::try_from(value)
                .map_err(|_| setup::SetupError::InvalidOptions)?;
            values.push(LocalShellEnvironment { name, value });
        }
    }
}

impl setup::SetupInteraction for SetupView {
    fn wait_for_login_update(&mut self) -> Result<bool, setup::SetupError> {
        let mut terminal =
            TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let controls = Controls::default();
        let body = "The Host is waiting for approval in the device login flow. Complete verification in your browser or on a phone. Press v to request a one-time display of the verification URL and code, r or Enter to check status now, or Esc to stop waiting.";
        let primary = [
            ("v", "Reveal once"),
            ("enter", "Check now"),
            ("tab", "Next"),
        ];
        let trailing = [("esc", "Stop waiting")];
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            let ready = terminal
                .draw_interactive(
                    "Waiting for device login",
                    body,
                    0,
                    &controls,
                    &primary,
                    &trailing,
                    None,
                )
                .map_err(|_| setup::SetupError::InteractionUnavailable)?;
            let Some(event) = terminal
                .read_event_until(&controls, deadline)
                .map_err(|_| setup::SetupError::InteractionUnavailable)?
            else {
                return Ok(true);
            };
            let key = match event {
                Event::Resize(_, _) => continue,
                Event::Mouse(mouse) => match controls.click(mouse) {
                    Some(Action::Key(key)) => key,
                    _ => continue,
                },
                Event::Key(key) if key.kind != KeyEventKind::Release => key,
                _ => continue,
            };
            if is_cancel_key(key.code, key.modifiers) || key.code == KeyCode::Char('q') {
                return Ok(false);
            }
            if !ready {
                continue;
            }
            let Some(key) = focused_key(&controls, key) else {
                continue;
            };
            if is_cancel_key(key.code, key.modifiers) {
                return Ok(false);
            }
            if let Some(backwards) = tab_direction(key) {
                controls.cycle(backwards);
                continue;
            }
            if horizontal_navigation_key(&controls, key) {
                continue;
            }
            match key.code {
                KeyCode::Char('v') | KeyCode::Char('V') => {
                    self.login_reveal_authorized = true;
                    return Ok(true);
                }
                KeyCode::Enter | KeyCode::Char('r') | KeyCode::Char('R') => return Ok(true),
                _ => {}
            }
        }
    }

    fn wait_for_publication_update(&mut self) -> Result<bool, setup::SetupError> {
        let mut terminal =
            TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let controls = Controls::default();
        let body = "The Host has not yet confirmed the current workspace publication. Wait for the Remote service to finish, then check the Host's durable publication status again. Waiting does not resend a share or unshare request. Press r or Enter to check now, or Esc to leave setup pending.";
        let primary = [("enter", "Check now"), ("r", "Retry"), ("tab", "Next")];
        let trailing = [("esc", "Leave pending")];
        let deadline = Instant::now() + Duration::from_millis(750);
        loop {
            let ready = terminal
                .draw_interactive(
                    "Waiting for Cloud publication",
                    body,
                    0,
                    &controls,
                    &primary,
                    &trailing,
                    None,
                )
                .map_err(|_| setup::SetupError::InteractionUnavailable)?;
            let Some(event) = terminal
                .read_event_until(&controls, deadline)
                .map_err(|_| setup::SetupError::InteractionUnavailable)?
            else {
                return Ok(true);
            };
            let key = match event {
                Event::Resize(_, _) => continue,
                Event::Mouse(mouse) => match controls.click(mouse) {
                    Some(Action::Key(key)) => key,
                    _ => continue,
                },
                Event::Key(key) if key.kind != KeyEventKind::Release => key,
                _ => continue,
            };
            if is_cancel_key(key.code, key.modifiers) || key.code == KeyCode::Char('q') {
                return Ok(false);
            }
            if !ready {
                continue;
            }
            let Some(key) = focused_key(&controls, key) else {
                continue;
            };
            if is_cancel_key(key.code, key.modifiers) {
                return Ok(false);
            }
            if let Some(backwards) = tab_direction(key) {
                controls.cycle(backwards);
                continue;
            }
            if horizontal_navigation_key(&controls, key) {
                continue;
            }
            if key.code == KeyCode::Enter || matches!(key.code, KeyCode::Char('r' | 'R')) {
                return Ok(true);
            }
        }
    }

    fn collect_choices(
        &mut self,
        binding: &setup::ServiceBinding,
        preflight: &setup::HostPreflight,
        progress: Option<&setup::SetupProgress>,
        shells: &[setup::ShellCandidate],
    ) -> Result<setup::SetupChoices, setup::SetupError> {
        let host_name = self.collect_host_name(preflight, progress)?;
        let auth_configuration = self.collect_auth_configuration(progress)?;
        let (workspace_name, workspace_root, create_missing_workspace) =
            self.collect_workspace(binding, preflight, progress)?;
        let shell = self.collect_shell(&workspace_root, shells)?;
        let default_share = progress.is_some_and(|progress| progress.share_remote);
        let Some(share_choice) = choose_index(
            "Choose workspace access",
            "Sharing lets approved sessions for this account use workspace files, Git and terminal controls. Shells keep the permissions of the selected OS account. Local-only preserves this workspace on the Host.",
            &[
                "Share with the currently authorized owner account",
                "Keep this workspace local to this Host",
            ],
            if default_share { 0 } else { 1 },
        )?
        else {
            return Err(setup::SetupError::InteractionUnavailable);
        };
        let share_remote = share_choice == 0;
        let disable_existing_share = if share_remote {
            false
        } else {
            confirm(
                "Confirm local-only access",
                "If this workspace is already shared, may setup turn off that remote sharing? This does not stop local terminal sessions.",
                false,
            )?
            .ok_or(setup::SetupError::InteractionUnavailable)?
        };
        Ok(setup::SetupChoices {
            host_name: Some(host_name),
            auth_configuration,
            workspace_name,
            workspace_root,
            create_missing_workspace,
            shell,
            share_remote,
            renew_share_consent: false,
            disable_existing_share,
        })
    }

    fn confirm_review(&mut self, review: &setup::SetupReview) -> Result<bool, setup::SetupError> {
        let mode = start_mode_label(review.mode);
        let account = match &review.account {
            setup::SetupAccount::Unix { uid, gid } => format!(
                "{} (uid {uid}, gid {gid})",
                display(&review.account_name, 255)
            ),
            setup::SetupAccount::Windows { sid } => format!(
                "{} (SID {})",
                display(&review.account_name, 255),
                display(sid, 184)
            ),
        };
        let args = review
            .shell_args
            .iter()
            .enumerate()
            .map(|(index, argument)| {
                format!(
                    "  {}: {}",
                    index + 1,
                    display(&String::from(argument.clone()), ARGUMENT_LIMIT)
                )
            })
            .collect::<Vec<_>>();
        let environment = if review.environment_names.is_empty() {
            "none".to_owned()
        } else {
            review
                .environment_names
                .iter()
                .map(|name| display(name, 32))
                .collect::<Vec<_>>()
                .join(", ")
        };
        confirm_scrolled(
            "Review first-run setup",
            &format!(
                "Release: {}\nHost label: {}\nHost ID: {}\nStart mode: {}\nAccount: {}\nProfile: {}\n\nWorkspace: {}\nName: {}\nGit repository detected: {}\nCreate missing directory after this review: {}\n\nShell profile: {}\nExecutable: {}\nArguments (stored in the local profile):\n{}\nEnvironment names: {}\nStorage provider: {}\n\nRemote sharing: {}\nDisable existing sharing: {}\n\nNo shell has been started by the review screen. Do not include secrets in shell arguments or environment values.",
                display(&review.release_version, 128),
                display(review.host_name.as_str(), NAME_LIMIT),
                review.host_id.map(String::from).unwrap_or_else(|| "pending".to_owned()),
                mode,
                account,
                display(&review.profile_path.to_string_lossy(), PATH_LIMIT),
                display(&review.workspace_root.to_string_lossy(), PATH_LIMIT),
                display(review.workspace_name.as_str(), NAME_LIMIT),
                if review.git_repository_detected { "yes" } else { "no" },
                if review.create_missing_workspace { "yes" } else { "no" },
                display(review.shell_name.as_str(), NAME_LIMIT),
                display(review.shell_executable.as_str(), PATH_LIMIT),
                if args.is_empty() { "  none".to_owned() } else { args.join("\n") },
                environment,
                review.storage_provider.unwrap_or("none / already configured"),
                if review.share_remote { "share with authorized owner account" } else { "local only" },
                if review.disable_existing_share { "yes, if currently shared" } else { "no" },
            ),
            true,
        )
        .map(|answer| answer.unwrap_or(false))
    }

    fn confirm_authorization_context_change(&mut self) -> Result<bool, setup::SetupError> {
        confirm(
            "Authorization context changed",
            "The Host now reports a different authorization generation than this setup journal. Continue only if you recognize the currently authorized account. The workspace will be checked again before any share change.",
            false,
        )
        .map(|answer| answer.unwrap_or(false))
    }

    fn reveal_login_presentation(&mut self) -> bool {
        if self.login_reveal_authorized {
            self.login_reveal_authorized = false;
            self.login_reveal_handled = true;
            return true;
        }
        if self.login_reveal_handled {
            return false;
        }
        self.login_reveal_handled = true;
        confirm(
            "Reveal device login details?",
            "The verification URL and one-time user code will be visible in this terminal until you dismiss the next screen. They are not written to setup progress or logs. You can also request a one-time reveal later by pressing v on the login wait screen.",
            false,
        )
        .ok()
        .flatten()
        .unwrap_or(false)
    }

    fn show_login_presentation(
        &mut self,
        presentation: &lomi_remote_protocol::ipc::LocalLoginPresentation,
    ) {
        self.login_reveal_authorized = false;
        self.login_reveal_handled = true;
        if let Ok(mut terminal) = TerminalSession::enter() {
            let body = format!(
                "Verification URL:\n{}\n\nOne-time user code:\n{}\n\nExpires at: {}\n\nYou may enter the URL on this device or on a phone. The code stays visible only until you dismiss this screen.",
                display(presentation.verification_url.as_str(), PATH_LIMIT),
                display(presentation.user_code.expose_wire(), 64),
                presentation.expires_at.0,
            );
            let _ = wait_for_dismiss(&mut terminal, "Device login", &body);
        }
    }

    fn confirm_renewed_share(
        &mut self,
        workspace_name: &LocalProjectName,
        workspace_id: WorkspaceId,
    ) -> Result<bool, setup::SetupError> {
        confirm(
            "Confirm a new share request",
            &format!(
                "An earlier share request had an uncertain result. A fresh Host read now reports this workspace as not shared. Send a new share request for {} ({}) to the currently authorized owner account?",
                display(workspace_name.as_str(), NAME_LIMIT),
                String::from(workspace_id),
            ),
            false,
        )
        .map(|answer| answer.unwrap_or(false))
    }
}

struct TerminalSession {
    // Field drop order matters: restore the pointer before terminal modes and
    // mouse capture are restored by `_restore`.
    pointer: PointerTracker,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    _restore: TerminalRestoreGuard,
}

struct TerminalRestoreGuard;

impl TerminalSession {
    fn enter() -> io::Result<Self> {
        enable_raw_mode()?;
        let restore = TerminalRestoreGuard;
        let mut stdout = io::stdout();
        execute!(
            stdout,
            EnterAlternateScreen,
            EnableBracketedPaste,
            EnableMouseCapture,
            EnableFocusChange,
            Hide
        )?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend)?;
        let mut pointer = PointerTracker::new();
        pointer.reset();
        Ok(Self {
            pointer,
            terminal,
            _restore: restore,
        })
    }

    fn draw_interactive(
        &mut self,
        title: &str,
        body: &str,
        scroll: u16,
        controls: &Controls,
        primary: &[(&str, &str)],
        trailing: &[(&str, &str)],
        input_hit: Option<(&str, &str)>,
    ) -> io::Result<bool> {
        let mut enough_room = false;
        self.terminal.draw(|frame| {
            controls.begin();
            theme::canvas(frame);
            enough_room = frame.area().width >= MIN_COLUMNS && frame.area().height >= MIN_ROWS;
            if !enough_room {
                frame.render_widget(
                    Paragraph::new(theme::content(
                        "Resize this terminal to at least 80 columns by 24 rows.\n\nPress Esc to cancel.",
                    ))
                    .block(theme::panel("Lomi Remote setup", theme::SURFACE))
                    .wrap(Wrap { trim: false }),
                    frame.area(),
                );
                theme::finish(frame);
                return;
            }
            let [header, content, footer_area] = Layout::vertical([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .areas(frame.area());
            frame.render_widget(
                Paragraph::new(theme::header(&display(title, 160)))
                    .block(theme::panel("", theme::SURFACE)),
                header,
            );
            let content_block = theme::panel("", theme::SURFACE);
            let content_inner = content_block.inner(content);
            let displayed_body = display_block(body, 32_768);
            frame.render_widget(
                Paragraph::new(theme::content(&displayed_body))
                    .block(content_block)
                    .wrap(Wrap { trim: false })
                    .scroll((scroll, 0)),
                content,
            );
            if let Some((description, field)) = input_hit {
                let description = display_block(description, 8192);
                let description_lines = Paragraph::new(theme::content(&description))
                    .wrap(Wrap { trim: false })
                    .line_count(content_inner.width);
                let field = display(field, 8192);
                let field_lines = Paragraph::new(theme::content(&field))
                    .wrap(Wrap { trim: false })
                    .line_count(content_inner.width)
                    .max(1);
                let field_top = content_inner
                    .y
                    .saturating_add(u16::try_from(description_lines).unwrap_or(u16::MAX))
                    .saturating_add(1);
                let field_bottom = field_top
                    .saturating_add(u16::try_from(field_lines).unwrap_or(u16::MAX));
                let field_top = field_top.saturating_sub(scroll);
                let field_bottom = field_bottom.saturating_sub(scroll);
                let target_top = field_top.max(content_inner.y);
                let target_bottom = field_bottom.min(content_inner.bottom());
                if target_bottom > target_top {
                    controls.row(
                        Rect::new(
                            content_inner.x,
                            target_top,
                            content_inner.width,
                            target_bottom - target_top,
                        ),
                        INPUT_FIELD_ACTION,
                    );
                }
            }
            controls.extend(theme::render_footer(
                frame,
                footer_area,
                primary,
                trailing,
            ));
            if input_hit.is_some() && controls.focused().is_none() {
                controls.focus_action(Action::Row(INPUT_FIELD_ACTION));
            }
            controls.highlight(frame);
            theme::finish(frame);
        })?;
        self.pointer
            .refresh(|column, row| controls.hoverable(column, row));
        Ok(enough_room)
    }

    fn draw_choices(
        &mut self,
        title: &str,
        description: &str,
        choices: &[&str],
        selected: usize,
        controls: &Controls,
        primary: &[(&str, &str)],
        trailing: &[(&str, &str)],
    ) -> io::Result<bool> {
        let mut enough_room = false;
        self.terminal.draw(|frame| {
            controls.begin();
            theme::canvas(frame);
            enough_room = frame.area().width >= MIN_COLUMNS && frame.area().height >= MIN_ROWS;
            if !enough_room {
                frame.render_widget(
                    Paragraph::new(theme::content(
                        "Resize this terminal to at least 80 columns by 24 rows.\n\nPress Esc to cancel.",
                    ))
                    .block(theme::panel("Lomi Remote setup", theme::SURFACE))
                    .wrap(Wrap { trim: false }),
                    frame.area(),
                );
                theme::finish(frame);
                return;
            }
            let [header, content, footer_area] = Layout::vertical([
                Constraint::Length(3),
                Constraint::Min(1),
                Constraint::Length(3),
            ])
            .areas(frame.area());
            frame.render_widget(
                Paragraph::new(theme::header(&display(title, 160)))
                    .block(theme::panel("", theme::SURFACE)),
                header,
            );

            let first = selected.saturating_sub(4);
            let last = (first + 10).min(choices.len());
            let mut visible = Vec::new();
            if first > 0 {
                visible.push((format!("… {} earlier choices", first), None));
            }
            visible.extend((first..last).map(|index| {
                (
                    format!(
                        "{} {}",
                        if index == selected { ">" } else { " " },
                        display(choices[index], 1024)
                    ),
                    Some(index),
                )
            }));
            if last < choices.len() {
                visible.push((format!("… {} later choices", choices.len() - last), None));
            }
            let description = display_block(description, 8192);
            let options = visible
                .iter()
                .map(|(text, _)| text.as_str())
                .collect::<Vec<_>>()
                .join("\n");
            let body = format!("{description}\n\n{options}");
            let content_block = theme::panel("", theme::SURFACE);
            let content_inner = content_block.inner(content);
            let rendered_body = display_block(&body, 32_768);
            frame.render_widget(
                Paragraph::new(theme::content(&rendered_body))
                    .block(content_block)
                    .wrap(Wrap { trim: false }),
                content,
            );

            let description_lines = Paragraph::new(theme::content(&description))
                .wrap(Wrap { trim: false })
                .line_count(content_inner.width);
            let mut row_y = content_inner
                .y
                .saturating_add(u16::try_from(description_lines).unwrap_or(u16::MAX))
                .saturating_add(1);
            for (text, index) in visible {
                let lines = Paragraph::new(theme::content(&text))
                    .wrap(Wrap { trim: false })
                    .line_count(content_inner.width)
                    .max(1);
                let row_bottom = row_y.saturating_add(u16::try_from(lines).unwrap_or(u16::MAX));
                if let Some(index) = index {
                    let target_top = row_y.max(content_inner.y);
                    let target_bottom = row_bottom.min(content_inner.bottom());
                    if target_bottom > target_top {
                        controls.row(
                            Rect::new(
                                content_inner.x,
                                target_top,
                                content_inner.width,
                                target_bottom - target_top,
                            ),
                            index,
                        );
                    }
                }
                row_y = row_bottom;
            }

            controls.extend(theme::render_footer(
                frame,
                footer_area,
                primary,
                trailing,
            ));
            controls.highlight(frame);
            theme::finish(frame);
        })?;
        self.pointer
            .refresh(|column, row| controls.hoverable(column, row));
        Ok(enough_room)
    }

    /// Read setup input while updating the terminal pointer from hover events.
    /// Mouse movement never dispatches a click or causes a screen redraw.
    fn read_event(&mut self, controls: &Controls) -> io::Result<Event> {
        loop {
            if let Some(event) = self.observe_event(controls, event::read()?) {
                return Ok(event);
            }
        }
    }

    /// A polling variant keeps timed setup waits responsive while consuming
    /// hover events between polls.
    fn read_event_until(
        &mut self,
        controls: &Controls,
        deadline: Instant,
    ) -> io::Result<Option<Event>> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() || !event::poll(remaining)? {
                return Ok(None);
            }
            if let Some(event) = self.observe_event(controls, event::read()?) {
                return Ok(Some(event));
            }
        }
    }

    fn observe_event(&mut self, controls: &Controls, event: Event) -> Option<Event> {
        match event {
            Event::Mouse(mouse) => {
                self.pointer.observe(mouse);
                self.pointer
                    .refresh(|column, row| controls.hoverable(column, row));
                (!matches!(mouse.kind, MouseEventKind::Moved | MouseEventKind::Drag(_)))
                    .then_some(Event::Mouse(mouse))
            }
            Event::FocusLost => {
                self.pointer.reset();
                None
            }
            Event::FocusGained => {
                self.pointer
                    .refresh(|column, row| controls.hoverable(column, row));
                None
            }
            event => Some(event),
        }
    }

    fn mouse_in_content(&self, mouse: MouseEvent) -> bool {
        let Ok(size) = self.terminal.size() else {
            return false;
        };
        let area = Rect::new(
            1,
            4,
            size.width.saturating_sub(2),
            size.height.saturating_sub(8),
        );
        area.contains((mouse.column, mouse.row).into())
    }
}

impl Drop for TerminalRestoreGuard {
    fn drop(&mut self) {
        let mut stdout = io::stdout();
        // Try each restoration independently. A failure writing one escape
        // sequence must not prevent the remaining terminal modes from being
        // restored.
        let _ = execute!(stdout, Show);
        let _ = execute!(stdout, DisableBracketedPaste);
        let _ = execute!(stdout, DisableFocusChange);
        let _ = execute!(stdout, DisableMouseCapture);
        let _ = execute!(stdout, LeaveAlternateScreen);
        let _ = disable_raw_mode();
    }
}

fn choose_index(
    title: &str,
    description: &str,
    choices: &[&str],
    initial: usize,
) -> Result<Option<usize>, setup::SetupError> {
    choose_index_with_footer(
        title,
        description,
        choices,
        initial,
        &[
            ("j", "Move down"),
            ("k", "Move up"),
            ("enter", "Continue"),
            ("tab", "Next control"),
        ],
        &[("esc", "Cancel")],
    )
}

#[derive(Debug, PartialEq, Eq)]
enum ChoicePointerAction {
    Selected(usize),
    Continue(usize),
    Cancel,
    Key(KeyEvent),
    Ignore,
}

fn step_choice_selection(selected: usize, choices_len: usize, down: bool) -> usize {
    if down {
        selected
            .saturating_add(1)
            .min(choices_len.saturating_sub(1))
    } else {
        selected.saturating_sub(1)
    }
}

fn choice_pointer_action(
    action: Action,
    selected: usize,
    choices_len: usize,
) -> ChoicePointerAction {
    match action {
        Action::Row(index) if index < choices_len => ChoicePointerAction::Selected(index),
        Action::Row(_) => ChoicePointerAction::Ignore,
        Action::Key(key) if key.code == KeyCode::Enter => ChoicePointerAction::Continue(selected),
        Action::Key(key) if is_cancel_key(key.code, key.modifiers) => ChoicePointerAction::Cancel,
        Action::Key(key) => ChoicePointerAction::Key(key),
    }
}

fn choose_index_with_footer(
    title: &str,
    description: &str,
    choices: &[&str],
    initial: usize,
    primary: &[(&str, &str)],
    trailing: &[(&str, &str)],
) -> Result<Option<usize>, setup::SetupError> {
    if choices.is_empty() {
        return Err(setup::SetupError::InteractionUnavailable);
    }
    let mut selected = initial.min(choices.len() - 1);
    let controls = Controls::default();
    let mut terminal =
        TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
    loop {
        let ready = terminal
            .draw_choices(
                title,
                description,
                choices,
                selected,
                &controls,
                primary,
                trailing,
            )
            .map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let key = match terminal
            .read_event(&controls)
            .map_err(|_| setup::SetupError::InteractionUnavailable)?
        {
            Event::Resize(_, _) => continue,
            Event::Mouse(mouse) if ready => match mouse.kind {
                MouseEventKind::ScrollUp if terminal.mouse_in_content(mouse) => {
                    controls.blur();
                    selected = step_choice_selection(selected, choices.len(), false);
                    continue;
                }
                MouseEventKind::ScrollDown if terminal.mouse_in_content(mouse) => {
                    controls.blur();
                    selected = step_choice_selection(selected, choices.len(), true);
                    continue;
                }
                _ => match controls
                    .click(mouse)
                    .map(|action| choice_pointer_action(action, selected, choices.len()))
                    .unwrap_or(ChoicePointerAction::Ignore)
                {
                    ChoicePointerAction::Selected(index) => {
                        selected = index;
                        continue;
                    }
                    ChoicePointerAction::Continue(index) => return Ok(Some(index)),
                    ChoicePointerAction::Cancel => return Ok(None),
                    ChoicePointerAction::Key(key) => key,
                    ChoicePointerAction::Ignore => continue,
                },
            },
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if !ready {
            continue;
        }
        let Some(key) = focused_key(&controls, key) else {
            continue;
        };
        if key.code == KeyCode::Enter {
            if let Some(Action::Row(index)) = controls.focused() {
                if index < choices.len() {
                    return Ok(Some(index));
                }
            }
        }
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if let Some(backwards) = tab_direction(key) {
            controls.cycle(backwards);
            continue;
        }
        if horizontal_navigation_key(&controls, key) {
            continue;
        }
        let code = key.code;
        if matches!(code, KeyCode::Up | KeyCode::Down) {
            if matches!(controls.focused(), Some(Action::Key(_))) {
                controls.move_focus(code);
                if let Some(Action::Row(index)) = controls.focused() {
                    if index < choices.len() {
                        selected = index;
                    }
                }
                continue;
            }
            if code == KeyCode::Down && selected.saturating_add(1) >= choices.len() {
                controls.focus_action(Action::Row(selected));
                if controls.move_focus(KeyCode::Down) {
                    continue;
                }
            }
            controls.blur();
        } else if matches!(
            code,
            KeyCode::Char('j' | 'k') | KeyCode::Home | KeyCode::End
        ) {
            controls.blur();
        }
        match code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Char('y' | 'Y')
                if plain_activation_char(key, 'y')
                    && primary.iter().any(|(key, _)| *key == "y") =>
            {
                return Ok(Some(0));
            }
            KeyCode::Char('n' | 'N')
                if plain_activation_char(key, 'n')
                    && primary.iter().any(|(key, _)| *key == "n") =>
            {
                return Ok(Some(1.min(choices.len() - 1)));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                selected = step_choice_selection(selected, choices.len(), false)
            }
            KeyCode::Down | KeyCode::Char('j') => {
                selected = step_choice_selection(selected, choices.len(), true)
            }
            KeyCode::Enter => return Ok(Some(selected)),
            KeyCode::Home => selected = 0,
            KeyCode::End => selected = choices.len() - 1,
            _ => {}
        }
    }
}

fn confirm(
    title: &str,
    description: &str,
    default: bool,
) -> Result<Option<bool>, setup::SetupError> {
    let choices = ["Yes", "No"];
    choose_index_with_footer(
        title,
        description,
        &choices,
        if default { 0 } else { 1 },
        &[
            ("y", "Yes"),
            ("n", "No"),
            ("enter", "Confirm"),
            ("tab", "Next control"),
        ],
        &[("esc", "Cancel")],
    )
    .map(|selection| selection.map(|selection| selection == 0))
}

fn confirm_scrolled(
    title: &str,
    description: &str,
    default: bool,
) -> Result<Option<bool>, setup::SetupError> {
    let mut scroll = 0u16;
    let controls = Controls::default();
    let mut terminal =
        TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
    let primary = [
        ("enter", if default { "Yes" } else { "No" }),
        ("y", "Yes"),
        ("n", "No"),
        ("tab", "Next control"),
    ];
    let trailing = [("esc", "Cancel")];
    loop {
        let ready = terminal
            .draw_interactive(
                title,
                description,
                scroll,
                &controls,
                &primary,
                &trailing,
                None,
            )
            .map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let key = match terminal
            .read_event(&controls)
            .map_err(|_| setup::SetupError::InteractionUnavailable)?
        {
            Event::Resize(_, _) => continue,
            Event::Mouse(mouse) if ready => match mouse.kind {
                MouseEventKind::ScrollUp if terminal.mouse_in_content(mouse) => {
                    scroll = scroll.saturating_sub(1);
                    continue;
                }
                MouseEventKind::ScrollDown if terminal.mouse_in_content(mouse) => {
                    scroll = scroll.saturating_add(1);
                    continue;
                }
                _ => match controls.click(mouse) {
                    Some(Action::Key(key)) => key,
                    _ => continue,
                },
            },
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if !ready {
            continue;
        }
        let Some(key) = focused_key(&controls, key) else {
            continue;
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if let Some(backwards) = tab_direction(key) {
            controls.cycle(backwards);
            continue;
        }
        if horizontal_navigation_key(&controls, key) {
            continue;
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Enter => return Ok(Some(default)),
            KeyCode::Char('y' | 'Y') if plain_activation_char(key, 'y') => {
                return Ok(Some(true));
            }
            KeyCode::Char('n' | 'N') if plain_activation_char(key, 'n') => {
                return Ok(Some(false));
            }
            KeyCode::Up => scroll = scroll.saturating_sub(1),
            KeyCode::Down => scroll = scroll.saturating_add(1),
            KeyCode::PageUp => scroll = scroll.saturating_sub(8),
            KeyCode::PageDown => scroll = scroll.saturating_add(8),
            KeyCode::Home => scroll = 0,
            _ => {}
        }
    }
}

fn input_line(
    title: &str,
    description: &str,
    initial: &str,
    limit: usize,
    masked: bool,
) -> Result<Option<String>, setup::SetupError> {
    let mut value = String::new();
    for character in initial.chars() {
        if !character.is_control() && value.len() + character.len_utf8() <= limit {
            value.push(character);
        }
    }
    let mut status = String::new();
    let mut scroll = 0u16;
    let controls = Controls::default();
    let mut terminal =
        TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
    let primary = [
        ("backspace", "Delete"),
        ("enter", "Continue"),
        ("tab", "Next control"),
    ];
    let trailing = [("esc", "Cancel")];
    loop {
        let visible = if masked {
            "•".repeat(value.chars().count().min(512))
        } else {
            display_tail(&value, 120)
        };
        let body = format!(
            "{}\n\n{}▏\n\n{}\n\nType or paste one control-free line. Backspace edits; Ctrl-U clears.",
            display_block(description, 8192),
            visible,
            status
        );
        let input_line = format!("{visible}▏");
        let ready = terminal
            .draw_interactive(
                title,
                &body,
                scroll,
                &controls,
                &primary,
                &trailing,
                Some((description, &input_line)),
            )
            .map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let key = match terminal
            .read_event(&controls)
            .map_err(|_| setup::SetupError::InteractionUnavailable)?
        {
            Event::Resize(_, _) => continue,
            Event::Paste(pasted) => {
                if !ready {
                    continue;
                }
                let pasted = pasted
                    .strip_suffix("\r\n")
                    .or_else(|| pasted.strip_suffix('\n'))
                    .or_else(|| pasted.strip_suffix('\r'))
                    .unwrap_or(&pasted);
                if has_terminal_controls(pasted) {
                    status = "Paste rejected: only one control-free line is accepted.".to_owned();
                } else if value.len().saturating_add(pasted.len()) > limit {
                    status = format!("Input is limited to {limit} UTF-8 bytes.");
                } else {
                    value.push_str(pasted);
                    status.clear();
                    input_edit_committed(&controls);
                }
                continue;
            }
            Event::Mouse(mouse) if ready => match mouse.kind {
                MouseEventKind::ScrollUp if terminal.mouse_in_content(mouse) => {
                    scroll = scroll.saturating_sub(1);
                    continue;
                }
                MouseEventKind::ScrollDown if terminal.mouse_in_content(mouse) => {
                    scroll = scroll.saturating_add(1);
                    continue;
                }
                _ => match controls.click(mouse) {
                    Some(Action::Key(key)) => key,
                    Some(Action::Row(INPUT_FIELD_ACTION)) | None => continue,
                    Some(Action::Row(_)) => continue,
                },
            },
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if !ready {
            continue;
        }
        let Some(key) = focused_key(&controls, key) else {
            continue;
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(None);
        }
        if let Some(backwards) = tab_direction(key) {
            controls.cycle(backwards);
            continue;
        }
        if input_horizontal_navigation_key(&controls, key) {
            continue;
        }
        if matches!(key.code, KeyCode::Up | KeyCode::Down) {
            match controls.focused() {
                Some(Action::Key(_)) => {
                    controls.move_focus(key.code);
                    continue;
                }
                Some(Action::Row(INPUT_FIELD_ACTION)) | None => {
                    if controls.focused().is_none() {
                        controls.focus_action(Action::Row(INPUT_FIELD_ACTION));
                    }
                    controls.move_focus(key.code);
                    continue;
                }
                Some(Action::Row(_)) => continue,
            }
        }
        match key.code {
            KeyCode::Esc => return Ok(None),
            KeyCode::Enter => return Ok(Some(value)),
            KeyCode::Backspace => {
                value.pop();
                input_edit_committed(&controls);
                status.clear();
            }
            KeyCode::Char('u') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                value.clear();
                status.clear();
                input_edit_committed(&controls);
            }
            KeyCode::Char(character)
                if !key.modifiers.contains(KeyModifiers::CONTROL)
                    && !key.modifiers.contains(KeyModifiers::ALT) =>
            {
                if character.is_control() {
                    status = "Control characters are not accepted.".to_owned();
                } else if value.len().saturating_add(character.len_utf8()) > limit {
                    status = format!("Input is limited to {limit} UTF-8 bytes.");
                } else {
                    value.push(character);
                    status.clear();
                    input_edit_committed(&controls);
                }
            }
            _ => {}
        }
    }
}

fn notice(message: &str) -> Result<(), setup::SetupError> {
    let mut terminal =
        TerminalSession::enter().map_err(|_| setup::SetupError::InteractionUnavailable)?;
    let _ = wait_for_dismiss(&mut terminal, "Setup", message)?;
    Ok(())
}

fn wait_for_dismiss(
    terminal: &mut TerminalSession,
    title: &str,
    body: &str,
) -> Result<(), setup::SetupError> {
    let controls = Controls::default();
    let primary = [("enter", "Dismiss")];
    let trailing = [("esc", "Dismiss")];
    loop {
        let ready = terminal
            .draw_interactive(title, body, 0, &controls, &primary, &trailing, None)
            .map_err(|_| setup::SetupError::InteractionUnavailable)?;
        let key = match terminal
            .read_event(&controls)
            .map_err(|_| setup::SetupError::InteractionUnavailable)?
        {
            Event::Resize(_, _) => continue,
            Event::Paste(_) if ready => return Ok(()),
            Event::Paste(_) => continue,
            Event::Mouse(mouse) => match controls.click(mouse) {
                Some(Action::Key(key)) => key,
                _ => continue,
            },
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(());
        }
        if !ready {
            continue;
        }
        let Some(key) = focused_key(&controls, key) else {
            continue;
        };
        if is_cancel_key(key.code, key.modifiers) {
            return Ok(());
        }
        if let Some(backwards) = tab_direction(key) {
            controls.cycle(backwards);
            continue;
        }
        if horizontal_navigation_key(&controls, key) {
            continue;
        }
        if matches!(key.code, KeyCode::Up | KeyCode::Down) {
            controls.move_focus(key.code);
            continue;
        }
        return Ok(());
    }
}

fn display(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .map(|character| {
            let code = character as u32;
            if character.is_control()
                || (0x202a..=0x202e).contains(&code)
                || (0x2066..=0x2069).contains(&code)
            {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn display_block(text: &str, limit: usize) -> String {
    text.chars()
        .take(limit)
        .map(|character| {
            let code = character as u32;
            if character == '\n' {
                '\n'
            } else if character.is_control()
                || (0x202a..=0x202e).contains(&code)
                || (0x2066..=0x2069).contains(&code)
            {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn display_tail(text: &str, visible_chars: usize) -> String {
    let start = text
        .char_indices()
        .rev()
        .nth(visible_chars.saturating_sub(1))
        .map_or(0, |(index, _)| index);
    let mut value = String::new();
    if start > 0 {
        value.push('…');
    }
    value.push_str(&display(&text[start..], visible_chars));
    value
}

fn has_terminal_controls(text: &str) -> bool {
    text.chars().any(|character| {
        let code = character as u32;
        character.is_control()
            || (0x202a..=0x202e).contains(&code)
            || (0x2066..=0x2069).contains(&code)
    })
}

fn is_cancel_key(code: KeyCode, modifiers: KeyModifiers) -> bool {
    code == KeyCode::Esc
        || (code == KeyCode::Char('c') && modifiers.contains(KeyModifiers::CONTROL))
}

fn tab_direction(key: KeyEvent) -> Option<bool> {
    match key.code {
        KeyCode::BackTab => Some(true),
        KeyCode::Tab => Some(key.modifiers.contains(KeyModifiers::SHIFT)),
        _ => None,
    }
}

fn focused_key(controls: &Controls, key: KeyEvent) -> Option<KeyEvent> {
    if key.code == KeyCode::Enter && !key.modifiers.is_empty() {
        return None;
    }
    if key.code != KeyCode::Enter {
        return Some(key);
    }
    Some(match controls.focused() {
        Some(Action::Key(focused)) => focused,
        Some(Action::Row(_)) | None => key,
    })
}

fn input_edit_committed(controls: &Controls) {
    controls.focus_action(Action::Row(INPUT_FIELD_ACTION));
}

fn horizontal_navigation_key(controls: &Controls, key: KeyEvent) -> bool {
    if matches!(key.code, KeyCode::Left | KeyCode::Right) {
        controls.move_focus(key.code);
        true
    } else {
        false
    }
}

fn input_horizontal_navigation_key(controls: &Controls, key: KeyEvent) -> bool {
    if matches!(key.code, KeyCode::Left | KeyCode::Right) {
        if matches!(controls.focused(), Some(Action::Key(_))) {
            controls.move_focus(key.code);
        }
        true
    } else {
        false
    }
}

fn plain_activation_char(key: KeyEvent, expected: char) -> bool {
    matches!(key.code, KeyCode::Char(character) if character.eq_ignore_ascii_case(&expected))
        && !key.modifiers.contains(KeyModifiers::CONTROL)
        && !key.modifiers.contains(KeyModifiers::ALT)
}

fn is_filesystem_root(path: &Path) -> bool {
    path.components()
        .all(|component| matches!(component, Component::RootDir | Component::Prefix(_)))
}

fn start_mode_label(mode: LocalStartMode) -> &'static str {
    match mode {
        LocalStartMode::Manual => "Manual",
        LocalStartMode::Login => "After login",
        LocalStartMode::Boot => "At boot",
    }
}

#[cfg(test)]
mod focused_interaction_tests {
    use super::*;

    #[test]
    fn clicking_a_choice_selects_it_without_accepting_it() {
        assert_eq!(
            choice_pointer_action(Action::Row(3), 1, 4),
            ChoicePointerAction::Selected(3)
        );
        assert_eq!(
            choice_pointer_action(
                Action::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE)),
                3,
                4,
            ),
            ChoicePointerAction::Continue(3)
        );
    }

    #[test]
    fn choice_pointer_ignores_invisible_rows_and_cancel_is_explicit() {
        assert_eq!(
            choice_pointer_action(Action::Row(4), 1, 4),
            ChoicePointerAction::Ignore
        );
        assert_eq!(
            choice_pointer_action(
                Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)),
                1,
                4,
            ),
            ChoicePointerAction::Cancel
        );
    }

    #[test]
    fn wheel_and_keyboard_selection_stay_within_available_choices() {
        assert_eq!(step_choice_selection(0, 4, false), 0);
        assert_eq!(step_choice_selection(3, 4, true), 3);
        assert_eq!(step_choice_selection(1, 4, true), 2);
    }

    #[test]
    fn focused_footer_actions_activate_with_enter_and_backtab_cycles_backwards() {
        let controls = Controls::default();
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Tab);
        controls.cycle(false);
        assert_eq!(
            focused_key(&controls, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .code,
            KeyCode::Tab
        );
        assert_eq!(
            tab_direction(KeyEvent::new(KeyCode::BackTab, KeyModifiers::NONE)),
            Some(true)
        );
    }

    #[test]
    fn input_edits_clear_a_focused_cancel_button_before_enter() {
        let controls = Controls::default();
        controls.row(Rect::new(0, 0, 8, 1), INPUT_FIELD_ACTION);
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Esc);
        controls.focus_action(Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)));
        assert_eq!(
            controls.focused(),
            Some(Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
        );

        input_edit_committed(&controls);

        assert_eq!(controls.focused(), Some(Action::Row(INPUT_FIELD_ACTION)));

        assert_eq!(
            focused_key(&controls, KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
                .unwrap()
                .code,
            KeyCode::Enter
        );
    }

    #[test]
    fn input_arrows_focus_footer_without_editing_or_activating() {
        let controls = Controls::default();
        controls.row(Rect::new(2, 2, 20, 1), INPUT_FIELD_ACTION);
        controls.key(Rect::new(2, 8, 8, 1), KeyCode::Esc);
        controls.focus_action(Action::Row(INPUT_FIELD_ACTION));

        assert!(input_horizontal_navigation_key(
            &controls,
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE)
        ));
        assert_eq!(controls.focused(), Some(Action::Row(INPUT_FIELD_ACTION)));
        assert!(controls.move_focus(KeyCode::Down));
        assert_eq!(
            controls.focused(),
            Some(Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
        );
        assert!(controls.move_focus(KeyCode::Up));
        assert_eq!(controls.focused(), Some(Action::Row(INPUT_FIELD_ACTION)));
    }

    #[test]
    fn modified_enter_and_yes_no_do_not_activate_focused_controls() {
        let controls = Controls::default();
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Char('y'));
        controls.cycle(false);

        assert!(
            focused_key(
                &controls,
                KeyEvent::new(KeyCode::Enter, KeyModifiers::CONTROL)
            )
            .is_none()
        );
        assert!(!plain_activation_char(
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::CONTROL),
            'y'
        ));
        assert!(is_cancel_key(KeyCode::Char('c'), KeyModifiers::CONTROL));
        assert_eq!(
            focused_key(
                &controls,
                KeyEvent::new(KeyCode::Char('u'), KeyModifiers::CONTROL)
            )
            .unwrap()
            .code,
            KeyCode::Char('u')
        );
    }
}
