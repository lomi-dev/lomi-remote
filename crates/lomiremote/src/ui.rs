//! The dashboard is an IPC client. Closing it never stops the host.
use crate::bootstrap::{self, BootstrapError, NativeProvider};
use crate::diagnostics::{DiagnosticReport, DiagnosticReportBuilder, DiagnosticRunMode};
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{LeaveAlternateScreen, disable_raw_mode},
};
use lomi_remote_protocol::ipc::{
    LocalAuthConfigure, LocalCall, LocalLoginPresentation, LocalLoginStatus, LocalProjectName,
    LocalResult, LocalRootPath, LocalSharing, LocalStartMode, LocalStartModePreference,
    LocalStatus, LocalWorkspaceAdd, LocalWorkspaceSummary, LocalWorkspaceTarget,
};
use lomi_remote_protocol::{OperationId, WorkspaceId, rpc::Confirmed};
use ratatui::{
    Frame, Terminal,
    backend::Backend as TerminalBackend,
    layout::{Constraint, Layout},
    text::Line,
    widgets::{Block, List, ListItem, Paragraph, Wrap},
};
use std::{io, path::Path, time::Duration};

pub mod operations;
use operations::{
    CurrentAccessSnapshot, Operations, Page, ServiceAction, ServiceSnapshot,
    UiDiagnosticLogSnapshot,
};

const WORKSPACE_PATH_MAX_BYTES: usize = 4096;
const WORKSPACE_NAME_MAX_BYTES: usize = 255;
const WORKSPACE_SEARCH_MAX_BYTES: usize = 255;

pub trait Backend {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str>;

    /// Typed native service adapter. Implementations must report observed state
    /// and must not shell out to parse display-oriented status text.
    fn service_status(&mut self) -> Result<ServiceSnapshot, &'static str> {
        Err("SERVICE_STATUS_UNAVAILABLE")
    }

    fn service_action(&mut self, _action: ServiceAction) -> Result<ServiceSnapshot, &'static str> {
        Err("SERVICE_ACTION_UNAVAILABLE")
    }

    /// Typed redacted snapshot of the current owner-account access state.
    fn current_access_snapshot(&mut self) -> Result<CurrentAccessSnapshot, &'static str> {
        match self.request(LocalCall::OperatorSnapshot {})? {
            LocalResult::OperatorSnapshot(snapshot) => Ok(CurrentAccessSnapshot {
                login: snapshot.login,
                connected_clients: snapshot.connected_clients,
                active_terminals: u32::try_from(snapshot.active_terminals.0).ok(),
            }),
            _ => Err("ACCESS_SNAPSHOT_INVALID"),
        }
    }

    /// Bounded closed-code diagnostic log page.
    fn read_diagnostic_logs(
        &mut self,
        cursor: Option<u64>,
        limit: usize,
    ) -> Result<UiDiagnosticLogSnapshot, &'static str> {
        let limit = u8::try_from(limit)
            .ok()
            .filter(|limit| (1..=128).contains(limit))
            .ok_or("DIAGNOSTIC_LOG_LIMIT_INVALID")?;
        match self.request(LocalCall::DiagnosticLogs(
            lomi_remote_protocol::ipc::LocalDiagnosticLogsRead {
                after_sequence: cursor.map(lomi_remote_protocol::DecimalU64),
                limit,
            },
        ))? {
            LocalResult::DiagnosticLogs(page) => Ok(UiDiagnosticLogSnapshot {
                entries: page
                    .entries
                    .0
                    .into_iter()
                    .map(|entry| operations::UiDiagnosticLogEntry {
                        sequence: entry.sequence.0,
                        unix_time_ms: entry.unix_time_ms.map(|time| time.0),
                        severity: entry.severity,
                        component: entry.component,
                        code: entry.code,
                    })
                    .collect(),
                next_cursor: page.next_cursor.0,
                truncated: page.truncated,
                available: page.available,
            }),
            _ => Err("DIAGNOSTIC_LOGS_INVALID"),
        }
    }

    /// Local profile location for offline, read-only diagnostics.
    fn diagnostic_profile_path(&self) -> Option<std::path::PathBuf> {
        None
    }

    /// Uses the canonical Doctor LocalCall; a failed request remains an error
    /// so the UI can show only checks it independently observed offline.
    fn doctor_report(&mut self) -> Result<DiagnosticReport, &'static str> {
        match self.request(LocalCall::Doctor {})? {
            LocalResult::Doctor(diagnostics) => {
                let mut builder = DiagnosticReportBuilder::new(DiagnosticRunMode::Online);
                builder.add_wire_diagnostics(&diagnostics.0);
                Ok(builder.finish())
            }
            _ => Err("DOCTOR_RESPONSE_INVALID"),
        }
    }
}

/// Untrusted labels are bounded and have all terminal controls replaced before
/// entering the renderer. Ratatui text is never an ANSI execution surface.
pub fn safe_label(text: &str) -> String {
    text.chars()
        .take(120)
        .map(|ch| if ch.is_control() { '�' } else { ch })
        .collect()
}

fn safe_configuration_value(text: &str) -> String {
    text.chars()
        .take(WORKSPACE_PATH_MAX_BYTES)
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn input_contains_terminal_control(text: &str) -> bool {
    text.chars().any(input_character_is_unsafe)
}

fn input_character_is_unsafe(character: char) -> bool {
    character.is_control() || matches!(character, '\u{2028}' | '\u{2029}')
}

/// A saved preference can be edited locally and written only on explicit save.
#[derive(Debug, Clone, Copy, Default)]
pub struct SetupDraft {
    pub start_mode: LocalStartMode,
    pub saved_start_mode: Option<LocalStartMode>,
}

#[derive(Default)]
pub struct Dashboard {
    pub status: Option<LocalStatus>,
    pub workspaces: Vec<LocalWorkspaceSummary>,
    pub selected: usize,
    search_query: String,
    search_active: bool,
    search_error: Option<&'static str>,
    pub message: Option<&'static str>,
    pub details: bool,
    pub help: bool,
    pub setup_draft: Option<SetupDraft>,
    pub wizard: Option<WorkspaceWizard>,
    operations: Operations,
    pub login_open: bool,
    auth_setup: Option<AuthSetupDraft>,
    login_status: Option<LocalLoginStatus>,
    login_presentation: Option<LocalLoginPresentation>,
    login_message: Option<&'static str>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthSetupStep {
    KeychainPath,
    LinuxStorageChoice,
    ProtectedFileConsent,
    Confirm,
}
#[derive(Debug, Clone)]
struct AuthSetupDraft {
    step: AuthSetupStep,
    keychain_path: String,
    protected_file_acknowledged: bool,
    error: Option<&'static str>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WizardStep {
    Path,
    Name,
    ShareConsent,
}
#[derive(Debug, Clone)]
pub struct WorkspaceWizard {
    pub step: WizardStep,
    pub path: String,
    pub name: String,
    pub workspace_id: Option<WorkspaceId>,
    error: Option<&'static str>,
}
impl Dashboard {
    pub fn refresh(&mut self, backend: &mut impl Backend) {
        let selected_id = self
            .selected_workspace()
            .map(|workspace| workspace.workspace_id);
        self.message = None;
        match backend.request(LocalCall::Status {}) {
            Ok(LocalResult::Status(status)) => self.status = Some(status),
            _ => {
                self.status = None;
                self.message = Some("Host unavailable. Start it with: lomiremote daemon start");
            }
        }
        match backend.request(LocalCall::Workspaces {}) {
            Ok(LocalResult::Workspaces(workspaces)) => self.workspaces = workspaces.0,
            _ => {
                self.workspaces.clear();
                self.message = Some("Workspace list unavailable. Press r to retry.");
            }
        }
        let visible = self.visible_workspace_indices();
        self.selected = match selected_id {
            Some(id) => visible
                .iter()
                .position(|index| self.workspaces[*index].workspace_id == id)
                .unwrap_or(0),
            None => self.selected.min(visible.len().saturating_sub(1)),
        };
    }

    fn visible_workspace_indices(&self) -> Vec<usize> {
        let query = self.search_query.to_lowercase();
        self.workspaces
            .iter()
            .enumerate()
            .filter_map(|(index, workspace)| {
                (query.is_empty() || workspace.name.as_str().to_lowercase().contains(&query))
                    .then_some(index)
            })
            .collect()
    }

    fn selected_workspace(&self) -> Option<&LocalWorkspaceSummary> {
        let index = *self.visible_workspace_indices().get(self.selected)?;
        self.workspaces.get(index)
    }

    fn replace_search_query(&mut self, query: String) {
        let selected_id = self
            .selected_workspace()
            .map(|workspace| workspace.workspace_id);
        self.search_query = query;
        let visible = self.visible_workspace_indices();
        self.selected = selected_id
            .and_then(|id| {
                visible
                    .iter()
                    .position(|index| self.workspaces[*index].workspace_id == id)
            })
            .unwrap_or(0);
    }
    pub fn draw(&self, frame: &mut Frame) {
        if self.operations.active() {
            self.operations.draw(frame, self);
            return;
        }
        let [header, body, footer] = Layout::vertical([
            Constraint::Length(4),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .areas(frame.area());
        let header_text = if let Some(status) = &self.status {
            format!(
                "Lomi Remote  v{}\nHost: {} ({})  |  Local IPC connected\nSharing policy: {}",
                env!("CARGO_PKG_VERSION"),
                safe_label(status.host_name.as_str()),
                String::from(status.host_id),
                sharing(status.sharing)
            )
        } else {
            format!(
                "Lomi Remote  v{}\nLocal host disconnected\nRemote sharing unavailable",
                env!("CARGO_PKG_VERSION")
            )
        };
        frame.render_widget(Paragraph::new(header_text), header);
        let right = if self.setup_draft.is_some() || self.login_open || self.auth_setup.is_some() {
            body
        } else {
            Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas::<2>(body)[1]
        };
        let visible_workspaces = self.visible_workspace_indices();
        let workspace_title = if self.search_query.is_empty() {
            "Workspaces".to_owned()
        } else {
            format!("Workspaces: {}", safe_label(&self.search_query))
        };
        let items: Vec<ListItem> = visible_workspaces
            .iter()
            .enumerate()
            .filter_map(|(i, index)| self.workspaces.get(*index).map(|workspace| (i, workspace)))
            .map(|(i, workspace)| {
                ListItem::new(format!(
                    "{} {} [{}]",
                    if self.selected == i { ">" } else { " " },
                    safe_label(workspace.name.as_str()),
                    sharing(workspace.sharing)
                ))
            })
            .collect();
        if self.setup_draft.is_none() && !self.login_open && self.auth_setup.is_none() {
            let left = Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)])
                .areas::<2>(body)[0];
            frame.render_widget(
                List::new(items).block(Block::bordered().title(workspace_title)),
                left,
            );
        }
        let content = if let Some(draft) = &self.auth_setup {
            self.draw_auth_setup(draft)
        } else if self.login_open {
            let status = self.login_status.as_ref().map_or_else(
                || "Status not loaded. Press [r] to refresh.".to_owned(),
                |status| {
                    format!(
                        "Authentication: {:?}\nStorage: {:?}\nNetwork: {:?}",
                        status.phase, status.storage, status.network
                    )
                },
            );
            let presentation = self.login_presentation.as_ref().map_or_else(
                || "".to_owned(),
                |presentation| {
                    format!(
                        "\n\nVerification URL: {}\nUser code: {}\nExpires at: {}",
                        safe_label(presentation.verification_url.as_str()),
                        presentation.user_code.expose_wire(),
                        presentation.expires_at.0
                    )
                },
            );
            format!(
                "Device-code login\n\n{}{}\n\n{}\n\n[s] Start login  [r] Refresh status  [c] Configure trusted host authentication  [v] Reveal code and verification URL  [Esc] Dashboard",
                status,
                presentation,
                self.login_message.unwrap_or("")
            )
        } else if self.help {
            "Keyboard\n\nUp/Down: select workspace\n/: search workspace names; type to filter\nEnter: workspace details\na: add workspace\ns: share/unshare\np: shell profiles\nv: access\no: service\ng: doctor\nk: logs\ne: settings\nr: refresh from host\nq / Ctrl-C: close dashboard\n\nThe host keeps running after this panel closes.".to_owned()
        } else if self.search_active {
            format!(
                "Search workspace names\n\n{}Query: {}▏\n\nType to filter the workspace list. Paste is accepted only as one bounded line.\n[Enter] keep filter  [Esc] clear filter",
                self.search_error
                    .map_or_else(String::new, |error| format!("{error}\n\n")),
                safe_label(&self.search_query)
            )
        } else if let Some(draft) = self.setup_draft {
            let mode = match draft.start_mode {
                LocalStartMode::Manual => "Manual start",
                LocalStartMode::Login => "After OS login",
                LocalStartMode::Boot => "At OS boot",
            };
            let saved = match draft.saved_start_mode {
                Some(saved) if saved == draft.start_mode => "Saved preference.",
                Some(_) => "Unsaved change.",
                None => "Saved preference could not be loaded.",
            };
            format!(
                "Start preference: {}\n{} {}\n\n[m] Manual  [l] Login  [b] Boot  [s] Save preference\n\nThis only saves a preference. It does not install or start a service, enroll an account, or share a workspace.\n\n[q] close; unsaved changes are discarded",
                mode,
                saved,
                self.message.unwrap_or("")
            )
        } else if let Some(wizard) = &self.wizard {
            match wizard.step {
                WizardStep::Path => format!(
                    "Add an existing directory\n\n{}Absolute directory path:\n{}▏\n\nType path, then Enter. Esc cancels.\nNo directory will be created or moved.",
                    wizard
                        .error
                        .map(|e| format!("Error: {e}\n\n"))
                        .unwrap_or_default(),
                    safe_label(&wizard.path)
                ),
                WizardStep::Name => format!(
                    "Add an existing directory\n\n{}Display name:\n{}▏\n\nType name, then Enter. Esc cancels.",
                    wizard
                        .error
                        .map(|e| format!("Error: {e}\n\n"))
                        .unwrap_or_default(),
                    safe_label(&wizard.name)
                ),
                WizardStep::ShareConsent => format!(
                    "Workspace added locally.\n\nShare {} with approved desktop, browser, and mobile windows signed in to this account?\n\nWhen you approve a connection request, they can view/control/create/resize/close shared terminals, read/edit project files, and use Git status, diffs, history, staging, commits, fetch, fast-forward pull, and push.\n\nEditor buffers, chat, browser panes, plugins, and AI-controlled terminals stay private. Sharing does not start a shell.\n\n[y] Yes, share  [n] Keep not shared\nNo sharing occurs until you press y.",
                    safe_label(&wizard.name)
                ),
            }
        } else if let Some(message) = self.message {
            message.to_owned()
        } else if self.workspaces.is_empty() {
            "No workspaces registered.\n\n[a] Add an existing directory\nThe wizard asks for a display name and an absolute path. It then asks separately before sharing with the cloud.\n[l] Configure authentication or start device login\n\nCLI: lomiremote workspace add --name NAME --path PATH\nProject files remain on this host.".to_owned()
        } else if let Some(workspace) = self.selected_workspace() {
            format!(
                "{}\n\nWorkspace: {}\nSharing: {}\n\n[Enter] details  [a] Add existing directory  [s] Share/unshare  [p] profiles  [v] access  [o] service  [g] doctor  [k] logs  [e] settings",
                safe_label(workspace.name.as_str()),
                String::from(workspace.workspace_id),
                sharing(workspace.sharing)
            )
        } else {
            format!(
                "No workspace names match this search.\n\nQuery: {}\n[/] Edit search  [Esc] Clear search\n[a] Add an existing directory",
                safe_label(&self.search_query)
            )
        };
        frame.render_widget(
            Paragraph::new(content)
                .block(Block::bordered().title(if self.auth_setup.is_some() {
                    "Configure host authentication"
                } else if self.help {
                    "Help"
                } else if self.login_open {
                    "Device-code login"
                } else if self.details {
                    "Workspace details"
                } else {
                    "Local host"
                }))
                .wrap(Wrap { trim: false }),
            right,
        );
        frame.render_widget(
            Paragraph::new(Line::from(if let Some(draft) = &self.auth_setup {
                match draft.step {
                    AuthSetupStep::KeychainPath => {
                        "Type an existing canonical keychain path  [Enter] Continue  [Esc] Cancel"
                    }
                    AuthSetupStep::LinuxStorageChoice => {
                        "[k] Secret Service keyring  [p] Protected file  [Esc] Cancel"
                    }
                    AuthSetupStep::ProtectedFileConsent => {
                        "[y] Acknowledge permissions-only storage  [n/Esc] Cancel"
                    }
                    AuthSetupStep::Confirm => {
                        "[y] Save these public pins  [n/Esc] Cancel; login remains separate"
                    }
                }
            } else if self.login_open {
                "[s] Start login  [r] Refresh status  [c] Configure  [v] Reveal code  [Esc] Back"
            } else if self.search_active {
                "Search workspace names: type to filter  [Backspace] edit  [Enter] finish  [Esc] clear  [Paste] bounded text"
            } else if !self.search_query.is_empty() {
                "[Up/Down] select result  [/] edit search  [Esc] clear  [Enter] details  [a] add  [s] share  [p] profiles  [v] access  [o] service  [g] doctor  [k] logs  [e] settings  [r] refresh  [?] help  [q] close"
            } else {
                "[Up/Down] select  [/] search  [Enter] details  [a] add  [s] share  [p] profiles  [v] access  [o] service  [g] doctor  [k] logs  [e] settings  [l] login  [r] refresh  [?] help  [q] close"
            }))
            .block(Block::bordered()),
            footer,
        );
    }

    fn draw_auth_setup(&self, draft: &AuthSetupDraft) -> String {
        let Some(pins) = bootstrap::public_release_pins() else {
            return "This build has no embedded public host configuration.\n\nConfigure a development endpoint explicitly with the CLI.".to_owned();
        };
        let error = draft
            .error
            .map(|error| format!("Error: {error}\n\n"))
            .unwrap_or_default();
        match draft.step {
            AuthSetupStep::KeychainPath => format!(
                "{}Trusted identity origin: {}\nRemote API: {}\nRelay: {}\nPublic client ID: {}\n\nThis release's public endpoint pins will be shown again before saving.\nEnter the path to an existing canonical macOS file Keychain. Lomi will not create, unlock, or change its default.\n\nKeychain path:\n{}▏",
                error,
                safe_configuration_value(pins.identity_origin),
                safe_configuration_value(pins.remote_api_origin),
                safe_configuration_value(pins.relay_endpoint),
                safe_configuration_value(pins.client_id),
                safe_configuration_value(&draft.keychain_path),
            ),
            AuthSetupStep::ProtectedFileConsent => format!(
                "{}Trusted identity origin: {}\nRemote API: {}\nRelay: {}\nPublic client ID: {}\n\nLinux protected-file storage keeps plaintext credentials protected only by OS file permissions. Administrators and disk backups can read them.\n\nPress y only if you explicitly accept this storage policy. No credentials are created until a separate login action.",
                error,
                safe_configuration_value(pins.identity_origin),
                safe_configuration_value(pins.remote_api_origin),
                safe_configuration_value(pins.relay_endpoint),
                safe_configuration_value(pins.client_id),
            ),
            AuthSetupStep::LinuxStorageChoice => format!(
                "{}Trusted identity origin: {}\nRemote API: {}\nRelay: {}\nPublic client ID: {}\n\nChoose Linux credential storage. Secret Service requires this account's OS keyring to already be available and unlocked. Lomi will not unlock it or switch providers automatically. Protected-file storage requires a separate explicit permissions-only acknowledgement.",
                error,
                safe_configuration_value(pins.identity_origin),
                safe_configuration_value(pins.remote_api_origin),
                safe_configuration_value(pins.relay_endpoint),
                safe_configuration_value(pins.client_id),
            ),
            AuthSetupStep::Confirm => {
                let provider = match bootstrap::native_provider() {
                    NativeProvider::MacOsKeychainPathRequired => format!(
                        "macOS Keychain at {}. The keychain is not unlocked here.",
                        safe_configuration_value(&draft.keychain_path)
                    ),
                    NativeProvider::WindowsDpapi => {
                        "Windows DPAPI for the current account.".to_owned()
                    }
                    NativeProvider::LinuxStorageChoiceRequired
                        if draft.protected_file_acknowledged =>
                    {
                        "Linux protected file, acknowledged as permissions-only.".to_owned()
                    }
                    NativeProvider::LinuxStorageChoiceRequired => {
                        "Linux Secret Service for this account's unlocked keyring.".to_owned()
                    }
                    NativeProvider::Unsupported => "No native provider is available.".to_owned(),
                };
                format!(
                    "{}Configure host authentication with these public release pins?\n\nIdentity origin: {}\nRemote API origin: {}\nRelay endpoint: {}\nPublic client ID: {}\nCredential storage: {}\n\nThis saves endpoint and provider configuration only. It does not start login, unlock a keychain, or share a workspace.",
                    error,
                    safe_configuration_value(pins.identity_origin),
                    safe_configuration_value(pins.remote_api_origin),
                    safe_configuration_value(pins.relay_endpoint),
                    safe_configuration_value(pins.client_id),
                    provider,
                )
            }
        }
    }
}

impl Dashboard {
    fn handle_key(&mut self, key: event::KeyEvent, backend: &mut impl Backend) -> bool {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        if self.operations.active() {
            let mut operations = std::mem::take(&mut self.operations);
            let handled = operations.handle_key(key, backend, self);
            self.operations = operations;
            return handled;
        }
        if self.auth_setup.is_some() {
            return self.handle_auth_setup_key(key, backend);
        }
        if self.login_open {
            match key.code {
                KeyCode::Char('q') => return false,
                KeyCode::Esc => {
                    self.login_open = false;
                    self.login_presentation = None;
                }
                KeyCode::Char('s') => {
                    self.login_presentation = None;
                    let operation_id = OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes())
                        .expect("UUID v4 is a valid operation id");
                    match backend.request(LocalCall::LoginStart(
                        lomi_remote_protocol::ipc::LocalLoginStart { operation_id },
                    )) {
                        Ok(LocalResult::LoginAccepted(_)) => {
                            self.login_message = None;
                            self.refresh_login_status(backend);
                        }
                        Err("AUTH_UNCONFIGURED") | Err("AUTH_CONFIGURATION_MISSING") => {
                            self.login_message = Some(
                                "Authentication is not configured. Run: lomiremote auth configure",
                            )
                        }
                        Err("AUTH_UNAVAILABLE") | Err("LOGIN_UNAVAILABLE") => {
                            self.login_message = Some(
                                "Authentication is unavailable. Check configuration with: lomiremote auth configure",
                            )
                        }
                        _ => {
                            self.login_message = Some(
                                "Could not start login. Check configuration: lomiremote auth configure",
                            )
                        }
                    }
                }
                KeyCode::Char('c') => self.begin_auth_setup(),
                KeyCode::Char('r') => self.refresh_login_status(backend),
                KeyCode::Char('v') => match backend.request(LocalCall::LoginPresentation {}) {
                    Ok(LocalResult::LoginPresentation(presentation)) => {
                        self.login_presentation = Some(presentation);
                        self.login_message = None;
                    }
                    Err("AUTH_UNCONFIGURED") | Err("AUTH_CONFIGURATION_MISSING") => {
                        self.login_message =
                            Some("Authentication is not configured. Run: lomiremote auth configure")
                    }
                    _ => {
                        self.login_message =
                            Some("No login code is available. Start login, then try again.")
                    }
                },
                _ => {}
            }
            return true;
        }
        if let Some(wizard) = self.wizard.as_mut() {
            match wizard.step {
                WizardStep::Path | WizardStep::Name => match key.code {
                    KeyCode::Esc => self.wizard = None,
                    KeyCode::Backspace => {
                        let _ = if wizard.step == WizardStep::Path {
                            wizard.path.pop()
                        } else {
                            wizard.name.pop()
                        };
                        wizard.error = None;
                    }
                    KeyCode::Char(c)
                        if !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                    {
                        let path_mode = wizard.step == WizardStep::Path;
                        let (value, limit) = if path_mode {
                            (&mut wizard.path, WORKSPACE_PATH_MAX_BYTES)
                        } else {
                            (&mut wizard.name, WORKSPACE_NAME_MAX_BYTES)
                        };
                        if input_character_is_unsafe(c) {
                            wizard.error = Some("Control characters are not allowed.");
                        } else if value.len() + c.len_utf8() > limit {
                            wizard.error = Some(if path_mode {
                                "Directory path limit is 4096 UTF-8 bytes."
                            } else {
                                "Display name limit is 255 UTF-8 bytes."
                            });
                        } else {
                            value.push(c);
                            wizard.error = None;
                        }
                    }
                    KeyCode::Enter if wizard.step == WizardStep::Path => {
                        if std::path::Path::new(&wizard.path).is_absolute() {
                            wizard.step = WizardStep::Name;
                            wizard.error = None;
                        } else {
                            wizard.error = Some("Enter an absolute directory path.");
                        }
                    }
                    KeyCode::Enter
                        if wizard.step == WizardStep::Name && !wizard.name.trim().is_empty() =>
                    {
                        let Ok(name) = LocalProjectName::try_from(wizard.name.trim().to_owned())
                        else {
                            wizard.error =
                                Some("Display name is invalid or exceeds 255 UTF-8 bytes.");
                            return true;
                        };
                        let Ok(root_path) = LocalRootPath::try_from(wizard.path.clone()) else {
                            wizard.error =
                                Some("Directory path is invalid or exceeds 4096 UTF-8 bytes.");
                            return true;
                        };
                        match backend.request(LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
                            name,
                            root_path,
                            operator_intent: Confirmed::Confirmed,
                        })) {
                            Ok(LocalResult::Workspace(workspace)) => {
                                wizard.workspace_id = Some(workspace.workspace_id);
                                wizard.name = workspace.name.as_str().to_owned();
                                wizard.step = WizardStep::ShareConsent;
                                self.refresh(backend);
                            }
                            _ => {
                                self.message = Some("Workspace add failed. It remains not shared.");
                                self.wizard = None;
                            }
                        }
                    }
                    _ => {}
                },
                WizardStep::ShareConsent => match key.code {
                    KeyCode::Char('y') => {
                        if let Some(id) = wizard.workspace_id {
                            match backend.request(LocalCall::Share(LocalWorkspaceTarget {
                                workspace_id: id,
                                operator_intent: Confirmed::Confirmed,
                            })) {
                                Ok(LocalResult::Workspace(_)) => {
                                    self.refresh(backend);
                                    self.wizard = None;
                                }
                                _ => {
                                    self.wizard = None;
                                    self.refresh(backend);
                                    self.message =
                                        Some("Sharing failed. Workspace remains not shared.");
                                }
                            }
                        }
                    }
                    KeyCode::Char('n') | KeyCode::Esc => {
                        self.wizard = None;
                        self.refresh(backend);
                    }
                    _ => {}
                },
            }
            return true;
        }
        if let Some(draft) = self.setup_draft.as_mut() {
            match key.code {
                KeyCode::Esc => {
                    self.setup_draft = None;
                    self.message =
                        Some("Start preference editor closed; no service action was taken.");
                }
                KeyCode::Char('m') => draft.start_mode = LocalStartMode::Manual,
                KeyCode::Char('l') => draft.start_mode = LocalStartMode::Login,
                KeyCode::Char('b') => draft.start_mode = LocalStartMode::Boot,
                KeyCode::Char('s') => {
                    let preference = LocalStartModePreference {
                        start_mode: draft.start_mode,
                    };
                    match backend.request(LocalCall::SetupStartModeSave(preference.clone())) {
                        Ok(LocalResult::SetupStartMode(saved)) if saved == preference => {
                            draft.saved_start_mode = Some(saved.start_mode);
                            self.message = None;
                        }
                        _ => self.message = Some("Saving the start preference failed."),
                    }
                }
                _ => return false,
            }
            return true;
        }
        if self.search_active {
            match key.code {
                KeyCode::Esc => {
                    self.search_active = false;
                    self.search_error = None;
                    self.replace_search_query(String::new());
                }
                KeyCode::Enter => {
                    self.search_active = false;
                    self.search_error = None;
                }
                KeyCode::Backspace => {
                    let mut query = self.search_query.clone();
                    query.pop();
                    self.replace_search_query(query);
                    self.search_error = None;
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if input_character_is_unsafe(character) {
                        self.search_error = Some("Control characters cannot be searched.");
                    } else if self.search_query.len() + character.len_utf8()
                        > WORKSPACE_SEARCH_MAX_BYTES
                    {
                        self.search_error = Some("Search is limited to 255 UTF-8 bytes.");
                    } else {
                        let mut query = self.search_query.clone();
                        query.push(character);
                        self.replace_search_query(query);
                        self.search_error = None;
                    }
                }
                _ => {}
            }
            return true;
        }
        match key.code {
            KeyCode::Char('/') => {
                self.search_active = true;
                self.search_error = None;
                true
            }
            KeyCode::Esc if !self.search_query.is_empty() => {
                self.search_error = None;
                self.replace_search_query(String::new());
                true
            }
            KeyCode::Enter => {
                let workspace_id = self.selected_workspace().map(|w| w.workspace_id);
                self.operations
                    .open(Page::WorkspaceDetails, workspace_id, backend);
                true
            }
            KeyCode::Char('p') => {
                let workspace_id = self.selected_workspace().map(|w| w.workspace_id);
                self.operations
                    .open(Page::ShellProfiles, workspace_id, backend);
                true
            }
            KeyCode::Char('v') => {
                let workspace_id = self.selected_workspace().map(|w| w.workspace_id);
                self.operations.open(Page::Access, workspace_id, backend);
                true
            }
            KeyCode::Char('o') => {
                self.operations.open(Page::Service, None, backend);
                true
            }
            KeyCode::Char('g') => {
                self.operations.open(Page::Doctor, None, backend);
                true
            }
            KeyCode::Char('k') => {
                self.operations.open(Page::Logs, None, backend);
                true
            }
            KeyCode::Char('e') => {
                self.operations.open(Page::Settings, None, backend);
                true
            }
            KeyCode::Char('a') => {
                self.message = None;
                self.wizard = Some(WorkspaceWizard {
                    step: WizardStep::Path,
                    path: String::new(),
                    name: String::new(),
                    workspace_id: None,
                    error: None,
                });
                true
            }
            KeyCode::Char('l') => {
                self.login_open = true;
                self.login_status = None;
                self.login_presentation = None;
                self.login_message = None;
                true
            }
            KeyCode::Char('s') => {
                if let Some(workspace) = self.selected_workspace() {
                    self.wizard = Some(WorkspaceWizard {
                        step: WizardStep::ShareConsent,
                        path: String::new(),
                        name: workspace.name.as_str().to_owned(),
                        workspace_id: Some(workspace.workspace_id),
                        error: None,
                    });
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn handle_paste(&mut self, text: &str) -> bool {
        if self.operations.active() {
            return self.operations.handle_paste(text);
        }
        if self.search_active {
            if input_contains_terminal_control(text) {
                self.search_error = Some("Paste one line without control characters.");
            } else if self.search_query.len().saturating_add(text.len())
                > WORKSPACE_SEARCH_MAX_BYTES
            {
                self.search_error = Some("Pasted search exceeds 255 UTF-8 bytes.");
            } else {
                let mut query = self.search_query.clone();
                query.push_str(text);
                self.replace_search_query(query);
                self.search_error = None;
            }
            return true;
        }
        if let Some(wizard) = self.wizard.as_mut() {
            let (value, limit, is_path) = match wizard.step {
                WizardStep::Path => (&mut wizard.path, WORKSPACE_PATH_MAX_BYTES, true),
                WizardStep::Name => (&mut wizard.name, WORKSPACE_NAME_MAX_BYTES, false),
                WizardStep::ShareConsent => return true,
            };
            if input_contains_terminal_control(text) {
                wizard.error = Some("Paste one line without control characters.");
            } else if value.len().saturating_add(text.len()) > limit {
                wizard.error = Some(if is_path {
                    "Directory path limit is 4096 UTF-8 bytes."
                } else {
                    "Display name limit is 255 UTF-8 bytes."
                });
            } else {
                value.push_str(text);
                wizard.error = None;
            }
            return true;
        }
        if let Some(draft) = self.auth_setup.as_mut() {
            if draft.step != AuthSetupStep::KeychainPath {
                return true;
            }
            if input_contains_terminal_control(text) {
                draft.error = Some("Paste one path line without control characters.");
            } else if draft.keychain_path.len().saturating_add(text.len())
                > WORKSPACE_PATH_MAX_BYTES
            {
                draft.error = Some("Keychain path exceeds 4096 UTF-8 bytes.");
            } else {
                draft.keychain_path.push_str(text);
                draft.error = None;
            }
            return true;
        }
        false
    }

    fn refresh_login_status(&mut self, backend: &mut impl Backend) {
        match backend.request(LocalCall::LoginStatus {}) {
            Ok(LocalResult::LoginStatus(status)) => {
                self.login_status = Some(status);
                self.login_message = None;
            }
            Err("AUTH_UNCONFIGURED") | Err("AUTH_CONFIGURATION_MISSING") => {
                self.login_message =
                    Some("Authentication is not configured. Run: lomiremote auth configure")
            }
            _ => {
                self.login_message = Some(
                    "Authentication status unavailable. Check configuration: lomiremote auth configure",
                )
            }
        }
    }

    fn begin_auth_setup(&mut self) {
        if bootstrap::public_release_pins().is_none() {
            self.login_message = Some(
                "This build has no embedded public host configuration. Use explicit CLI configuration.",
            );
            return;
        }
        let step = match bootstrap::native_provider() {
            NativeProvider::MacOsKeychainPathRequired => AuthSetupStep::KeychainPath,
            NativeProvider::WindowsDpapi => AuthSetupStep::Confirm,
            NativeProvider::LinuxStorageChoiceRequired => AuthSetupStep::LinuxStorageChoice,
            NativeProvider::Unsupported => {
                self.login_message = Some("No supported native credential provider is available.");
                return;
            }
        };
        self.login_message = None;
        self.auth_setup = Some(AuthSetupDraft {
            step,
            keychain_path: String::new(),
            protected_file_acknowledged: false,
            error: None,
        });
    }

    fn handle_auth_setup_key(&mut self, key: event::KeyEvent, backend: &mut impl Backend) -> bool {
        let Some(mut draft) = self.auth_setup.take() else {
            return true;
        };
        if key.code == KeyCode::Esc {
            self.login_message = Some("Authentication configuration was not changed.");
            return true;
        }
        match draft.step {
            AuthSetupStep::KeychainPath => match key.code {
                KeyCode::Backspace => {
                    draft.keychain_path.pop();
                    draft.error = None;
                    self.auth_setup = Some(draft);
                }
                KeyCode::Char(character)
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    if input_character_is_unsafe(character) {
                        draft.error = Some("Control characters are not allowed in the path.");
                    } else if draft.keychain_path.len() + character.len_utf8()
                        > WORKSPACE_PATH_MAX_BYTES
                    {
                        draft.error = Some("Keychain path exceeds 4096 UTF-8 bytes.");
                    } else {
                        draft.keychain_path.push(character);
                        draft.error = None;
                    }
                    self.auth_setup = Some(draft);
                }
                KeyCode::Enter => {
                    let path = Path::new(&draft.keychain_path);
                    if !path.is_absolute() {
                        draft.error = Some("Enter an absolute path to an existing Keychain file.");
                    } else {
                        match bootstrap::default_auth_configuration(Some(path), false) {
                            Ok(_) => {
                                draft.step = AuthSetupStep::Confirm;
                                draft.error = None;
                            }
                            Err(error) => draft.error = Some(bootstrap_error_message(error)),
                        }
                    }
                    self.auth_setup = Some(draft);
                }
                _ => self.auth_setup = Some(draft),
            },
            AuthSetupStep::ProtectedFileConsent => match key.code {
                KeyCode::Char('y') => {
                    draft.protected_file_acknowledged = true;
                    draft.step = AuthSetupStep::Confirm;
                    draft.error = None;
                    self.auth_setup = Some(draft);
                }
                KeyCode::Char('n') => {
                    self.login_message = Some("Protected-file storage was not acknowledged.");
                }
                _ => self.auth_setup = Some(draft),
            },
            AuthSetupStep::LinuxStorageChoice => match key.code {
                KeyCode::Char('k') | KeyCode::Char('K') => {
                    draft.protected_file_acknowledged = false;
                    draft.step = AuthSetupStep::Confirm;
                    draft.error = None;
                    self.auth_setup = Some(draft);
                }
                KeyCode::Char('p')
                | KeyCode::Char('P')
                | KeyCode::Char('b')
                | KeyCode::Char('B') => {
                    draft.protected_file_acknowledged = false;
                    draft.step = AuthSetupStep::ProtectedFileConsent;
                    draft.error = None;
                    self.auth_setup = Some(draft);
                }
                _ => self.auth_setup = Some(draft),
            },
            AuthSetupStep::Confirm => match key.code {
                KeyCode::Char('y') => {
                    let keychain_path =
                        (!draft.keychain_path.is_empty()).then(|| Path::new(&draft.keychain_path));
                    match bootstrap::default_auth_configuration(
                        keychain_path,
                        draft.protected_file_acknowledged,
                    ) {
                        Ok(configuration) => {
                            let request = LocalCall::AuthConfigure(LocalAuthConfigure {
                                configuration,
                                operator_intent: Confirmed::Confirmed,
                            });
                            match backend.request(request) {
                                Ok(LocalResult::AuthConfigured {}) => {
                                    self.auth_setup = None;
                                    self.refresh_login_status(backend);
                                    self.login_message = Some(
                                        "Configuration saved. Press s when you are ready to start device login.",
                                    );
                                }
                                _ => {
                                    draft.error = Some(
                                        "Host rejected the configuration. No login was started.",
                                    );
                                    self.auth_setup = Some(draft);
                                }
                            }
                        }
                        Err(error) => {
                            draft.error = Some(bootstrap_error_message(error));
                            self.auth_setup = Some(draft);
                        }
                    }
                }
                KeyCode::Char('n') => {
                    self.login_message = Some("Authentication configuration was not changed.");
                }
                _ => self.auth_setup = Some(draft),
            },
        }
        true
    }
}

fn bootstrap_error_message(error: BootstrapError) -> &'static str {
    match error {
        BootstrapError::ConfigurationRequired => "Public host pins are not embedded in this build.",
        BootstrapError::ProtectedFileConsentRequired => {
            "Acknowledge the permissions-only storage warning before continuing."
        }
        BootstrapError::KeychainPathRequired => "Enter the existing macOS Keychain file path.",
        BootstrapError::InvalidKeychainPath => {
            "Keychain path must name an existing canonical file."
        }
        BootstrapError::UnexpectedKeychainPath
        | BootstrapError::UnexpectedProtectedFileAcknowledgement
        | BootstrapError::UnsupportedProvider => {
            "This platform's native provider selection is invalid."
        }
        BootstrapError::InvalidCompiledConfiguration => {
            "Embedded public host configuration is invalid."
        }
    }
}
fn sharing(value: LocalSharing) -> &'static str {
    match value {
        LocalSharing::Disabled => "Local",
        LocalSharing::Enabled => "Shared",
    }
}

pub(crate) trait Cleanup {
    fn bracketed_paste(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn raw(&mut self) -> io::Result<()>;
    fn alternate(&mut self) -> io::Result<()>;
    fn cursor(&mut self) -> io::Result<()>;
}
pub(crate) struct NativeCleanup;
impl Cleanup for NativeCleanup {
    fn bracketed_paste(&mut self) -> io::Result<()> {
        execute!(io::stdout(), DisableBracketedPaste)
    }
    fn raw(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
    fn alternate(&mut self) -> io::Result<()> {
        execute!(io::stdout(), LeaveAlternateScreen)
    }
    fn cursor(&mut self) -> io::Result<()> {
        execute!(io::stdout(), Show)
    }
}
pub(crate) struct RestoreGuard<C: Cleanup>(C);
pub(crate) fn restore_guard() -> RestoreGuard<NativeCleanup> {
    RestoreGuard(NativeCleanup)
}
impl<C: Cleanup> Drop for RestoreGuard<C> {
    fn drop(&mut self) {
        // Never short-circuit restoration after an earlier cleanup error.
        let _ = self.0.bracketed_paste();
        let _ = self.0.raw();
        let _ = self.0.alternate();
        let _ = self.0.cursor();
    }
}

pub fn run(backend: &mut impl Backend) -> io::Result<()> {
    run_dashboard(backend, Dashboard::default())
}
pub fn run_setup(backend: &mut impl Backend) -> io::Result<()> {
    let draft = load_setup_draft(backend);
    run_dashboard(
        backend,
        Dashboard {
            setup_draft: Some(draft),
            ..Dashboard::default()
        },
    )
}
fn load_setup_draft(backend: &mut impl Backend) -> SetupDraft {
    let (start_mode, saved_start_mode) = match backend.request(LocalCall::SetupStartModeRead {}) {
        Ok(LocalResult::SetupStartMode(preference)) => {
            (preference.start_mode, Some(preference.start_mode))
        }
        _ => (LocalStartMode::Manual, None),
    };
    SetupDraft {
        start_mode,
        saved_start_mode,
    }
}
fn run_dashboard(backend: &mut impl Backend, state: Dashboard) -> io::Result<()> {
    // Construct before try_init: partial initialization also needs independent
    // raw/alternate/cursor restoration. No process::exit while this guard lives.
    let _restore = RestoreGuard(NativeCleanup);
    let mut terminal = ratatui::try_init()?;
    execute!(io::stdout(), EnableBracketedPaste)?;
    run_loop(&mut terminal, backend, state)
}
fn run_loop<B: TerminalBackend>(
    terminal: &mut Terminal<B>,
    backend: &mut impl Backend,
    mut state: Dashboard,
) -> io::Result<()>
where
    B::Error: Into<io::Error>,
{
    state.refresh(backend);
    let mut changed = true;
    loop {
        if changed {
            terminal
                .draw(|frame| state.draw(frame))
                .map_err(Into::into)?;
            changed = false;
        }
        // One thread owns polling and reading. Idle does not redraw continuously.
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if state.handle_key(key, backend) {
                    changed = true;
                    continue;
                }
                match key.code {
                    KeyCode::Char('q') => return Ok(()),
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Ok(());
                    }
                    KeyCode::Up => state.selected = state.selected.saturating_sub(1),
                    KeyCode::Down => {
                        state.selected = (state.selected + 1)
                            .min(state.visible_workspace_indices().len().saturating_sub(1))
                    }
                    KeyCode::Enter => state.details = !state.details,
                    KeyCode::Char('?') => state.help = !state.help,
                    KeyCode::Char('r') => state.refresh(backend),
                    KeyCode::Char('a' | 's' | 'l') => {
                        state.handle_key(key, backend);
                    }
                    _ => continue,
                }
                changed = true;
            }
            Event::Paste(text) => {
                changed = state.handle_paste(&text);
            }
            Event::Resize(..) => changed = true,
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::ipc::{LocalStatus, LocalWorkspaceSummary};
    use lomi_remote_protocol::{HostId, RuntimeId, WorkspaceId};
    use std::{cell::RefCell, rc::Rc};

    struct Fake {
        calls: Vec<LocalCall>,
        added: bool,
        shared: bool,
        fail_add: bool,
        fail_share: bool,
    }
    impl Backend for Fake {
        fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
            self.calls.push(call.clone());
            match call {
                LocalCall::Status {} => Ok(LocalResult::Status(LocalStatus {
                    host_id: HostId::try_from("11111111-1111-4111-8111-111111111111".to_owned())
                        .unwrap(),
                    runtime_id: RuntimeId::try_from(
                        "11111111-1111-4111-8111-111111111111".to_owned(),
                    )
                    .unwrap(),
                    sharing: LocalSharing::Disabled,
                })),
                LocalCall::SetupStartModeRead {} => {
                    Ok(LocalResult::SetupStartMode(LocalStartModePreference {
                        start_mode: LocalStartMode::Manual,
                    }))
                }
                LocalCall::SetupStartModeSave(preference) => {
                    Ok(LocalResult::SetupStartMode(preference))
                }
                LocalCall::LoginStart(params) => Ok(LocalResult::LoginAccepted(
                    lomi_remote_protocol::ipc::LocalLoginAccepted {
                        operation_id: params.operation_id,
                        generation: lomi_remote_protocol::DecimalU64(1),
                    },
                )),
                LocalCall::LoginStatus {} => Ok(LocalResult::LoginStatus(LocalLoginStatus {
                    phase: lomi_remote_protocol::ipc::LocalAuthPhase::AwaitingApproval,
                    storage: lomi_remote_protocol::ipc::LocalAuthStorage::Available,
                    network: lomi_remote_protocol::ipc::LocalAuthNetwork::Available,
                    generation: lomi_remote_protocol::DecimalU64(1),
                    locked: false,
                    pending_cloud_revoke: false,
                    operation_id: None,
                    access_expires_at: None,
                    refresh_at: None,
                })),
                LocalCall::LoginPresentation {} => {
                    Ok(LocalResult::LoginPresentation(LocalLoginPresentation {
                        user_code: lomi_remote_protocol::http::UserCode::try_from(
                            "TEST-USER-CODE".to_owned(),
                        )
                        .unwrap(),
                        verification_url: LocalRootPath::try_from(
                            "https://login.example/verify".to_owned(),
                        )
                        .unwrap(),
                        expires_at: lomi_remote_protocol::DecimalU64(2),
                        next_poll_at: lomi_remote_protocol::DecimalU64(1),
                    }))
                }
                LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(
                    lomi_remote_protocol::rpc::BoundedList(vec![summary(self.shared)]),
                )),
                LocalCall::WorkspaceAdd(_) if self.fail_add => Err("LOCAL_REQUEST_REJECTED"),
                LocalCall::WorkspaceAdd(_) => {
                    self.added = true;
                    Ok(LocalResult::Workspace(summary(false)))
                }
                LocalCall::Share(_) if self.fail_share => Err("LOCAL_REQUEST_REJECTED"),
                LocalCall::Share(_) => {
                    self.shared = true;
                    Ok(LocalResult::Workspace(summary(true)))
                }
                _ => Err("unexpected call"),
            }
        }
    }
    fn summary(shared: bool) -> LocalWorkspaceSummary {
        LocalWorkspaceSummary {
            workspace_id: WorkspaceId::try_from("11111111-1111-4111-8111-111111111111".to_owned())
                .unwrap(),
            name: LocalProjectName::try_from("project".to_owned()).unwrap(),
            sharing: if shared {
                LocalSharing::Enabled
            } else {
                LocalSharing::Disabled
            },
        }
    }
    fn key(code: KeyCode) -> event::KeyEvent {
        event::KeyEvent::new(code, KeyModifiers::NONE)
    }
    fn key_with_modifiers(code: KeyCode, modifiers: KeyModifiers) -> event::KeyEvent {
        event::KeyEvent::new(code, modifiers)
    }

    fn fake() -> Fake {
        Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        }
    }

    fn screen(terminal: &Terminal<ratatui::backend::TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn login_start_is_explicit_and_does_not_fetch_presentation() {
        let mut backend = fake();
        let mut state = Dashboard::default();
        state.handle_key(key(KeyCode::Char('l')), &mut backend);
        assert!(backend.calls.is_empty());
        state.handle_key(key(KeyCode::Char('s')), &mut backend);
        assert!(matches!(
            backend.calls.first(),
            Some(LocalCall::LoginStart(_))
        ));
        assert!(
            backend
                .calls
                .iter()
                .any(|call| matches!(call, LocalCall::LoginStatus {}))
        );
        assert!(
            !backend
                .calls
                .iter()
                .any(|call| matches!(call, LocalCall::LoginPresentation {}))
        );
        assert!(state.login_presentation.is_none());
        assert!(state.login_open);
    }

    #[test]
    fn login_status_refresh_does_not_fetch_or_reveal_code() {
        let mut backend = fake();
        let mut state = Dashboard {
            login_open: true,
            ..Dashboard::default()
        };
        state.handle_key(key(KeyCode::Char('r')), &mut backend);
        assert!(matches!(
            backend.calls.as_slice(),
            [LocalCall::LoginStatus {}]
        ));
        assert!(state.login_presentation.is_none());
    }

    #[test]
    fn login_code_requires_reveal_key_and_escape_returns_to_dashboard() {
        let mut backend = fake();
        let mut state = Dashboard {
            login_open: true,
            ..Dashboard::default()
        };
        state.handle_key(key(KeyCode::Char('s')), &mut backend);
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| state.draw(frame)).unwrap();
        assert!(!screen(&terminal).contains("TEST-USER-CODE"));
        state.handle_key(key(KeyCode::Char('r')), &mut backend);
        assert!(
            !backend
                .calls
                .iter()
                .any(|call| matches!(call, LocalCall::LoginPresentation {}))
        );
        state.handle_key(key(KeyCode::Char('v')), &mut backend);
        assert!(matches!(
            backend.calls.last(),
            Some(LocalCall::LoginPresentation {})
        ));
        terminal.draw(|frame| state.draw(frame)).unwrap();
        assert!(screen(&terminal).contains("TEST-USER-CODE"));
        let presentations_before_escape = backend
            .calls
            .iter()
            .filter(|call| matches!(call, LocalCall::LoginPresentation {}))
            .count();
        state.handle_key(key(KeyCode::Esc), &mut backend);
        assert!(!state.login_open);
        assert!(state.login_presentation.is_none());
        terminal.draw(|frame| state.draw(frame)).unwrap();
        assert!(!screen(&terminal).contains("TEST-USER-CODE"));
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|call| matches!(call, LocalCall::LoginPresentation {}))
                .count(),
            presentations_before_escape
        );
    }

    #[test]
    fn q_closes_from_the_login_panel() {
        let mut backend = fake();
        let mut state = Dashboard {
            login_open: true,
            ..Dashboard::default()
        };
        assert!(!state.handle_key(key(KeyCode::Char('q')), &mut backend));
    }

    #[test]
    fn setup_persists_only_after_explicit_save_and_keeps_unsaved_draft_on_close() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        let mut state = Dashboard {
            setup_draft: Some(SetupDraft {
                start_mode: LocalStartMode::Manual,
                saved_start_mode: Some(LocalStartMode::Manual),
            }),
            ..Dashboard::default()
        };
        state.handle_key(key(KeyCode::Char('b')), &mut backend);
        assert!(backend.calls.is_empty());
        assert_eq!(state.setup_draft.unwrap().start_mode, LocalStartMode::Boot);
        assert!(!state.handle_key(key(KeyCode::Char('q')), &mut backend));
        assert!(backend.calls.is_empty());
        state.handle_key(key(KeyCode::Char('s')), &mut backend);
        assert_eq!(
            backend.calls,
            vec![LocalCall::SetupStartModeSave(LocalStartModePreference {
                start_mode: LocalStartMode::Boot,
            })]
        );
        assert_eq!(
            state.setup_draft.unwrap().saved_start_mode,
            Some(LocalStartMode::Boot)
        );
    }

    #[test]
    fn opening_setup_loads_the_saved_start_mode() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        let draft = load_setup_draft(&mut backend);
        assert_eq!(draft.start_mode, LocalStartMode::Manual);
        assert_eq!(draft.saved_start_mode, Some(LocalStartMode::Manual));
        assert!(matches!(
            backend.calls.as_slice(),
            [LocalCall::SetupStartModeRead {}]
        ));
    }
    fn add_and_reach_consent(state: &mut Dashboard, backend: &mut Fake) {
        state.handle_key(key(KeyCode::Char('a')), backend);
        for c in "/tmp/project".chars() {
            state.handle_key(key(KeyCode::Char(c)), backend);
        }
        state.handle_key(key(KeyCode::Enter), backend);
        for c in "project".chars() {
            state.handle_key(key(KeyCode::Char(c)), backend);
        }
        state.handle_key(key(KeyCode::Enter), backend);
    }

    #[test]
    fn empty_dashboard_explains_the_first_workspace_and_separate_share_consent() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        let mut state = Dashboard::default();
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(100, 24)).unwrap();
        terminal.draw(|frame| state.draw(frame)).unwrap();
        let snapshot = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(snapshot.contains("[a] Add an existing directory"));
        assert!(snapshot.contains("asks separately before sharing with the cloud"));

        state.handle_key(key(KeyCode::Char('a')), &mut backend);
        assert_eq!(state.wizard.as_ref().unwrap().step, WizardStep::Path);
        assert!(backend.calls.is_empty());
        assert!(!backend.shared);
    }

    #[test]
    fn add_waits_for_explicit_share_consent_and_refresh_confirms_shared() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        let mut state = Dashboard::default();
        add_and_reach_consent(&mut state, &mut backend);
        assert!(backend.added);
        assert!(!backend.shared);
        assert!(
            !backend
                .calls
                .iter()
                .any(|c| matches!(c, LocalCall::Share(_)))
        );
        state.handle_key(key(KeyCode::Char('y')), &mut backend);
        assert!(backend.shared);
        assert!(
            state
                .workspaces
                .iter()
                .any(|w| w.sharing == LocalSharing::Enabled)
        );
    }

    #[test]
    fn share_failure_keeps_workspace_not_shared_and_reports_error() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: true,
        };
        let mut state = Dashboard::default();
        add_and_reach_consent(&mut state, &mut backend);
        state.handle_key(key(KeyCode::Char('y')), &mut backend);
        assert!(!backend.shared);
        assert_eq!(
            state.message,
            Some("Sharing failed. Workspace remains not shared.")
        );
        assert!(
            state
                .workspaces
                .iter()
                .all(|w| w.sharing == LocalSharing::Disabled)
        );
    }

    #[test]
    fn add_failure_surfaces_error_without_sharing() {
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: true,
            fail_share: false,
        };
        let mut state = Dashboard::default();
        add_and_reach_consent(&mut state, &mut backend);
        assert!(!backend.shared);
        assert_eq!(
            state.message,
            Some("Workspace add failed. It remains not shared.")
        );
        assert!(
            !backend
                .calls
                .iter()
                .any(|c| matches!(c, LocalCall::Share(_)))
        );
    }

    #[test]
    fn wizard_draws_without_panicking_in_a_small_terminal() {
        let mut state = Dashboard::default();
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        state.handle_key(key(KeyCode::Char('a')), &mut backend);
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(32, 8)).unwrap();
        terminal.draw(|frame| state.draw(frame)).unwrap();
        assert_eq!(terminal.backend().buffer().area.width, 32);
        assert_eq!(terminal.backend().buffer().area.height, 8);
    }

    #[test]
    fn wizard_input_is_byte_bounded_and_limit_error_is_visible() {
        let mut state = Dashboard::default();
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        state.wizard = Some(WorkspaceWizard {
            step: WizardStep::Name,
            path: "/tmp/project".to_owned(),
            name: String::new(),
            workspace_id: None,
            error: None,
        });
        for _ in 0..(WORKSPACE_NAME_MAX_BYTES / 2) {
            state.handle_key(key(KeyCode::Char('é')), &mut backend);
        }
        let wizard = state.wizard.as_ref().unwrap();
        assert_eq!(wizard.name.len(), 254);
        state.handle_key(key(KeyCode::Char('é')), &mut backend);
        let wizard = state.wizard.as_ref().unwrap();
        assert_eq!(wizard.name.len(), 254);
        assert_eq!(wizard.error, Some("Display name limit is 255 UTF-8 bytes."));
        let mut terminal = Terminal::new(ratatui::backend::TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| state.draw(frame)).unwrap();
        let snapshot = terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect::<String>();
        assert!(snapshot.contains("Display name limit is 255 UTF-8 bytes"));
    }

    #[test]
    fn ctrl_c_bubbles_out_of_wizard_and_keeps_draft_intact() {
        let mut state = Dashboard::default();
        let mut backend = Fake {
            calls: vec![],
            added: false,
            shared: false,
            fail_add: false,
            fail_share: false,
        };
        state.handle_key(key(KeyCode::Char('a')), &mut backend);
        let handled = state.handle_key(
            key_with_modifiers(KeyCode::Char('c'), KeyModifiers::CONTROL),
            &mut backend,
        );
        assert!(!handled);
        assert_eq!(state.wizard.as_ref().unwrap().step, WizardStep::Path);
        assert!(backend.calls.is_empty());
    }
    struct Trace(Rc<RefCell<Vec<&'static str>>>);
    impl Cleanup for Trace {
        fn raw(&mut self) -> io::Result<()> {
            self.0.borrow_mut().push("raw");
            Err(io::Error::other("synthetic raw cleanup failure"))
        }
        fn alternate(&mut self) -> io::Result<()> {
            self.0.borrow_mut().push("alternate");
            Ok(())
        }
        fn cursor(&mut self) -> io::Result<()> {
            self.0.borrow_mut().push("cursor");
            Ok(())
        }
    }
    #[test]
    fn guard_restores_all_terminal_parts_on_early_return_and_unwind() {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let partial = || -> io::Result<()> {
            let _guard = RestoreGuard(Trace(trace.clone()));
            Err(io::Error::other("synthetic setup failure"))
        };
        assert!(partial().is_err());
        assert_eq!(&*trace.borrow(), &["raw", "alternate", "cursor"]);
        trace.borrow_mut().clear();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = RestoreGuard(Trace(trace.clone()));
            panic!("synthetic");
        }));
        assert!(result.is_err());
        assert_eq!(&*trace.borrow(), &["raw", "alternate", "cursor"]);
    }
}
