//! The dashboard is an IPC client. Closing it never stops the host.
use crate::bootstrap::{self, BootstrapError, NativeProvider};
use crate::diagnostics::{DiagnosticReport, DiagnosticReportBuilder, DiagnosticRunMode};
use crossterm::{
    cursor::Show,
    event::{
        self, DisableBracketedPaste, DisableFocusChange, DisableMouseCapture, EnableBracketedPaste,
        EnableFocusChange, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
        MouseEvent, MouseEventKind,
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
    layout::{Constraint, Layout, Rect},
    style::Style,
    text::{Line, Span},
    widgets::{List, ListItem, ListState, Paragraph, Wrap},
};
use std::{cell::Cell, io, path::Path, time::Duration};

mod directory_picker;
pub(crate) mod interaction;
#[cfg(test)]
mod navigation_tests;
pub mod operations;
pub(crate) mod pointer;
mod sharing_dialog;
#[cfg(test)]
mod sharing_tests;
mod shortcuts;
pub(crate) mod theme;
mod workspace_form;
#[cfg(test)]
mod workspace_form_tests;
mod workspace_panel;
#[cfg(test)]
mod workspace_panel_integration_tests;
use directory_picker::{DirectoryPicker, PickerAction};
use interaction::{Action, Controls};
use operations::{
    CurrentAccessSnapshot, Operations, Page, ServiceAction, ServiceSnapshot,
    UiDiagnosticLogSnapshot,
};
use pointer::PointerTracker;
use workspace_form::{FormAction, WorkspaceForm};
use workspace_panel::{PanelAction, WorkspacePanel, WorkspaceTab};

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

fn workspace_name_label(name: &str, width: usize) -> String {
    let name = safe_label(name);
    let label = Span::raw(&name);
    if label.width() <= width {
        return name;
    }
    if width == 0 {
        return String::new();
    }
    let mut shortened = String::new();
    let mut columns = 0;
    for grapheme in label.styled_graphemes(Style::default()) {
        let grapheme_width = Span::raw(grapheme.symbol).width();
        if columns + grapheme_width > width - 1 {
            break;
        }
        shortened.push_str(grapheme.symbol);
        columns += grapheme_width;
    }
    shortened.push('…');
    shortened
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
    workspace_panel: WorkspacePanel,
    focus: DashboardFocus,
    footer_from_panel: bool,
    controls: Controls,
    frame_area: Cell<Rect>,
    sidebar_area: Cell<Rect>,
    content_area: Cell<Rect>,
    content_scroll: usize,
    content_max_scroll: Cell<usize>,
    quit_requested: bool,
    pub status: Option<LocalStatus>,
    pub workspaces: Vec<LocalWorkspaceSummary>,
    pub selected: usize,
    search_query: String,
    search_active: bool,
    search_error: Option<&'static str>,
    pub message: Option<&'static str>,
    pub help: bool,
    help_scroll: usize,
    help_max_scroll: Cell<usize>,
    sharing_confirmation: Option<SharingConfirmation>,
    pub setup_draft: Option<SetupDraft>,
    workspace_form: Option<WorkspaceForm>,
    directory_picker: Option<DirectoryPicker>,
    operations: Operations,
    pub login_open: bool,
    auth_setup: Option<AuthSetupDraft>,
    login_status: Option<LocalLoginStatus>,
    login_presentation: Option<LocalLoginPresentation>,
    login_message: Option<&'static str>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum DashboardFocus {
    #[default]
    Sidebar,
    Panel,
    Footer,
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
struct SharingConfirmation {
    workspace_id: WorkspaceId,
    name: String,
    share: bool,
    confirm_selected: bool,
    scroll: usize,
    max_scroll: Cell<usize>,
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
        self.bind_workspace_panel(backend, true);
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
        self.frame_area.set(frame.area());
        self.controls.begin();
        self.draw_dashboard(frame);
        if self.help {
            self.help_max_scroll
                .set(shortcuts::draw(frame, self.help_scroll, &self.controls));
            self.controls.highlight(frame);
        } else if let Some(confirmation) = &self.sharing_confirmation {
            confirmation.max_scroll.set(sharing_dialog::draw(
                frame,
                &safe_label(&confirmation.name),
                confirmation.share,
                confirmation.confirm_selected,
                confirmation.scroll,
                &self.controls,
            ));
        } else if let Some(picker) = &self.directory_picker {
            picker.draw(frame);
        } else {
            self.controls.highlight(frame);
        }
    }

    fn draw_dashboard(&self, frame: &mut Frame) {
        theme::canvas(frame);
        let footer_height = if frame.area().width < 80 { 5 } else { 3 };
        let [body, footer] =
            Layout::vertical([Constraint::Min(4), Constraint::Length(footer_height)])
                .areas(frame.area());
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(25), Constraint::Percentage(75)])
                .areas::<2>(body);
        self.sidebar_area.set(left);
        self.content_area.set(right);
        let visible_workspaces = self.visible_workspace_indices();
        let focused_workspace = if self.workspace_view_active() && !self.overlay_active() {
            match self.controls.focused() {
                Some(Action::Row(index)) => Some(index),
                None if self.focus == DashboardFocus::Sidebar => Some(self.selected),
                _ => None,
            }
        } else {
            None
        };
        let items: Vec<ListItem> = visible_workspaces
            .iter()
            .enumerate()
            .filter_map(|(i, index)| self.workspaces.get(*index).map(|workspace| (i, workspace)))
            .map(|(i, workspace)| {
                let selected = self.selected == i;
                let focused = focused_workspace == Some(i);
                let name_style = if selected || focused {
                    theme::selection_style(focused)
                } else {
                    Style::default().fg(theme::SECONDARY).bg(theme::SIDEBAR)
                };
                let background = name_style.bg.unwrap_or(theme::SIDEBAR);
                let indent = 1;
                let name_width =
                    usize::from(left.width.saturating_sub(2)).saturating_sub(indent + 1);
                let shared = workspace.sharing == LocalSharing::Enabled;
                ListItem::new(vec![
                    Line::from(vec![
                        Span::raw(" ".repeat(indent)),
                        Span::styled(
                            workspace_name_label(workspace.name.as_str(), name_width),
                            name_style,
                        ),
                    ])
                    .style(Style::default().bg(background)),
                    Line::from(vec![
                        Span::raw(" ".repeat(indent)),
                        Span::styled(
                            if shared { "Sharing enabled" } else { "Offline" },
                            Style::default().fg(if shared { theme::SUCCESS } else { theme::MUTED }),
                        ),
                    ])
                    .style(Style::default().bg(background)),
                    Line::styled("", Style::default().bg(theme::SIDEBAR)),
                ])
                .style(Style::default().bg(theme::SIDEBAR))
            })
            .collect();
        {
            let mut list_state = ListState::default()
                .with_selected((!visible_workspaces.is_empty()).then_some(self.selected));
            frame.render_stateful_widget(
                List::new(items).block(theme::panel("", theme::SIDEBAR)),
                left,
                &mut list_state,
            );
            if self.can_select_workspace() && !self.overlay_active() {
                let inner = theme::panel("", theme::SIDEBAR).inner(left);
                for index in list_state.offset()..visible_workspaces.len() {
                    let y = inner.y.saturating_add(
                        ((index - list_state.offset()) * 3).min(usize::from(u16::MAX)) as u16,
                    );
                    if y.saturating_add(3) > inner.bottom() {
                        break;
                    }
                    self.controls
                        .row(Rect::new(inner.x, y, inner.width, 3), index);
                }
            }
        }
        if self.operations.active() {
            self.operations.draw(frame, self, right, footer);
            return;
        }
        if let Some(form) = &self.workspace_form {
            form.draw(frame, right, self.directory_picker.is_none());
            let targets = theme::render_footer(
                frame,
                footer,
                &[("tab", "Next field")],
                &[("esc", "Cancel")],
            );
            if !self.overlay_active() {
                self.controls.extend(targets);
            }
            return;
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
        } else if let Some(message) = self.message {
            message.to_owned()
        } else if self.workspaces.is_empty() {
            "No workspaces registered.\n\n[a] Add workspace\nEnter a name and select an existing directory. Sharing requires separate confirmation.\n[l] Configure authentication or start device login\n\nCLI: lomiremote workspace add --name NAME --path PATH\nProject files remain on this host.".to_owned()
        } else if self.selected_workspace().is_some() {
            String::new()
        } else {
            format!(
                "No workspace names match this search.\n\nQuery: {}\n[/] Edit search  [Esc] Clear search\n[a] Add an existing directory",
                safe_label(&self.search_query)
            )
        };
        let panel = theme::panel(
            if self.auth_setup.is_some() {
                "Configure host authentication"
            } else if self.login_open {
                "Device-code login"
            } else {
                ""
            },
            theme::CANVAS,
        );
        let inner = panel.inner(right);
        let paragraph = Paragraph::new(theme::content(&content)).wrap(Wrap { trim: false });
        let max_scroll = paragraph
            .line_count(inner.width)
            .saturating_sub(usize::from(inner.height));
        self.content_max_scroll.set(max_scroll);
        if self.workspace_view_active() {
            self.workspace_panel.draw(
                frame,
                right,
                self.focus == DashboardFocus::Panel && !self.overlay_active(),
                self.message,
            );
        } else {
            frame.render_widget(
                paragraph.block(panel).scroll((
                    self.content_scroll
                        .min(max_scroll)
                        .min(usize::from(u16::MAX)) as u16,
                    0,
                )),
                right,
            );
        }
        let mut workspace_hints = vec![
            ("↑↓", "Select"),
            ("←→", "Navigate"),
            ("/", "Search"),
            ("a", "Add workspace"),
        ];
        if let Some(workspace) = self.selected_workspace() {
            workspace_hints.push((
                "s",
                if workspace.sharing == LocalSharing::Enabled {
                    "Unshare"
                } else {
                    "Share"
                },
            ));
        }
        let (primary, trailing): (&[(&str, &str)], &[(&str, &str)]) =
            if let Some(draft) = &self.auth_setup {
                match draft.step {
                    AuthSetupStep::KeychainPath => (&[("enter", "Continue")], &[("esc", "Cancel")]),
                    AuthSetupStep::LinuxStorageChoice => (
                        &[("k", "Keyring"), ("p", "Protected file")],
                        &[("esc", "Cancel")],
                    ),
                    AuthSetupStep::ProtectedFileConsent => {
                        (&[("y", "Acknowledge")], &[("n / esc", "Cancel")])
                    }
                    AuthSetupStep::Confirm => (&[("y", "Save")], &[("n / esc", "Cancel")]),
                }
            } else if self.setup_draft.is_some() {
                (
                    &[
                        ("m", "Manual"),
                        ("l", "Login"),
                        ("b", "Boot"),
                        ("s", "Save"),
                    ],
                    &[("esc", "Back")],
                )
            } else if self.login_open {
                (
                    &[
                        ("s", "Start login"),
                        ("r", "Refresh"),
                        ("c", "Configure"),
                        ("v", "Show code"),
                    ],
                    &[("esc", "Back")],
                )
            } else if self.search_active {
                (
                    &[("enter", "Apply filter"), ("backspace", "Edit")],
                    &[("esc", "Clear")],
                )
            } else if !self.search_query.is_empty() {
                (
                    &workspace_hints,
                    &[("esc", "Clear"), ("?", "Shortcuts"), ("q", "Quit")],
                )
            } else {
                (&workspace_hints, &[("?", "Shortcuts"), ("q", "Quit")])
            };
        let targets = theme::render_footer(frame, footer, primary, trailing);
        if !self.overlay_active() {
            self.controls.extend(targets);
        }
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
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
            && matches!(key.code, KeyCode::Enter | KeyCode::Tab | KeyCode::BackTab)
        {
            return true;
        }
        if matches!(
            key.code,
            KeyCode::Char(_) | KeyCode::Backspace | KeyCode::Delete
        ) {
            self.controls.blur();
        }
        if self.help {
            if matches!(
                key.code,
                KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
            ) {
                if !self.controls.move_focus(key.code) {
                    let max_scroll = self.help_max_scroll.get();
                    if key.code == KeyCode::Down {
                        self.help_scroll = self.help_scroll.saturating_add(1).min(max_scroll);
                    } else if key.code == KeyCode::Up {
                        self.help_scroll = self.help_scroll.min(max_scroll).saturating_sub(1);
                    }
                }
                return true;
            }
            if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
                self.controls.cycle(key.code == KeyCode::BackTab);
                return true;
            }
            if key.code == KeyCode::Enter {
                if let Some(action) = self.controls.focused() {
                    self.activate_help_control(action, backend);
                }
                return true;
            }
            let max_scroll = self.help_max_scroll.get();
            self.help_scroll = self.help_scroll.min(max_scroll);
            match key.code {
                KeyCode::Esc | KeyCode::Char('?') => {
                    self.help = false;
                    self.controls.reset();
                }
                KeyCode::Up => self.help_scroll = self.help_scroll.saturating_sub(1),
                KeyCode::Down => self.help_scroll = (self.help_scroll + 1).min(max_scroll),
                KeyCode::PageUp => self.help_scroll = self.help_scroll.saturating_sub(5),
                KeyCode::PageDown => self.help_scroll = (self.help_scroll + 5).min(max_scroll),
                KeyCode::Home => self.help_scroll = 0,
                KeyCode::End => self.help_scroll = max_scroll,
                _ => {}
            }
            return true;
        }
        if self.sharing_confirmation.is_some() {
            return self.handle_sharing_confirmation_key(key, backend);
        }
        if let Some(picker) = self.directory_picker.as_mut() {
            let action = picker.handle_key(key);
            self.apply_picker_action(action);
            return true;
        }
        if self.operations.active() {
            let was_active = self.operations.active();
            let mut operations = std::mem::take(&mut self.operations);
            let handled = operations.handle_key(key, backend, self);
            self.operations = operations;
            if was_active && !self.operations.active() {
                self.bind_workspace_panel(backend, true);
            }
            return handled;
        }
        if self.workspace_view_active() && self.handle_workspace_navigation(key, backend) {
            return true;
        }
        if self.workspace_form.is_none()
            && !self.workspace_view_active()
            && matches!(
                key.code,
                KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down
            )
        {
            let text_entry = self.search_active
                || self
                    .auth_setup
                    .as_ref()
                    .is_some_and(|draft| draft.step == AuthSetupStep::KeychainPath);
            if text_entry && key.code == KeyCode::Up {
                self.controls.blur();
                return true;
            }
            if self.search_active && key.code == KeyCode::Down && self.controls.focused().is_none()
            {
                self.search_active = false;
                self.search_error = None;
                self.focus = DashboardFocus::Sidebar;
                self.bind_workspace_panel(backend, false);
                return true;
            }
            if !text_entry || key.code == KeyCode::Down || self.controls.focused().is_some() {
                self.controls.move_focus(key.code);
                return true;
            }
        }
        if self.workspace_form.is_none() {
            match key.code {
                KeyCode::Tab | KeyCode::BackTab => {
                    let previous = self.focus;
                    self.controls.cycle(key.code == KeyCode::BackTab);
                    if self.workspace_view_active() {
                        self.focus = match self.controls.focused() {
                            Some(Action::Key(_)) => {
                                if previous != DashboardFocus::Footer {
                                    self.footer_from_panel = previous == DashboardFocus::Panel;
                                }
                                DashboardFocus::Footer
                            }
                            _ => DashboardFocus::Sidebar,
                        };
                    }
                    return true;
                }
                KeyCode::Enter if self.controls.focused().is_some() => {
                    let action = self.controls.focused().unwrap();
                    self.activate_control(action, backend);
                    return true;
                }
                KeyCode::PageUp | KeyCode::PageDown => {
                    if self.can_select_workspace() {
                        let page = usize::from(self.sidebar_area.get().height / 3).max(1);
                        let selected = if key.code == KeyCode::PageUp {
                            self.selected.saturating_sub(page)
                        } else {
                            self.selected.saturating_add(page)
                        };
                        self.select_workspace(selected, backend);
                    } else {
                        self.scroll_content(key.code == KeyCode::PageDown, 5);
                    }
                    return true;
                }
                _ => {}
            }
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
        if let Some(form) = self.workspace_form.as_mut() {
            let action = form.handle_key(key);
            self.apply_form_action(action, backend);
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
                    self.bind_workspace_panel(backend, false);
                }
                KeyCode::Enter => {
                    self.search_active = false;
                    self.search_error = None;
                    self.focus = DashboardFocus::Sidebar;
                    self.bind_workspace_panel(backend, false);
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
                self.controls.reset();
                self.content_scroll = 0;
                self.search_active = true;
                self.search_error = None;
                true
            }
            KeyCode::Esc if !self.search_query.is_empty() => {
                self.search_error = None;
                self.replace_search_query(String::new());
                self.bind_workspace_panel(backend, false);
                true
            }
            KeyCode::Char('p') => {
                self.controls.reset();
                self.content_scroll = 0;
                let workspace_id = self.selected_workspace().map(|w| w.workspace_id);
                self.operations
                    .open(Page::ShellProfiles, workspace_id, backend);
                true
            }
            KeyCode::Char('v') => {
                self.controls.reset();
                self.content_scroll = 0;
                let workspace_id = self.selected_workspace().map(|w| w.workspace_id);
                self.operations.open(Page::Access, workspace_id, backend);
                true
            }
            KeyCode::Char('o') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.operations.open(Page::Service, None, backend);
                true
            }
            KeyCode::Char('g') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.operations.open(Page::Doctor, None, backend);
                true
            }
            KeyCode::Char('k') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.operations.open(Page::Logs, None, backend);
                true
            }
            KeyCode::Char('e') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.operations.open(Page::Settings, None, backend);
                true
            }
            KeyCode::Char('a') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.message = None;
                self.workspace_form = Some(WorkspaceForm::new());
                true
            }
            KeyCode::Char('l') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.login_open = true;
                self.login_status = None;
                self.login_presentation = None;
                self.login_message = None;
                true
            }
            KeyCode::Char('s') => {
                if let Some(workspace) = self.selected_workspace() {
                    self.sharing_confirmation = Some(SharingConfirmation {
                        workspace_id: workspace.workspace_id,
                        name: workspace.name.as_str().to_owned(),
                        share: workspace.sharing == LocalSharing::Disabled,
                        confirm_selected: false,
                        scroll: 0,
                        max_scroll: Cell::new(0),
                    });
                    self.message = None;
                    self.controls.reset();
                    true
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn apply_picker_action(&mut self, action: PickerAction) {
        match action {
            PickerAction::None => {}
            PickerAction::Cancel => self.directory_picker = None,
            PickerAction::Select(path) => {
                self.directory_picker = None;
                if let Some(form) = self.workspace_form.as_mut() {
                    form.directory_selected(path);
                }
            }
        }
    }

    fn apply_form_action(&mut self, action: FormAction, backend: &mut impl Backend) {
        match action {
            FormAction::None => {}
            FormAction::Cancel => {
                self.workspace_form = None;
                self.directory_picker = None;
            }
            FormAction::PickDirectory => {
                let Some(form) = self.workspace_form.as_mut() else {
                    return;
                };
                let start = form
                    .directory
                    .clone()
                    .or_else(|| std::env::current_dir().ok());
                if let Some(start) = start {
                    self.directory_picker = Some(DirectoryPicker::new(start));
                } else {
                    form.error = Some("Current directory is unavailable. Select another location.");
                }
            }
            FormAction::Submit => self.submit_workspace(backend),
        }
    }

    fn submit_workspace(&mut self, backend: &mut impl Backend) {
        let Some(form) = self.workspace_form.as_mut() else {
            return;
        };
        let name = form.name.trim();
        if name.is_empty() || name.len() > WORKSPACE_NAME_MAX_BYTES {
            form.error = Some("Enter a workspace name of at most 255 UTF-8 bytes.");
            return;
        }
        let Ok(name) = LocalProjectName::try_from(name.to_owned()) else {
            form.error = Some("Enter a valid workspace name.");
            return;
        };
        let Some(path) = form.directory.as_ref() else {
            form.error = Some("Select an existing directory first.");
            return;
        };
        if !path.is_absolute()
            || !std::fs::canonicalize(path)
                .is_ok_and(|current| current == *path && current.is_dir())
        {
            form.error = Some("The selected directory changed or is unavailable. Select it again.");
            return;
        }
        let Some(path) = path.to_str() else {
            form.error = Some("The directory path must be valid UTF-8.");
            return;
        };
        let Ok(root_path) = LocalRootPath::try_from(path.to_owned()) else {
            form.error = Some("Directory path is invalid or exceeds 4096 UTF-8 bytes.");
            return;
        };
        match backend.request(LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name: name.clone(),
            root_path,
            operator_intent: Confirmed::Confirmed,
        })) {
            Ok(LocalResult::Workspace(workspace))
                if workspace.name == name && workspace.sharing == LocalSharing::Disabled =>
            {
                self.workspace_form = None;
                self.search_query.clear();
                self.refresh(backend);
                self.selected = self
                    .workspaces
                    .iter()
                    .position(|entry| entry.workspace_id == workspace.workspace_id)
                    .unwrap_or(0);
                self.focus = DashboardFocus::Sidebar;
                self.bind_workspace_panel(backend, false);
                self.sharing_confirmation = Some(SharingConfirmation {
                    workspace_id: workspace.workspace_id,
                    name: workspace.name.as_str().to_owned(),
                    share: true,
                    confirm_selected: false,
                    scroll: 0,
                    max_scroll: Cell::new(0),
                });
            }
            Err("UI_PREVIEW_ACTION_DISABLED") => {
                form.error = Some("UI preview: workspace creation is disabled.");
            }
            _ => {
                form.error = Some("Creation was not confirmed. Refresh before retrying.");
            }
        }
    }

    fn overlay_active(&self) -> bool {
        self.help || self.sharing_confirmation.is_some() || self.directory_picker.is_some()
    }

    fn workspace_view_active(&self) -> bool {
        !self.operations.active()
            && self.workspace_form.is_none()
            && self.auth_setup.is_none()
            && !self.login_open
            && !self.search_active
            && self.setup_draft.is_none()
            && self.selected_workspace().is_some()
    }

    fn bind_workspace_panel(&mut self, backend: &mut impl Backend, force: bool) {
        let workspace = self.selected_workspace().cloned();
        if workspace.is_none() {
            self.focus = DashboardFocus::Sidebar;
        }
        self.workspace_panel.bind(workspace, backend, force);
    }

    fn focus_workspace_footer(&mut self, from_panel: bool) {
        self.footer_from_panel = from_panel;
        self.focus = DashboardFocus::Footer;
        self.controls.blur();
        self.controls.focus_action(Action::Key(event::KeyEvent::new(
            KeyCode::Char('/'),
            KeyModifiers::NONE,
        )));
    }

    fn apply_panel_action(&mut self, action: PanelAction, backend: &mut impl Backend) {
        match action {
            PanelAction::None => {}
            PanelAction::Sidebar => {
                self.focus = DashboardFocus::Sidebar;
                self.controls.blur();
            }
            PanelAction::Footer => self.focus_workspace_footer(true),
            PanelAction::Share => {
                self.handle_key(
                    event::KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE),
                    backend,
                );
            }
            PanelAction::Profiles => {
                self.handle_key(
                    event::KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE),
                    backend,
                );
            }
            PanelAction::Rename | PanelAction::Remove => {
                if let Some(workspace_id) = self
                    .selected_workspace()
                    .map(|workspace| workspace.workspace_id)
                {
                    self.controls.reset();
                    if action == PanelAction::Rename {
                        self.operations
                            .begin_workspace_rename(workspace_id, backend);
                    } else {
                        self.operations
                            .begin_workspace_remove(workspace_id, backend);
                    }
                }
            }
        }
    }

    fn handle_workspace_navigation(
        &mut self,
        key: event::KeyEvent,
        backend: &mut impl Backend,
    ) -> bool {
        match self.focus {
            DashboardFocus::Sidebar => {
                let current = match self.controls.focused() {
                    Some(Action::Row(index)) => index,
                    _ => self.selected,
                };
                match key.code {
                    KeyCode::Right => {
                        if current != self.selected {
                            self.select_workspace(current, backend);
                        }
                        self.controls.blur();
                        self.focus = DashboardFocus::Panel;
                        self.workspace_panel.focus_tabs();
                    }
                    KeyCode::Left => {}
                    KeyCode::Up => self.select_workspace(current.saturating_sub(1), backend),
                    KeyCode::Down => {
                        if current.saturating_add(1) < self.visible_workspace_indices().len() {
                            self.select_workspace(current + 1, backend);
                        } else {
                            self.focus_workspace_footer(false);
                        }
                    }
                    _ => return false,
                }
            }
            DashboardFocus::Panel => {
                if matches!(
                    key.code,
                    KeyCode::Left
                        | KeyCode::Right
                        | KeyCode::Up
                        | KeyCode::Down
                        | KeyCode::Enter
                        | KeyCode::Tab
                        | KeyCode::BackTab
                        | KeyCode::PageUp
                        | KeyCode::PageDown
                        | KeyCode::Home
                        | KeyCode::End
                ) || (key.code == KeyCode::Char('n')
                    && self.workspace_panel.active_tab() == WorkspaceTab::Logs)
                {
                    let action = self.workspace_panel.handle_key(key, backend);
                    self.apply_panel_action(action, backend);
                } else if key.code == KeyCode::Esc {
                    self.focus = DashboardFocus::Sidebar;
                    self.controls.blur();
                } else {
                    return false;
                }
            }
            DashboardFocus::Footer => match key.code {
                KeyCode::Left | KeyCode::Right => {
                    if self.controls.focused().is_none() {
                        self.controls.focus_action(Action::Key(event::KeyEvent::new(
                            KeyCode::Char('/'),
                            KeyModifiers::NONE,
                        )));
                    }
                    self.controls.move_focus(key.code);
                    if let Some(Action::Row(index)) = self.controls.focused() {
                        self.select_workspace(index, backend);
                    }
                }
                KeyCode::Up | KeyCode::Esc => {
                    self.controls.blur();
                    if self.footer_from_panel {
                        self.focus = DashboardFocus::Panel;
                        self.workspace_panel.focus_content();
                    } else {
                        self.focus = DashboardFocus::Sidebar;
                    }
                }
                KeyCode::Down => {
                    self.controls.blur();
                    self.focus = DashboardFocus::Sidebar;
                }
                _ => return false,
            },
        }
        true
    }

    fn can_select_workspace(&self) -> bool {
        self.workspace_form.is_none()
            && self.directory_picker.is_none()
            && self.auth_setup.is_none()
            && !self.login_open
            && self.setup_draft.is_none()
            && (!self.operations.active() || self.operations.can_switch_workspace())
    }

    fn select_workspace(&mut self, selected: usize, backend: &mut impl Backend) {
        if !self.can_select_workspace() {
            return;
        }
        self.selected = selected.min(self.visible_workspace_indices().len().saturating_sub(1));
        self.search_active = false;
        self.message = None;
        self.content_scroll = 0;
        self.controls.blur();
        self.focus = DashboardFocus::Sidebar;
        self.bind_workspace_panel(backend, false);
        if self.operations.active() {
            if let Some(workspace_id) = self
                .selected_workspace()
                .map(|workspace| workspace.workspace_id)
            {
                self.operations.retarget_workspace(workspace_id, backend);
            }
        }
    }

    fn scroll_content(&mut self, down: bool, amount: usize) {
        let max_scroll = self.content_max_scroll.get();
        self.content_scroll = if down {
            self.content_scroll.saturating_add(amount).min(max_scroll)
        } else {
            self.content_scroll.min(max_scroll).saturating_sub(amount)
        };
    }

    fn activate_control(&mut self, action: Action, backend: &mut impl Backend) {
        self.controls.blur();
        match action {
            Action::Row(index) => self.select_workspace(index, backend),
            Action::Key(key) => {
                if self.workspace_view_active() {
                    self.footer_from_panel = self.focus == DashboardFocus::Panel;
                    self.focus = DashboardFocus::Footer;
                }
                if !self.dispatch_key(key, backend) {
                    self.quit_requested = true;
                }
            }
        }
    }

    fn activate_help_control(&mut self, action: Action, backend: &mut impl Backend) {
        if let Action::Key(key) = action {
            let max_scroll = self.help_max_scroll.get();
            match key.code {
                KeyCode::Up => {
                    self.help_scroll = self.help_scroll.min(max_scroll).saturating_sub(1);
                    return;
                }
                KeyCode::Down => {
                    self.help_scroll = self.help_scroll.saturating_add(1).min(max_scroll);
                    return;
                }
                KeyCode::PageUp => {
                    self.help_scroll = self.help_scroll.min(max_scroll).saturating_sub(5);
                    return;
                }
                KeyCode::PageDown => {
                    self.help_scroll = self.help_scroll.saturating_add(5).min(max_scroll);
                    return;
                }
                KeyCode::Home => {
                    self.help_scroll = 0;
                    return;
                }
                KeyCode::End => {
                    self.help_scroll = max_scroll;
                    return;
                }
                _ => {}
            }
        }
        self.help = false;
        self.controls.reset();
        if matches!(action, Action::Key(key) if matches!(key.code, KeyCode::Esc | KeyCode::Char('?')))
        {
            return;
        }
        // The reference lists application commands, independent of the page
        // under the dialog. Leave its read-only page before dispatching one.
        if self.operations.active() && self.operations.can_switch_workspace() {
            self.operations = Operations::default();
        }
        self.activate_control(action, backend);
    }

    fn dispatch_key(&mut self, key: event::KeyEvent, backend: &mut impl Backend) -> bool {
        if self.handle_key(key, backend) {
            return !self.quit_requested;
        }
        match key.code {
            KeyCode::Char('q') => return false,
            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => return false,
            KeyCode::Up => self.select_workspace(self.selected.saturating_sub(1), backend),
            KeyCode::Down => self.select_workspace(self.selected.saturating_add(1), backend),
            KeyCode::Home => self.select_workspace(0, backend),
            KeyCode::End => self.select_workspace(usize::MAX, backend),
            KeyCode::Char('?') => {
                self.controls.reset();
                self.help = true;
                self.help_scroll = 0;
            }
            KeyCode::Char('r') => {
                self.controls.reset();
                self.content_scroll = 0;
                self.refresh(backend);
            }
            _ => {}
        }
        !self.quit_requested
    }

    fn handle_mouse(&mut self, event: MouseEvent, backend: &mut impl Backend) -> bool {
        if !matches!(
            event.kind,
            MouseEventKind::Down(_) | MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        ) {
            return false;
        }
        let scrolling = matches!(
            event.kind,
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
        );
        let down = event.kind == MouseEventKind::ScrollDown;
        if self.help {
            if scrolling
                && shortcuts::bounds(self.frame_area.get())
                    .contains((event.column, event.row).into())
            {
                let max_scroll = self.help_max_scroll.get();
                self.help_scroll = if down {
                    self.help_scroll.saturating_add(3).min(max_scroll)
                } else {
                    self.help_scroll.min(max_scroll).saturating_sub(3)
                };
            } else if let Some(action) = self.controls.click(event) {
                self.activate_help_control(action, backend);
            }
            return true;
        }
        if self.sharing_confirmation.is_some() {
            if scrolling
                && sharing_dialog::bounds(
                    self.frame_area.get(),
                    self.sharing_confirmation.as_ref().unwrap().share,
                )
                .contains((event.column, event.row).into())
            {
                let confirmation = self.sharing_confirmation.as_mut().unwrap();
                let max_scroll = confirmation.max_scroll.get();
                confirmation.scroll = if down {
                    confirmation.scroll.saturating_add(3).min(max_scroll)
                } else {
                    confirmation.scroll.min(max_scroll).saturating_sub(3)
                };
            } else if let Some(Action::Key(key)) = self.controls.click(event) {
                self.controls.blur();
                self.handle_sharing_confirmation_key(key, backend);
            }
            return true;
        }
        if let Some(picker) = self.directory_picker.as_mut() {
            let action = picker.handle_mouse(event);
            self.apply_picker_action(action);
            return true;
        }
        if let Some(action) = self.controls.click(event) {
            self.activate_control(action, backend);
            return true;
        }
        if scrolling
            && self
                .sidebar_area
                .get()
                .contains((event.column, event.row).into())
            && self.can_select_workspace()
        {
            let selected = if down {
                self.selected.saturating_add(1)
            } else {
                self.selected.saturating_sub(1)
            };
            self.select_workspace(selected, backend);
            return true;
        }
        if self.operations.active() {
            let was_active = self.operations.active();
            let mut operations = std::mem::take(&mut self.operations);
            let handled = operations.handle_mouse(event, backend, self);
            self.operations = operations;
            if was_active && !self.operations.active() {
                self.bind_workspace_panel(backend, true);
            }
            return handled;
        }
        if self.workspace_view_active()
            && self
                .content_area
                .get()
                .contains((event.column, event.row).into())
        {
            self.focus = DashboardFocus::Panel;
            self.controls.blur();
            let action = self.workspace_panel.handle_mouse(event, backend);
            self.apply_panel_action(action, backend);
            return true;
        }
        if let Some(form) = self.workspace_form.as_mut() {
            let action = form.handle_mouse(event);
            self.apply_form_action(action, backend);
            return true;
        }
        if scrolling
            && self
                .content_area
                .get()
                .contains((event.column, event.row).into())
        {
            self.scroll_content(down, 3);
            return true;
        }
        if event.kind == MouseEventKind::Down(event::MouseButton::Left) {
            self.controls.blur();
            return true;
        }
        false
    }

    fn hoverable(&self, column: u16, row: u16) -> bool {
        if self.help || self.sharing_confirmation.is_some() {
            return self.controls.hoverable(column, row);
        }
        if let Some(picker) = &self.directory_picker {
            return picker.hoverable(column, row);
        }
        if self.controls.hoverable(column, row) {
            return true;
        }
        if self.operations.active() {
            return self.operations.hoverable(column, row);
        }
        if self.workspace_view_active() {
            return self.workspace_panel.hoverable(column, row);
        }
        self.workspace_form
            .as_ref()
            .is_some_and(|form| form.hoverable(column, row))
    }

    fn handle_sharing_confirmation_key(
        &mut self,
        key: event::KeyEvent,
        backend: &mut impl Backend,
    ) -> bool {
        let Some(confirmation) = self.sharing_confirmation.as_mut() else {
            return false;
        };
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return true;
        }
        let max_scroll = confirmation.max_scroll.get();
        confirmation.scroll = confirmation.scroll.min(max_scroll);
        match key.code {
            KeyCode::Esc | KeyCode::Char('n' | 'N') => {
                self.sharing_confirmation = None;
            }
            KeyCode::Left => confirmation.confirm_selected = false,
            KeyCode::Right => confirmation.confirm_selected = true,
            KeyCode::Tab | KeyCode::BackTab => {
                confirmation.confirm_selected = !confirmation.confirm_selected;
            }
            KeyCode::Up => confirmation.scroll = confirmation.scroll.saturating_sub(1),
            KeyCode::Down => confirmation.scroll = (confirmation.scroll + 1).min(max_scroll),
            KeyCode::PageUp => confirmation.scroll = confirmation.scroll.saturating_sub(5),
            KeyCode::PageDown => {
                confirmation.scroll = (confirmation.scroll + 5).min(max_scroll);
            }
            KeyCode::Home => confirmation.scroll = 0,
            KeyCode::End => confirmation.scroll = max_scroll,
            KeyCode::Enter if !confirmation.confirm_selected => {
                self.sharing_confirmation = None;
            }
            KeyCode::Char('y' | 'Y') | KeyCode::Enter => {
                let confirmation = self.sharing_confirmation.take().unwrap();
                let target = LocalWorkspaceTarget {
                    workspace_id: confirmation.workspace_id,
                    operator_intent: Confirmed::Confirmed,
                };
                let (call, expected_sharing) = if confirmation.share {
                    (LocalCall::Share(target), LocalSharing::Enabled)
                } else {
                    (LocalCall::Unshare(target), LocalSharing::Disabled)
                };
                let confirmed = matches!(
                    backend.request(call),
                    Ok(LocalResult::Workspace(workspace))
                        if workspace.workspace_id == confirmation.workspace_id
                            && workspace.sharing == expected_sharing
                );
                self.refresh(backend);
                if !confirmed {
                    self.message = Some(
                        "Sharing change was not confirmed. Refresh to verify the current state.",
                    );
                }
            }
            _ => {}
        }
        true
    }

    fn handle_paste(&mut self, text: &str) -> bool {
        if self.help || self.sharing_confirmation.is_some() || self.directory_picker.is_some() {
            return false;
        }
        if self.operations.active() {
            return self.operations.handle_paste(text);
        }
        if let Some(form) = self.workspace_form.as_mut() {
            return form.handle_paste(text);
        }
        self.controls.blur();
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
    fn focus_change(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn mouse_capture(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn bracketed_paste(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn raw(&mut self) -> io::Result<()>;
    fn alternate(&mut self) -> io::Result<()>;
    fn cursor(&mut self) -> io::Result<()>;
}
pub(crate) struct NativeCleanup;
impl Cleanup for NativeCleanup {
    fn focus_change(&mut self) -> io::Result<()> {
        execute!(io::stdout(), DisableFocusChange)
    }
    fn mouse_capture(&mut self) -> io::Result<()> {
        execute!(io::stdout(), DisableMouseCapture)
    }
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
        let _ = self.0.focus_change();
        let _ = self.0.mouse_capture();
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
    execute!(
        io::stdout(),
        EnableBracketedPaste,
        EnableMouseCapture,
        EnableFocusChange
    )?;
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
    let mut pointer = PointerTracker::new();
    let mut changed = true;
    loop {
        if changed {
            terminal
                .draw(|frame| {
                    state.draw(frame);
                    theme::finish(frame);
                })
                .map_err(Into::into)?;
            pointer.refresh(|column, row| state.hoverable(column, row));
            changed = false;
        }
        // One thread owns polling and reading. Idle does not redraw continuously.
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        match event::read()? {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if !state.dispatch_key(key, backend) {
                    return Ok(());
                }
                changed = true;
            }
            Event::Paste(text) => {
                changed = state.handle_paste(&text);
            }
            Event::Mouse(event) => {
                pointer.observe(event);
                pointer.refresh(|column, row| state.hoverable(column, row));
                changed = state.handle_mouse(event, backend);
                if state.quit_requested {
                    return Ok(());
                }
            }
            Event::Resize(..) => changed = true,
            Event::FocusLost => pointer.reset(),
            Event::FocusGained => pointer.refresh(|column, row| state.hoverable(column, row)),
            _ => {}
        }
    }
}
