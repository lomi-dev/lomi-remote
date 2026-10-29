//! Dashboard operation pages. Every mutation is issued only after an explicit
//! key action; opening a page performs bounded reads only.

use super::{Backend, Dashboard, safe_label, sharing};
use crate::diagnostics::{
    DiagnosticReport, DiagnosticReportBuilder, DiagnosticRunMode, HostAvailability,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use lomi_remote_protocol::{
    DecimalU64, MutationContext, OperationId, TerminalContext, WorkspaceId,
    ipc::{
        LocalCall, LocalLoginStatus, LocalProcessArgument, LocalProjectName, LocalResult,
        LocalRootPath, LocalSharing, LocalShellEnvironment, LocalShellProfileRegister,
        LocalWorkspaceDetails, LocalWorkspaceRead, LocalWorkspaceRename, LocalWorkspaceTarget,
    },
    rpc::{
        BoundedList, DisplayText, HostProfile, PaneState, RpcCall, RpcResponse, RpcResult,
        TerminalCloseParams, TerminalCreateParams, TerminalLayout, WorkspaceCapabilitiesResult,
        WorkspaceReadParams, WorkspaceState,
    },
};
use ratatui::{
    Frame,
    layout::{Constraint, Layout},
    text::Line,
    widgets::{Block, Paragraph, Wrap},
};
use std::path::Path;
use uuid::Uuid;

const DISPLAY_NAME_MAX: usize = 255;
const LOCAL_PATH_MAX: usize = 4096;
const DETAIL_ROWS: usize = 12;
const LOG_PAGE_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMode {
    Manual,
    Login,
    Boot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceRuntimeState {
    Running,
    Starting,
    Stopped,
    Failed,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAutostartState {
    Enabled,
    Disabled,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAccountKind {
    CurrentUser,
    Dedicated,
    Unknown,
}

/// Typed, non-secret service snapshot from the native adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceSnapshot {
    pub mode: Option<ServiceMode>,
    pub runtime: ServiceRuntimeState,
    pub autostart: ServiceAutostartState,
    pub account: ServiceAccountKind,
    pub host_uptime_seconds: Option<u64>,
    pub connected_clients: Option<u32>,
    pub active_terminals: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceAction {
    InstallLogin,
    InstallBoot,
    Start,
    Stop,
    Restart,
    Uninstall,
}

pub use lomi_remote_protocol::ipc::{
    DiagnosticCode as UiLogCode, DiagnosticComponent as UiLogComponent,
    DiagnosticSeverity as UiLogSeverity,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiDiagnosticLogEntry {
    pub sequence: u64,
    pub unix_time_ms: Option<u64>,
    pub severity: UiLogSeverity,
    pub component: UiLogComponent,
    pub code: UiLogCode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiDiagnosticLogSnapshot {
    pub entries: Vec<UiDiagnosticLogEntry>,
    pub next_cursor: u64,
    pub truncated: bool,
    pub available: bool,
}

/// Redacted owner-account access counters and authentication state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentAccessSnapshot {
    pub login: LocalLoginStatus,
    pub connected_clients: Option<u32>,
    pub active_terminals: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Page {
    WorkspaceDetails,
    ShellProfiles,
    Access,
    Service,
    Doctor,
    Logs,
    Settings,
}

#[derive(Debug, Clone)]
struct PaneRow {
    tab_name: String,
    pane_id: lomi_remote_protocol::PaneId,
    state: PaneState,
    session: Option<TerminalContext>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProfileDraftField {
    Name,
    Executable,
    WorkingDirectory,
    Confirm,
}

#[derive(Debug, Clone)]
struct ShellProfileDraft {
    field: ProfileDraftField,
    name: String,
    executable: String,
    working_directory: String,
    error: Option<&'static str>,
}

struct RenameDraft {
    expected_name: LocalProjectName,
    name: String,
}

#[derive(Debug, Clone)]
enum Confirmation {
    RenameWorkspace(LocalWorkspaceRename),
    StopTerminal(PaneRow),
    RemoveWorkspace(WorkspaceId),
    ChangeSharing {
        workspace_id: WorkspaceId,
        share: bool,
    },
    Service(ServiceAction),
    Logout,
}

#[derive(Default)]
pub(super) struct Operations {
    page: Option<Page>,
    workspace_id: Option<WorkspaceId>,
    workspace_state: Option<WorkspaceState>,
    workspace_details: Option<LocalWorkspaceDetails>,
    removal_status: Option<lomi_remote_protocol::ipc::LocalWorkspaceRemovalStatus>,
    profiles: Vec<HostProfile>,
    selected: usize,
    message: Option<&'static str>,
    confirmation: Option<Confirmation>,
    shell_draft: Option<ShellProfileDraft>,
    rename_draft: Option<RenameDraft>,
    service: Option<ServiceSnapshot>,
    access: Option<CurrentAccessSnapshot>,
    doctor: Option<DiagnosticReport>,
    logs: Option<UiDiagnosticLogSnapshot>,
    log_cursor: Option<u64>,
    login_status: Option<LocalLoginStatus>,
    start_mode: Option<lomi_remote_protocol::ipc::LocalStartModePreference>,
}

impl Operations {
    pub(super) fn active(&self) -> bool {
        self.page.is_some()
    }

    pub(super) fn open(
        &mut self,
        page: Page,
        workspace_id: Option<WorkspaceId>,
        backend: &mut impl Backend,
    ) {
        self.page = Some(page);
        self.workspace_id = workspace_id;
        self.workspace_state = None;
        self.workspace_details = None;
        self.removal_status = None;
        self.profiles.clear();
        self.selected = 0;
        self.message = None;
        self.confirmation = None;
        self.shell_draft = None;
        self.rename_draft = None;
        self.service = None;
        self.access = None;
        self.doctor = None;
        self.logs = None;
        match page {
            Page::WorkspaceDetails => self.refresh_workspace(backend),
            Page::Access => {
                if self.workspace_id.is_some() {
                    self.refresh_workspace(backend);
                }
                self.refresh_access(backend);
            }
            Page::ShellProfiles => {
                self.refresh_workspace(backend);
                self.refresh_profiles(backend);
            }
            Page::Service => self.refresh_service(backend),
            Page::Doctor => self.refresh_doctor(backend),
            Page::Logs => self.refresh_logs(backend, None),
            Page::Settings => self.refresh_settings(backend),
        }
    }

    pub(super) fn draw(&self, frame: &mut Frame, dashboard: &Dashboard) {
        let [header, body, footer_area] = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(3),
        ])
        .areas(frame.area());
        let title = self.page.map_or("Dashboard", page_title);
        let workspace = dashboard.selected_workspace();
        let header_text = format!(
            "Lomi Remote  v{}  |  {}\nWorkspace: {}",
            env!("CARGO_PKG_VERSION"),
            title,
            workspace.map_or_else(|| "None".to_owned(), |w| safe_label(w.name.as_str()))
        );
        frame.render_widget(Paragraph::new(header_text), header);

        let content = if let Some(draft) = &self.rename_draft {
            format!(
                "New workspace name:\n{}▏\n\n{}",
                safe_label(&draft.name),
                self.message.unwrap_or("")
            )
        } else if let Some(draft) = &self.shell_draft {
            self.draw_shell_draft(draft)
        } else if self.confirmation.is_some() {
            self.draw_confirmation(dashboard)
        } else {
            match self.page {
                Some(Page::WorkspaceDetails) => self.draw_workspace_details(dashboard),
                Some(Page::ShellProfiles) => self.draw_shell_profiles(),
                Some(Page::Access) => self.draw_access(dashboard),
                Some(Page::Service) => self.draw_service(),
                Some(Page::Doctor) => self.draw_doctor(),
                Some(Page::Logs) => self.draw_logs(),
                Some(Page::Settings) => self.draw_settings(),
                None => String::new(),
            }
        };
        frame.render_widget(
            Paragraph::new(content)
                .block(Block::bordered().title(title))
                .wrap(Wrap { trim: false }),
            body,
        );

        let footer_text = if self.shell_draft.is_some() || self.rename_draft.is_some() {
            "Type the requested value  [Enter] next  [Esc] cancel"
        } else if self.confirmation.is_some() {
            "[y] confirm  [n/Esc] cancel"
        } else if self.page == Some(Page::WorkspaceDetails) && self.removal_status.is_some() {
            "[r] check removal status without repeating cleanup  [Esc] back"
        } else {
            match self.page {
                Some(Page::WorkspaceDetails) => {
                    "[c/p] choose profile and create terminal  [x] stop selected  [v] access  [n] rename  [d] remove  [r] refresh  [Esc] back"
                }
                Some(Page::ShellProfiles) => {
                    "[Up/Down] select  [Enter] create terminal with selected profile  [a] add  [r] refresh  [Esc] back"
                }
                Some(Page::Access) => "[s/u] share/unshare  [x] logout  [r] refresh  [Esc] back",
                Some(Page::Service) => {
                    "[i/b] install login/boot  [s/t/R/u] start/stop/restart/uninstall  [r] refresh  [Esc] back"
                }
                Some(Page::Doctor) => "[r] refresh  [Esc] back",
                Some(Page::Logs) => "[n] next  [r] latest  [Esc] back",
                Some(Page::Settings) => {
                    "[m] start preference  [l] login/auth  [x] logout  [Esc] back"
                }
                None => "[Esc] back",
            }
        };
        frame.render_widget(
            Paragraph::new(Line::from(footer_text)).block(Block::bordered()),
            footer_area,
        );
    }

    pub(super) fn handle_key(
        &mut self,
        key: KeyEvent,
        backend: &mut impl Backend,
        dashboard: &mut Dashboard,
    ) -> bool {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        if let Some(mut draft) = self.rename_draft.take() {
            match key.code {
                KeyCode::Esc => {
                    self.message = Some("No change was made.");
                    return true;
                }
                KeyCode::Backspace => {
                    draft.name.pop();
                }
                KeyCode::Char(ch)
                    if !ch.is_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
                        && draft.name.len() + ch.len_utf8() <= DISPLAY_NAME_MAX =>
                {
                    draft.name.push(ch);
                }
                KeyCode::Enter => {
                    if let (Some(workspace_id), Ok(name)) = (
                        self.workspace_id,
                        LocalProjectName::try_from(draft.name.clone()),
                    ) {
                        self.confirmation =
                            Some(Confirmation::RenameWorkspace(LocalWorkspaceRename {
                                workspace_id,
                                expected_name: draft.expected_name,
                                name,
                                operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                            }));
                        self.message = None;
                        return true;
                    }
                    self.message = Some("Enter a workspace name.");
                }
                _ => {}
            }
            self.rename_draft = Some(draft);
            return true;
        }
        if let Some(mut draft) = self.shell_draft.take() {
            self.handle_shell_draft_key(key, &mut draft, backend);
            if self.shell_draft.is_none() && draft.field != ProfileDraftField::Confirm {
                // Saving/canceling owns the draft; intermediate edit branches put
                // it back. This prevents a stale draft surviving page changes.
            }
            return true;
        }
        if self.confirmation.is_some() {
            match key.code {
                KeyCode::Char('y') => self.confirm(backend, dashboard),
                KeyCode::Char('n') | KeyCode::Esc => {
                    self.confirmation = None;
                    self.message = Some("No change was made.");
                }
                _ => {}
            }
            return true;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Backspace => {
                self.leave_page();
                true
            }
            KeyCode::Char('q') => {
                self.leave_page();
                true
            }
            KeyCode::Up => {
                self.selected = self.selected.saturating_sub(1);
                true
            }
            KeyCode::Down => {
                let count = match self.page {
                    Some(Page::ShellProfiles) => self.profiles.len(),
                    Some(Page::WorkspaceDetails) => self.pane_rows().len(),
                    Some(Page::Doctor) => self.doctor.as_ref().map_or(0, |r| r.findings.len()),
                    Some(Page::Logs) => self.logs.as_ref().map_or(0, |r| r.entries.len()),
                    _ => 0,
                };
                self.selected = (self.selected + 1).min(count.saturating_sub(1));
                true
            }
            KeyCode::Char('R') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::Restart));
                true
            }
            KeyCode::Char('r') if self.page == Some(Page::Logs) => {
                self.refresh_logs(backend, None);
                true
            }
            KeyCode::Char('r') => {
                self.refresh(backend);
                true
            }
            KeyCode::Char('c') if self.page == Some(Page::WorkspaceDetails) => {
                self.open(Page::ShellProfiles, self.workspace_id, backend);
                true
            }
            KeyCode::Char('p') if self.page == Some(Page::WorkspaceDetails) => {
                self.open(Page::ShellProfiles, self.workspace_id, backend);
                true
            }
            KeyCode::Char('v') if self.page == Some(Page::WorkspaceDetails) => {
                self.open(Page::Access, self.workspace_id, backend);
                true
            }
            KeyCode::Char('x') if self.page == Some(Page::WorkspaceDetails) => {
                match self.pane_rows().get(self.selected).cloned() {
                    Some(row) => {
                        self.confirmation = Some(Confirmation::StopTerminal(row));
                        self.message = None;
                    }
                    None => self.message = Some("Select a terminal pane first."),
                }
                true
            }
            KeyCode::Char('n') if self.page == Some(Page::WorkspaceDetails) => {
                self.refresh_workspace(backend);
                if let Some(state) = &self.workspace_state {
                    if let Ok(name) = LocalProjectName::try_from(state.name.as_str().to_owned()) {
                        self.rename_draft = Some(RenameDraft {
                            expected_name: name,
                            name: state.name.as_str().to_owned(),
                        });
                    }
                }
                true
            }
            KeyCode::Char('d') if self.page == Some(Page::WorkspaceDetails) => {
                self.confirmation = self.workspace_id.map(Confirmation::RemoveWorkspace);
                true
            }
            KeyCode::Char('x') if self.page == Some(Page::Access) => {
                self.confirmation = Some(Confirmation::Logout);
                true
            }
            KeyCode::Char('s') if self.page == Some(Page::Access) => {
                self.set_sharing_confirmation(dashboard, true);
                true
            }
            KeyCode::Char('u') if self.page == Some(Page::Access) => {
                self.set_sharing_confirmation(dashboard, false);
                true
            }
            KeyCode::Char('i') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::InstallLogin));
                true
            }
            KeyCode::Char('b') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::InstallBoot));
                true
            }
            KeyCode::Char('s') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::Start));
                true
            }
            KeyCode::Char('t') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::Stop));
                true
            }
            KeyCode::Char('u') if self.page == Some(Page::Service) => {
                self.confirmation = Some(Confirmation::Service(ServiceAction::Uninstall));
                true
            }
            KeyCode::Char('a') if self.page == Some(Page::ShellProfiles) => {
                self.shell_draft = Some(ShellProfileDraft {
                    field: ProfileDraftField::Name,
                    name: String::new(),
                    executable: String::new(),
                    working_directory: String::new(),
                    error: None,
                });
                true
            }
            KeyCode::Enter if self.page == Some(Page::ShellProfiles) => {
                self.create_terminal(backend);
                true
            }
            KeyCode::Char('n') if self.page == Some(Page::Logs) => {
                match self.logs.as_ref() {
                    Some(page)
                        if page.truncated
                            && self
                                .log_cursor
                                .map_or(true, |current| page.next_cursor > current) =>
                    {
                        let cursor = page.next_cursor;
                        self.refresh_logs(backend, Some(cursor));
                    }
                    _ => self.message = Some("There is no later log page to load."),
                }
                true
            }
            KeyCode::Char('m') if self.page == Some(Page::Settings) => {
                dashboard.setup_draft = Some(super::load_setup_draft(backend));
                self.leave_page();
                true
            }
            KeyCode::Char('l') if self.page == Some(Page::Settings) => {
                dashboard.login_open = true;
                dashboard.login_status = None;
                dashboard.login_presentation = None;
                dashboard.login_message = None;
                self.leave_page();
                true
            }
            KeyCode::Char('x') if self.page == Some(Page::Settings) => {
                self.confirmation = Some(Confirmation::Logout);
                true
            }
            _ => true,
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) -> bool {
        if let Some(draft) = self.rename_draft.as_mut() {
            if super::input_contains_terminal_control(text) {
                self.message = Some("Paste one workspace name line without control characters.");
            } else if draft.name.len().saturating_add(text.len()) > DISPLAY_NAME_MAX {
                self.message = Some("Workspace name limit is 255 UTF-8 bytes.");
            } else {
                draft.name.push_str(text);
                self.message = None;
            }
            return true;
        }
        if let Some(draft) = self.shell_draft.as_mut() {
            let (value, limit, limit_message) = match draft.field {
                ProfileDraftField::Name => (
                    &mut draft.name,
                    DISPLAY_NAME_MAX,
                    "Profile name limit is 255 UTF-8 bytes.",
                ),
                ProfileDraftField::Executable => (
                    &mut draft.executable,
                    LOCAL_PATH_MAX,
                    "Executable path limit is 4096 UTF-8 bytes.",
                ),
                ProfileDraftField::WorkingDirectory => (
                    &mut draft.working_directory,
                    LOCAL_PATH_MAX,
                    "Working directory limit is 4096 UTF-8 bytes.",
                ),
                ProfileDraftField::Confirm => return true,
            };
            if super::input_contains_terminal_control(text) {
                draft.error = Some("Paste one line without control characters.");
            } else if value.len().saturating_add(text.len()) > limit {
                draft.error = Some(limit_message);
            } else {
                value.push_str(text);
                draft.error = None;
            }
            return true;
        }
        false
    }

    fn leave_page(&mut self) {
        self.page = None;
        self.confirmation = None;
        self.shell_draft = None;
        self.rename_draft = None;
        self.message = None;
        self.removal_status = None;
    }

    fn refresh(&mut self, backend: &mut impl Backend) {
        match self.page {
            Some(Page::WorkspaceDetails) => self.refresh_workspace(backend),
            Some(Page::Access) => {
                if self.workspace_id.is_some() {
                    self.refresh_workspace(backend);
                }
                self.refresh_access(backend);
            }
            Some(Page::ShellProfiles) => {
                self.refresh_workspace(backend);
                self.refresh_profiles(backend);
            }
            Some(Page::Service) => self.refresh_service(backend),
            Some(Page::Doctor) => self.refresh_doctor(backend),
            Some(Page::Logs) => self.refresh_logs(backend, None),
            Some(Page::Settings) => self.refresh_settings(backend),
            None => {}
        }
    }

    fn refresh_workspace(&mut self, backend: &mut impl Backend) {
        if self.removal_status.is_some() {
            self.refresh_removal_status(backend);
            return;
        }
        self.workspace_details = None;
        let Some(workspace_id) = self.workspace_id else {
            self.workspace_state = None;
            self.message = Some("Select a workspace first.");
            return;
        };
        match backend.request(LocalCall::WorkspaceInspect(
            lomi_remote_protocol::ipc::LocalWorkspaceRead { workspace_id },
        )) {
            Ok(LocalResult::WorkspaceState(state)) => {
                self.workspace_state = Some(*state);
                self.selected = self.selected.min(self.pane_rows().len().saturating_sub(1));
                self.message = None;
            }
            _ => {
                self.workspace_state = None;
                self.message = Some("Workspace details are unavailable. Press r to retry.");
                if let Ok(LocalResult::WorkspaceRemovalStatus(status)) =
                    backend.request(LocalCall::WorkspaceRemovalStatus(LocalWorkspaceRead {
                        workspace_id,
                    }))
                {
                    if status.workspace_id == workspace_id
                        && status.validate().is_ok()
                        && status.phase
                            != lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::NotStarted
                    {
                        self.removal_status = Some(status);
                        self.message = None;
                        return;
                    }
                }
            }
        }
        if let Ok(LocalResult::WorkspaceDetails(details)) =
            backend.request(LocalCall::WorkspaceDetails(LocalWorkspaceRead {
                workspace_id,
            }))
        {
            if details.workspace.workspace_id == workspace_id {
                self.workspace_details = Some(details);
            }
        }
    }

    fn refresh_removal_status(&mut self, backend: &mut impl Backend) {
        let Some(workspace_id) = self.workspace_id else {
            return;
        };
        match backend.request(LocalCall::WorkspaceRemovalStatus(LocalWorkspaceRead {
            workspace_id,
        })) {
            Ok(LocalResult::WorkspaceRemovalStatus(status))
                if status.workspace_id == workspace_id && status.validate().is_ok() =>
            {
                self.removal_status = Some(status);
                self.message = None;
            }
            _ => self.message = Some("Removal status is unavailable. Cleanup was not repeated."),
        }
    }

    fn refresh_profiles(&mut self, backend: &mut impl Backend) {
        self.profiles.clear();
        let Some(state) = self.workspace_state.as_ref() else {
            self.message = Some("Workspace is unavailable; shell profiles were not read.");
            return;
        };
        let call = RpcCall::WorkspaceCapabilities(WorkspaceReadParams {
            context: state.context.clone(),
        });
        match rpc(backend, call) {
            Ok(RpcResult::WorkspaceCapabilities(WorkspaceCapabilitiesResult {
                profiles, ..
            })) => {
                self.profiles = profiles.0;
                self.selected = self.selected.min(self.profiles.len().saturating_sub(1));
                self.message = None;
            }
            _ => self.message = Some("Shell profile list is unavailable. Press r to retry."),
        }
    }

    fn refresh_service(&mut self, backend: &mut impl Backend) {
        match backend.service_status() {
            Ok(snapshot) => {
                self.service = Some(snapshot);
                self.message = None;
            }
            Err(error) => {
                self.service = None;
                self.message = Some(service_status_error_message(error));
            }
        }
    }

    fn refresh_access(&mut self, backend: &mut impl Backend) {
        match backend.current_access_snapshot() {
            Ok(snapshot) => self.access = Some(snapshot),
            Err(_) => {
                self.access = None;
                self.message = Some("Current access snapshot adapter is unavailable.");
            }
        }
    }

    fn refresh_doctor(&mut self, backend: &mut impl Backend) {
        match backend.doctor_report() {
            Ok(report) => {
                self.doctor = Some(report);
                self.message = None;
            }
            Err(_) => {
                let mut builder = DiagnosticReportBuilder::new(DiagnosticRunMode::Offline);
                builder.add_host_availability(HostAvailability::Unavailable);
                let profile = backend.diagnostic_profile_path();
                builder.add_offline_observations(profile.as_deref());
                self.doctor = Some(builder.finish());
                self.message = Some("Host unavailable; showing only locally verified checks.");
            }
        }
    }

    fn refresh_logs(&mut self, backend: &mut impl Backend, cursor: Option<u64>) {
        match backend.read_diagnostic_logs(cursor, LOG_PAGE_SIZE) {
            Ok(mut page) => {
                if page.entries.len() > LOG_PAGE_SIZE {
                    page.entries.truncate(LOG_PAGE_SIZE);
                    page.truncated = true;
                }
                self.logs = Some(page);
                self.log_cursor = cursor;
                self.selected = 0;
                self.message = None;
            }
            Err(_) => {
                self.logs = None;
                self.message = Some("Structured log adapter is unavailable.");
            }
        }
    }

    fn refresh_settings(&mut self, backend: &mut impl Backend) {
        self.start_mode = match backend.request(LocalCall::SetupStartModeRead {}) {
            Ok(LocalResult::SetupStartMode(value)) => Some(value),
            _ => None,
        };
        self.login_status = match backend.request(LocalCall::LoginStatus {}) {
            Ok(LocalResult::LoginStatus(value)) => Some(value),
            _ => None,
        };
        self.message = None;
    }

    fn pane_rows(&self) -> Vec<PaneRow> {
        fn collect(layout: &TerminalLayout, tab_name: &str, rows: &mut Vec<PaneRow>) {
            if rows.len() >= 32 {
                return;
            }
            match layout {
                TerminalLayout::Pane { pane } => rows.push(PaneRow {
                    tab_name: tab_name.to_owned(),
                    pane_id: pane.pane_id,
                    state: pane.state,
                    session: pane.session.clone(),
                }),
                TerminalLayout::Split { first, second, .. } => {
                    collect(first, tab_name, rows);
                    collect(second, tab_name, rows);
                }
            }
        }
        let mut rows = Vec::with_capacity(32);
        if let Some(state) = &self.workspace_state {
            for tab in &state.tabs.0 {
                collect(&tab.layout, tab.name.as_str(), &mut rows);
            }
        }
        rows
    }

    fn set_sharing_confirmation(&mut self, dashboard: &Dashboard, share: bool) {
        let Some(workspace) = dashboard
            .workspaces
            .iter()
            .find(|workspace| Some(workspace.workspace_id) == self.workspace_id)
        else {
            self.message = Some("Select a workspace first.");
            return;
        };
        if (share && workspace.sharing == LocalSharing::Enabled)
            || (!share && workspace.sharing == LocalSharing::Disabled)
        {
            self.message = Some(if share {
                "This workspace is already shared."
            } else {
                "This workspace is already local-only."
            });
            return;
        }
        self.confirmation = Some(Confirmation::ChangeSharing {
            workspace_id: workspace.workspace_id,
            share,
        });
    }

    fn confirm(&mut self, backend: &mut impl Backend, dashboard: &mut Dashboard) {
        let Some(confirmation) = self.confirmation.take() else {
            return;
        };
        match confirmation {
            Confirmation::RenameWorkspace(rename) => {
                let result = backend.request(LocalCall::WorkspaceRename(rename.clone()));
                dashboard.refresh(backend);
                self.refresh_workspace(backend);
                self.message = Some(match result {
                    Ok(LocalResult::Workspace(workspace))
                        if workspace.workspace_id == rename.workspace_id
                            && workspace.name == rename.name =>
                    {
                        "Workspace renamed."
                    }
                    _ => {
                        "Rename was not confirmed. Current state refreshed; the request was not repeated."
                    }
                });
            }
            Confirmation::StopTerminal(row) => self.close_terminal(backend, row),
            Confirmation::RemoveWorkspace(workspace_id) => {
                let result = backend.request(LocalCall::WorkspaceRemove(LocalWorkspaceTarget {
                    workspace_id,
                    operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                }));
                match result {
                    Ok(LocalResult::Removed(_)) => {
                        dashboard.refresh(backend);
                        self.leave_page();
                    }
                    Ok(LocalResult::WorkspaceRemovalStatus(status))
                        if status.workspace_id == workspace_id && status.validate().is_ok() =>
                    {
                        self.workspace_state = None;
                        self.workspace_details = None;
                        self.removal_status = Some(status);
                        self.message = None;
                    }
                    _ => {
                        self.workspace_state = None;
                        self.workspace_details = None;
                        self.removal_status = Some(
                            lomi_remote_protocol::ipc::LocalWorkspaceRemovalStatus {
                                workspace_id,
                                attempt_id: None,
                                phase:
                                    lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain,
                                total_sessions: DecimalU64(0),
                                confirmed_sessions: DecimalU64(0),
                            },
                        );
                        self.refresh_removal_status(backend);
                    }
                }
            }
            Confirmation::ChangeSharing {
                workspace_id,
                share,
            } => {
                let target = LocalWorkspaceTarget {
                    workspace_id,
                    operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                };
                let call = if share {
                    LocalCall::Share(target)
                } else {
                    LocalCall::Unshare(target)
                };
                match backend.request(call) {
                    Ok(LocalResult::Workspace(_)) => {
                        dashboard.refresh(backend);
                        self.workspace_id = Some(workspace_id);
                        self.refresh_workspace(backend);
                        self.message = Some(if share {
                            "Workspace sharing was enabled for the owner account."
                        } else {
                            "Sharing was revoked. Local workspace and terminal sessions were preserved."
                        });
                    }
                    _ => {
                        self.message =
                            Some("Access change failed. Refresh to verify the current policy.")
                    }
                }
            }
            Confirmation::Service(action) => match backend.service_action(action) {
                Ok(snapshot) => {
                    self.service = Some(snapshot);
                    self.message =
                        Some("Service action completed; review the observed state below.");
                }
                Err(error) => self.message = Some(service_action_error_message(error)),
            },
            Confirmation::Logout => {
                match backend.request(LocalCall::Logout(
                    lomi_remote_protocol::ipc::LocalOperatorIntent {
                        operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                    },
                )) {
                    Ok(LocalResult::LoginStatus(status)) => {
                        self.login_status = Some(status);
                        self.message =
                            Some("Logout was accepted. Authentication status refreshed.");
                    }
                    _ => self.message = Some("Logout was not confirmed by the host."),
                }
            }
        }
    }

    fn close_terminal(&mut self, backend: &mut impl Backend, row: PaneRow) {
        let Some(state) = self.workspace_state.as_ref() else {
            self.message = Some("Workspace state is unavailable; terminal was not stopped.");
            return;
        };
        let operation_id = new_operation_id();
        let call = RpcCall::TerminalClose(TerminalCloseParams {
            mutation: MutationContext {
                operation_id,
                context: state.context.clone(),
                expected_revision: state.domain_revision,
            },
            pane_id: row.pane_id,
            expected_session: row.session,
        });
        match rpc(backend, call) {
            Ok(RpcResult::TerminalClose(_)) => {
                self.refresh_workspace(backend);
                self.message = Some("Terminal stop was accepted; state refreshed.");
            }
            Err("OUTCOME_UNKNOWN") => {
                self.refresh_workspace(backend);
                self.message = Some(
                    "Terminal stop outcome is unknown. State refreshed; do not repeat until verified.",
                );
            }
            _ => {
                self.refresh_workspace(backend);
                self.message =
                    Some("Terminal stop was not confirmed. State refreshed before retry.");
            }
        }
    }

    fn create_terminal(&mut self, backend: &mut impl Backend) {
        let (Some(state), Some(profile)) = (
            self.workspace_state.as_ref(),
            self.profiles.get(self.selected),
        ) else {
            self.message = Some("Select an available shell profile first.");
            return;
        };
        let tab_name = format!("Terminal {}", state.tabs.0.len().saturating_add(1));
        let Ok(tab_name) = DisplayText::try_from(tab_name) else {
            self.message = Some("Terminal name could not be created.");
            return;
        };
        let call = RpcCall::TerminalCreate(TerminalCreateParams {
            mutation: MutationContext {
                operation_id: new_operation_id(),
                context: state.context.clone(),
                expected_revision: state.domain_revision,
            },
            tab_name,
            profile_id: profile.profile_id.clone(),
        });
        match rpc(backend, call) {
            Ok(RpcResult::TerminalCreate(_)) => {
                self.refresh_workspace(backend);
                self.message = Some("Terminal creation was accepted; state refreshed.");
                self.page = Some(Page::WorkspaceDetails);
            }
            Err("OUTCOME_UNKNOWN") => {
                self.refresh_workspace(backend);
                self.message = Some(
                    "Terminal creation outcome is unknown. State refreshed; do not repeat until verified.",
                );
                self.page = Some(Page::WorkspaceDetails);
            }
            _ => {
                self.refresh_workspace(backend);
                self.message = Some("Terminal creation was not confirmed. State refreshed.");
                self.page = Some(Page::WorkspaceDetails);
            }
        }
    }

    fn handle_shell_draft_key(
        &mut self,
        key: KeyEvent,
        draft: &mut ShellProfileDraft,
        backend: &mut impl Backend,
    ) {
        if key.code == KeyCode::Esc {
            self.message = Some("Shell profile was not saved.");
            return;
        }
        let (value, limit) = match draft.field {
            ProfileDraftField::Name => (&mut draft.name, DISPLAY_NAME_MAX),
            ProfileDraftField::Executable => (&mut draft.executable, LOCAL_PATH_MAX),
            ProfileDraftField::WorkingDirectory => (&mut draft.working_directory, LOCAL_PATH_MAX),
            ProfileDraftField::Confirm => {
                if key.code == KeyCode::Char('y') {
                    self.save_shell_profile(draft, backend);
                } else if key.code == KeyCode::Char('n') {
                    self.message = Some("Shell profile was not saved.");
                } else {
                    self.shell_draft = Some(draft.clone());
                }
                return;
            }
        };
        match key.code {
            KeyCode::Backspace => {
                value.pop();
                draft.error = None;
            }
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                if super::input_character_is_unsafe(character) {
                    draft.error = Some("Control characters are not allowed.");
                } else if value.len() + character.len_utf8() > limit {
                    draft.error = Some("The entered value exceeds its UTF-8 byte limit.");
                } else {
                    value.push(character);
                    draft.error = None;
                }
            }
            KeyCode::Enter => self.advance_shell_draft(draft),
            _ => {}
        }
        self.shell_draft = Some(draft.clone());
    }

    fn advance_shell_draft(&mut self, draft: &mut ShellProfileDraft) {
        match draft.field {
            ProfileDraftField::Name if !draft.name.trim().is_empty() => {
                if LocalProjectName::try_from(draft.name.trim().to_owned()).is_err() {
                    draft.error = Some("Enter a display name up to 255 UTF-8 bytes.");
                } else {
                    draft.field = ProfileDraftField::Executable;
                    draft.error = None;
                }
            }
            ProfileDraftField::Executable => {
                if !Path::new(&draft.executable).is_absolute() {
                    draft.error = Some("Enter an absolute executable path.");
                } else {
                    draft.field = ProfileDraftField::WorkingDirectory;
                    draft.error = None;
                }
            }
            ProfileDraftField::WorkingDirectory => {
                if !Path::new(&draft.working_directory).is_absolute() {
                    draft.error = Some("Enter an absolute working directory.");
                } else {
                    draft.field = ProfileDraftField::Confirm;
                    draft.error = None;
                }
            }
            _ => draft.error = Some("Enter a value before continuing."),
        }
    }

    fn save_shell_profile(&mut self, draft: &ShellProfileDraft, backend: &mut impl Backend) {
        let (Some(workspace_id), Ok(name), Ok(executable), Ok(cwd)) = (
            self.workspace_id,
            LocalProjectName::try_from(draft.name.trim().to_owned()),
            LocalRootPath::try_from(draft.executable.clone()),
            LocalRootPath::try_from(draft.working_directory.clone()),
        ) else {
            self.message = Some("Shell profile values are invalid; nothing was saved.");
            self.shell_draft = None;
            return;
        };
        let Ok(parameters) = LocalShellProfileRegister::new(
            workspace_id,
            name,
            executable,
            BoundedList::<LocalProcessArgument, 32>(Vec::new()),
            cwd,
            BoundedList::<LocalShellEnvironment, 8>(Vec::new()),
        ) else {
            self.message = Some("Shell profile values could not be validated; nothing was saved.");
            self.shell_draft = None;
            return;
        };
        match backend.request(LocalCall::ShellProfileRegister(parameters)) {
            Ok(LocalResult::ShellProfileRegistered { .. }) => {
                self.shell_draft = None;
                self.refresh_workspace(backend);
                self.refresh_profiles(backend);
                self.message = Some(
                    "Shell profile saved. No shell starts until you explicitly create a terminal.",
                );
            }
            _ => {
                self.shell_draft = None;
                self.message =
                    Some("Shell profile registration was rejected; nothing was started.");
            }
        }
    }

    fn draw_workspace_details(&self, dashboard: &Dashboard) -> String {
        if let Some(status) = &self.removal_status {
            let phase = match status.phase {
                lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::NotStarted => {
                    "Removal did not start"
                }
                lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Stopping => {
                    "Session cleanup in progress"
                }
                lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain => {
                    "Cleanup outcome uncertain; workspace remains fenced"
                }
                lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Complete => {
                    "Workspace registration removed"
                }
            };
            return format!(
                "Workspace removal\n\nWorkspace: {}\n{}\nConfirmed session cleanup: {}/{}\n\nProject files are preserved. Checking status does not repeat cleanup.\n{}",
                String::from(status.workspace_id),
                phase,
                status.confirmed_sessions.0,
                status.total_sessions.0,
                self.message.unwrap_or("")
            );
        }
        let Some(workspace_id) = self.workspace_id else {
            return "Select a workspace first.".to_owned();
        };
        let workspace = dashboard
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == workspace_id);
        let name = workspace.map_or_else(
            || {
                self.workspace_state
                    .as_ref()
                    .map(|state| safe_label(state.name.as_str()))
                    .unwrap_or_else(|| "Unavailable".to_owned())
            },
            |workspace| safe_label(workspace.name.as_str()),
        );
        let path = self
            .workspace_details
            .as_ref()
            .map(|details| super::safe_configuration_value(details.root_path.as_str()))
            .unwrap_or_else(|| "Unavailable".to_owned());
        let link = self
            .workspace_details
            .as_ref()
            .and_then(|details| details.remote_web_url.as_ref())
            .map(|url| super::safe_configuration_value(url.as_str()))
            .unwrap_or_else(|| "Unavailable in this installation".to_owned());
        let mut output = format!(
            "Name: {}\nID: {}\nSharing: {}\nLocal path: {}\nRemote Web: {}\n\nTerminals\n",
            name,
            safe_label(&String::from(workspace_id)),
            workspace.map_or("Unknown", |w| sharing(w.sharing)),
            path,
            link,
        );
        let rows = self.pane_rows();
        if rows.is_empty() {
            output.push_str("No terminal panes. Press c to choose a shell profile, then explicitly create a terminal.\n");
        } else {
            let range = visible_range(rows.len(), self.selected, DETAIL_ROWS);
            if range.start > 0 {
                output.push_str("… earlier panes omitted …\n");
            }
            for (index, row) in rows.iter().enumerate().take(range.end).skip(range.start) {
                let session = row
                    .session
                    .as_ref()
                    .map(|session| {
                        format!(" session {}", safe_label(&String::from(session.session_id)))
                    })
                    .unwrap_or_default();
                output.push_str(&format!(
                    "{} {} / pane {} — {:?}{}\n",
                    if index == self.selected { ">" } else { " " },
                    safe_label(&row.tab_name),
                    safe_label(&String::from(row.pane_id)),
                    row.state,
                    session,
                ));
            }
            if range.end < rows.len() {
                output.push_str("… later panes omitted …\n");
            }
        }
        if let Some(message) = self.message {
            output.push_str(&format!("\n{}\n", message));
        }
        output.push_str("\n[n] Rename workspace  [d] Remove registration");
        output
    }

    fn draw_shell_profiles(&self) -> String {
        let mut output = String::from(
            "Host-selected shell profiles\nA profile is only inspected here. No shell starts until Enter explicitly creates a terminal.\n\n",
        );
        if self.profiles.is_empty() {
            output.push_str("No profiles were returned by WorkspaceCapabilities.\n");
        } else {
            let range = visible_range(self.profiles.len(), self.selected, DETAIL_ROWS);
            if range.start > 0 {
                output.push_str("… earlier profiles omitted …\n");
            }
            for (index, profile) in self
                .profiles
                .iter()
                .enumerate()
                .take(range.end)
                .skip(range.start)
            {
                output.push_str(&format!(
                    "{} {} [{}]\n",
                    if index == self.selected { ">" } else { " " },
                    safe_label(profile.name.as_str()),
                    safe_label(profile.profile_id.as_str())
                ));
            }
            if range.end < self.profiles.len() {
                output.push_str("… later profiles omitted …\n");
            }
        }
        output.push_str("\n[a] Add profile with explicit name, executable, and working directory.");
        if let Some(message) = self.message {
            output.push_str(&format!("\n\n{}", message));
        }
        output
    }

    fn draw_access(&self, dashboard: &Dashboard) -> String {
        let sharing_state = self
            .workspace_id
            .map_or("No workspace selected", |workspace_id| {
                dashboard
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == workspace_id)
                    .map(|workspace| sharing(workspace.sharing))
                    .unwrap_or("Unknown")
            });
        let current = self.access.as_ref().map_or_else(
            || "Current account access: unavailable; no access is inferred.".to_owned(),
            |snapshot| {
                format!(
                    "Authentication: {:?}\nCredential storage: {:?}\nNetwork: {:?}\nPending cloud revocation: {}\nConnected owner clients: {}\nActive remote terminals: {}",
                    snapshot.login.phase,
                    snapshot.login.storage,
                    snapshot.login.network,
                    snapshot.login.pending_cloud_revoke,
                    snapshot.connected_clients.map_or_else(|| "Unknown".to_owned(), |v| v.to_string()),
                    snapshot.active_terminals.map_or_else(|| "Unknown".to_owned(), |v| v.to_string()),
                )
            },
        );
        format!(
            "Workspace access\n\nCurrent policy: {}\n\n{}\n\n[s] Share with the signed-in owner account\n[u] Revoke workspace sharing; local workspace and sessions remain\n[x] Log out this Host\n\nNo per-device approval is required in this owner-account mode. Revoke an individual consumer session in the account management UI. Account tokens and pairing material are never displayed.\n\n{}",
            sharing_state,
            current,
            self.message.unwrap_or("")
        )
    }

    fn draw_service(&self) -> String {
        let status = self.service.map_or_else(
            || "Service snapshot unavailable. No healthy state is inferred.".to_owned(),
            |state| {
                format!(
                    "Runtime: {:?}\nMode: {}\nAutostart: {:?}\nAccount class: {:?}\nHost uptime: {}\nConnected clients: {}\nActive terminals: {}",
                    state.runtime,
                    state.mode.map_or("Unknown", service_mode_name),
                    state.autostart,
                    state.account,
                    state.host_uptime_seconds.map_or_else(|| "Unknown".to_owned(), |v| format!("{v}s")),
                    state.connected_clients.map_or_else(|| "Unknown".to_owned(), |v| v.to_string()),
                    state.active_terminals.map_or_else(|| "Unknown".to_owned(), |v| v.to_string()),
                )
            },
        );
        format!(
            "{}\n\nChanging the service can end active terminal sessions.\n\n{}",
            status,
            self.message.unwrap_or("")
        )
    }

    fn draw_doctor(&self) -> String {
        let Some(report) = &self.doctor else {
            return format!(
                "Doctor report unavailable.\n\n{}",
                self.message.unwrap_or("Press r to retry.")
            );
        };
        let mut output = format!("Mode: {:?}\n\n", report.mode);
        if let Some(code) = report.last_error {
            output.push_str(&format!("Last error: {:?}\n\n", code));
        }
        if !report.logs_available {
            output.push_str("Structured diagnostic logs are unavailable for this Host.\n\n");
        }
        if report.findings.is_empty() {
            output.push_str("No observations were returned.\n");
        } else {
            let range = visible_range(report.findings.len(), self.selected, DETAIL_ROWS);
            if range.start > 0 {
                output.push_str("… earlier findings omitted …\n");
            }
            for finding in report.findings.iter().take(range.end).skip(range.start) {
                output.push_str(&format!(
                    "{:?}: {:?} — {:?}\n",
                    finding.check, finding.state, finding.guidance
                ));
            }
            if range.end < report.findings.len() || report.truncated {
                output.push_str("… report is bounded; some findings may be omitted.\n");
            }
        }
        if let Some(message) = self.message {
            output.push_str(&format!("\n{}", message));
        }
        output
    }

    fn draw_logs(&self) -> String {
        let Some(page) = &self.logs else {
            return format!(
                "Structured logs unavailable. No transcript, file content, path, or environment data is shown.\n\n{}",
                self.message.unwrap_or("Press r to retry.")
            );
        };
        if !page.available {
            return "Structured log snapshot is unavailable.".to_owned();
        }
        let mut output = String::from("Recent closed-code events\n\n");
        if page.entries.is_empty() {
            output.push_str("No retained events.\n");
        } else {
            let range = visible_range(page.entries.len(), self.selected, DETAIL_ROWS);
            if range.start > 0 {
                output.push_str("… earlier events omitted …\n");
            }
            for entry in page.entries.iter().take(range.end).skip(range.start) {
                output.push_str(&format!(
                    "{} {:?} {:?} {:?}\n",
                    entry
                        .unix_time_ms
                        .map_or_else(|| "time unknown".to_owned(), |time| time.to_string()),
                    entry.severity,
                    entry.component,
                    entry.code,
                ));
            }
        }
        if page.truncated {
            output.push_str("\nPage/history truncated. Press n to continue from the cursor.\n");
        }
        if let Some(message) = self.message {
            output.push_str(&format!("\n{}", message));
        }
        output
    }

    fn draw_settings(&self) -> String {
        let start =
            self.start_mode
                .as_ref()
                .map_or("Unavailable", |value| match value.start_mode {
                    lomi_remote_protocol::ipc::LocalStartMode::Manual => "Manual",
                    lomi_remote_protocol::ipc::LocalStartMode::Login => "Login",
                    lomi_remote_protocol::ipc::LocalStartMode::Boot => "Boot",
                });
        let auth = self.login_status.as_ref().map_or_else(
            || "Authentication status unavailable.".to_owned(),
            |status| {
                format!(
                    "Authentication: {:?}\nCredential storage: {:?}\nNetwork: {:?}\nPending cloud revoke: {}",
                    status.phase, status.storage, status.network, status.pending_cloud_revoke
                )
            },
        );
        format!(
            "Settings\n\nSaved start preference: {}\n{}\n\n[m] Edit start preference\n[l] Open authentication and login\n[x] Confirm account logout\n\nThe start preference is not a service installation or start command.\n{}",
            start,
            auth,
            self.message.unwrap_or("")
        )
    }

    fn draw_confirmation(&self, dashboard: &Dashboard) -> String {
        match self.confirmation.as_ref() {
            Some(Confirmation::RenameWorkspace(rename)) => format!(
                "Rename workspace from {} to {}?\n\nProject files and sharing policy are preserved.",
                safe_label(rename.expected_name.as_str()), safe_label(rename.name.as_str())),
            Some(Confirmation::StopTerminal(row)) => format!(
                "Stop terminal pane {} in {}?\n\n{}\n[y] Confirm  [n/Esc] Cancel.",
                safe_label(&String::from(row.pane_id)),
                safe_label(&row.tab_name),
                if row.session.is_some() {
                    "This ends its shell session."
                } else {
                    "This removes the stopped pane descriptor; it has no live shell session."
                }
            ),
            Some(Confirmation::RemoveWorkspace(id)) => {
                let name = dashboard
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == *id)
                    .map_or("workspace", |workspace| workspace.name.as_str());
                format!(
                    "Remove workspace registration for {}?\n\nIts terminal sessions end; project files on disk remain untouched.\n[y] Remove registration  [n/Esc] Cancel.",
                    safe_label(name)
                )
            }
            Some(Confirmation::ChangeSharing { share: true, .. }) => {
                "Share this workspace with the signed-in owner account?\n\nApproved windows can view, control, create, resize, and close shared terminals; read and edit project files; and use the workspace Git tools. Editor buffers, chat, browser panes, plugins, and AI-controlled terminals stay private. Sharing does not start a shell.\n[y] Share  [n/Esc] Keep local-only.".to_owned()
            }
            Some(Confirmation::ChangeSharing { share: false, .. }) => {
                "Revoke workspace sharing?\n\nRemote access is cut off; local workspace files and sessions are preserved.\n[y] Revoke  [n/Esc] Keep shared.".to_owned()
            }
            Some(Confirmation::Service(action)) => format!(
                "Confirm service action: {:?}\n\nThe service adapter will report its actual state after the action.\n[y] Confirm  [n/Esc] Cancel.",
                action
            ),
            Some(Confirmation::Logout) => {
                "Log out this Host and revoke its remote authorization?\n\nThis fences remote access and may stop shared Host activity.\n[y] Confirm logout  [n/Esc] Cancel.".to_owned()
            }
            None => String::new(),
        }
    }

    fn draw_shell_draft(&self, draft: &ShellProfileDraft) -> String {
        let error = draft
            .error
            .map_or_else(String::new, |e| format!("Error: {e}\n\n"));
        match draft.field {
            ProfileDraftField::Name => {
                format!("{error}Profile display name:\n{}▏", safe_label(&draft.name))
            }
            ProfileDraftField::Executable => format!(
                "{error}Absolute executable path:\n{}▏\n\nThe path is stored locally; it is not launched during setup.",
                safe_label(&draft.executable)
            ),
            ProfileDraftField::WorkingDirectory => format!(
                "{error}Absolute working directory:\n{}▏\n\nNo environment values or arguments are copied.",
                safe_label(&draft.working_directory)
            ),
            ProfileDraftField::Confirm => format!(
                "Save shell profile?\n\nName: {}\nExecutable: {}\nWorking directory: {}\n\nNo shell starts until you explicitly create a terminal.\n[y] Save  [n/Esc] Cancel.",
                safe_label(&draft.name),
                safe_label(&draft.executable),
                safe_label(&draft.working_directory),
            ),
        }
    }
}

fn rpc(backend: &mut impl Backend, call: RpcCall) -> Result<RpcResult, &'static str> {
    let request = crate::terminal_commands::request(call);
    match backend.request(LocalCall::Rpc(Box::new(request)))? {
        LocalResult::Rpc(reply) => match *reply {
            RpcResponse::Result { result, .. } => Ok(result),
            RpcResponse::Error { error, .. }
                if error.effect() == lomi_remote_protocol::Effect::Unknown =>
            {
                Err("OUTCOME_UNKNOWN")
            }
            RpcResponse::Error { .. } => Err("RPC_REQUEST_REJECTED"),
        },
        _ => Err("LOCAL_RESPONSE_INVALID"),
    }
}

fn new_operation_id() -> OperationId {
    OperationId::from_bytes(*Uuid::new_v4().as_bytes()).expect("UUID v4 operation ID")
}

fn page_title(page: Page) -> &'static str {
    match page {
        Page::WorkspaceDetails => "Workspace details",
        Page::ShellProfiles => "Shell profiles",
        Page::Access => "Access and sharing",
        Page::Service => "Service and autostart",
        Page::Doctor => "Doctor",
        Page::Logs => "Logs",
        Page::Settings => "Settings",
    }
}

fn service_mode_name(mode: ServiceMode) -> &'static str {
    match mode {
        ServiceMode::Manual => "Manual",
        ServiceMode::Login => "Login",
        ServiceMode::Boot => "Boot",
    }
}

fn service_action_error_message(code: &'static str) -> &'static str {
    match code {
        "SERVICE_ADMINISTRATOR_INSTALL_REQUIRED" => {
            #[cfg(target_os = "macos")]
            {
                "Administrator setup is required. Install the signed Lomi Remote companion for this account, then retry."
            }
            #[cfg(target_os = "windows")]
            {
                "Administrator access is required. Use an elevated terminal for the account-bound `lomiremote service` command, then retry."
            }
            #[cfg(target_os = "linux")]
            {
                "Administrator access is required for this service action. No elevation was attempted; use the supported user service or foreground Host mode if system service setup is unavailable."
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
            {
                "Administrator access is required for this service action. Use the platform's supported installer, then retry."
            }
        }
        "SERVICE_OS_CREDENTIALS_REQUIRED" => {
            #[cfg(target_os = "windows")]
            {
                "The Windows service account needs current credentials. Use `lomiremote service update --account <account> --repair-credentials --confirm` in an elevated terminal; enter the password only at its secure prompt."
            }
            #[cfg(target_os = "macos")]
            {
                "The OS service account needs credentials or permissions. Check the account's Keychain and access to the workspace, then inspect `lomiremote service status`."
            }
            #[cfg(target_os = "linux")]
            {
                "The OS could not start the service account. Check user-service permissions and access to the workspace, then inspect `lomiremote service status`."
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
            {
                "The OS service account needs credentials or permissions. Correct them in the native service manager, then retry."
            }
        }
        "SERVICE_MANAGER_UNAVAILABLE" => {
            #[cfg(target_os = "macos")]
            {
                "launchd is unavailable for this service action. Check the current login session, then retry `lomiremote service status`."
            }
            #[cfg(target_os = "windows")]
            {
                "Windows Service Control Manager is unavailable. Check that the service manager is running and that this account can access it."
            }
            #[cfg(target_os = "linux")]
            {
                "The user service manager is unavailable. Check the systemd user session; manual mode can run under a supported foreground supervisor."
            }
            #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
            {
                "The native service manager is unavailable. Check its status and retry."
            }
        }
        "SERVICE_MODE_UNAVAILABLE" => {
            "This start mode is unavailable for the current installation. Review the observed mode, then explicitly install a supported mode."
        }
        "SERVICE_MANUAL_MODE_HAS_NO_AUTOSTART_REGISTRATION" => {
            "Manual mode has no autostart registration. Choose Login or Boot in Settings, then explicitly install that mode."
        }
        "SERVICE_MODE_CHANGE_REQUIRES_EXPLICIT_UNINSTALL" => {
            "The installed service uses a different mode. Explicitly uninstall it before installing the requested mode; no mode change was made."
        }
        "SERVICE_OPERATION_UNCERTAIN" | "SERVICE_STOP_NOT_CONFIRMED" => {
            "The OS may have applied this action, but it was not confirmed. Do not repeat it yet; press r to read the observed service state."
        }
        "SERVICE_OWNERSHIP_CONFLICT" => {
            "Another service registration or Host owns this profile. Inspect `lomiremote service status` and resolve that registration before retrying."
        }
        "SERVICE_INVALID_CONFIGURATION" => {
            "The native service configuration does not match this installation. Inspect `lomiremote doctor` and the account-bound service status before changing it."
        }
        "SERVICE_NOT_READY" => {
            "The service did not become ready. Press r to refresh its observed state, then review Doctor for the reported cause."
        }
        "LOCAL_HOST_IDENTITY_CHANGED" => {
            "The local Host identity changed during this action. No retry was sent; refresh the dashboard and verify the selected Host."
        }
        "SERVICE_ACTION_UNAVAILABLE" => {
            "No native service action adapter is available in this build. Use the platform's documented service manager or foreground Host mode."
        }
        _ => {
            "The service action failed without a confirmed outcome. Press r to observe current state before retrying."
        }
    }
}

fn service_status_error_message(code: &'static str) -> &'static str {
    match code {
        "SERVICE_EXECUTABLE_UNAVAILABLE" => {
            "The current executable path could not be verified. Run the installed Lomi Remote CLI, then refresh service status."
        }
        "SERVICE_STATUS_UNAVAILABLE" => {
            "Native service status could not be read. Check the OS service manager or run `lomiremote service status`; no healthy state is inferred."
        }
        "SERVICE_OWNERSHIP_CONFLICT"
        | "SERVICE_MANAGER_UNAVAILABLE"
        | "SERVICE_INVALID_CONFIGURATION"
        | "SERVICE_ADMINISTRATOR_INSTALL_REQUIRED"
        | "SERVICE_OS_CREDENTIALS_REQUIRED"
        | "SERVICE_MODE_UNAVAILABLE" => service_action_error_message(code),
        _ => {
            "Native service status is unknown. Check the OS service manager, then press r to retry; no healthy state is inferred."
        }
    }
}

fn visible_range(length: usize, selected: usize, visible: usize) -> std::ops::Range<usize> {
    let start = selected
        .saturating_sub(visible / 2)
        .min(length.saturating_sub(visible));
    let end = start.saturating_add(visible).min(length);
    start..end
}
