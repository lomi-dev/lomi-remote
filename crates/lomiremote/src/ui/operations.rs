//! Dashboard operation pages. Every mutation is issued only after an explicit
//! key action; opening a page performs bounded reads only.

use super::{
    Backend, Dashboard,
    interaction::{Action, Controls},
    safe_label, sharing, theme,
};
use crate::diagnostics::{
    DiagnosticReport, DiagnosticReportBuilder, DiagnosticRunMode, HostAvailability,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
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
    layout::{Constraint, Layout, Rect},
    widgets::{Paragraph, Wrap},
};
use std::{cell::Cell, path::Path};
use uuid::Uuid;

const DISPLAY_NAME_MAX: usize = 255;
const LOCAL_PATH_MAX: usize = 4096;
const DETAIL_ROWS: usize = 12;
const LOG_PAGE_SIZE: usize = 64;
const DRAFT_INPUT_ACTION: usize = usize::MAX;

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
    controls: Controls,
    body_area: Cell<Rect>,
    body_scroll: Cell<usize>,
    body_scroll_max: Cell<usize>,
}

impl Operations {
    pub(super) fn active(&self) -> bool {
        self.page.is_some()
    }

    pub(super) fn hoverable(&self, column: u16, row: u16) -> bool {
        self.controls.hoverable(column, row)
    }

    pub(super) fn open(
        &mut self,
        page: Page,
        workspace_id: Option<WorkspaceId>,
        backend: &mut impl Backend,
    ) {
        self.controls.reset();
        self.body_scroll.set(0);
        self.body_scroll_max.set(0);
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

    /// Open the pinned workspace details page and begin the guarded rename
    /// flow from the name returned by the Host.
    pub(super) fn begin_workspace_rename(
        &mut self,
        workspace_id: WorkspaceId,
        backend: &mut impl Backend,
    ) {
        self.open(Page::WorkspaceDetails, Some(workspace_id), backend);
        self.start_workspace_rename();
    }

    /// Open the pinned workspace details page and show the existing removal
    /// confirmation. Opening the confirmation performs reads only.
    pub(super) fn begin_workspace_remove(
        &mut self,
        workspace_id: WorkspaceId,
        backend: &mut impl Backend,
    ) {
        self.open(Page::WorkspaceDetails, Some(workspace_id), backend);
        self.start_workspace_remove();
    }

    pub(super) fn draw(
        &self,
        frame: &mut Frame,
        dashboard: &Dashboard,
        area: Rect,
        footer_area: Rect,
    ) {
        self.controls.begin();
        let [header, body] =
            Layout::vertical([Constraint::Length(3), Constraint::Min(4)]).areas(area);
        let title = self.page.map_or("Dashboard", page_title);
        let workspace = match self.workspace_id {
            Some(workspace_id) => self
                .workspace_state
                .as_ref()
                .filter(|state| state.context.workspace_id == workspace_id)
                .map(|state| safe_label(state.name.as_str()))
                .or_else(|| {
                    dashboard
                        .workspaces
                        .iter()
                        .find(|workspace| workspace.workspace_id == workspace_id)
                        .map(|workspace| safe_label(workspace.name.as_str()))
                })
                .unwrap_or_else(|| "Unavailable".to_owned()),
            None => dashboard.selected_workspace().map_or_else(
                || "None".to_owned(),
                |workspace| safe_label(workspace.name.as_str()),
            ),
        };
        let header_text = format!(
            "Lomi Remote  v{}  |  {}\nWorkspace: {}",
            env!("CARGO_PKG_VERSION"),
            title,
            workspace
        );
        frame.render_widget(Paragraph::new(theme::header(&header_text)), header);

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
        let panel = theme::panel(title, theme::SURFACE);
        let body_inner = panel.inner(body);
        self.body_area.set(body_inner);
        let total_lines = wrapped_line_count(&content, body_inner.width);
        let max_scroll = total_lines.saturating_sub(usize::from(body_inner.height));
        let scroll = self
            .scroll_for_selected_row(&content, body_inner)
            .min(max_scroll);
        self.body_scroll.set(scroll);
        self.body_scroll_max.set(max_scroll);
        frame.render_widget(
            Paragraph::new(theme::content(&content))
                .block(panel)
                .wrap(Wrap { trim: false })
                .scroll((scroll.min(usize::from(u16::MAX)) as u16, 0)),
            body,
        );

        if let Some(label) = self.draft_input_label() {
            let lines = content.lines().collect::<Vec<_>>();
            if let Some(label_index) = lines.iter().position(|line| *line == label) {
                let input_index = label_index.saturating_add(1);
                if let Some(input_line) = lines.get(input_index) {
                    let rows_before = lines
                        .iter()
                        .take(input_index)
                        .map(|line| wrapped_line_count(line, body_inner.width))
                        .sum::<usize>();
                    let input_height = wrapped_line_count(input_line, body_inner.width);
                    let input_top = body_inner
                        .y
                        .saturating_add(u16::try_from(rows_before).unwrap_or(u16::MAX))
                        .saturating_sub(u16::try_from(scroll).unwrap_or(u16::MAX));
                    let input_bottom =
                        input_top.saturating_add(u16::try_from(input_height).unwrap_or(u16::MAX));
                    let target_top = input_top.max(body_inner.y);
                    let target_bottom = input_bottom.min(body_inner.bottom());
                    if target_bottom > target_top {
                        self.controls.row(
                            Rect::new(
                                body_inner.x,
                                target_top,
                                body_inner.width,
                                target_bottom - target_top,
                            ),
                            DRAFT_INPUT_ACTION,
                        );
                    }
                }
            }
        } else if self.body_actions_enabled() {
            self.register_row_targets(&content, body_inner);
        }

        let (primary, trailing): (&[(&str, &str)], &[(&str, &str)]) = if self
            .shell_draft
            .as_ref()
            .is_some_and(|draft| draft.field == ProfileDraftField::Confirm)
        {
            (&[("y", "Save profile")], &[("n", "Cancel")])
        } else if self.shell_draft.is_some() || self.rename_draft.is_some() {
            (&[("Enter", "Next")], &[("Esc", "Cancel")])
        } else if self.confirmation.is_some() {
            (&[("y", "Confirm"), ("↑/↓", "Scroll")], &[("n", "Cancel")])
        } else if self.page == Some(Page::WorkspaceDetails) && self.removal_status.is_some() {
            (
                &[("r", "Check status"), ("↑/↓", "Scroll")],
                &[("Esc", "Back")],
            )
        } else {
            match self.page {
                Some(Page::WorkspaceDetails) => (
                    &[
                        ("p", "Profiles"),
                        ("x", "Stop"),
                        ("v", "Access"),
                        ("n", "Rename"),
                        ("d", "Remove"),
                        ("↑/↓", "Select"),
                    ],
                    &[("r", "Refresh"), ("Esc", "Back")],
                ),
                Some(Page::ShellProfiles) => (
                    &[
                        ("↑/↓", "Select"),
                        ("Enter", "Create terminal"),
                        ("a", "Add profile"),
                    ],
                    &[("r", "Refresh"), ("Esc", "Back")],
                ),
                Some(Page::Access) => (
                    &[
                        ("↑/↓", "Scroll"),
                        ("s", "Share"),
                        ("u", "Unshare"),
                        ("x", "Log out"),
                    ],
                    &[("r", "Refresh"), ("Esc", "Back")],
                ),
                Some(Page::Service) => (
                    &[
                        ("i", "Install at login"),
                        ("b", "Install at boot"),
                        ("s", "Start"),
                        ("t", "Stop"),
                        ("R", "Restart"),
                        ("u", "Uninstall"),
                        ("↑/↓", "Scroll"),
                    ],
                    &[("r", "Refresh"), ("Esc", "Back")],
                ),
                Some(Page::Doctor) => (&[("↑/↓", "Select")], &[("r", "Refresh"), ("Esc", "Back")]),
                Some(Page::Logs) => (
                    &[("↑/↓", "Select"), ("n", "Next page")],
                    &[("r", "Latest"), ("Esc", "Back")],
                ),
                Some(Page::Settings) => (
                    &[
                        ("↑/↓", "Scroll"),
                        ("m", "Start preference"),
                        ("l", "Login/auth"),
                        ("x", "Log out"),
                    ],
                    &[("Esc", "Back")],
                ),
                None => (&[], &[("Esc", "Back")]),
            }
        };
        self.controls
            .extend(theme::render_footer(frame, footer_area, primary, trailing));
        if self.controls.focused().is_none() {
            if self.draft_input_label().is_some() {
                self.controls.focus_action(Action::Row(DRAFT_INPUT_ACTION));
            } else if self.confirmation.is_some()
                || self
                    .shell_draft
                    .as_ref()
                    .is_some_and(|draft| draft.field == ProfileDraftField::Confirm)
            {
                self.controls.focus_action(Action::Key(KeyEvent::new(
                    KeyCode::Char('n'),
                    KeyModifiers::NONE,
                )));
            }
        }
        self.controls.highlight(frame);
    }

    pub(super) fn handle_key(
        &mut self,
        key: KeyEvent,
        backend: &mut impl Backend,
        dashboard: &mut Dashboard,
    ) -> bool {
        let editing = self.rename_draft.is_some() || self.shell_draft.is_some();

        // Keep the global exit gesture ahead of focused-action dispatch.
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        if key.code == KeyCode::Enter && !key.modifiers.is_empty() {
            return true;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return true;
        }

        if matches!(key.code, KeyCode::Tab | KeyCode::BackTab) {
            self.controls.cycle(key.code == KeyCode::BackTab);
            return true;
        }
        if key.code == KeyCode::Enter {
            match self.controls.focused() {
                Some(Action::Key(activation)) => {
                    self.controls.blur();
                    return self.handle_key(activation, backend, dashboard);
                }
                Some(Action::Row(index)) if !editing => {
                    self.selected = index;
                    self.body_scroll.set(0);
                    self.controls.blur();
                }
                None => {}
                Some(Action::Row(_)) => {}
            }
        }
        if editing
            && matches!(
                key.code,
                KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right
            )
        {
            if !matches!(key.code, KeyCode::Left | KeyCode::Right)
                || matches!(self.controls.focused(), Some(Action::Key(_)))
            {
                self.controls.move_focus(key.code);
            }
            return true;
        }
        if matches!(key.code, KeyCode::Left | KeyCode::Right) {
            self.controls.move_focus(key.code);
            return true;
        }
        if !editing
            && self.confirmation.is_none()
            && !matches!(key.code, KeyCode::Up | KeyCode::Down)
        {
            self.controls.blur();
            if matches!(key.code, KeyCode::Char(_)) {
                self.body_scroll.set(0);
            }
        }
        if let Some(mut draft) = self.rename_draft.take() {
            self.controls.blur();
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
            self.controls.blur();
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
                KeyCode::Up => {
                    if !self.controls.move_focus(KeyCode::Up) {
                        self.move_selection_or_scroll(false);
                    }
                }
                KeyCode::Down => {
                    if !self.controls.move_focus(KeyCode::Down) {
                        self.move_selection_or_scroll(true);
                    }
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
            KeyCode::Up | KeyCode::Down => {
                let down = key.code == KeyCode::Down;
                if matches!(self.controls.focused(), Some(Action::Key(_))) {
                    self.controls.move_focus(key.code);
                    if let Some(Action::Row(index)) = self.controls.focused() {
                        if self.selection_count().is_some_and(|count| index < count) {
                            self.selected = index;
                            self.body_scroll.set(0);
                        }
                    }
                } else if down
                    && self
                        .selection_count()
                        .is_some_and(|count| count > 0 && self.selected.saturating_add(1) >= count)
                {
                    self.controls.focus_action(Action::Row(self.selected));
                    if !self.controls.move_focus(KeyCode::Down) {
                        self.move_selection_or_scroll(true);
                    }
                } else {
                    self.move_selection_or_scroll(down);
                }
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
                self.start_workspace_rename();
                true
            }
            KeyCode::Char('d') if self.page == Some(Page::WorkspaceDetails) => {
                self.refresh_workspace(backend);
                self.start_workspace_remove();
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

    pub(super) fn handle_mouse(
        &mut self,
        event: MouseEvent,
        backend: &mut impl Backend,
        dashboard: &mut Dashboard,
    ) -> bool {
        if !self.active() {
            return false;
        }

        match event.kind {
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown => {
                if !rect_contains(self.body_area.get(), event.column, event.row) {
                    return false;
                }
                if self.rename_draft.is_some() || self.shell_draft.is_some() {
                    return true;
                }
                let down = event.kind == MouseEventKind::ScrollDown;
                self.move_selection_or_scroll_by(down, 3);
                true
            }
            _ => match self.controls.click(event) {
                Some(Action::Key(key)) => {
                    self.controls.blur();
                    self.handle_key(key, backend, dashboard)
                }
                Some(Action::Row(index)) if self.body_actions_enabled() => {
                    self.selected = index;
                    self.body_scroll.set(0);
                    self.controls.blur();
                    true
                }
                Some(Action::Row(_)) => true,
                None => false,
            },
        }
    }

    pub(super) fn can_switch_workspace(&self) -> bool {
        self.confirmation.is_none()
            && self.shell_draft.is_none()
            && self.rename_draft.is_none()
            && self.removal_status.is_none()
    }

    pub(super) fn retarget_workspace(
        &mut self,
        workspace_id: WorkspaceId,
        backend: &mut impl Backend,
    ) {
        if !self.can_switch_workspace() {
            return;
        }
        if self.workspace_id == Some(workspace_id) {
            return;
        }
        match self.page {
            Some(page @ (Page::WorkspaceDetails | Page::ShellProfiles | Page::Access)) => {
                self.open(page, Some(workspace_id), backend);
            }
            _ => {
                self.workspace_id = Some(workspace_id);
            }
        }
    }

    fn body_actions_enabled(&self) -> bool {
        self.active()
            && self.confirmation.is_none()
            && self.shell_draft.is_none()
            && self.rename_draft.is_none()
            && self.removal_status.is_none()
            && matches!(
                self.page,
                Some(Page::WorkspaceDetails | Page::ShellProfiles | Page::Doctor | Page::Logs)
            )
    }

    fn draft_input_label(&self) -> Option<&'static str> {
        if self.rename_draft.is_some() {
            Some("New workspace name:")
        } else {
            match self.shell_draft.as_ref()?.field {
                ProfileDraftField::Name => Some("Profile display name:"),
                ProfileDraftField::Executable => Some("Absolute executable path:"),
                ProfileDraftField::WorkingDirectory => Some("Absolute working directory:"),
                ProfileDraftField::Confirm => None,
            }
        }
    }

    fn start_workspace_rename(&mut self) {
        let Some(workspace_id) = self.workspace_id else {
            return;
        };
        let Some(state) = self
            .workspace_state
            .as_ref()
            .filter(|state| state.context.workspace_id == workspace_id)
        else {
            self.message = Some("Workspace details are unavailable. Press r to retry.");
            return;
        };
        match LocalProjectName::try_from(state.name.as_str().to_owned()) {
            Ok(name) => {
                self.rename_draft = Some(RenameDraft {
                    expected_name: name,
                    name: state.name.as_str().to_owned(),
                });
                self.message = None;
            }
            Err(_) => self.message = Some("Workspace name cannot be renamed safely."),
        }
    }

    fn start_workspace_remove(&mut self) {
        if self.workspace_id.is_some_and(|workspace_id| {
            self.workspace_state
                .as_ref()
                .is_some_and(|state| state.context.workspace_id == workspace_id)
        }) {
            self.confirmation = self.workspace_id.map(Confirmation::RemoveWorkspace);
            self.message = None;
        } else {
            self.message = Some("Workspace details are unavailable. Press r to retry.");
        }
    }

    fn row_action_lines(&self) -> Vec<(usize, String)> {
        match self.page {
            Some(Page::WorkspaceDetails) => {
                let rows = self.pane_rows();
                let range = visible_range(rows.len(), self.selected, DETAIL_ROWS);
                rows.iter()
                    .enumerate()
                    .take(range.end)
                    .skip(range.start)
                    .map(|(index, row)| {
                        let session = row
                            .session
                            .as_ref()
                            .map(|session| {
                                format!(
                                    " session {}",
                                    safe_label(&String::from(session.session_id))
                                )
                            })
                            .unwrap_or_default();
                        (
                            index,
                            format!(
                                "{} {} / pane {} — {:?}{}",
                                if index == self.selected { ">" } else { " " },
                                safe_label(&row.tab_name),
                                safe_label(&String::from(row.pane_id)),
                                row.state,
                                session,
                            ),
                        )
                    })
                    .collect()
            }
            Some(Page::ShellProfiles) => {
                let range = visible_range(self.profiles.len(), self.selected, DETAIL_ROWS);
                self.profiles
                    .iter()
                    .enumerate()
                    .take(range.end)
                    .skip(range.start)
                    .map(|(index, profile)| {
                        (
                            index,
                            format!(
                                "{} {} [{}]",
                                if index == self.selected { ">" } else { " " },
                                safe_label(profile.name.as_str()),
                                safe_label(profile.profile_id.as_str())
                            ),
                        )
                    })
                    .collect()
            }
            Some(Page::Doctor) => {
                let Some(report) = &self.doctor else {
                    return Vec::new();
                };
                let range = visible_range(report.findings.len(), self.selected, DETAIL_ROWS);
                report
                    .findings
                    .iter()
                    .enumerate()
                    .take(range.end)
                    .skip(range.start)
                    .map(|(index, finding)| {
                        (
                            index,
                            format!(
                                "{:?}: {:?} — {:?}",
                                finding.check, finding.state, finding.guidance
                            ),
                        )
                    })
                    .collect()
            }
            Some(Page::Logs) => {
                let Some(page) = &self.logs else {
                    return Vec::new();
                };
                if !page.available {
                    return Vec::new();
                }
                let range = visible_range(page.entries.len(), self.selected, DETAIL_ROWS);
                page.entries
                    .iter()
                    .enumerate()
                    .take(range.end)
                    .skip(range.start)
                    .map(|(index, entry)| {
                        (
                            index,
                            format!(
                                "{} {:?} {:?} {:?}",
                                entry.unix_time_ms.map_or_else(
                                    || "time unknown".to_owned(),
                                    |time| time.to_string()
                                ),
                                entry.severity,
                                entry.component,
                                entry.code,
                            ),
                        )
                    })
                    .collect()
            }
            _ => Vec::new(),
        }
    }

    fn register_row_targets(&self, content: &str, body: Rect) {
        if body.is_empty() {
            return;
        }
        let lines = content.split('\n').collect::<Vec<_>>();
        let scroll = self.body_scroll.get();
        let visible_end = scroll.saturating_add(usize::from(body.height));
        let mut search_from = 0usize;
        for (row_index, row_text) in self.row_action_lines() {
            let Some(line_index) = lines
                .iter()
                .enumerate()
                .skip(search_from)
                .find_map(|(index, line)| (*line == row_text).then_some(index))
            else {
                continue;
            };
            search_from = line_index.saturating_add(1);
            let line_start = lines[..line_index]
                .iter()
                .map(|line| wrapped_line_count(line, body.width))
                .sum::<usize>();
            let row_height = wrapped_line_count(&row_text, body.width);
            let row_end = line_start.saturating_add(row_height);
            let visible_start = line_start.max(scroll);
            let visible_row_end = row_end.min(visible_end);
            if visible_start >= visible_row_end {
                continue;
            }
            let y = body
                .y
                .saturating_add((visible_start.saturating_sub(scroll)) as u16);
            let height = (visible_row_end.saturating_sub(visible_start)) as u16;
            self.controls.row(
                Rect::new(
                    body.x,
                    y,
                    body.width,
                    height.min(body.bottom().saturating_sub(y)),
                ),
                row_index,
            );
        }
    }

    fn scroll_for_selected_row(&self, content: &str, body: Rect) -> usize {
        let current = self.body_scroll.get();
        if !self.body_actions_enabled() || body.is_empty() {
            return current;
        }
        let Some((_, row_text)) = self
            .row_action_lines()
            .into_iter()
            .find(|(index, _)| *index == self.selected)
        else {
            return current;
        };
        let lines = content.split('\n').collect::<Vec<_>>();
        let Some(line_index) = lines.iter().position(|line| *line == row_text) else {
            return current;
        };
        let line_start = lines[..line_index]
            .iter()
            .map(|line| wrapped_line_count(line, body.width))
            .sum::<usize>();
        let row_end = line_start.saturating_add(wrapped_line_count(&row_text, body.width));
        let viewport_height = usize::from(body.height);
        if line_start < current {
            line_start
        } else if row_end > current.saturating_add(viewport_height) {
            row_end.saturating_sub(viewport_height)
        } else {
            current
        }
    }

    fn selection_count(&self) -> Option<usize> {
        if self.confirmation.is_some()
            || self.shell_draft.is_some()
            || self.rename_draft.is_some()
            || self.removal_status.is_some()
        {
            return None;
        }
        match self.page {
            Some(Page::WorkspaceDetails) => Some(self.pane_rows().len()),
            Some(Page::ShellProfiles) => Some(self.profiles.len()),
            Some(Page::Doctor) => Some(
                self.doctor
                    .as_ref()
                    .map_or(0, |report| report.findings.len()),
            ),
            Some(Page::Logs) => Some(self.logs.as_ref().map_or(0, |page| page.entries.len())),
            _ => None,
        }
    }

    fn move_selection_or_scroll(&mut self, down: bool) {
        self.move_selection_or_scroll_by(down, 1);
    }

    fn move_selection_or_scroll_by(&mut self, down: bool, scroll_amount: usize) {
        if let Some(count) = self.selection_count().filter(|count| *count > 0) {
            self.selected = if down {
                self.selected.saturating_add(1).min(count.saturating_sub(1))
            } else {
                self.selected.saturating_sub(1)
            };
            self.body_scroll.set(0);
            self.controls.blur();
        } else {
            let current = self.body_scroll.get();
            let next = if down {
                current
                    .saturating_add(scroll_amount)
                    .min(self.body_scroll_max.get())
            } else {
                current.saturating_sub(scroll_amount)
            };
            self.body_scroll.set(next);
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) -> bool {
        if let Some(draft) = self.rename_draft.as_mut() {
            self.controls.blur();
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
            self.controls.blur();
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
        self.controls.reset();
        self.body_area.set(Rect::default());
        self.body_scroll.set(0);
        self.body_scroll_max.set(0);
        self.confirmation = None;
        self.shell_draft = None;
        self.rename_draft = None;
        self.message = None;
        self.removal_status = None;
    }

    fn refresh(&mut self, backend: &mut impl Backend) {
        self.body_scroll.set(0);
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
                let selection_len = if self.page == Some(Page::ShellProfiles) {
                    self.profiles.len()
                } else {
                    self.pane_rows().len()
                };
                self.selected = self.selected.min(selection_len.saturating_sub(1));
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
        self.body_scroll.set(0);
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
            }
            Err("OUTCOME_UNKNOWN") => {
                self.refresh_workspace(backend);
                self.message = Some(
                    "Terminal creation outcome is unknown. State refreshed; do not repeat until verified.",
                );
            }
            _ => {
                self.refresh_workspace(backend);
                self.message = Some("Terminal creation was not confirmed. State refreshed.");
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
        let name = self
            .workspace_state
            .as_ref()
            .filter(|state| state.context.workspace_id == workspace_id)
            .map(|state| safe_label(state.name.as_str()))
            .or_else(|| {
                dashboard
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == workspace_id)
                    .map(|workspace| safe_label(workspace.name.as_str()))
            })
            .unwrap_or_else(|| "Unavailable".to_owned());
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
            "Name: {}\nLocal path: {}\nRemote Web: {}\n\nTerminals\n",
            name, path, link,
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
                let loaded_name = self
                    .workspace_state
                    .as_ref()
                    .filter(|state| {
                        self.workspace_id == Some(*id) && state.context.workspace_id == *id
                    })
                    .map(|state| state.name.as_str())
                    ;
                let dashboard_name = dashboard
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == *id)
                    .map(|workspace| workspace.name.as_str());
                let name = loaded_name.or(dashboard_name).unwrap_or("workspace");
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

fn wrapped_line_count(text: &str, width: u16) -> usize {
    if width == 0 {
        return text.split('\n').count().max(1);
    }
    Paragraph::new(theme::content(text))
        .wrap(Wrap { trim: false })
        .line_count(width)
}

fn rect_contains(rect: Rect, x: u16, y: u16) -> bool {
    !rect.is_empty() && x >= rect.x && x < rect.right() && y >= rect.y && y < rect.bottom()
}

#[cfg(test)]
mod interaction_tests {
    use super::{
        Backend, Dashboard, HostProfile, LocalCall, LocalProjectName, LocalResult, Operations,
        Page, ProfileDraftField, RenameDraft, ShellProfileDraft,
    };
    use crossterm::event::{
        KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
    };
    use lomi_remote_protocol::ipc::LocalWorkspaceRead;
    use lomi_remote_protocol::rpc::{
        BoundedList, DisplayText, HostProfileId, PaneState, RpcCall, RpcResponse, RpcResult,
        TerminalLayout, TerminalPane, TerminalTab, WorkspaceState,
    };
    use lomi_remote_protocol::{
        CapabilitySet, ConsumerAuthorizationId, DecimalU64, Effect, ErrorCode, ErrorDetails,
        Method, OperationId, OperationLookup, OperationParameterHash, OperationReceipt,
        OperationResult, OperationState, RemoteError, RuntimeId, SessionEpoch, TerminalSessionId,
        WorkspaceContext, WorkspaceEpoch, WorkspaceId,
    };
    use ratatui::{
        Terminal,
        backend::TestBackend,
        layout::Rect,
        widgets::{Paragraph, Wrap},
    };

    struct NoBackend;

    impl Backend for NoBackend {
        fn request(&mut self, _call: LocalCall) -> Result<LocalResult, &'static str> {
            panic!("this interaction must not issue a backend request")
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum TerminalCreateOutcome {
        Succeeded,
        Failed,
        Unknown,
    }

    struct TerminalCreateBackend {
        workspace_id: WorkspaceId,
        outcome: TerminalCreateOutcome,
        refreshed_tabs: Vec<TerminalTab>,
        created_profiles: Vec<HostProfileId>,
    }

    impl Backend for TerminalCreateBackend {
        fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
            match call {
                LocalCall::Rpc(request) => {
                    let RpcCall::TerminalCreate(params) = request.call else {
                        return Err("unexpected RPC request in terminal creation fixture");
                    };
                    self.created_profiles.push(params.profile_id);
                    let operation_id = OperationId::from_bytes([6; 16]).unwrap();
                    let response = match self.outcome {
                        TerminalCreateOutcome::Succeeded => RpcResponse::Result {
                            v: request.v,
                            request_id: request.request_id,
                            result: RpcResult::TerminalCreate(terminal_create_receipt(
                                self.workspace_id,
                            )),
                        },
                        TerminalCreateOutcome::Failed => RpcResponse::Error {
                            v: request.v,
                            request_id: request.request_id,
                            operation_id: None,
                            error: RemoteError::new(
                                ErrorCode::InvalidArgument,
                                false,
                                Effect::None,
                                ErrorDetails::empty(),
                                None,
                            )
                            .unwrap(),
                        },
                        TerminalCreateOutcome::Unknown => RpcResponse::Error {
                            v: request.v,
                            request_id: request.request_id,
                            operation_id: Some(operation_id),
                            error: RemoteError::new(
                                ErrorCode::OutcomeUnknown,
                                false,
                                Effect::Unknown,
                                ErrorDetails::empty(),
                                Some(OperationLookup {
                                    workspace_id: self.workspace_id,
                                    operation_id,
                                }),
                            )
                            .unwrap(),
                        },
                    };
                    Ok(LocalResult::Rpc(Box::new(response)))
                }
                LocalCall::WorkspaceInspect(LocalWorkspaceRead { workspace_id }) => {
                    assert_eq!(workspace_id, self.workspace_id);
                    Ok(LocalResult::WorkspaceState(Box::new(workspace_state(
                        self.workspace_id,
                        self.refreshed_tabs.clone(),
                    ))))
                }
                LocalCall::WorkspaceDetails(_) => Err("details are not needed by this fixture"),
                _ => Err("unexpected local request in terminal creation fixture"),
            }
        }
    }

    fn workspace_state(workspace_id: WorkspaceId, tabs: Vec<TerminalTab>) -> WorkspaceState {
        WorkspaceState {
            context: WorkspaceContext {
                workspace_id,
                workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
                runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
                runtime_generation: DecimalU64(1),
                host_access_epoch: DecimalU64(1),
                grant_revision: DecimalU64(1),
            },
            domain_revision: DecimalU64(1),
            name: DisplayText::try_from("fixture".to_owned()).unwrap(),
            tabs: BoundedList(tabs),
        }
    }

    fn terminal_tab() -> TerminalTab {
        TerminalTab {
            tab_id: lomi_remote_protocol::TabId::from_bytes([7; 16]).unwrap(),
            name: DisplayText::try_from("Terminal 1".to_owned()).unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: lomi_remote_protocol::PaneId::from_bytes([8; 16]).unwrap(),
                    session: None,
                    state: PaneState::Running,
                },
            },
        }
    }

    fn terminal_create_receipt(workspace_id: WorkspaceId) -> OperationReceipt {
        let operation_id = OperationId::from_bytes([6; 16]).unwrap();
        let stored_rights = lomi_remote_protocol::StoredOperationRights::new(
            operation_id,
            ConsumerAuthorizationId::from_bytes([5; 16]).unwrap(),
            workspace_id,
            Method::TerminalCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap();
        OperationReceipt::new(
            &stored_rights,
            OperationParameterHash::try_from("0".repeat(64)).unwrap(),
            OperationState::Succeeded,
            false,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: DecimalU64(2),
                pane_id: lomi_remote_protocol::PaneId::from_bytes([8; 16]).unwrap(),
                session_id: TerminalSessionId::from_bytes([9; 16]).unwrap(),
                session_epoch: SessionEpoch::from_bytes([10; 16]).unwrap(),
            }),
        )
        .unwrap()
    }

    #[test]
    fn hover_query_uses_controls_without_changing_focus() {
        let mut operations = Operations::default();
        operations
            .controls
            .key(Rect::new(2, 3, 12, 1), KeyCode::Char('r'));
        operations.controls.cycle(false);
        let focused = operations.controls.focused();

        assert!(operations.hoverable(4, 3));
        assert!(!operations.hoverable(20, 3));
        assert_eq!(operations.controls.focused(), focused);
    }

    #[test]
    fn clicking_a_profile_row_only_selects_it() {
        let mut operations = Operations::default();
        operations.page = Some(Page::ShellProfiles);
        operations.profiles = ["first", "second"]
            .into_iter()
            .map(|name| HostProfile {
                profile_id: HostProfileId::try_from(name.to_owned()).unwrap(),
                name: DisplayText::try_from(name.to_owned()).unwrap(),
            })
            .collect();
        operations.controls.row(Rect::new(2, 2, 32, 1), 1);
        let mut backend = NoBackend;

        assert!(operations.handle_mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 5,
                row: 2,
                modifiers: KeyModifiers::NONE,
            },
            &mut backend,
            &mut Dashboard::default(),
        ));
        assert_eq!(operations.selected, 1);
    }

    #[test]
    fn terminal_creation_refresh_preserves_profile_selection_for_every_outcome() {
        let workspace_id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let selected_profile = HostProfileId::try_from("second".to_owned()).unwrap();
        for (outcome, refreshed_tabs, expected_tabs, expected_message) in [
            (
                TerminalCreateOutcome::Succeeded,
                vec![terminal_tab()],
                1,
                "Terminal creation was accepted; state refreshed.",
            ),
            (
                TerminalCreateOutcome::Failed,
                Vec::new(),
                0,
                "Terminal creation was not confirmed. State refreshed.",
            ),
            (
                TerminalCreateOutcome::Unknown,
                vec![terminal_tab()],
                1,
                "Terminal creation outcome is unknown. State refreshed; do not repeat until verified.",
            ),
        ] {
            let mut operations = Operations::default();
            operations.page = Some(Page::ShellProfiles);
            operations.workspace_id = Some(workspace_id);
            operations.workspace_state = Some(workspace_state(workspace_id, Vec::new()));
            operations.profiles = ["first", "second"]
                .into_iter()
                .map(|name| HostProfile {
                    profile_id: HostProfileId::try_from(name.to_owned()).unwrap(),
                    name: DisplayText::try_from(name.to_owned()).unwrap(),
                })
                .collect();
            operations.selected = 1;
            let mut backend = TerminalCreateBackend {
                workspace_id,
                outcome,
                refreshed_tabs,
                created_profiles: Vec::new(),
            };

            assert!(
                operations
                    .workspace_state
                    .as_ref()
                    .unwrap()
                    .tabs
                    .0
                    .is_empty()
            );
            operations.create_terminal(&mut backend);

            assert_eq!(operations.selected, 1, "outcome: {outcome:?}");
            assert_eq!(operations.message, Some(expected_message));
            assert_eq!(
                operations.workspace_state.as_ref().unwrap().tabs.0.len(),
                expected_tabs,
                "outcome: {outcome:?}"
            );
            assert_eq!(backend.created_profiles, vec![selected_profile.clone()]);

            // A second create stands in for pressing Enter after the refresh.
            operations.create_terminal(&mut backend);
            assert_eq!(operations.selected, 1, "outcome: {outcome:?}");
            assert_eq!(
                backend.created_profiles,
                vec![selected_profile.clone(), selected_profile.clone()],
                "outcome: {outcome:?}"
            );
        }
    }

    #[test]
    fn paragraph_line_count_accounts_for_word_wrapping() {
        assert_eq!(super::wrapped_line_count("1234 1234 1234", 8), 3);
    }

    #[test]
    fn spaced_long_profile_rows_register_at_paragraph_wrapped_lines() {
        let mut operations = Operations::default();
        operations.page = Some(Page::ShellProfiles);
        operations.profiles = [("first", "1234 1234 1234"), ("second", "5678 5678 5678")]
            .into_iter()
            .map(|(profile_id, name)| HostProfile {
                profile_id: HostProfileId::try_from(profile_id.to_owned()).unwrap(),
                name: DisplayText::try_from(name.to_owned()).unwrap(),
            })
            .collect();
        let content = operations.draw_shell_profiles();
        let second_row = operations.row_action_lines()[1].1.clone();
        let lines = content.split('\n').collect::<Vec<_>>();
        let row_line = lines
            .iter()
            .position(|line| *line == second_row)
            .expect("second profile row is present in content");
        let body_width = 8;
        let row_y = lines[..row_line]
            .iter()
            .map(|line| {
                Paragraph::new(super::theme::content(line))
                    .wrap(Wrap { trim: false })
                    .line_count(body_width)
            })
            .sum::<usize>() as u16;
        let body = Rect::new(0, 0, body_width, 80);
        operations.register_row_targets(&content, body);
        let mut backend = NoBackend;

        assert!(operations.handle_mouse(
            MouseEvent {
                kind: MouseEventKind::Down(MouseButton::Left),
                column: 2,
                row: row_y,
                modifiers: KeyModifiers::NONE,
            },
            &mut backend,
            &mut Dashboard::default(),
        ));
        assert_eq!(operations.selected, 1);
    }

    #[test]
    fn non_list_pages_scroll_the_body_instead_of_moving_hidden_selection() {
        let mut operations = Operations::default();
        operations.page = Some(Page::Service);
        operations.selected = 7;
        operations.body_scroll_max.set(4);

        operations.move_selection_or_scroll(true);
        assert_eq!(operations.body_scroll.get(), 1);
        operations.move_selection_or_scroll_by(true, 3);
        assert_eq!(operations.body_scroll.get(), 4);
        operations.move_selection_or_scroll(false);
        assert_eq!(operations.body_scroll.get(), 3);
        assert_eq!(operations.selected, 7);
    }

    #[test]
    fn empty_selectable_pages_fall_back_to_body_scroll() {
        let mut operations = Operations::default();
        operations.page = Some(Page::ShellProfiles);
        operations.body_scroll_max.set(2);

        operations.move_selection_or_scroll(true);

        assert_eq!(operations.body_scroll.get(), 1);
        assert_eq!(operations.selected, 0);
    }

    #[test]
    fn workspace_switch_guard_blocks_confirmation_and_edit_drafts() {
        let mut operations = Operations::default();
        assert!(operations.can_switch_workspace());

        operations.confirmation = Some(super::Confirmation::Logout);
        assert!(!operations.can_switch_workspace());
        operations.confirmation = None;

        operations.shell_draft = Some(ShellProfileDraft {
            field: ProfileDraftField::Name,
            name: String::new(),
            executable: String::new(),
            working_directory: String::new(),
            error: None,
        });
        assert!(!operations.can_switch_workspace());
        operations.shell_draft = None;
        operations.removal_status = Some(lomi_remote_protocol::ipc::LocalWorkspaceRemovalStatus {
            workspace_id: WorkspaceId::from_bytes([7; 16]).unwrap(),
            attempt_id: None,
            phase: lomi_remote_protocol::ipc::LocalWorkspaceRemovalPhase::Uncertain,
            total_sessions: super::DecimalU64(0),
            confirmed_sessions: super::DecimalU64(0),
        });
        assert!(!operations.can_switch_workspace());
    }

    #[test]
    fn modified_enter_cannot_activate_a_focused_confirmation() {
        for (code, modifiers) in [
            (KeyCode::Enter, KeyModifiers::CONTROL),
            (KeyCode::Enter, KeyModifiers::ALT),
            (KeyCode::Char('y'), KeyModifiers::CONTROL),
            (KeyCode::Char('y'), KeyModifiers::ALT),
        ] {
            let mut operations = Operations::default();
            operations.confirmation = Some(super::Confirmation::Logout);
            operations
                .controls
                .key(Rect::new(1, 1, 8, 1), KeyCode::Char('y'));
            operations.controls.cycle(false);
            let mut backend = NoBackend;

            assert!(operations.handle_key(
                KeyEvent::new(code, modifiers),
                &mut backend,
                &mut Dashboard::default(),
            ));
            assert!(operations.confirmation.is_some());
        }
    }

    #[test]
    fn arrows_navigate_from_the_last_list_row_to_footer_and_back_without_activation() {
        let mut operations = Operations::default();
        operations.page = Some(Page::ShellProfiles);
        operations.profiles = ["first", "second"]
            .into_iter()
            .map(|name| HostProfile {
                profile_id: HostProfileId::try_from(name.to_owned()).unwrap(),
                name: DisplayText::try_from(name.to_owned()).unwrap(),
            })
            .collect();
        operations.selected = 1;
        operations.controls.row(Rect::new(1, 1, 20, 1), 0);
        operations.controls.row(Rect::new(1, 2, 20, 1), 1);
        operations
            .controls
            .key(Rect::new(1, 10, 8, 1), KeyCode::Char('r'));
        operations
            .controls
            .key(Rect::new(20, 10, 8, 1), KeyCode::Esc);
        operations.controls.focus_action(super::Action::Row(1));
        let mut backend = NoBackend;
        let mut dashboard = Dashboard::default();

        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert_eq!(
            operations.controls.focused(),
            Some(super::Action::Key(KeyEvent::new(
                KeyCode::Char('r'),
                KeyModifiers::NONE,
            )))
        );
        assert_eq!(operations.selected, 1);

        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert_eq!(operations.controls.focused(), Some(super::Action::Row(1)));
        assert_eq!(operations.selected, 1);
    }

    #[test]
    fn confirmation_arrows_change_focus_without_confirming() {
        let mut operations = Operations::default();
        operations.confirmation = Some(super::Confirmation::Logout);
        operations
            .controls
            .key(Rect::new(1, 10, 8, 1), KeyCode::Char('y'));
        operations
            .controls
            .key(Rect::new(20, 10, 8, 1), KeyCode::Char('n'));
        operations
            .controls
            .focus_action(super::Action::Key(KeyEvent::new(
                KeyCode::Char('n'),
                KeyModifiers::NONE,
            )));
        let mut backend = NoBackend;
        let mut dashboard = Dashboard::default();

        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Left, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert_eq!(
            operations.controls.focused(),
            Some(super::Action::Key(KeyEvent::new(
                KeyCode::Char('y'),
                KeyModifiers::NONE,
            )))
        );
        assert!(matches!(
            operations.confirmation,
            Some(super::Confirmation::Logout)
        ));
    }

    #[test]
    fn confirmation_draw_starts_on_the_safe_cancel_action() {
        let mut operations = Operations::default();
        operations.page = Some(Page::Settings);
        operations.confirmation = Some(super::Confirmation::Logout);
        let dashboard = Dashboard::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        terminal
            .draw(|frame| {
                operations.draw(
                    frame,
                    &dashboard,
                    Rect::new(0, 0, 70, 18),
                    Rect::new(0, 19, 70, 3),
                );
            })
            .unwrap();

        assert_eq!(
            operations.controls.focused(),
            Some(super::Action::Key(KeyEvent::new(
                KeyCode::Char('n'),
                KeyModifiers::NONE,
            )))
        );
    }

    #[test]
    fn draft_arrows_do_not_edit_or_dismiss_text() {
        let mut operations = Operations::default();
        operations.page = Some(Page::WorkspaceDetails);
        operations.rename_draft = Some(RenameDraft {
            expected_name: LocalProjectName::try_from("Original".to_owned()).unwrap(),
            name: "Updated".to_owned(),
        });
        operations
            .controls
            .row(Rect::new(1, 1, 20, 2), super::DRAFT_INPUT_ACTION);
        operations
            .controls
            .key(Rect::new(1, 5, 8, 1), KeyCode::Enter);
        operations
            .controls
            .key(Rect::new(20, 5, 8, 1), KeyCode::Esc);
        operations
            .controls
            .focus_action(super::Action::Row(super::DRAFT_INPUT_ACTION));
        let mut backend = NoBackend;
        let mut dashboard = Dashboard::default();

        for code in [KeyCode::Left, KeyCode::Right] {
            assert!(operations.handle_key(
                KeyEvent::new(code, KeyModifiers::NONE),
                &mut backend,
                &mut dashboard,
            ));
            assert_eq!(
                operations
                    .rename_draft
                    .as_ref()
                    .map(|draft| draft.name.as_str()),
                Some("Updated")
            );
            assert!(operations.confirmation.is_none());
        }
        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Down, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert!(operations.rename_draft.is_some());
        assert!(operations.confirmation.is_none());
        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Up, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert_eq!(
            operations.controls.focused(),
            Some(super::Action::Row(super::DRAFT_INPUT_ACTION))
        );
    }

    #[test]
    fn pinned_workspace_actions_require_loaded_state() {
        let mut operations = Operations::default();
        operations.workspace_id = Some(WorkspaceId::from_bytes([5; 16]).unwrap());

        operations.start_workspace_rename();
        operations.start_workspace_remove();

        assert!(operations.rename_draft.is_none());
        assert!(operations.confirmation.is_none());
    }

    #[test]
    fn normal_workspace_details_hide_internal_id_and_sharing_fields() {
        let mut operations = Operations::default();
        operations.workspace_id = Some(WorkspaceId::from_bytes([6; 16]).unwrap());

        let content = operations.draw_workspace_details(&Dashboard::default());

        assert!(!content.contains("ID:"));
        assert!(!content.contains("Sharing:"));
    }

    #[test]
    fn editing_footers_tab_and_text_input_cannot_cancel_the_draft() {
        let mut operations = Operations::default();
        operations.page = Some(Page::WorkspaceDetails);
        operations.workspace_id = Some(WorkspaceId::from_bytes([3; 16]).unwrap());
        operations.rename_draft = Some(RenameDraft {
            expected_name: LocalProjectName::try_from("Original".to_owned()).unwrap(),
            name: "Updated".to_owned(),
        });
        operations.controls.event(
            Rect::new(0, 0, 10, 1),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        operations.controls.event(
            Rect::new(12, 0, 10, 1),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        operations.controls.cycle(false);
        let mut backend = NoBackend;
        let mut dashboard = Dashboard::default();

        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert_eq!(
            operations.controls.focused(),
            Some(super::Action::Key(KeyEvent::new(
                KeyCode::Esc,
                KeyModifiers::NONE
            )))
        );
        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert!(operations.controls.focused().is_none());
        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Char('d'), KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert!(operations.controls.focused().is_none());
        assert!(operations.handle_paste(" project"));
        assert!(operations.controls.focused().is_none());
        assert!(operations.handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));

        assert!(operations.rename_draft.is_none());
        assert!(matches!(
            operations.confirmation,
            Some(super::Confirmation::RenameWorkspace(_))
        ));
    }

    #[test]
    fn enter_activates_focused_next_and_cancel_edit_actions() {
        let mut next = Operations::default();
        next.page = Some(Page::WorkspaceDetails);
        next.workspace_id = Some(WorkspaceId::from_bytes([4; 16]).unwrap());
        next.rename_draft = Some(RenameDraft {
            expected_name: LocalProjectName::try_from("Original".to_owned()).unwrap(),
            name: "Updated".to_owned(),
        });
        next.controls.event(
            Rect::new(0, 0, 10, 1),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        next.controls.event(
            Rect::new(12, 0, 10, 1),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        next.controls.cycle(false);
        let mut backend = NoBackend;
        let mut dashboard = Dashboard::default();

        assert!(next.handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert!(next.rename_draft.is_none());
        assert!(matches!(
            next.confirmation,
            Some(super::Confirmation::RenameWorkspace(_))
        ));

        let mut cancel = Operations::default();
        cancel.page = Some(Page::WorkspaceDetails);
        cancel.rename_draft = Some(RenameDraft {
            expected_name: LocalProjectName::try_from("Original".to_owned()).unwrap(),
            name: "Updated".to_owned(),
        });
        cancel.controls.event(
            Rect::new(0, 0, 10, 1),
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
        );
        cancel.controls.event(
            Rect::new(12, 0, 10, 1),
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
        );
        cancel.controls.cycle(false);
        cancel.controls.cycle(false);

        assert!(cancel.handle_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut backend,
            &mut dashboard,
        ));
        assert!(cancel.rename_draft.is_none());
        assert!(cancel.confirmation.is_none());
    }

    #[test]
    fn retargeting_global_pages_preserves_the_page_without_backend_calls() {
        let mut operations = Operations::default();
        operations.page = Some(Page::Service);
        let workspace_id = WorkspaceId::from_bytes([9; 16]).unwrap();
        let mut backend = NoBackend;

        operations.retarget_workspace(workspace_id, &mut backend);

        assert_eq!(operations.page, Some(Page::Service));
        assert_eq!(operations.workspace_id, Some(workspace_id));
    }
}
