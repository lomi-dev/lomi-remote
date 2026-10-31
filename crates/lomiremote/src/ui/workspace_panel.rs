//! Read-only workspace view embedded in the dashboard's right panel.

use super::{Backend, operations, safe_label, theme, workspace_name_label};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use lomi_remote_protocol::{
    WorkspaceId,
    ipc::{
        LocalCall, LocalResult, LocalSharing, LocalWorkspaceDetails, LocalWorkspaceRead,
        LocalWorkspaceSummary,
    },
    rpc::{PaneState, TerminalLayout, WorkspaceState},
};
use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Wrap},
};
use std::cell::{Cell, RefCell};

const LOG_PAGE_SIZE: usize = 64;
const TAB_LABELS: [&str; 3] = ["Open tabs", "Logs", "Settings"];
const SETTINGS_ACTIONS: [PanelAction; 4] = [
    PanelAction::Rename,
    PanelAction::Profiles,
    PanelAction::Share,
    PanelAction::Remove,
];

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum WorkspaceTab {
    #[default]
    OpenTabs,
    Logs,
    Settings,
}

impl WorkspaceTab {
    fn index(self) -> usize {
        match self {
            Self::OpenTabs => 0,
            Self::Logs => 1,
            Self::Settings => 2,
        }
    }

    fn from_index(index: usize) -> Self {
        match index {
            0 => Self::OpenTabs,
            1 => Self::Logs,
            _ => Self::Settings,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PanelAction {
    None,
    Sidebar,
    Footer,
    Share,
    Profiles,
    Rename,
    Remove,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FocusArea {
    Tabs,
    Content,
}

#[derive(Debug, Clone, Copy)]
struct TabTarget {
    area: Rect,
    tab: WorkspaceTab,
}

#[derive(Debug, Clone, Copy)]
struct RowTarget {
    area: Rect,
    index: usize,
}

#[derive(Debug, Clone, Copy)]
struct ActionTarget {
    area: Rect,
    action: PanelAction,
    index: usize,
}

/// Right-side workspace panel. Reads are bound to the selected workspace ID;
/// rendering and pointer queries are pure; tab changes perform bounded reads.
pub(super) struct WorkspacePanel {
    workspace_id: Option<WorkspaceId>,
    workspace: Option<LocalWorkspaceSummary>,
    state: Option<WorkspaceState>,
    details: Option<LocalWorkspaceDetails>,
    state_error: bool,
    details_error: bool,
    selected_item: usize,
    selected_action: usize,
    tab: WorkspaceTab,
    focus: FocusArea,
    logs: Option<operations::UiDiagnosticLogSnapshot>,
    logs_attempted: bool,
    logs_error: bool,
    logs_cursor: Option<u64>,
    selected_log: usize,
    last_area: Cell<Rect>,
    tab_targets: RefCell<Vec<TabTarget>>,
    open_row_targets: RefCell<Vec<RowTarget>>,
    log_row_targets: RefCell<Vec<RowTarget>>,
    action_targets: RefCell<Vec<ActionTarget>>,
}

impl Default for WorkspacePanel {
    fn default() -> Self {
        Self {
            workspace_id: None,
            workspace: None,
            state: None,
            details: None,
            state_error: false,
            details_error: false,
            selected_item: 0,
            selected_action: 0,
            tab: WorkspaceTab::OpenTabs,
            focus: FocusArea::Tabs,
            logs: None,
            logs_attempted: false,
            logs_error: false,
            logs_cursor: None,
            selected_log: 0,
            last_area: Cell::new(Rect::default()),
            tab_targets: RefCell::new(Vec::new()),
            open_row_targets: RefCell::new(Vec::new()),
            log_row_targets: RefCell::new(Vec::new()),
            action_targets: RefCell::new(Vec::new()),
        }
    }
}

impl WorkspacePanel {
    /// Bind the selected workspace. A changed ID loads its read-only snapshot;
    /// rebinding the same ID is cache-only unless `force` is set.
    pub(super) fn bind(
        &mut self,
        workspace: Option<LocalWorkspaceSummary>,
        backend: &mut impl Backend,
        force: bool,
    ) {
        let Some(workspace) = workspace else {
            self.clear_workspace();
            return;
        };

        let id = workspace.workspace_id;
        let changed = self.workspace_id != Some(id);
        if changed {
            self.state = None;
            self.details = None;
            self.state_error = false;
            self.details_error = false;
            self.selected_item = 0;
            self.selected_action = 0;
            self.workspace_id = Some(id);
            self.clear_targets();
        }
        self.workspace = Some(workspace);

        if changed || force {
            self.read_workspace(backend, id);
        }
        if force && self.tab == WorkspaceTab::Logs && self.logs_attempted {
            self.read_logs(backend, None);
        }
    }

    /// Draw the panel inside the area left after the dashboard's fixed sidebar.
    pub(super) fn draw(&self, frame: &mut Frame, area: Rect, focused: bool, message: Option<&str>) {
        self.clear_targets();
        self.last_area.set(area);
        if area.is_empty() {
            return;
        }

        frame.render_widget(
            Block::default().style(Style::default().bg(theme::CANVAS).fg(theme::SECONDARY)),
            area,
        );

        let tab_height = if area.height >= 4 {
            3
        } else {
            area.height.min(1)
        };
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(tab_height), Constraint::Min(0)])
            .split(area);
        if !chunks[0].is_empty() {
            self.draw_tabs(frame, chunks[0], focused);
        }
        let body = chunks[1];
        if body.is_empty() {
            return;
        }
        let message_height = reserved_message_height(message, body);
        let body = Rect::new(
            body.x,
            body.y,
            body.width,
            body.height.saturating_sub(message_height),
        );
        if message_height > 0 {
            let message_area = Rect::new(
                chunks[1].x,
                chunks[1].bottom().saturating_sub(message_height),
                chunks[1].width,
                message_height,
            );
            self.draw_message(frame, message_area, message.unwrap_or_default());
        }
        if body.is_empty() {
            return;
        }

        match self.tab {
            WorkspaceTab::OpenTabs => self.draw_open_tabs(frame, body, focused),
            WorkspaceTab::Logs => self.draw_logs(frame, body, focused),
            WorkspaceTab::Settings => self.draw_settings(frame, body, focused),
        }
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> PanelAction {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return PanelAction::None;
        }
        if key.code == KeyCode::Tab && key.modifiers.contains(KeyModifiers::SHIFT)
            || key.code == KeyCode::BackTab
        {
            return PanelAction::Sidebar;
        }
        if key.code == KeyCode::Tab {
            return PanelAction::Footer;
        }
        if self.tab == WorkspaceTab::Logs && key.code == KeyCode::Char('n') {
            self.load_next_logs_page(backend);
            return PanelAction::None;
        }

        match self.focus {
            FocusArea::Tabs => self.handle_tab_key(key, backend),
            FocusArea::Content => self.handle_content_key(key, backend),
        }
    }

    pub(super) fn handle_mouse(
        &mut self,
        mouse: MouseEvent,
        backend: &mut impl Backend,
    ) -> PanelAction {
        if mouse
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return PanelAction::None;
        }
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                let tab_target = {
                    self.tab_targets
                        .borrow()
                        .iter()
                        .find(|target| target.area.contains((mouse.column, mouse.row).into()))
                        .copied()
                };
                if let Some(target) = tab_target {
                    self.focus = FocusArea::Tabs;
                    self.activate_tab(target.tab, backend);
                    return PanelAction::None;
                }
                match self.tab {
                    WorkspaceTab::OpenTabs => {
                        if let Some(target) = self
                            .open_row_targets
                            .borrow()
                            .iter()
                            .find(|target| target.area.contains((mouse.column, mouse.row).into()))
                            .copied()
                        {
                            self.focus = FocusArea::Content;
                            self.selected_item = target.index;
                        }
                        PanelAction::None
                    }
                    WorkspaceTab::Logs => {
                        let target = {
                            self.log_row_targets
                                .borrow()
                                .iter()
                                .find(|target| {
                                    target.area.contains((mouse.column, mouse.row).into())
                                })
                                .copied()
                        };
                        if let Some(target) = target {
                            self.focus = FocusArea::Content;
                            self.selected_log = target.index;
                            if target.index == self.log_entry_count() && self.has_next_logs_page() {
                                self.load_next_logs_page(backend);
                            }
                        }
                        PanelAction::None
                    }
                    WorkspaceTab::Settings => {
                        let Some(target) = self
                            .action_targets
                            .borrow()
                            .iter()
                            .find(|target| target.area.contains((mouse.column, mouse.row).into()))
                            .copied()
                        else {
                            return PanelAction::None;
                        };
                        let Some(key) = panel_action_key(target.action) else {
                            return PanelAction::None;
                        };
                        if !super::interaction::accept_pointer_key(mouse, target.area, key) {
                            return PanelAction::None;
                        }
                        self.focus = FocusArea::Content;
                        self.selected_action = target.index;
                        target.action
                    }
                }
            }
            MouseEventKind::ScrollUp | MouseEventKind::ScrollDown
                if self
                    .last_area
                    .get()
                    .contains((mouse.column, mouse.row).into()) =>
            {
                let delta = if mouse.kind == MouseEventKind::ScrollUp {
                    -1isize
                } else {
                    1isize
                };
                match self.tab {
                    WorkspaceTab::OpenTabs => {
                        if row_at(&self.open_row_targets.borrow(), mouse.column, mouse.row)
                            .is_some()
                        {
                            self.selected_item =
                                move_selection(self.selected_item, self.item_count(), delta);
                        }
                    }
                    WorkspaceTab::Logs => {
                        if row_at(&self.log_row_targets.borrow(), mouse.column, mouse.row).is_some()
                        {
                            self.selected_log =
                                move_selection(self.selected_log, self.log_count(), delta);
                        }
                    }
                    WorkspaceTab::Settings => {
                        if self
                            .action_targets
                            .borrow()
                            .iter()
                            .any(|target| target.area.contains((mouse.column, mouse.row).into()))
                        {
                            self.selected_action =
                                move_selection(self.selected_action, SETTINGS_ACTIONS.len(), delta);
                        }
                    }
                }
                PanelAction::None
            }
            _ => PanelAction::None,
        }
    }

    /// Whether the last rendered geometry has an interactive target here.
    /// This method is intentionally read-only and never fetches backend data.
    pub(super) fn hoverable(&self, x: u16, y: u16) -> bool {
        self.tab_targets
            .borrow()
            .iter()
            .any(|target| target.area.contains((x, y).into()))
            || self
                .open_row_targets
                .borrow()
                .iter()
                .any(|target| target.area.contains((x, y).into()))
            || self
                .log_row_targets
                .borrow()
                .iter()
                .any(|target| target.area.contains((x, y).into()))
            || self
                .action_targets
                .borrow()
                .iter()
                .any(|target| target.area.contains((x, y).into()))
    }

    pub(super) fn focus_tabs(&mut self) {
        self.focus = FocusArea::Tabs;
    }

    pub(super) fn focus_content(&mut self) {
        self.focus = FocusArea::Content;
    }

    pub(super) fn active_tab(&self) -> WorkspaceTab {
        self.tab
    }

    fn clear_workspace(&mut self) {
        self.workspace_id = None;
        self.workspace = None;
        self.state = None;
        self.details = None;
        self.state_error = false;
        self.details_error = false;
        self.selected_item = 0;
        self.selected_action = 0;
        self.clear_targets();
    }

    fn clear_targets(&self) {
        self.last_area.set(Rect::default());
        self.tab_targets.borrow_mut().clear();
        self.open_row_targets.borrow_mut().clear();
        self.log_row_targets.borrow_mut().clear();
        self.action_targets.borrow_mut().clear();
    }

    fn read_workspace(&mut self, backend: &mut impl Backend, id: WorkspaceId) {
        self.clear_targets();
        self.state = None;
        self.details = None;
        self.state_error = false;
        self.details_error = false;
        self.selected_item = 0;

        match backend.request(LocalCall::WorkspaceInspect(LocalWorkspaceRead {
            workspace_id: id,
        })) {
            Ok(LocalResult::WorkspaceState(state))
                if state.context.workspace_id == id && state.validate().is_ok() =>
            {
                self.state = Some(*state);
                self.selected_item = self.selected_item.min(self.item_count().saturating_sub(1));
            }
            _ => self.state_error = true,
        }

        match backend.request(LocalCall::WorkspaceDetails(LocalWorkspaceRead {
            workspace_id: id,
        })) {
            Ok(LocalResult::WorkspaceDetails(details)) if details.workspace.workspace_id == id => {
                self.details = Some(details);
            }
            _ => self.details_error = true,
        }
    }

    fn read_logs(&mut self, backend: &mut impl Backend, cursor: Option<u64>) {
        self.clear_targets();
        self.logs_attempted = true;
        self.logs_error = false;
        self.logs = None;
        self.selected_log = 0;
        self.logs_cursor = cursor;
        match backend.read_diagnostic_logs(cursor, LOG_PAGE_SIZE) {
            Ok(mut page) => {
                if page.entries.len() > LOG_PAGE_SIZE {
                    page.entries.truncate(LOG_PAGE_SIZE);
                    page.truncated = true;
                }
                self.logs = Some(page);
            }
            Err(_) => self.logs_error = true,
        }
    }

    fn has_next_logs_page(&self) -> bool {
        self.logs.as_ref().is_some_and(|page| {
            let previous = self.logs_cursor.unwrap_or(0);
            page.available && page.truncated && page.next_cursor > previous
        })
    }

    fn load_next_logs_page(&mut self, backend: &mut impl Backend) {
        if self.tab != WorkspaceTab::Logs || !self.has_next_logs_page() {
            return;
        }
        let Some(cursor) = self.logs.as_ref().map(|page| page.next_cursor) else {
            return;
        };
        self.read_logs(backend, Some(cursor));
    }

    fn activate_tab(&mut self, tab: WorkspaceTab, backend: &mut impl Backend) {
        self.tab = tab;
        self.clear_targets();
        if tab == WorkspaceTab::Logs && !self.logs_attempted {
            self.read_logs(backend, None);
        }
    }

    fn handle_tab_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> PanelAction {
        match key.code {
            KeyCode::Left => {
                let index = self.tab.index();
                if index == 0 {
                    PanelAction::Sidebar
                } else {
                    self.activate_tab(WorkspaceTab::from_index(index - 1), backend);
                    PanelAction::None
                }
            }
            KeyCode::Right => {
                let index = self.tab.index();
                if index + 1 < TAB_LABELS.len() {
                    self.activate_tab(WorkspaceTab::from_index(index + 1), backend);
                }
                PanelAction::None
            }
            KeyCode::Up => PanelAction::Sidebar,
            KeyCode::Down | KeyCode::Enter => {
                self.focus = FocusArea::Content;
                PanelAction::None
            }
            _ => PanelAction::None,
        }
    }

    fn handle_content_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> PanelAction {
        match key.code {
            KeyCode::Left => return PanelAction::Sidebar,
            KeyCode::Right => return PanelAction::Footer,
            KeyCode::Enter => {
                if self.tab == WorkspaceTab::Settings {
                    return SETTINGS_ACTIONS
                        .get(self.selected_action)
                        .copied()
                        .unwrap_or(PanelAction::None);
                }
                if self.tab == WorkspaceTab::Logs
                    && self.selected_log == self.log_entry_count()
                    && self.has_next_logs_page()
                {
                    self.load_next_logs_page(backend);
                }
                return PanelAction::None;
            }
            KeyCode::Up => {
                let (selected, count) = self.current_selection();
                if count == 0 || selected == 0 {
                    self.focus = FocusArea::Tabs;
                } else {
                    self.set_current_selection(selected - 1);
                }
            }
            KeyCode::Down => {
                let (selected, count) = self.current_selection();
                if count == 0 || selected + 1 >= count {
                    return PanelAction::Footer;
                }
                self.set_current_selection(selected + 1);
            }
            _ => {}
        }
        PanelAction::None
    }

    fn current_selection(&self) -> (usize, usize) {
        match self.tab {
            WorkspaceTab::OpenTabs => (self.selected_item, self.item_count()),
            WorkspaceTab::Logs => (self.selected_log, self.log_count()),
            WorkspaceTab::Settings => (self.selected_action, SETTINGS_ACTIONS.len()),
        }
    }

    fn set_current_selection(&mut self, index: usize) {
        match self.tab {
            WorkspaceTab::OpenTabs => self.selected_item = index,
            WorkspaceTab::Logs => self.selected_log = index,
            WorkspaceTab::Settings => self.selected_action = index,
        }
    }

    fn item_count(&self) -> usize {
        self.state.as_ref().map_or(0, |state| state.tabs.0.len())
    }

    fn log_count(&self) -> usize {
        self.logs
            .as_ref()
            .filter(|page| page.available)
            .map_or(0, |page| {
                page.entries.len() + if self.has_next_logs_page() { 1 } else { 0 }
            })
    }

    fn log_entry_count(&self) -> usize {
        self.logs
            .as_ref()
            .filter(|page| page.available)
            .map_or(0, |page| page.entries.len())
    }

    fn settings_action_label(&self, action: PanelAction) -> &'static str {
        match action {
            PanelAction::Rename => "Rename workspace",
            PanelAction::Profiles => "Terminal profiles",
            PanelAction::Share => {
                if self
                    .workspace
                    .as_ref()
                    .is_some_and(|workspace| workspace.sharing == LocalSharing::Enabled)
                {
                    "Unshare workspace"
                } else {
                    "Share workspace"
                }
            }
            PanelAction::Remove => "Remove workspace",
            _ => "",
        }
    }

    fn draw_tabs(&self, frame: &mut Frame, area: Rect, focused: bool) {
        let segments = Layout::horizontal([Constraint::Fill(1); 3]).split(area);
        for (index, (label, segment)) in TAB_LABELS.iter().zip(segments.iter()).enumerate() {
            if segment.is_empty() {
                continue;
            }
            let tab = WorkspaceTab::from_index(index);
            let selected = tab == self.tab;
            let active = selected && focused && self.focus == FocusArea::Tabs;
            let style = if selected {
                theme::selection_style(active)
            } else {
                Style::default().fg(theme::SECONDARY).bg(theme::SURFACE)
            };
            frame.render_widget(Block::default().style(style), *segment);
            let label_y = segment.y + segment.height.saturating_sub(1) / 2;
            frame.render_widget(
                Paragraph::new(*label)
                    .alignment(Alignment::Center)
                    .style(style),
                Rect::new(segment.x, label_y, segment.width, 1),
            );
            if segment.height > 1 {
                frame.render_widget(
                    Paragraph::new(
                        if selected { "━" } else { "─" }.repeat(usize::from(segment.width)),
                    )
                    .style(style.fg(if active {
                        theme::ACCENT
                    } else if selected {
                        theme::SECONDARY
                    } else {
                        theme::BORDER
                    })),
                    Rect::new(segment.x, segment.bottom() - 1, segment.width, 1),
                );
            }
            self.tab_targets.borrow_mut().push(TabTarget {
                area: *segment,
                tab,
            });
        }
    }

    fn draw_open_tabs(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.width >= 64 {
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Percentage(42), Constraint::Min(0)])
                .split(area);
            self.draw_open_list(frame, columns[0], focused);
            frame.render_widget(
                Block::default()
                    .borders(Borders::LEFT)
                    .border_style(Style::default().fg(theme::BORDER)),
                columns[1],
            );
            let detail = Rect::new(
                columns[1].x.saturating_add(1),
                columns[1].y,
                columns[1].width.saturating_sub(1),
                columns[1].height,
            );
            self.draw_tab_detail(frame, detail);
        } else {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Percentage(38), Constraint::Min(0)])
                .split(area);
            self.draw_open_list(frame, chunks[0], focused);
            self.draw_tab_detail(frame, chunks[1]);
        }
    }

    fn draw_open_list(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.is_empty() {
            return;
        }
        frame.render_widget(
            Paragraph::new("Terminal tabs").style(
                Style::default()
                    .fg(theme::SECONDARY)
                    .add_modifier(Modifier::BOLD),
            ),
            Rect::new(area.x, area.y, area.width, 1),
        );
        let rows_area = Rect::new(
            area.x,
            area.y.saturating_add(1),
            area.width,
            area.height.saturating_sub(1),
        );
        let Some(state) = &self.state else {
            let text = if self.state_error {
                "Terminal tab state is unavailable."
            } else {
                "No workspace selected."
            };
            self.draw_muted_text(frame, rows_area, text);
            return;
        };
        if state.tabs.0.is_empty() {
            self.draw_muted_text(frame, rows_area, "No terminal tabs are open.");
            return;
        }
        if rows_area.is_empty() {
            return;
        }

        let row_height = if rows_area.height >= 2 { 2 } else { 1 };
        let visible = usize::from(rows_area.height / row_height).max(1);
        let start = visible_start(self.selected_item, state.tabs.0.len(), visible);
        let end = (start + visible).min(state.tabs.0.len());
        for index in start..end {
            let slot = index - start;
            let y = rows_area.y.saturating_add(slot as u16 * row_height);
            let height = row_height.min(rows_area.bottom().saturating_sub(y));
            let row_area = Rect::new(rows_area.x, y, rows_area.width, height);
            let tab = &state.tabs.0[index];
            let counts = pane_counts(&tab.layout);
            let title = workspace_name_label(tab.name.as_str(), usize::from(row_area.width));
            let pane_label = if counts.total == 1 { "pane" } else { "panes" };
            let description = format!(
                "Terminal · {} {pane_label} · {}",
                counts.total,
                counts.status()
            );
            let style = if index == self.selected_item {
                theme::selection_style(focused && self.focus == FocusArea::Content)
            } else {
                Style::default().fg(theme::TEXT).bg(theme::CANVAS)
            };
            frame.render_widget(
                Paragraph::new(Line::styled(title, style)),
                Rect::new(row_area.x, row_area.y, row_area.width, 1),
            );
            if row_area.height > 1 {
                frame.render_widget(
                    Paragraph::new(workspace_name_label(
                        &description,
                        usize::from(row_area.width),
                    ))
                    .style(
                        Style::default()
                            .fg(theme::MUTED)
                            .bg(style.bg.unwrap_or(theme::CANVAS)),
                    ),
                    Rect::new(row_area.x, row_area.y.saturating_add(1), row_area.width, 1),
                );
            }
            self.open_row_targets.borrow_mut().push(RowTarget {
                area: row_area,
                index,
            });
        }
    }

    fn draw_tab_detail(&self, frame: &mut Frame, area: Rect) {
        if area.is_empty() {
            return;
        }
        let mut lines = vec![Line::styled(
            "Selected terminal tab",
            Style::default()
                .fg(theme::SECONDARY)
                .add_modifier(Modifier::BOLD),
        )];
        let Some(state) = &self.state else {
            lines.push(Line::styled(
                if self.state_error {
                    "Terminal state is unavailable."
                } else {
                    "Waiting for a workspace."
                },
                Style::default().fg(theme::MUTED),
            ));
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
            return;
        };
        let Some(tab) = state.tabs.0.get(self.selected_item) else {
            lines.push(Line::styled(
                "No terminal tab selected.",
                Style::default().fg(theme::MUTED),
            ));
            if let Some(details) = &self.details {
                lines.push(Line::from(""));
                lines.push(Line::styled(
                    format!("Local folder: {}", safe_label(details.root_path.as_str())),
                    Style::default().fg(theme::MUTED),
                ));
            }
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
            return;
        };

        let counts = pane_counts(&tab.layout);
        lines.extend([
            Line::styled(
                workspace_name_label(tab.name.as_str(), usize::from(area.width)),
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::from("Type: Terminal"),
            Line::from(format!("Panes: {}", counts.total)),
            Line::from(format!("State: {}", counts.status())),
        ]);
        for (label, count) in [
            ("Running", counts.running),
            ("Starting", counts.starting),
            ("Publishing", counts.publishing),
            ("Exited", counts.exited),
            ("Stopped", counts.stopped),
            ("Lost", counts.lost),
        ] {
            if count > 0 {
                lines.push(Line::from(format!("{label}: {count}")));
            }
        }
        if let Some(details) = &self.details {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!("Local folder: {}", safe_label(details.root_path.as_str())),
                Style::default().fg(theme::MUTED),
            ));
        } else if self.details_error {
            lines.push(Line::styled(
                "Local folder unavailable.",
                Style::default().fg(theme::MUTED),
            ));
        }
        frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), area);
    }

    fn draw_logs(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.is_empty() {
            return;
        }
        let heading = vec![
            Line::styled(
                "Host diagnostics",
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            Line::styled(
                "All workspaces · host-wide events",
                Style::default().fg(theme::MUTED),
            ),
        ];
        let mut heading = heading;
        if self.has_next_logs_page() {
            heading.push(Line::styled(
                "Next page available · select Load more or press n",
                Style::default().fg(theme::WARNING),
            ));
        } else if self.logs.as_ref().is_some_and(|page| page.truncated) {
            heading.push(Line::styled(
                "Some host log history may be missing.",
                Style::default().fg(theme::WARNING),
            ));
        }
        let heading_height = area.height.min(heading.len() as u16);
        frame.render_widget(
            Paragraph::new(heading).wrap(Wrap { trim: true }),
            Rect::new(area.x, area.y, area.width, heading_height),
        );
        if area.height <= heading_height {
            return;
        }
        let entries_area = Rect::new(
            area.x,
            area.y.saturating_add(heading_height),
            area.width,
            area.height.saturating_sub(heading_height),
        );
        if self.logs_error {
            self.draw_muted_text(frame, entries_area, "Host diagnostic logs are unavailable.");
            return;
        }
        let Some(page) = &self.logs else {
            self.draw_muted_text(frame, entries_area, "Select Logs to read host diagnostics.");
            return;
        };
        if !page.available {
            self.draw_muted_text(frame, entries_area, "Host diagnostic logs are unavailable.");
            return;
        }
        if page.entries.is_empty() && !self.has_next_logs_page() {
            self.draw_muted_text(frame, entries_area, "No retained host diagnostic events.");
            return;
        }
        if entries_area.is_empty() {
            return;
        }

        let row_height = if entries_area.height >= 2 { 2 } else { 1 };
        let has_next = self.has_next_logs_page();
        let button_height = if has_next {
            row_height.min(entries_area.height)
        } else {
            0
        };
        let list_area = Rect::new(
            entries_area.x,
            entries_area.y,
            entries_area.width,
            entries_area.height.saturating_sub(button_height),
        );
        if !list_area.is_empty() && !page.entries.is_empty() {
            let visible = usize::from(list_area.height / row_height).max(1);
            let selected_entry = self.selected_log.min(page.entries.len() - 1);
            let start = visible_start(selected_entry, page.entries.len(), visible);
            let end = (start + visible).min(page.entries.len());
            for index in start..end {
                let slot = index - start;
                let y = list_area.y.saturating_add(slot as u16 * row_height);
                let height = row_height.min(list_area.bottom().saturating_sub(y));
                let row_area = Rect::new(list_area.x, y, list_area.width, height);
                let selected = index == self.selected_log;
                let active = selected && focused && self.focus == FocusArea::Content;
                let entry = &page.entries[index];
                let background = if selected {
                    theme::selection_style(active).bg.unwrap_or(theme::KEYCAP)
                } else {
                    theme::SURFACE
                };
                let severity_style = Style::default()
                    .fg(severity_color(entry.severity))
                    .bg(background)
                    .add_modifier(if selected {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    });
                let first = Line::from(vec![
                    Span::styled(
                        format_timestamp(entry.unix_time_ms),
                        Style::default().fg(theme::MUTED).bg(background),
                    ),
                    Span::raw("  "),
                    Span::styled(humanize(&format!("{:?}", entry.severity)), severity_style),
                ]);
                frame.render_widget(
                    Paragraph::new(first),
                    Rect::new(row_area.x, row_area.y, row_area.width, 1),
                );
                if row_area.height > 1 {
                    let code = format!(
                        "{} · {}",
                        humanize(&format!("{:?}", entry.component)),
                        humanize(&format!("{:?}", entry.code)),
                    );
                    frame.render_widget(
                        Paragraph::new(workspace_name_label(&code, usize::from(row_area.width)))
                            .style(
                                Style::default()
                                    .fg(if active {
                                        theme::ACCENT
                                    } else {
                                        theme::SECONDARY
                                    })
                                    .bg(background),
                            ),
                        Rect::new(row_area.x, row_area.y.saturating_add(1), row_area.width, 1),
                    );
                }
                self.log_row_targets.borrow_mut().push(RowTarget {
                    area: row_area,
                    index,
                });
            }
        }
        if button_height > 0 {
            let button_area = Rect::new(
                entries_area.x,
                entries_area.bottom().saturating_sub(button_height),
                entries_area.width,
                button_height,
            );
            let selected = self.selected_log == page.entries.len();
            let active = selected && focused && self.focus == FocusArea::Content;
            let background = if selected {
                theme::selection_style(active).bg.unwrap_or(theme::KEYCAP)
            } else {
                theme::SURFACE
            };
            frame.render_widget(
                Paragraph::new(workspace_name_label(
                    "Load more host diagnostics",
                    usize::from(button_area.width),
                ))
                .style(
                    Style::default()
                        .fg(if active {
                            theme::ACCENT
                        } else {
                            theme::SECONDARY
                        })
                        .bg(background)
                        .add_modifier(Modifier::BOLD),
                ),
                Rect::new(button_area.x, button_area.y, button_area.width, 1),
            );
            if button_area.height > 1 {
                frame.render_widget(
                    Paragraph::new("Enter or click · n")
                        .style(Style::default().fg(theme::MUTED).bg(background)),
                    Rect::new(
                        button_area.x,
                        button_area.y.saturating_add(1),
                        button_area.width,
                        1,
                    ),
                );
            }
            self.log_row_targets.borrow_mut().push(RowTarget {
                area: button_area,
                index: page.entries.len(),
            });
        }
    }

    fn draw_settings(&self, frame: &mut Frame, area: Rect, focused: bool) {
        if area.is_empty() {
            return;
        }
        let name = self.workspace.as_ref().map_or_else(
            || "Unavailable".to_owned(),
            |workspace| safe_label(workspace.name.as_str()),
        );
        let path = self.details.as_ref().map_or_else(
            || {
                if self.details_error {
                    "Unavailable".to_owned()
                } else {
                    "Loading".to_owned()
                }
            },
            |details| safe_label(details.root_path.as_str()),
        );
        let compact = area.height < 7;
        let mut y = area.y;
        if !compact {
            self.draw_setting_value(frame, &mut y, area, "Workspace", &name);
            self.draw_setting_value(frame, &mut y, area, "Local folder", &path);
            y = y.saturating_add(1);
        }
        if !compact && y < area.bottom() {
            frame.render_widget(
                Paragraph::new("Actions").style(
                    Style::default()
                        .fg(theme::SECONDARY)
                        .add_modifier(Modifier::BOLD),
                ),
                Rect::new(area.x, y, area.width, 1),
            );
            y = y.saturating_add(1);
        }
        let action_area = Rect::new(area.x, y, area.width, area.bottom().saturating_sub(y));
        let visible = usize::from(action_area.height).min(SETTINGS_ACTIONS.len());
        let start = visible_start(self.selected_action, SETTINGS_ACTIONS.len(), visible);
        let end = (start + visible).min(SETTINGS_ACTIONS.len());
        for index in start..end {
            let action = SETTINGS_ACTIONS[index];
            let label = self.settings_action_label(action);
            let row = Rect::new(
                action_area.x,
                action_area.y.saturating_add((index - start) as u16),
                action_area.width,
                1,
            );
            let selected = self.selected_action == index;
            let style = if selected {
                theme::selection_style(focused && self.focus == FocusArea::Content)
            } else {
                Style::default().fg(theme::SECONDARY)
            };
            frame.render_widget(
                Paragraph::new(workspace_name_label(label, usize::from(row.width))).style(style),
                row,
            );
            self.action_targets.borrow_mut().push(ActionTarget {
                area: row,
                action,
                index,
            });
        }
    }

    fn draw_message(&self, frame: &mut Frame, area: Rect, message: &str) {
        if area.is_empty() {
            return;
        }
        let message = safe_label(message);
        frame.render_widget(
            Block::default().style(Style::default().bg(theme::KEYCAP)),
            area,
        );
        frame.render_widget(
            Paragraph::new(message)
                .style(Style::default().fg(theme::SECONDARY).bg(theme::KEYCAP))
                .wrap(Wrap { trim: true }),
            area,
        );
    }

    fn draw_setting_value(
        &self,
        frame: &mut Frame,
        y: &mut u16,
        area: Rect,
        label: &str,
        value: &str,
    ) {
        if *y >= area.bottom() {
            return;
        }
        let value_width = area.width.saturating_sub(label.len() as u16 + 2);
        let value = workspace_name_label(value, usize::from(value_width));
        let line = Line::from(vec![
            Span::styled(format!("{label}: "), Style::default().fg(theme::MUTED)),
            Span::styled(value, Style::default().fg(theme::SECONDARY)),
        ]);
        frame.render_widget(Paragraph::new(line), Rect::new(area.x, *y, area.width, 1));
        *y = (*y).saturating_add(1);
    }

    fn draw_muted_text(&self, frame: &mut Frame, area: Rect, text: &str) {
        if !area.is_empty() {
            frame.render_widget(
                Paragraph::new(text)
                    .style(Style::default().fg(theme::MUTED))
                    .wrap(Wrap { trim: true }),
                area,
            );
        }
    }
}

#[derive(Default)]
struct PaneCounts {
    total: usize,
    starting: usize,
    publishing: usize,
    running: usize,
    exited: usize,
    stopped: usize,
    lost: usize,
}

impl PaneCounts {
    fn add_layout(&mut self, layout: &TerminalLayout) {
        match layout {
            TerminalLayout::Pane { pane } => {
                self.total += 1;
                match pane.state {
                    PaneState::Starting => self.starting += 1,
                    PaneState::Publishing => self.publishing += 1,
                    PaneState::Running => self.running += 1,
                    PaneState::Exited => self.exited += 1,
                    PaneState::Stopped => self.stopped += 1,
                    PaneState::Lost => self.lost += 1,
                }
            }
            TerminalLayout::Split { first, second, .. } => {
                self.add_layout(first);
                self.add_layout(second);
            }
        }
    }

    fn status(&self) -> &'static str {
        if self.total == 0 {
            "No panes"
        } else if self.running == self.total {
            "Running"
        } else if self.stopped + self.exited + self.lost == self.total {
            "Stopped"
        } else if self.starting + self.publishing == self.total {
            "Starting"
        } else {
            "Mixed state"
        }
    }
}

fn pane_counts(layout: &TerminalLayout) -> PaneCounts {
    let mut counts = PaneCounts::default();
    counts.add_layout(layout);
    counts
}

fn visible_start(selected: usize, total: usize, visible: usize) -> usize {
    let visible = visible.max(1);
    let start = selected.saturating_sub(visible.saturating_sub(1));
    start.min(total.saturating_sub(visible))
}

fn reserved_message_height(message: Option<&str>, area: Rect) -> u16 {
    let Some(message) = message else {
        return 0;
    };
    if area.is_empty() {
        return 0;
    }
    let paragraph = Paragraph::new(safe_label(message)).wrap(Wrap { trim: true });
    let lines = paragraph.line_count(area.width).max(1);
    let max_height = if area.height > 1 {
        area.height - 1
    } else {
        area.height
    };
    (lines.min(2).min(usize::from(max_height))) as u16
}

fn move_selection(selected: usize, count: usize, delta: isize) -> usize {
    if count == 0 {
        return 0;
    }
    if delta < 0 {
        selected.saturating_sub(delta.unsigned_abs())
    } else {
        selected.saturating_add(delta as usize).min(count - 1)
    }
}

fn row_at(targets: &[RowTarget], x: u16, y: u16) -> Option<usize> {
    targets
        .iter()
        .find(|target| target.area.contains((x, y).into()))
        .map(|target| target.index)
}

fn panel_action_key(action: PanelAction) -> Option<KeyCode> {
    match action {
        PanelAction::Rename => Some(KeyCode::Char('n')),
        PanelAction::Profiles => Some(KeyCode::Char('p')),
        PanelAction::Share => Some(KeyCode::Char('s')),
        PanelAction::Remove => Some(KeyCode::Char('d')),
        _ => None,
    }
}

fn severity_color(severity: operations::UiLogSeverity) -> ratatui::style::Color {
    match severity {
        operations::UiLogSeverity::Info => theme::SECONDARY,
        operations::UiLogSeverity::Warning => theme::WARNING,
        operations::UiLogSeverity::Error => theme::ERROR,
    }
}

fn humanize(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 8);
    let mut previous_lowercase = false;
    for character in value.chars() {
        if character.is_ascii_uppercase() && previous_lowercase {
            output.push(' ');
        }
        output.push(character);
        previous_lowercase = character.is_ascii_lowercase() || character.is_ascii_digit();
    }
    output
}

fn format_timestamp(unix_time_ms: Option<u64>) -> String {
    let Some(seconds) = unix_time_ms.map(|milliseconds| milliseconds / 1_000) else {
        return "Time unknown".to_owned();
    };
    let Ok(seconds) = i64::try_from(seconds) else {
        return "Time out of range".to_owned();
    };
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    let Some(days_from_epoch) = days.checked_add(719_468) else {
        return "Time out of range".to_owned();
    };
    let era = if days_from_epoch >= 0 {
        days_from_epoch
    } else {
        days_from_epoch - 146_096
    }
    .div_euclid(146_097);
    let day_of_era = days_from_epoch - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_part = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_part + 2) / 5 + 1;
    let month = month_part + if month_part < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    let hour = day_seconds / 3_600;
    let minute = (day_seconds % 3_600) / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{
        DecimalU64, PaneId, RuntimeId, TabId, WorkspaceContext, WorkspaceEpoch,
        ipc::{LocalProjectName, LocalRootPath},
        rpc::{BoundedList, DisplayText, TerminalPane, TerminalTab},
    };
    use ratatui::{Terminal, backend::TestBackend};

    #[derive(Default)]
    struct FakeBackend {
        responses: Vec<LocalResult>,
        request_count: usize,
        requested_ids: Vec<WorkspaceId>,
        logs: Option<operations::UiDiagnosticLogSnapshot>,
        log_reads: usize,
        log_cursors: Vec<Option<u64>>,
    }

    impl Backend for FakeBackend {
        fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
            self.request_count += 1;
            match call {
                LocalCall::WorkspaceInspect(read) | LocalCall::WorkspaceDetails(read) => {
                    self.requested_ids.push(read.workspace_id);
                }
                _ => {}
            }
            if self.responses.is_empty() {
                return Err("TEST_UNEXPECTED_REQUEST");
            }
            Ok(self.responses.remove(0))
        }

        fn read_diagnostic_logs(
            &mut self,
            cursor: Option<u64>,
            limit: usize,
        ) -> Result<operations::UiDiagnosticLogSnapshot, &'static str> {
            self.log_reads += 1;
            self.log_cursors.push(cursor);
            assert_eq!(limit, LOG_PAGE_SIZE);
            self.logs.clone().ok_or("TEST_LOGS_UNAVAILABLE")
        }
    }

    fn workspace(id: WorkspaceId, name: &str) -> LocalWorkspaceSummary {
        LocalWorkspaceSummary {
            workspace_id: id,
            name: LocalProjectName::try_from(name.to_owned()).unwrap(),
            sharing: lomi_remote_protocol::ipc::LocalSharing::Disabled,
        }
    }

    fn workspace_state(id: WorkspaceId, tabs: Vec<TerminalTab>) -> WorkspaceState {
        WorkspaceState {
            context: WorkspaceContext {
                workspace_id: id,
                workspace_epoch: WorkspaceEpoch::from_bytes([2; 16]).unwrap(),
                runtime_id: RuntimeId::from_bytes([3; 16]).unwrap(),
                runtime_generation: DecimalU64(1),
                host_access_epoch: DecimalU64(1),
                grant_revision: DecimalU64(1),
            },
            domain_revision: DecimalU64(1),
            name: DisplayText::try_from("Workspace state name".to_owned()).unwrap(),
            tabs: BoundedList(tabs),
        }
    }

    fn terminal_tab(name: &str, id: u8, state: PaneState) -> TerminalTab {
        TerminalTab {
            tab_id: TabId::from_bytes([id; 16]).unwrap(),
            name: DisplayText::try_from(name.to_owned()).unwrap(),
            layout: TerminalLayout::Pane {
                pane: TerminalPane {
                    pane_id: PaneId::from_bytes([id.wrapping_add(1); 16]).unwrap(),
                    session: None,
                    state,
                },
            },
        }
    }

    fn details(id: WorkspaceId, name: &str) -> LocalWorkspaceDetails {
        LocalWorkspaceDetails {
            workspace: workspace(id, name),
            root_path: LocalRootPath::try_from("/tmp/example".to_owned()).unwrap(),
            remote_web_url: None,
        }
    }

    fn backend_for(id: WorkspaceId, name: &str, tabs: Vec<TerminalTab>) -> FakeBackend {
        FakeBackend {
            responses: vec![
                LocalResult::WorkspaceState(Box::new(workspace_state(id, tabs))),
                LocalResult::WorkspaceDetails(details(id, name)),
            ],
            ..FakeBackend::default()
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn buffer_text(terminal: &Terminal<TestBackend>) -> String {
        let buffer = terminal.backend().buffer();
        (0..buffer.area.height)
            .map(|y| {
                (0..buffer.area.width)
                    .map(|x| buffer[(x, y)].symbol())
                    .collect::<String>()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn binding_caches_same_workspace_and_force_reloads_reads() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(
            id,
            "Alpha",
            vec![
                terminal_tab("Development", 10, PaneState::Running),
                terminal_tab("Other", 12, PaneState::Stopped),
            ],
        );

        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        assert_eq!(backend.request_count, 2);
        assert_eq!(backend.requested_ids, vec![id, id]);
        panel.selected_item = 1;
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        assert_eq!(backend.request_count, 2);
        assert_eq!(panel.selected_item, 1);

        backend.responses = vec![
            LocalResult::WorkspaceState(Box::new(workspace_state(
                id,
                vec![terminal_tab("Only tab", 12, PaneState::Stopped)],
            ))),
            LocalResult::WorkspaceDetails(details(id, "Alpha")),
        ];
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, true);
        assert_eq!(backend.request_count, 4);
        assert_eq!(backend.requested_ids, vec![id, id, id, id]);
        assert_eq!(panel.selected_item, 0);
    }

    #[test]
    fn changed_workspace_clears_old_rows_and_rejects_mismatched_response_ids() {
        let first = WorkspaceId::from_bytes([1; 16]).unwrap();
        let second = WorkspaceId::from_bytes([2; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(
            first,
            "Alpha",
            vec![
                terminal_tab("One", 10, PaneState::Running),
                terminal_tab("Two", 12, PaneState::Stopped),
            ],
        );
        panel.bind(Some(workspace(first, "Alpha")), &mut backend, false);
        panel.selected_item = 1;

        backend.responses = vec![
            LocalResult::WorkspaceState(Box::new(workspace_state(
                first,
                vec![terminal_tab("Stale", 14, PaneState::Running)],
            ))),
            LocalResult::WorkspaceDetails(details(first, "Alpha")),
        ];
        panel.bind(Some(workspace(second, "Beta")), &mut backend, false);

        assert_eq!(&backend.requested_ids[2..], &[second, second]);
        assert_eq!(panel.selected_item, 0);
        assert!(panel.state.is_none());
        assert!(panel.details.is_none());
        assert!(panel.state_error);
        assert!(panel.details_error);
    }

    #[test]
    fn logs_are_lazy_and_labeled_host_wide() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        backend.logs = Some(operations::UiDiagnosticLogSnapshot {
            entries: vec![],
            next_cursor: 0,
            truncated: false,
            available: true,
        });
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        assert_eq!(backend.log_reads, 0);
        panel.focus_tabs();
        panel.handle_key(key(KeyCode::Right), &mut backend);
        assert_eq!(panel.active_tab(), WorkspaceTab::Logs);
        assert_eq!(backend.log_reads, 1);

        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                panel.draw(frame, area, true, None);
            })
            .unwrap();
        let text = buffer_text(&terminal);
        assert!(text.contains("Host diagnostics"));
        assert!(text.contains("All workspaces"));
    }

    #[test]
    fn truncated_host_logs_can_request_the_next_page() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        backend.logs = Some(operations::UiDiagnosticLogSnapshot {
            entries: vec![],
            next_cursor: 64,
            truncated: true,
            available: true,
        });
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        panel.focus_tabs();
        panel.handle_key(key(KeyCode::Right), &mut backend);

        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                panel.draw(frame, area, true, None);
            })
            .unwrap();
        assert!(buffer_text(&terminal).contains("press n"));

        panel.focus_tabs();
        panel.handle_key(key(KeyCode::Char('n')), &mut backend);
        assert_eq!(backend.log_cursors, vec![None, Some(64)]);
    }

    #[test]
    fn load_more_log_row_is_clickable() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        backend.logs = Some(operations::UiDiagnosticLogSnapshot {
            entries: vec![],
            next_cursor: 64,
            truncated: true,
            available: true,
        });
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        panel.activate_tab(WorkspaceTab::Logs, &mut backend);
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                panel.draw(frame, area, true, None);
            })
            .unwrap();
        assert!(buffer_text(&terminal).contains("Load more host diagnostics"));
        let target = panel.log_row_targets.borrow()[0];
        assert!(panel.hoverable(target.area.x, target.area.y));

        assert_eq!(
            panel.handle_mouse(
                MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: target.area.x,
                    row: target.area.y,
                    modifiers: KeyModifiers::NONE,
                },
                &mut backend,
            ),
            PanelAction::None
        );
        assert_eq!(backend.log_cursors, vec![None, Some(64)]);
    }

    #[test]
    fn dashboard_status_is_visible_on_each_tab_without_overlapping_targets() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let status =
            "Sharing change was not confirmed. The workspace sharing preference remains unchanged.";
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(
            id,
            "Alpha",
            vec![terminal_tab("Development", 10, PaneState::Running)],
        );
        backend.logs = Some(operations::UiDiagnosticLogSnapshot {
            entries: vec![operations::UiDiagnosticLogEntry {
                sequence: 1,
                unix_time_ms: Some(0),
                severity: operations::UiLogSeverity::Warning,
                component: operations::UiLogComponent::Host,
                code: operations::UiLogCode::HostStarted,
            }],
            next_cursor: 64,
            truncated: true,
            available: true,
        });
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);

        for (tab, visible_content) in [
            (WorkspaceTab::OpenTabs, "Terminal tabs"),
            (WorkspaceTab::Logs, "Host diagnostics"),
            (WorkspaceTab::Settings, "Rename workspace"),
        ] {
            panel.activate_tab(tab, &mut backend);
            panel.focus_content();
            let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    panel.draw(frame, area, true, Some(status));
                })
                .unwrap();
            let text = buffer_text(&terminal);
            assert!(text.contains(visible_content), "tab {tab:?}: {text}");
            assert!(text.contains("Sharing change was not confirmed"));

            let panel_area = Rect::new(0, 0, 60, 12);
            let body_area = Rect::new(0, 3, 60, 9);
            let status_top = body_area.bottom() - reserved_message_height(Some(status), body_area);
            let targets_end_before_status =
                |targets: &[Rect]| targets.iter().all(|target| target.bottom() <= status_top);
            assert!(targets_end_before_status(
                &panel
                    .tab_targets
                    .borrow()
                    .iter()
                    .map(|target| target.area)
                    .collect::<Vec<_>>()
            ));
            assert!(targets_end_before_status(
                &panel
                    .open_row_targets
                    .borrow()
                    .iter()
                    .map(|target| target.area)
                    .collect::<Vec<_>>()
            ));
            assert!(targets_end_before_status(
                &panel
                    .log_row_targets
                    .borrow()
                    .iter()
                    .map(|target| target.area)
                    .collect::<Vec<_>>()
            ));
            assert!(targets_end_before_status(
                &panel
                    .action_targets
                    .borrow()
                    .iter()
                    .map(|target| target.area)
                    .collect::<Vec<_>>()
            ));
            assert!(!panel.hoverable(panel_area.x, status_top));
        }
    }

    #[test]
    fn settings_action_returns_to_parent_without_backend_mutation() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        let read_count = backend.request_count;
        panel.activate_tab(WorkspaceTab::Settings, &mut backend);
        panel.focus_content();

        assert_eq!(
            panel.handle_key(key(KeyCode::Enter), &mut backend),
            PanelAction::Rename
        );
        assert_eq!(backend.request_count, read_count);
    }

    #[test]
    fn share_action_label_reflects_the_bound_workspace_preference() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        panel.workspace = Some(workspace(id, "Alpha"));
        assert_eq!(
            panel.settings_action_label(PanelAction::Share),
            "Share workspace"
        );
        panel.workspace.as_mut().unwrap().sharing = LocalSharing::Enabled;
        assert_eq!(
            panel.settings_action_label(PanelAction::Share),
            "Unshare workspace"
        );
        assert_eq!(
            panel_action_key(PanelAction::Rename),
            Some(KeyCode::Char('n'))
        );
        assert_eq!(
            panel_action_key(PanelAction::Profiles),
            Some(KeyCode::Char('p'))
        );
        assert_eq!(
            panel_action_key(PanelAction::Share),
            Some(KeyCode::Char('s'))
        );
        assert_eq!(
            panel_action_key(PanelAction::Remove),
            Some(KeyCode::Char('d'))
        );
    }

    #[test]
    fn settings_pointer_action_uses_shared_confirmation_click_guard() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        panel.activate_tab(WorkspaceTab::Settings, &mut backend);
        panel.focus_content();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                panel.draw(frame, area, true, None);
            })
            .unwrap();
        let target = panel
            .action_targets
            .borrow()
            .iter()
            .find(|target| target.action == PanelAction::Rename)
            .copied()
            .unwrap();
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: target.area.x,
            row: target.area.y,
            modifiers: KeyModifiers::NONE,
        };

        assert_eq!(panel.handle_mouse(click, &mut backend), PanelAction::Rename);
        assert_eq!(panel.handle_mouse(click, &mut backend), PanelAction::None);
        assert_eq!(backend.request_count, 2);
    }

    #[test]
    fn arrow_navigation_never_creates_or_starts_a_terminal() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(
            id,
            "Alpha",
            vec![terminal_tab("Stopped tab", 10, PaneState::Stopped)],
        );
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);
        let read_count = backend.request_count;
        panel.focus_content();
        panel.handle_key(key(KeyCode::Up), &mut backend);
        panel.handle_key(key(KeyCode::Down), &mut backend);
        panel.handle_key(key(KeyCode::Enter), &mut backend);
        assert_eq!(backend.request_count, read_count);
    }

    #[test]
    fn empty_and_narrow_render_has_no_orphan_row_targets() {
        let id = WorkspaceId::from_bytes([1; 16]).unwrap();
        let mut panel = WorkspacePanel::default();
        let mut backend = backend_for(id, "Alpha", Vec::new());
        panel.bind(Some(workspace(id, "Alpha")), &mut backend, false);

        for (width, height) in [(1, 1), (18, 6), (60, 24)] {
            let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
            terminal
                .draw(|frame| {
                    let area = frame.area();
                    panel.draw(frame, area, true, None);
                })
                .unwrap();
            let area = Rect::new(0, 0, width, height);
            assert!(panel.tab_targets.borrow().iter().all(|target| {
                !target.area.is_empty() && target.area.intersection(area) == target.area
            }));
            assert!(!panel.hoverable(width, 0));
            assert!(!panel.hoverable(0, height));
        }
        assert!(panel.open_row_targets.borrow().is_empty());
    }

    #[test]
    fn log_timestamps_and_enum_labels_are_human_readable() {
        assert_eq!(format_timestamp(Some(0)), "1970-01-01 00:00:00 UTC");
        assert_eq!(humanize("HostStarted"), "Host Started");
        assert_eq!(
            humanize("AuthenticationConfigurationMissing"),
            "Authentication Configuration Missing"
        );
    }
}
