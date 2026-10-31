use super::{
    Backend, Dashboard,
    interaction::Action,
    operations::{
        ServiceAccountKind, ServiceAction, ServiceAutostartState, ServiceMode, ServiceRuntimeState,
        ServiceSnapshot,
    },
    theme,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use lomi_remote_protocol::ipc::{
    LocalCall, LocalHostName, LocalProjectName, LocalResult, LocalRootPath, LocalSharing,
    LocalStatus, LocalWorkspaceDetails, LocalWorkspaceSummary,
};
use lomi_remote_protocol::rpc::{BoundedList, DisplayText, WorkspaceState};
use lomi_remote_protocol::{
    DecimalU64, HostId, RuntimeId, WorkspaceContext, WorkspaceEpoch, WorkspaceId,
};
use ratatui::{Terminal, backend::TestBackend, layout::Rect};

#[derive(Default)]
struct FakeBackend {
    calls: Vec<LocalCall>,
    workspaces: Vec<LocalWorkspaceSummary>,
    service_status_calls: usize,
    service_actions: Vec<ServiceAction>,
}

impl FakeBackend {
    fn with_workspaces(workspaces: Vec<LocalWorkspaceSummary>) -> Self {
        Self {
            workspaces,
            ..Self::default()
        }
    }
}

impl Backend for FakeBackend {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        self.calls.push(call.clone());
        match call {
            LocalCall::Status {} => Ok(LocalResult::Status(LocalStatus {
                host_name: LocalHostName::try_from("Test host".to_owned()).unwrap(),
                host_id: HostId::from_bytes([1; 16]).unwrap(),
                runtime_id: RuntimeId::from_bytes([2; 16]).unwrap(),
                sharing: LocalSharing::Disabled,
            })),
            LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(
                self.workspaces.clone(),
            ))),
            LocalCall::WorkspaceInspect(read) => {
                let Some(workspace) = self
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == read.workspace_id)
                else {
                    return Err("workspace not found in navigation fixture");
                };
                Ok(LocalResult::WorkspaceState(Box::new(workspace_state(
                    read.workspace_id,
                    workspace.name.as_str(),
                ))))
            }
            LocalCall::WorkspaceDetails(read) => {
                let Some(workspace) = self
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == read.workspace_id)
                    .cloned()
                else {
                    return Err("workspace not found in navigation fixture");
                };
                Ok(LocalResult::WorkspaceDetails(LocalWorkspaceDetails {
                    root_path: LocalRootPath::try_from(format!(
                        "/workspace/{}",
                        workspace.name.as_str()
                    ))
                    .unwrap(),
                    workspace,
                    remote_web_url: None,
                }))
            }
            _ => Err("unexpected navigation test request"),
        }
    }

    fn service_status(&mut self) -> Result<ServiceSnapshot, &'static str> {
        self.service_status_calls += 1;
        Ok(ServiceSnapshot {
            mode: Some(ServiceMode::Manual),
            runtime: ServiceRuntimeState::Stopped,
            autostart: ServiceAutostartState::Disabled,
            account: ServiceAccountKind::CurrentUser,
            host_uptime_seconds: None,
            connected_clients: None,
            active_terminals: None,
        })
    }

    fn service_action(&mut self, action: ServiceAction) -> Result<ServiceSnapshot, &'static str> {
        self.service_actions.push(action);
        self.service_status()
    }
}

fn workspace_id(byte: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([byte; 16]).unwrap()
}

fn workspace(byte: u8, name: &str, sharing: LocalSharing) -> LocalWorkspaceSummary {
    LocalWorkspaceSummary {
        workspace_id: workspace_id(byte),
        name: LocalProjectName::try_from(name.to_owned()).unwrap(),
        sharing,
    }
}

fn workspace_state(id: WorkspaceId, name: &str) -> WorkspaceState {
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
        name: DisplayText::try_from(name.to_owned()).unwrap(),
        tabs: BoundedList(Vec::new()),
    }
}

fn assert_navigation_reads_only(backend: &FakeBackend) {
    assert!(
        backend.calls.iter().all(|call| matches!(
            call,
            LocalCall::Status {}
                | LocalCall::Workspaces {}
                | LocalCall::WorkspaceInspect(_)
                | LocalCall::WorkspaceDetails(_)
        )),
        "unexpected non-navigation backend call: {:?}",
        backend.calls
    );
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn mouse(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

fn text_column(terminal: &Terminal<TestBackend>, y: u16, text: &str, last: bool) -> Option<u16> {
    let buffer = terminal.backend().buffer();
    let width = usize::from(buffer.area.width);
    let start = usize::from(y.saturating_sub(buffer.area.y)) * width;
    let mut line = String::new();
    let mut byte_columns = Vec::with_capacity(width);
    for cell in &buffer.content[start..start + width] {
        byte_columns.push(line.len());
        line.push_str(cell.symbol());
    }
    let byte_column = if last {
        line.rfind(text)
    } else {
        line.find(text)
    }?;
    byte_columns
        .iter()
        .position(|column| *column == byte_column)
        .map(|column| column as u16)
}

fn text_position(terminal: &Terminal<TestBackend>, text: &str) -> Option<(u16, u16)> {
    let area = terminal.backend().buffer().area;
    (area.y..area.bottom()).find_map(|y| {
        text_column(terminal, y, text, false)
            .map(|column| (area.x.saturating_add(column).saturating_add(1), y))
    })
}

fn last_text_position(terminal: &Terminal<TestBackend>, text: &str) -> Option<(u16, u16)> {
    let area = terminal.backend().buffer().area;
    let mut found = None;
    for y in area.y..area.bottom() {
        if let Some(column) = text_column(terminal, y, text, true) {
            found = Some((area.x.saturating_add(column).saturating_add(1), y));
        }
    }
    found
}

fn click_text(
    dashboard: &mut Dashboard,
    backend: &mut FakeBackend,
    terminal: &Terminal<TestBackend>,
    text: &str,
    last: bool,
) -> bool {
    let position = if last {
        last_text_position(terminal, text)
    } else {
        text_position(terminal, text)
    }
    .expect("visible control label");
    dashboard.handle_mouse(
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            position.0,
            position.1,
        ),
        backend,
    )
}

#[test]
fn sidebar_click_scroll_and_filter_follow_visible_workspace_rows() {
    let workspaces = vec![
        workspace(1, "Alpha", LocalSharing::Disabled),
        workspace(2, "Beta", LocalSharing::Disabled),
        workspace(3, "Gamma", LocalSharing::Disabled),
    ];
    let mut dashboard = Dashboard {
        workspaces: workspaces.clone(),
        ..Dashboard::default()
    };
    let mut backend = FakeBackend::with_workspaces(workspaces);
    let mut terminal = Terminal::new(TestBackend::new(100, 24)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    assert!(click_text(
        &mut dashboard,
        &mut backend,
        &terminal,
        "Beta",
        false
    ));
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(2)
    );
    let sidebar = dashboard.sidebar_area.get();
    assert!(dashboard.handle_mouse(
        mouse(
            MouseEventKind::ScrollDown,
            sidebar.x.saturating_add(1),
            sidebar.y.saturating_add(1),
        ),
        &mut backend,
    ));
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(3)
    );

    dashboard.dispatch_key(key(KeyCode::Char('/')), &mut backend);
    for character in "Alpha".chars() {
        dashboard.dispatch_key(key(KeyCode::Char(character)), &mut backend);
    }
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(1)
    );
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(click_text(
        &mut dashboard,
        &mut backend,
        &terminal,
        "Alpha",
        false
    ));
    assert_eq!(dashboard.selected, 0);
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(1)
    );
    assert_navigation_reads_only(&backend);
}

#[test]
fn sidebar_remainder_below_a_partial_workspace_row_has_no_hit_target() {
    let workspaces = (1..=8)
        .map(|index| workspace(index, &format!("Workspace {index}"), LocalSharing::Disabled))
        .collect::<Vec<_>>();
    let mut dashboard = Dashboard {
        workspaces: workspaces.clone(),
        selected: 5,
        ..Dashboard::default()
    };
    let mut backend = FakeBackend::with_workspaces(workspaces);
    let mut terminal = Terminal::new(TestBackend::new(80, 25)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    let sidebar = dashboard.sidebar_area.get();
    let inner = theme::panel("", theme::SIDEBAR).inner(sidebar);
    assert_ne!(inner.height % 3, 0);
    let (column, last_full_row) = last_text_position(&terminal, "Workspace 6").unwrap();
    let partial_row_remainder = last_full_row + 3;
    assert!(partial_row_remainder < inner.bottom());
    assert!(dashboard.handle_mouse(
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            column,
            partial_row_remainder,
        ),
        &mut backend,
    ));

    assert_eq!(dashboard.selected, 5);
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(6)
    );
    assert_navigation_reads_only(&backend);
}

#[test]
fn opening_profiles_clears_keyboard_focus_from_sidebar_rows() {
    let workspaces = vec![
        workspace(1, "Alpha", LocalSharing::Disabled),
        workspace(2, "Beta", LocalSharing::Disabled),
    ];
    let mut dashboard = Dashboard {
        workspaces: workspaces.clone(),
        ..Dashboard::default()
    };
    let mut backend = FakeBackend::with_workspaces(workspaces);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    dashboard.dispatch_key(key(KeyCode::Tab), &mut backend);
    assert_eq!(dashboard.controls.focused(), Some(Action::Row(0)));
    dashboard.dispatch_key(key(KeyCode::Char('p')), &mut backend);

    assert!(dashboard.operations.active());
    assert!(dashboard.controls.focused().is_none());
}

#[test]
fn one_column_footer_cannot_register_a_clipped_confirm_target() {
    let mut terminal = Terminal::new(TestBackend::new(3, 4)).unwrap();
    let mut targets = Vec::new();
    terminal
        .draw(|frame| {
            targets = theme::render_footer(frame, Rect::new(0, 0, 3, 4), &[("y", "Confirm")], &[]);
        })
        .unwrap();

    assert!(targets.is_empty());
}

#[test]
fn setup_preference_back_click_and_escape_return_without_quitting_or_saving() {
    let mut dashboard = Dashboard {
        setup_draft: Some(super::SetupDraft::default()),
        ..Dashboard::default()
    };
    let mut backend = FakeBackend::default();
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let (column, row) = last_text_position(&terminal, "Back").unwrap();

    assert!(dashboard.handle_mouse(
        mouse(MouseEventKind::Down(MouseButton::Left), column, row),
        &mut backend,
    ));
    assert!(dashboard.setup_draft.is_none());
    assert!(!dashboard.quit_requested);
    assert!(backend.calls.is_empty());

    let mut keyboard = Dashboard {
        setup_draft: Some(super::SetupDraft::default()),
        ..Dashboard::default()
    };
    let mut keyboard_backend = FakeBackend::default();
    assert!(keyboard.dispatch_key(key(KeyCode::Esc), &mut keyboard_backend));
    assert!(keyboard.setup_draft.is_none());
    assert!(!keyboard.quit_requested);
    assert!(keyboard_backend.calls.is_empty());
}

#[test]
fn footer_actions_open_add_search_help_and_quit_without_requests() {
    let mut add = Dashboard::default();
    let mut add_backend = FakeBackend::default();
    let mut add_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    add_terminal.draw(|frame| add.draw(frame)).unwrap();
    assert!(click_text(
        &mut add,
        &mut add_backend,
        &add_terminal,
        "Add workspace",
        true,
    ));
    assert!(add.workspace_form.is_some());
    assert!(add_backend.calls.is_empty());

    let mut search = Dashboard::default();
    let mut search_backend = FakeBackend::default();
    let mut search_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    search_terminal.draw(|frame| search.draw(frame)).unwrap();
    assert!(click_text(
        &mut search,
        &mut search_backend,
        &search_terminal,
        "Search",
        true,
    ));
    assert!(search.search_active);
    assert!(search_backend.calls.is_empty());

    let mut help = Dashboard::default();
    let mut help_backend = FakeBackend::default();
    let mut help_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    help_terminal.draw(|frame| help.draw(frame)).unwrap();
    assert!(click_text(
        &mut help,
        &mut help_backend,
        &help_terminal,
        "Shortcuts",
        true,
    ));
    assert!(help.help);
    assert!(help_backend.calls.is_empty());

    let mut quit = Dashboard::default();
    let mut quit_backend = FakeBackend::default();
    let mut quit_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    quit_terminal.draw(|frame| quit.draw(frame)).unwrap();
    let old_quit = last_text_position(&quit_terminal, "Quit").unwrap();
    quit_terminal.backend_mut().resize(40, 14);
    quit_terminal.draw(|frame| quit.draw(frame)).unwrap();
    assert!(quit.handle_mouse(
        mouse(
            MouseEventKind::Down(MouseButton::Left),
            old_quit.0,
            old_quit.1
        ),
        &mut quit_backend,
    ));
    assert!(!quit.quit_requested);
    assert!(click_text(
        &mut quit,
        &mut quit_backend,
        &quit_terminal,
        "Quit",
        true,
    ));
    assert!(quit.quit_requested);
    assert!(quit_backend.calls.is_empty());
}

#[test]
fn share_footer_tracks_selected_action_and_modal_cancel_blocks_outside_clicks() {
    let workspaces = vec![
        workspace(1, "Local", LocalSharing::Disabled),
        workspace(2, "Shared", LocalSharing::Enabled),
    ];
    for (selected, label, share) in [(0, "Share", true), (1, "Unshare", false)] {
        let mut dashboard = Dashboard {
            workspaces: workspaces.clone(),
            selected,
            ..Dashboard::default()
        };
        let mut backend = FakeBackend::with_workspaces(workspaces.clone());
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| dashboard.draw(frame)).unwrap();
        assert!(click_text(
            &mut dashboard,
            &mut backend,
            &terminal,
            label,
            true,
        ));
        let confirmation = dashboard.sharing_confirmation.as_ref().unwrap();
        assert_eq!(confirmation.workspace_id, workspace_id(selected as u8 + 1));
        assert_eq!(confirmation.share, share);

        terminal.draw(|frame| dashboard.draw(frame)).unwrap();
        let sidebar = dashboard.sidebar_area.get();
        assert!(dashboard.handle_mouse(
            mouse(
                MouseEventKind::Down(MouseButton::Left),
                sidebar.x.saturating_add(1),
                sidebar.y.saturating_add(1),
            ),
            &mut backend,
        ));
        assert_eq!(dashboard.selected, selected);
        assert!(dashboard.sharing_confirmation.is_some());
        assert!(backend.calls.is_empty());
        assert!(click_text(
            &mut dashboard,
            &mut backend,
            &terminal,
            "Cancel",
            true,
        ));
        assert!(dashboard.sharing_confirmation.is_none());
        assert_eq!(dashboard.selected, selected);
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn help_service_shortcut_works_by_click_and_keyboard_but_letters_stay_blocked() {
    let mut clicked = Dashboard::default();
    let mut click_backend = FakeBackend::default();
    clicked.dispatch_key(key(KeyCode::Char('?')), &mut click_backend);
    let mut click_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    click_terminal.draw(|frame| clicked.draw(frame)).unwrap();
    assert!(click_text(
        &mut clicked,
        &mut click_backend,
        &click_terminal,
        "Service",
        false,
    ));
    assert!(!clicked.help);
    assert!(clicked.operations.active());
    assert_eq!(click_backend.service_status_calls, 1);
    assert!(click_backend.calls.is_empty());

    let mut keyboard = Dashboard::default();
    let mut keyboard_backend = FakeBackend::default();
    keyboard.dispatch_key(key(KeyCode::Char('?')), &mut keyboard_backend);
    let mut keyboard_terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    keyboard_terminal
        .draw(|frame| keyboard.draw(frame))
        .unwrap();
    assert!(keyboard.dispatch_key(key(KeyCode::Char('o')), &mut keyboard_backend));
    assert!(keyboard.help);
    assert!(!keyboard.operations.active());
    assert_eq!(keyboard_backend.service_status_calls, 0);
    for _ in 0..7 {
        keyboard.dispatch_key(key(KeyCode::Tab), &mut keyboard_backend);
    }
    keyboard.dispatch_key(key(KeyCode::Enter), &mut keyboard_backend);
    assert!(!keyboard.help);
    assert!(keyboard.operations.active());
    assert_eq!(keyboard_backend.service_status_calls, 1);
    assert!(keyboard_backend.calls.is_empty());
}

#[test]
fn wrapped_service_footer_targets_visible_label_and_preserves_uppercase_r() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::default();
    dashboard.dispatch_key(key(KeyCode::Char('o')), &mut backend);
    assert_eq!(backend.service_status_calls, 1);
    let mut terminal = Terminal::new(TestBackend::new(80, 40)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    let (column, row) = last_text_position(&terminal, "Restart").unwrap();
    assert!(
        row > 37,
        "Restart should wrap within the visible footer rows"
    );
    assert!(dashboard.handle_mouse(
        mouse(MouseEventKind::Down(MouseButton::Left), column, row),
        &mut backend,
    ));
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    assert!(text_position(&terminal, "Confirm service action: Restart").is_some());
    assert_eq!(backend.service_status_calls, 1);
    assert!(backend.service_actions.is_empty());
    assert!(backend.calls.is_empty());
}
