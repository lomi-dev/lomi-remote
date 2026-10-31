use super::{Backend, Dashboard, interaction::Action, operations};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use lomi_remote_protocol::{
    DecimalU64, HostId, PaneId, RuntimeId, TabId, WorkspaceContext, WorkspaceEpoch, WorkspaceId,
    ipc::{
        LocalCall, LocalHostName, LocalProjectName, LocalResult, LocalRootPath, LocalSharing,
        LocalStatus, LocalWorkspaceAdd, LocalWorkspaceDetails, LocalWorkspaceSummary,
    },
    rpc::{
        BoundedList, Confirmed, DisplayText, PaneState, TerminalLayout, TerminalPane, TerminalTab,
        WorkspaceState,
    },
};
use ratatui::{Terminal, backend::TestBackend};
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lomi-panel-add-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create temporary workspace fixture");
        Self(path)
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Default)]
struct FakeBackend {
    calls: Vec<LocalCall>,
    workspaces: Vec<LocalWorkspaceSummary>,
    inspect_ids: Vec<WorkspaceId>,
    details_ids: Vec<WorkspaceId>,
    mismatched_inspect_id: Option<WorkspaceId>,
    workspace_tabs_override: Option<Vec<TerminalTab>>,
    log_reads: usize,
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
                self.inspect_ids.push(read.workspace_id);
                let response_id = self.mismatched_inspect_id.unwrap_or(read.workspace_id);
                let name = self
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == response_id)
                    .map_or("Stale response", |workspace| workspace.name.as_str());
                Ok(LocalResult::WorkspaceState(Box::new(workspace_state(
                    response_id,
                    name,
                    self.workspace_tabs_override
                        .clone()
                        .unwrap_or_else(|| tabs_for(response_id)),
                ))))
            }
            LocalCall::WorkspaceDetails(read) => {
                self.details_ids.push(read.workspace_id);
                let workspace = self
                    .workspaces
                    .iter()
                    .find(|workspace| workspace.workspace_id == read.workspace_id)
                    .cloned()
                    .ok_or("workspace missing from panel fixture")?;
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
            LocalCall::WorkspaceAdd(add) => {
                let created = LocalWorkspaceSummary {
                    workspace_id: workspace_id(3),
                    name: add.name,
                    sharing: LocalSharing::Disabled,
                };
                self.workspaces.push(created.clone());
                Ok(LocalResult::Workspace(created))
            }
            _ => Err("unexpected panel test request"),
        }
    }

    fn read_diagnostic_logs(
        &mut self,
        _cursor: Option<u64>,
        limit: usize,
    ) -> Result<operations::UiDiagnosticLogSnapshot, &'static str> {
        self.log_reads += 1;
        assert_eq!(limit, 64);
        Ok(operations::UiDiagnosticLogSnapshot {
            entries: Vec::new(),
            next_cursor: 0,
            truncated: false,
            available: true,
        })
    }
}

fn workspace_id(byte: u8) -> WorkspaceId {
    WorkspaceId::from_bytes([byte; 16]).unwrap()
}

fn workspace(byte: u8, name: &str) -> LocalWorkspaceSummary {
    LocalWorkspaceSummary {
        workspace_id: workspace_id(byte),
        name: LocalProjectName::try_from(name.to_owned()).unwrap(),
        sharing: LocalSharing::Disabled,
    }
}

fn tabs_for(id: WorkspaceId) -> Vec<TerminalTab> {
    let (name, byte) = if id == workspace_id(1) {
        ("Alpha terminal", 10)
    } else if id == workspace_id(2) {
        ("Beta terminal", 12)
    } else {
        return Vec::new();
    };
    vec![TerminalTab {
        tab_id: TabId::from_bytes([byte; 16]).unwrap(),
        name: DisplayText::try_from(name.to_owned()).unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id: PaneId::from_bytes([byte + 1; 16]).unwrap(),
                session: None,
                state: PaneState::Running,
            },
        },
    }]
}

fn workspace_state(id: WorkspaceId, name: &str, tabs: Vec<TerminalTab>) -> WorkspaceState {
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
        tabs: BoundedList(tabs),
    }
}

fn assert_backend_reads_only(backend: &FakeBackend) {
    assert!(
        backend.calls.iter().all(|call| matches!(
            call,
            LocalCall::Status {}
                | LocalCall::Workspaces {}
                | LocalCall::WorkspaceInspect(_)
                | LocalCall::WorkspaceDetails(_)
        )),
        "unexpected non-read backend call: {:?}",
        backend.calls
    );
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn mouse_at(x: u16, y: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: x,
        row: y,
        modifiers: KeyModifiers::NONE,
    }
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

fn text_position(terminal: &Terminal<TestBackend>, text: &str) -> Option<(u16, u16)> {
    let buffer = terminal.backend().buffer();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        let mut cell_columns = Vec::with_capacity(usize::from(buffer.area.width));
        for x in 0..buffer.area.width {
            cell_columns.push(line.len());
            line.push_str(buffer[(x, y)].symbol());
        }
        if let Some(byte_column) = line.find(text) {
            let cell_column = cell_columns
                .iter()
                .position(|column| *column == byte_column)?;
            return Some((
                buffer
                    .area
                    .x
                    .saturating_add(cell_column as u16)
                    .saturating_add(1),
                buffer.area.y.saturating_add(y),
            ));
        }
    }
    None
}

fn click_text(
    dashboard: &mut Dashboard,
    backend: &mut FakeBackend,
    terminal: &Terminal<TestBackend>,
    text: &str,
) {
    let (x, y) = text_position(terminal, text).unwrap_or_else(|| {
        panic!(
            "expected visible label {text:?} in screen:\n{}",
            buffer_text(terminal)
        )
    });
    assert!(dashboard.handle_mouse(mouse_at(x, y), backend));
}

fn dashboard_with(workspaces: Vec<LocalWorkspaceSummary>) -> (Dashboard, FakeBackend) {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend {
        workspaces,
        ..FakeBackend::default()
    };
    dashboard.refresh(&mut backend);
    (dashboard, backend)
}

#[test]
fn selection_rebinds_panel_header_and_open_tab_rows_to_the_new_workspace() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend {
        workspaces: vec![workspace(1, "Alpha"), workspace(2, "Beta")],
        ..FakeBackend::default()
    };
    dashboard.refresh(&mut backend);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(buffer_text(&terminal).contains("Alpha terminal"));

    assert!(dashboard.dispatch_key(key(KeyCode::Down), &mut backend));
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let rendered = buffer_text(&terminal);

    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(2)
    );
    assert!(rendered.contains("Beta terminal"));
    assert!(!rendered.contains("Alpha terminal"));
    assert_eq!(backend.inspect_ids, vec![workspace_id(1), workspace_id(2)]);
    assert_eq!(backend.details_ids, vec![workspace_id(1), workspace_id(2)]);
    assert_backend_reads_only(&backend);
}

#[test]
fn logs_tab_click_shows_host_wide_diagnostics_without_workspace_scoping() {
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    click_text(&mut dashboard, &mut backend, &terminal, "Logs");
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let rendered = buffer_text(&terminal);

    assert_eq!(
        dashboard.workspace_panel.active_tab(),
        super::workspace_panel::WorkspaceTab::Logs
    );
    assert_eq!(backend.log_reads, 1);
    assert!(rendered.contains("Host diagnostics"));
    assert!(rendered.contains("All workspaces · host-wide events"));
    assert_backend_reads_only(&backend);
}

#[test]
fn keyboard_arrows_move_between_panel_tabs_without_workspace_mutations() {
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);

    // From the sidebar, the first right arrow enters the panel tab strip.
    dashboard.dispatch_key(key(KeyCode::Right), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Right), &mut backend);
    assert_eq!(
        dashboard.workspace_panel.active_tab(),
        super::workspace_panel::WorkspaceTab::Logs
    );
    dashboard.dispatch_key(key(KeyCode::Right), &mut backend);
    assert_eq!(
        dashboard.workspace_panel.active_tab(),
        super::workspace_panel::WorkspaceTab::Settings
    );
    dashboard.dispatch_key(key(KeyCode::Left), &mut backend);
    assert_eq!(
        dashboard.workspace_panel.active_tab(),
        super::workspace_panel::WorkspaceTab::Logs
    );

    assert_eq!(backend.log_reads, 1);
    assert_eq!(backend.inspect_ids, vec![workspace_id(1)]);
    assert_backend_reads_only(&backend);
}

#[test]
fn settings_rename_and_remove_open_existing_cancelable_flows_without_writes() {
    for (action, expected_text) in [
        ("Rename workspace", "New workspace name:"),
        ("Remove workspace", "Remove workspace registration"),
    ] {
        let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| dashboard.draw(frame)).unwrap();
        click_text(&mut dashboard, &mut backend, &terminal, "Settings");
        terminal.draw(|frame| dashboard.draw(frame)).unwrap();
        click_text(&mut dashboard, &mut backend, &terminal, action);
        terminal.draw(|frame| dashboard.draw(frame)).unwrap();

        assert!(dashboard.operations.active());
        assert!(buffer_text(&terminal).contains(expected_text));
        assert!(dashboard.dispatch_key(key(KeyCode::Esc), &mut backend));
        assert_backend_reads_only(&backend);
    }
}

#[test]
fn mismatched_inspect_response_is_cleared_and_empty_tabs_do_not_open_a_shell() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend {
        workspaces: vec![workspace(1, "Alpha")],
        mismatched_inspect_id: Some(workspace_id(2)),
        ..FakeBackend::default()
    };
    dashboard.refresh(&mut backend);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let rendered = buffer_text(&terminal);
    assert!(rendered.contains("Terminal tab state"));
    assert!(rendered.contains("unavailable."));
    assert!(!rendered.contains("Beta terminal"));

    let (mut empty, mut empty_backend) = dashboard_with(vec![workspace(3, "Empty")]);
    empty.dispatch_key(key(KeyCode::Right), &mut empty_backend);
    empty.dispatch_key(key(KeyCode::Enter), &mut empty_backend);
    empty.dispatch_key(key(KeyCode::Enter), &mut empty_backend);
    assert!(!empty.operations.active());
    assert_eq!(
        empty.workspace_panel.active_tab(),
        super::workspace_panel::WorkspaceTab::OpenTabs
    );
    assert_backend_reads_only(&backend);
    assert_backend_reads_only(&empty_backend);
}

#[test]
fn clearing_search_rebinds_beta_before_settings_rename_targets_it() {
    let (mut dashboard, mut backend) =
        dashboard_with(vec![workspace(1, "Alpha"), workspace(2, "Beta")]);
    dashboard.dispatch_key(key(KeyCode::Char('/')), &mut backend);
    for character in "Beta".chars() {
        dashboard.dispatch_key(key(KeyCode::Char(character)), &mut backend);
    }
    dashboard.dispatch_key(key(KeyCode::Esc), &mut backend);
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(2)
    );

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(buffer_text(&terminal).contains("Beta terminal"));
    click_text(&mut dashboard, &mut backend, &terminal, "Settings");
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    click_text(&mut dashboard, &mut backend, &terminal, "Rename workspace");
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(buffer_text(&terminal).contains("New workspace name:"));
    assert_eq!(backend.inspect_ids.last(), Some(&workspace_id(2)));
    assert_eq!(backend.details_ids.last(), Some(&workspace_id(2)));

    // Enter advances the draft to its explicit confirmation. It must still be
    // read-only until the user separately confirms that dialog.
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(buffer_text(&terminal).contains("Rename workspace from Beta to Beta?"));
    assert!(
        !backend
            .calls
            .iter()
            .any(|call| matches!(call, LocalCall::WorkspaceRename(_)))
    );
    dashboard.dispatch_key(key(KeyCode::Esc), &mut backend);
    assert!(
        !backend
            .calls
            .iter()
            .any(|call| matches!(call, LocalCall::WorkspaceRename(_)))
    );
}

#[test]
fn clearing_unmatched_search_rebinds_the_restored_workspace_panel() {
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);

    dashboard.dispatch_key(key(KeyCode::Char('/')), &mut backend);
    for character in "zzz".chars() {
        dashboard.dispatch_key(key(KeyCode::Char(character)), &mut backend);
    }
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    assert!(dashboard.selected_workspace().is_none());

    dashboard.dispatch_key(key(KeyCode::Esc), &mut backend);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(1)
    );
    assert!(buffer_text(&terminal).contains("Alpha terminal"));
    assert_eq!(backend.inspect_ids, vec![workspace_id(1), workspace_id(1)]);
    assert_backend_reads_only(&backend);
}

#[test]
fn exiting_operations_with_escape_refreshes_current_terminal_rows() {
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);
    dashboard.dispatch_key(key(KeyCode::Char('k')), &mut backend);
    assert!(dashboard.operations.active());

    let mut updated_tabs = tabs_for(workspace_id(1));
    updated_tabs[0].name = DisplayText::try_from("Updated terminal".to_owned()).unwrap();
    backend.workspace_tabs_override = Some(updated_tabs);

    assert!(dashboard.dispatch_key(key(KeyCode::Esc), &mut backend));
    assert!(!dashboard.operations.active());
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    let rendered = buffer_text(&terminal);
    assert!(rendered.contains("Updated terminal"));
    assert!(!rendered.contains("Alpha terminal"));
    assert_eq!(backend.inspect_ids, vec![workspace_id(1), workspace_id(1)]);
    assert_eq!(backend.log_reads, 1);
    assert_backend_reads_only(&backend);
}

#[test]
fn exiting_operations_with_mouse_back_refreshes_current_terminal_rows() {
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);
    dashboard.dispatch_key(key(KeyCode::Char('k')), &mut backend);
    assert!(dashboard.operations.active());

    let mut updated_tabs = tabs_for(workspace_id(1));
    updated_tabs[0].name = DisplayText::try_from("Updated terminal".to_owned()).unwrap();
    backend.workspace_tabs_override = Some(updated_tabs);

    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    click_text(&mut dashboard, &mut backend, &terminal, "Back");
    assert!(!dashboard.operations.active());
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    let rendered = buffer_text(&terminal);
    assert!(rendered.contains("Updated terminal"));
    assert!(!rendered.contains("Alpha terminal"));
    assert_eq!(backend.inspect_ids, vec![workspace_id(1), workspace_id(1)]);
    assert_eq!(backend.log_reads, 1);
    assert_backend_reads_only(&backend);
}

#[test]
fn shortcuts_navigation_hint_scrolls_without_closing_on_mouse_click() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::default();
    let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
    dashboard.dispatch_key(key(KeyCode::Char('?')), &mut backend);
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    click_text(&mut dashboard, &mut backend, &terminal, "Navigate");

    assert!(dashboard.help);
    assert!(dashboard.help_scroll > 0);
    assert!(!dashboard.quit_requested);
    assert!(backend.calls.is_empty());
}

#[test]
fn shortcuts_navigation_hint_scrolls_without_closing_on_enter() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::default();
    let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
    dashboard.dispatch_key(key(KeyCode::Char('?')), &mut backend);
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();

    let navigate_action = Action::Key(key(KeyCode::Down));
    for _ in 0..40 {
        if dashboard.controls.focused() == Some(navigate_action) {
            break;
        }
        dashboard.dispatch_key(key(KeyCode::Tab), &mut backend);
    }
    assert_eq!(dashboard.controls.focused(), Some(navigate_action));
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);

    assert!(dashboard.help);
    assert!(dashboard.help_scroll > 0);
    assert!(!dashboard.quit_requested);
    assert!(backend.calls.is_empty());
}

#[test]
fn successful_add_cancel_share_binds_new_workspace_for_settings_actions() {
    let fixture = TempDirectory::new();
    let selected_path = fixture.0.canonicalize().unwrap();
    let expected_name = LocalProjectName::try_from("New project".to_owned()).unwrap();
    let expected_path =
        LocalRootPath::try_from(selected_path.to_str().unwrap().to_owned()).unwrap();
    let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Existing")]);
    dashboard.dispatch_key(key(KeyCode::Char('a')), &mut backend);
    for character in "  New project  ".chars() {
        dashboard.dispatch_key(key(KeyCode::Char(character)), &mut backend);
    }
    dashboard.workspace_form.as_mut().unwrap().directory = Some(selected_path.clone());
    dashboard.dispatch_key(key(KeyCode::Tab), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Tab), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);

    assert!(backend.calls.iter().any(|call| matches!(
        call,
        LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name,
            root_path,
            operator_intent: Confirmed::Confirmed,
        }) if name == &expected_name && root_path == &expected_path
    )));
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(3)
    );
    assert!(dashboard.sharing_confirmation.is_some());
    assert!(
        !dashboard
            .sharing_confirmation
            .as_ref()
            .unwrap()
            .confirm_selected
    );
    assert!(
        !backend
            .calls
            .iter()
            .any(|call| matches!(call, LocalCall::Share(_) | LocalCall::Unshare(_)))
    );
    assert_eq!(backend.inspect_ids.last(), Some(&workspace_id(3)));
    assert_eq!(backend.details_ids.last(), Some(&workspace_id(3)));

    // The default action cancels sharing and reveals the already-bound panel.
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    assert!(dashboard.sharing_confirmation.is_none());
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    assert!(buffer_text(&terminal).contains("New project"));
    click_text(&mut dashboard, &mut backend, &terminal, "Settings");
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    click_text(&mut dashboard, &mut backend, &terminal, "Rename workspace");

    assert!(dashboard.operations.active());
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(3)
    );
    assert_eq!(backend.inspect_ids.last(), Some(&workspace_id(3)));
    assert_eq!(backend.details_ids.last(), Some(&workspace_id(3)));
    assert!(!backend.calls.iter().any(|call| matches!(
        call,
        LocalCall::WorkspaceRename(_) | LocalCall::Share(_) | LocalCall::Unshare(_)
    )));
}

#[test]
fn narrow_panel_draw_and_non_action_clicks_do_not_hit_through() {
    for (width, height) in [(80, 24), (40, 14)] {
        let (mut dashboard, mut backend) = dashboard_with(vec![workspace(1, "Alpha")]);
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|frame| dashboard.draw(frame)).unwrap();

        let content = dashboard.content_area.get();
        assert!(dashboard.handle_mouse(
            mouse_at(
                content.right().saturating_sub(1),
                content.bottom().saturating_sub(1)
            ),
            &mut backend,
        ));
        assert!(!dashboard.operations.active());
        assert!(dashboard.sharing_confirmation.is_none());
        assert_eq!(
            dashboard.selected_workspace().unwrap().workspace_id,
            workspace_id(1)
        );
        assert_backend_reads_only(&backend);
    }
}
