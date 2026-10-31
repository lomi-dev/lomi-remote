use super::{Backend, Cleanup, Dashboard, RestoreGuard};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use lomi_remote_protocol::ipc::{
    LocalCall, LocalHostName, LocalProjectName, LocalResult, LocalRootPath, LocalSharing,
    LocalStatus, LocalWorkspaceAdd, LocalWorkspaceSummary,
};
use lomi_remote_protocol::rpc::{BoundedList, Confirmed};
use lomi_remote_protocol::{HostId, RuntimeId, WorkspaceId};
use ratatui::{Terminal, backend::TestBackend};
use std::{
    cell::RefCell,
    fs, io,
    path::{Path, PathBuf},
    rc::Rc,
    sync::atomic::{AtomicU64, Ordering},
};

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
enum AddReply {
    Created,
    Error,
    Unexpected,
}

struct FakeBackend {
    calls: Vec<LocalCall>,
    workspaces: Vec<LocalWorkspaceSummary>,
    add_reply: AddReply,
}

impl FakeBackend {
    fn new(workspaces: Vec<LocalWorkspaceSummary>) -> Self {
        Self {
            calls: Vec::new(),
            workspaces,
            add_reply: AddReply::Created,
        }
    }

    fn with_add_reply(mut self, add_reply: AddReply) -> Self {
        self.add_reply = add_reply;
        self
    }
}

impl Backend for FakeBackend {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        self.calls.push(call.clone());
        match call {
            LocalCall::Status {} => Ok(LocalResult::Status(status())),
            LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(
                self.workspaces.clone(),
            ))),
            LocalCall::WorkspaceAdd(add) => match self.add_reply {
                AddReply::Created => {
                    let created = workspace(2, add.name.as_str(), LocalSharing::Disabled);
                    self.workspaces.push(created.clone());
                    Ok(LocalResult::Workspace(created))
                }
                AddReply::Error => Err("test workspace creation error"),
                AddReply::Unexpected => Ok(LocalResult::Status(status())),
            },
            _ => Err("unexpected test request"),
        }
    }
}

struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "lomi-workspace-form-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create temporary workspace fixture");
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn status() -> LocalStatus {
    LocalStatus {
        host_name: LocalHostName::try_from("Test host".to_owned()).unwrap(),
        host_id: HostId::from_bytes([1; 16]).unwrap(),
        runtime_id: RuntimeId::from_bytes([2; 16]).unwrap(),
        sharing: LocalSharing::Disabled,
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

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn type_text(dashboard: &mut Dashboard, backend: &mut FakeBackend, text: &str) {
    for character in text.chars() {
        dashboard.handle_key(key(KeyCode::Char(character)), backend);
    }
}

fn enter_picker(dashboard: &mut Dashboard, backend: &mut FakeBackend) {
    dashboard.handle_key(key(KeyCode::Tab), backend);
    dashboard.handle_key(key(KeyCode::Enter), backend);
    assert!(dashboard.directory_picker.is_some());
}

fn text_position(terminal: &Terminal<TestBackend>, text: &str) -> Option<(u16, u16)> {
    let buffer = terminal.backend().buffer();
    let area = buffer.area;
    (0..area.height).find_map(|row| {
        let start = usize::from(row) * usize::from(area.width);
        let symbols = buffer.content[start..start + usize::from(area.width)]
            .iter()
            .fold(String::new(), |mut line, cell| {
                line.push_str(cell.symbol());
                line
            });
        symbols.find(text).map(|column| {
            (
                area.x.saturating_add(column as u16).saturating_add(1),
                area.y.saturating_add(row),
            )
        })
    })
}

fn mouse_click(column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

#[test]
fn add_opens_a_form_and_question_mark_or_q_are_name_input() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::new(Vec::new());

    assert!(dashboard.handle_key(key(KeyCode::Char('a')), &mut backend));
    assert!(dashboard.handle_key(key(KeyCode::Char('?')), &mut backend));
    assert!(dashboard.handle_key(key(KeyCode::Char('q')), &mut backend));

    let form = dashboard.workspace_form.as_ref().unwrap();
    assert_eq!(form.name, "?q");
    assert!(!dashboard.help);
    assert!(backend.calls.is_empty());
}

#[test]
fn picker_cancel_preserves_form_and_mouse_selection_updates_it_locally() {
    let fixture = TempDir::new();
    let selected = fixture.path().canonicalize().unwrap();
    let child = fixture.path().join("selected-child");
    fs::create_dir(&child).unwrap();
    let child = child.canonicalize().unwrap();
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::new(Vec::new());
    dashboard.handle_key(key(KeyCode::Char('a')), &mut backend);
    type_text(&mut dashboard, &mut backend, "Draft name");
    dashboard.workspace_form.as_mut().unwrap().directory = Some(selected.clone());

    enter_picker(&mut dashboard, &mut backend);
    dashboard.handle_key(key(KeyCode::Esc), &mut backend);

    let form = dashboard.workspace_form.as_ref().unwrap();
    assert_eq!(form.name, "Draft name");
    assert_eq!(form.directory.as_deref(), Some(selected.as_path()));
    assert!(dashboard.directory_picker.is_none());
    assert!(backend.calls.is_empty());

    dashboard.handle_key(key(KeyCode::Enter), &mut backend);
    dashboard.handle_key(key(KeyCode::Right), &mut backend);
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let (column, row) = text_position(&terminal, "Select this directory").unwrap();
    assert!(dashboard.handle_mouse(mouse_click(column, row), &mut backend));

    let form = dashboard.workspace_form.as_ref().unwrap();
    assert_eq!(form.name, "Draft name");
    assert_eq!(form.directory.as_deref(), Some(child.as_path()));
    assert!(dashboard.directory_picker.is_none());
    assert!(backend.calls.is_empty());
}

#[test]
fn invalid_or_unconfirmed_add_stays_inline_without_losing_form_data() {
    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::new(Vec::new());
    dashboard.handle_key(key(KeyCode::Char('a')), &mut backend);
    type_text(&mut dashboard, &mut backend, "Needs a directory");
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Enter), &mut backend);

    let form = dashboard.workspace_form.as_ref().unwrap();
    assert_eq!(form.name, "Needs a directory");
    assert!(form.directory.is_none());
    assert_eq!(form.error, Some("Select a directory for this workspace."));
    assert!(dashboard.sharing_confirmation.is_none());
    assert!(backend.calls.is_empty());

    let fixture = TempDir::new();
    let selected = fixture.path().canonicalize().unwrap();
    for reply in [AddReply::Error, AddReply::Unexpected] {
        let mut dashboard = Dashboard::default();
        let mut backend = FakeBackend::new(Vec::new()).with_add_reply(reply);
        dashboard.handle_key(key(KeyCode::Char('a')), &mut backend);
        type_text(&mut dashboard, &mut backend, "Retry me");
        dashboard.workspace_form.as_mut().unwrap().directory = Some(selected.clone());
        dashboard.handle_key(key(KeyCode::Tab), &mut backend);
        dashboard.handle_key(key(KeyCode::Tab), &mut backend);
        dashboard.handle_key(key(KeyCode::Enter), &mut backend);

        let form = dashboard.workspace_form.as_ref().unwrap();
        assert_eq!(form.name, "Retry me");
        assert_eq!(form.directory.as_deref(), Some(selected.as_path()));
        assert_eq!(
            form.error,
            Some("Creation was not confirmed. Refresh before retrying.")
        );
        assert!(dashboard.sharing_confirmation.is_none());
        assert_eq!(backend.calls.len(), 1);
        assert!(matches!(&backend.calls[0], LocalCall::WorkspaceAdd(_)));
    }
}

#[test]
fn submit_sends_exact_local_add_and_opens_separate_default_cancel_confirmation() {
    let fixture = TempDir::new();
    let selected = fixture.path().canonicalize().unwrap();
    let existing = workspace(1, "Existing", LocalSharing::Disabled);
    let mut dashboard = Dashboard {
        workspaces: vec![existing.clone()],
        ..Dashboard::default()
    };
    let mut backend = FakeBackend::new(vec![existing]);
    dashboard.handle_key(key(KeyCode::Char('a')), &mut backend);
    type_text(&mut dashboard, &mut backend, "  New project  ");
    dashboard.workspace_form.as_mut().unwrap().directory = Some(selected.clone());
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Enter), &mut backend);

    let expected_name = LocalProjectName::try_from("New project".to_owned()).unwrap();
    let expected_path = LocalRootPath::try_from(selected.to_str().unwrap().to_owned()).unwrap();
    assert!(matches!(
        backend.calls.first(),
        Some(LocalCall::WorkspaceAdd(LocalWorkspaceAdd {
            name,
            root_path,
            operator_intent: Confirmed::Confirmed,
        })) if name == &expected_name && root_path == &expected_path
    ));
    assert_eq!(backend.calls[1], LocalCall::Status {});
    assert_eq!(backend.calls[2], LocalCall::Workspaces {});
    assert_eq!(backend.calls.len(), 7);
    assert!(backend.calls[3..].iter().all(|call| matches!(
        call,
        LocalCall::WorkspaceInspect(_) | LocalCall::WorkspaceDetails(_)
    )));
    assert!(dashboard.workspace_form.is_none());
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        workspace_id(2)
    );
    let confirmation = dashboard.sharing_confirmation.as_ref().unwrap();
    assert!(confirmation.share);
    assert!(!confirmation.confirm_selected);
    assert!(
        !backend
            .calls
            .iter()
            .any(|call| matches!(call, LocalCall::Share(_) | LocalCall::Unshare(_)))
    );
}

#[cfg(unix)]
#[test]
fn replacing_selected_directory_with_symlink_prevents_workspace_add() {
    use std::os::unix::fs::symlink;

    let fixture = TempDir::new();
    let selected = fixture.path().join("selected");
    let replacement = fixture.path().join("replacement");
    fs::create_dir(&selected).unwrap();
    fs::create_dir(&replacement).unwrap();
    let selected = selected.canonicalize().unwrap();
    let moved = fixture.path().join("moved-selected");

    let mut dashboard = Dashboard::default();
    let mut backend = FakeBackend::new(Vec::new());
    dashboard.handle_key(key(KeyCode::Char('a')), &mut backend);
    type_text(&mut dashboard, &mut backend, "Stable target");
    dashboard.workspace_form.as_mut().unwrap().directory = Some(selected.clone());
    fs::rename(&selected, &moved).unwrap();
    symlink(&replacement, &selected).unwrap();
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Tab), &mut backend);
    dashboard.handle_key(key(KeyCode::Enter), &mut backend);

    let form = dashboard.workspace_form.as_ref().unwrap();
    assert_eq!(form.name, "Stable target");
    assert_eq!(form.directory.as_deref(), Some(selected.as_path()));
    assert_eq!(
        form.error,
        Some("The selected directory changed or is unavailable. Select it again.")
    );
    assert!(dashboard.sharing_confirmation.is_none());
    assert!(backend.calls.is_empty());
}

struct RecordingCleanup {
    calls: Rc<RefCell<Vec<&'static str>>>,
    fail_at: usize,
    next: usize,
}

impl RecordingCleanup {
    fn record(&mut self, name: &'static str) -> io::Result<()> {
        let index = self.next;
        self.next += 1;
        self.calls.borrow_mut().push(name);
        if index == self.fail_at {
            Err(io::Error::other("injected cleanup failure"))
        } else {
            Ok(())
        }
    }
}

impl Cleanup for RecordingCleanup {
    fn mouse_capture(&mut self) -> io::Result<()> {
        self.record("mouse")
    }

    fn bracketed_paste(&mut self) -> io::Result<()> {
        self.record("paste")
    }

    fn raw(&mut self) -> io::Result<()> {
        self.record("raw")
    }

    fn alternate(&mut self) -> io::Result<()> {
        self.record("alternate")
    }

    fn cursor(&mut self) -> io::Result<()> {
        self.record("cursor")
    }
}

#[test]
fn restore_guard_attempts_every_cleanup_even_when_each_step_fails() {
    for fail_at in 0..5 {
        let calls = Rc::new(RefCell::new(Vec::new()));
        {
            let _guard = RestoreGuard(RecordingCleanup {
                calls: Rc::clone(&calls),
                fail_at,
                next: 0,
            });
        }
        assert_eq!(
            calls.borrow().as_slice(),
            &["mouse", "paste", "raw", "alternate", "cursor"]
        );
    }
}
