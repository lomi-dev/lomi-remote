use super::{Backend, Dashboard};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use lomi_remote_protocol::ipc::{
    LocalCall, LocalHostName, LocalProjectName, LocalResult, LocalSharing, LocalStatus,
    LocalWorkspaceSummary, LocalWorkspaceTarget,
};
use lomi_remote_protocol::rpc::{BoundedList, Confirmed};
use lomi_remote_protocol::{HostId, RuntimeId, WorkspaceId};
use ratatui::{Terminal, backend::TestBackend};

#[derive(Clone, Copy)]
enum SharingReply {
    Correct,
    Error,
    WrongWorkspace,
}

struct FakeBackend {
    workspaces: Vec<LocalWorkspaceSummary>,
    calls: Vec<LocalCall>,
    sharing_reply: SharingReply,
}

impl FakeBackend {
    fn new(workspaces: Vec<LocalWorkspaceSummary>) -> Self {
        Self {
            workspaces,
            calls: Vec::new(),
            sharing_reply: SharingReply::Correct,
        }
    }

    fn with_reply(mut self, reply: SharingReply) -> Self {
        self.sharing_reply = reply;
        self
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
            LocalCall::Share(target) => self.change_sharing(target, LocalSharing::Enabled),
            LocalCall::Unshare(target) => self.change_sharing(target, LocalSharing::Disabled),
            _ => Err("unexpected test request"),
        }
    }
}

impl FakeBackend {
    fn change_sharing(
        &mut self,
        target: LocalWorkspaceTarget,
        sharing: LocalSharing,
    ) -> Result<LocalResult, &'static str> {
        let Some(index) = self
            .workspaces
            .iter()
            .position(|workspace| workspace.workspace_id == target.workspace_id)
        else {
            return Err("unknown workspace");
        };
        match self.sharing_reply {
            SharingReply::Correct => {
                self.workspaces[index].sharing = sharing;
                Ok(LocalResult::Workspace(self.workspaces[index].clone()))
            }
            SharingReply::Error => Err("sharing request failed"),
            SharingReply::WrongWorkspace => {
                self.workspaces[index].sharing = sharing;
                let mut reply = self.workspaces[index].clone();
                reply.workspace_id = workspace_id(90);
                Ok(LocalResult::Workspace(reply))
            }
        }
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

fn dashboard_with_selection(selected: usize) -> Dashboard {
    Dashboard {
        workspaces: vec![
            workspace(1, "local", LocalSharing::Disabled),
            workspace(2, "shared", LocalSharing::Enabled),
        ],
        selected,
        ..Dashboard::default()
    }
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

#[test]
fn s_opens_the_inverse_sharing_confirmation_without_a_request() {
    for (selected, should_share) in [(0, true), (1, false)] {
        let mut dashboard = dashboard_with_selection(selected);
        let mut backend = FakeBackend::new(dashboard.workspaces.clone());
        let selected_id = dashboard.selected_workspace().unwrap().workspace_id;

        assert!(dashboard.handle_key(key(KeyCode::Char('s')), &mut backend));

        let confirmation = dashboard.sharing_confirmation.as_ref().unwrap();
        assert_eq!(confirmation.workspace_id, selected_id);
        assert_eq!(confirmation.share, should_share);
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn confirmation_blocks_dashboard_keys_and_paste_then_cancel_is_read_only() {
    let mut dashboard = dashboard_with_selection(0);
    let mut backend = FakeBackend::new(dashboard.workspaces.clone());
    let selected_id = dashboard.selected_workspace().unwrap().workspace_id;
    dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);

    for code in [
        KeyCode::Char('a'),
        KeyCode::Char('p'),
        KeyCode::Char('q'),
        KeyCode::Char('?'),
        KeyCode::Up,
        KeyCode::Down,
        KeyCode::Left,
        KeyCode::Right,
    ] {
        assert!(dashboard.handle_key(key(code), &mut backend));
    }
    assert!(!dashboard.handle_paste("pasted text"));
    assert!(!dashboard.help);
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        selected_id
    );
    assert!(backend.calls.is_empty());

    dashboard.handle_key(key(KeyCode::Esc), &mut backend);
    assert!(dashboard.sharing_confirmation.is_none());

    for cancel in [KeyCode::Enter, KeyCode::Char('n'), KeyCode::Esc] {
        dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);
        assert!(
            !dashboard
                .sharing_confirmation
                .as_ref()
                .unwrap()
                .confirm_selected
        );
        dashboard.handle_key(key(cancel), &mut backend);
        assert!(dashboard.sharing_confirmation.is_none());
        assert!(backend.calls.is_empty());
    }
}

#[test]
fn y_shares_the_captured_workspace_and_refreshes_dashboard_state() {
    let mut dashboard = dashboard_with_selection(1);
    dashboard.workspaces[1].sharing = LocalSharing::Disabled;
    let selected_id = dashboard.selected_workspace().unwrap().workspace_id;
    let mut backend = FakeBackend::new(dashboard.workspaces.clone());
    dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);
    dashboard.handle_key(key(KeyCode::Char('y')), &mut backend);

    assert!(matches!(
        backend.calls.first(),
        Some(LocalCall::Share(LocalWorkspaceTarget {
            workspace_id,
            operator_intent: Confirmed::Confirmed,
        })) if *workspace_id == selected_id
    ));
    assert_eq!(backend.calls[1], LocalCall::Status {});
    assert_eq!(backend.calls[2], LocalCall::Workspaces {});
    assert!(dashboard.sharing_confirmation.is_none());
    assert_eq!(
        dashboard.selected_workspace().unwrap().workspace_id,
        selected_id
    );
    assert_eq!(
        dashboard.selected_workspace().unwrap().sharing,
        LocalSharing::Enabled
    );
    assert!(dashboard.message.is_none());

    let mut terminal = Terminal::new(TestBackend::new(100, 20)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    let rendered =
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .fold(String::new(), |mut text, cell| {
                text.push_str(cell.symbol());
                text
            });
    assert!(rendered.contains("Unshare"));
    assert!(rendered.contains("Sharing enabled"));
}

#[test]
fn tab_and_right_then_enter_confirms_unshare() {
    for select_confirm in [KeyCode::Tab, KeyCode::Right] {
        let mut dashboard = dashboard_with_selection(1);
        let selected_id = dashboard.selected_workspace().unwrap().workspace_id;
        let mut backend = FakeBackend::new(dashboard.workspaces.clone());
        dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);
        dashboard.handle_key(key(select_confirm), &mut backend);
        dashboard.handle_key(key(KeyCode::Enter), &mut backend);

        assert!(matches!(
            backend.calls.first(),
            Some(LocalCall::Unshare(LocalWorkspaceTarget {
                workspace_id,
                operator_intent: Confirmed::Confirmed,
            })) if *workspace_id == selected_id
        ));
        assert_eq!(
            dashboard.selected_workspace().unwrap().sharing,
            LocalSharing::Disabled
        );
        assert!(dashboard.message.is_none());
    }
}

#[test]
fn failed_or_mismatched_reply_is_not_reported_as_confirmed() {
    for reply in [SharingReply::Error, SharingReply::WrongWorkspace] {
        let mut dashboard = dashboard_with_selection(0);
        let mut backend = FakeBackend::new(dashboard.workspaces.clone()).with_reply(reply);
        dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);
        dashboard.handle_key(key(KeyCode::Char('y')), &mut backend);

        assert_eq!(
            dashboard.message,
            Some("Sharing change was not confirmed. Refresh to verify the current state.")
        );
        assert_eq!(backend.calls.len(), 5);
        assert!(backend.calls[3..].iter().all(|call| matches!(
            call,
            LocalCall::WorkspaceInspect(_) | LocalCall::WorkspaceDetails(_)
        )));
    }
}

#[test]
fn sharing_confirmation_renders_at_tiny_sizes() {
    let mut dashboard = dashboard_with_selection(0);
    let mut backend = FakeBackend::new(dashboard.workspaces.clone());
    dashboard.handle_key(key(KeyCode::Char('s')), &mut backend);
    let mut terminal = Terminal::new(TestBackend::new(1, 1)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
    terminal.backend_mut().resize(2, 2);
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
}
