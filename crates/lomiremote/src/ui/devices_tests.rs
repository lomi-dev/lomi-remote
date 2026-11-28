use super::{Backend, Dashboard};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use lomi_remote_protocol::{
    DecimalU64,
    ipc::{
        LocalCall, LocalDeviceApproval, LocalDeviceGrant, LocalDeviceLevel, LocalDeviceMode,
        LocalDeviceNotice, LocalDeviceNoticeKind, LocalDeviceReason, LocalDeviceText, LocalDevices,
        LocalResult,
    },
    rpc::BoundedList,
};
use ratatui::{Terminal, backend::TestBackend};

fn text(s: &str) -> LocalDeviceText {
    LocalDeviceText::try_from(s.to_owned()).unwrap()
}
fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

struct Fake {
    calls: Vec<LocalCall>,
    pending: Vec<LocalDeviceApproval>,
    grants: Vec<LocalDeviceGrant>,
    notices: Vec<LocalDeviceNotice>,
}
impl Fake {
    fn state(&self) -> LocalResult {
        LocalResult::Devices(LocalDevices {
            mode: LocalDeviceMode::Confirm,
            grants: BoundedList(self.grants.clone()),
            pending: BoundedList(self.pending.clone()),
        })
    }
}
impl Backend for Fake {
    fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
        self.calls.push(call.clone());
        match call {
            LocalCall::DevicesNotices {} => Ok(LocalResult::DeviceNotices(BoundedList(
                std::mem::take(&mut self.notices),
            ))),
            LocalCall::DevicesList {} => Ok(self.state()),
            LocalCall::DevicesApprove(_) | LocalCall::DevicesDeny(_) => {
                self.pending.clear();
                Ok(self.state())
            }
            LocalCall::DevicesRevoke(_) => {
                self.grants.clear();
                Ok(self.state())
            }
            _ => Err("unexpected"),
        }
    }
}

fn screen(dashboard: &Dashboard) -> String {
    let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
    terminal.draw(|frame| dashboard.draw(frame)).unwrap();
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
fn the_owner_types_the_device_code_to_approve_and_the_screen_revokes() {
    let mut backend = Fake {
        calls: Vec::new(),
        pending: vec![LocalDeviceApproval {
            circuit: text(&"11".repeat(16)),
            device_name: text("Phone"),
            fingerprint: text(&"ab".repeat(32)),
            reason: LocalDeviceReason::NewDevice,
            at: DecimalU64(1),
        }],
        grants: vec![LocalDeviceGrant {
            name: text("Laptop"),
            kind: text("web"),
            fingerprint: text(&"cd".repeat(32)),
            level: LocalDeviceLevel::Read,
            granted_at: DecimalU64(1),
            server_confirmed_at: DecimalU64(1),
            valid: true,
        }],
        notices: vec![LocalDeviceNotice {
            kind: LocalDeviceNoticeKind::NewDevice,
            device_name: text("Phone"),
        }],
    };
    let mut dashboard = Dashboard::default();
    assert!(dashboard.poll_devices(&mut backend));
    let first_row = screen(&dashboard).lines().next().unwrap().to_owned();
    assert!(
        !first_row.contains("123456") && first_row.contains("Phone"),
        "{first_row}"
    );

    assert!(dashboard.dispatch_key(key(KeyCode::Char('i')), &mut backend));
    let open = screen(&dashboard);
    assert!(
        open.contains("Devices") && open.contains("Waiting for approval"),
        "{open}"
    );
    assert!(
        !open.contains("123456") && open.contains("Laptop"),
        "{open}"
    );

    // `a` on a selected row asks for the device's code; Enter alone approves nothing
    dashboard.dispatch_key(key(KeyCode::Char('a')), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    for c in "12345".chars() {
        dashboard.dispatch_key(key(KeyCode::Char(c)), &mut backend);
    }
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    assert!(
        !backend
            .calls
            .iter()
            .any(|c| matches!(c, LocalCall::DevicesApprove(_))),
        "five digits are not a code"
    );
    dashboard.dispatch_key(key(KeyCode::Char('6')), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Enter), &mut backend);
    assert!(
        matches!(backend.calls.last(), Some(LocalCall::DevicesApprove(t)) if t.code.as_str() == "123456")
    );
    assert!(
        dashboard.devices.banner().is_some(),
        "the notice stays until the screen closes"
    );

    // the only row left is the grant; revoke asks first
    dashboard.dispatch_key(key(KeyCode::Char('v')), &mut backend);
    assert!(screen(&dashboard).contains("Revoke Laptop?"));
    dashboard.dispatch_key(key(KeyCode::Char('n')), &mut backend);
    assert!(
        !backend
            .calls
            .iter()
            .any(|c| matches!(c, LocalCall::DevicesRevoke(_)))
    );
    dashboard.dispatch_key(key(KeyCode::Char('v')), &mut backend);
    dashboard.dispatch_key(key(KeyCode::Char('y')), &mut backend);
    assert!(
        matches!(backend.calls.last(), Some(LocalCall::DevicesRevoke(r)) if r.fingerprint.as_str() == "cd".repeat(32))
    );
    assert!(backend.grants.is_empty());

    dashboard.dispatch_key(key(KeyCode::Esc), &mut backend);
    assert!(dashboard.devices.banner().is_none());
}
