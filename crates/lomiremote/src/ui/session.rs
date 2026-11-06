//! Route all foreground input through the authentication screen until ready.

use super::{
    AuthSetupStep, Backend, Dashboard, interaction::Action, shortcuts, sign_in::SignIn, theme,
};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::Style,
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};
use std::cell::Cell;

pub(super) struct Session {
    sign_in: SignIn,
    dashboard: Dashboard,
    authenticated: bool,
    configuration_scroll: usize,
    configuration_max_scroll: Cell<usize>,
    configuration_body: Cell<Rect>,
    pub(super) quit_requested: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::{
        DecimalU64, HostId, RuntimeId,
        ipc::{
            LocalAuthNetwork, LocalAuthPhase, LocalAuthStorage, LocalCall, LocalHostName,
            LocalLoginStatus, LocalResult, LocalSharing, LocalStatus,
        },
        rpc::BoundedList,
    };
    use ratatui::{Terminal, backend::TestBackend};
    use std::sync::mpsc::{self, Receiver, SyncSender};

    struct FakeBackend {
        phase: Option<LocalAuthPhase>,
        locked: bool,
        pending_revoke: bool,
        calls: Vec<LocalCall>,
        block_async: bool,
        async_calls: Vec<LocalCall>,
        async_senders: Vec<SyncSender<Result<LocalResult, &'static str>>>,
    }

    impl FakeBackend {
        fn new(phase: LocalAuthPhase) -> Self {
            Self {
                phase: Some(phase),
                locked: false,
                pending_revoke: false,
                calls: Vec::new(),
                block_async: false,
                async_calls: Vec::new(),
                async_senders: Vec::new(),
            }
        }
    }

    impl Backend for FakeBackend {
        fn request_async(
            &mut self,
            call: LocalCall,
        ) -> Result<Receiver<Result<LocalResult, &'static str>>, &'static str> {
            self.async_calls.push(call.clone());
            if self.block_async {
                let (sender, receiver) = mpsc::sync_channel(1);
                self.async_senders.push(sender);
                Ok(receiver)
            } else {
                let result = self.request(call);
                let (sender, receiver) = mpsc::sync_channel(1);
                let _ = sender.send(result);
                Ok(receiver)
            }
        }

        fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
            self.calls.push(call.clone());
            match call {
                LocalCall::LoginStatus {} => Ok(LocalResult::LoginStatus(LocalLoginStatus {
                    phase: self.phase.ok_or("HOST_UNAVAILABLE")?,
                    storage: LocalAuthStorage::Available,
                    network: LocalAuthNetwork::Available,
                    generation: DecimalU64(1),
                    locked: self.locked,
                    pending_cloud_revoke: self.pending_revoke,
                    operation_id: None,
                    access_expires_at: None,
                    refresh_at: None,
                })),
                LocalCall::Status {} => Ok(LocalResult::Status(LocalStatus {
                    host_name: LocalHostName::try_from("Test host".to_owned()).unwrap(),
                    host_id: HostId::from_bytes([1; 16]).unwrap(),
                    runtime_id: RuntimeId::from_bytes([2; 16]).unwrap(),
                    sharing: LocalSharing::Disabled,
                })),
                LocalCall::Workspaces {} => Ok(LocalResult::Workspaces(BoundedList(Vec::new()))),
                _ => Err("UNEXPECTED_REQUEST"),
            }
        }
    }

    fn frame(session: &Session) -> String {
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal.draw(|frame| session.draw(frame)).unwrap();
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn configuration_consumes_modified_actions_and_requires_visible_content() {
        let mut backend = FakeBackend::new(LocalAuthPhase::Unconfigured);
        let mut session = Session::new(Dashboard::default());
        session.dashboard.auth_setup = Some(super::super::AuthSetupDraft {
            step: AuthSetupStep::ProtectedFileConsent,
            keychain_path: String::new(),
            protected_file_acknowledged: false,
            error: None,
        });
        frame(&session);
        for modifiers in [KeyModifiers::CONTROL, KeyModifiers::ALT] {
            assert!(
                session.dispatch_key(KeyEvent::new(KeyCode::Char('y'), modifiers), &mut backend)
            );
            assert!(
                !session
                    .dashboard
                    .auth_setup
                    .as_ref()
                    .unwrap()
                    .protected_file_acknowledged
            );
        }
        let mut terminal = Terminal::new(TestBackend::new(12, 3)).unwrap();
        terminal.draw(|frame| session.draw(frame)).unwrap();
        session.dispatch_key(
            KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE),
            &mut backend,
        );
        assert!(
            !session
                .dashboard
                .auth_setup
                .as_ref()
                .unwrap()
                .protected_file_acknowledged
        );
        assert!(backend.calls.is_empty());
        session.dispatch_key(
            KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE),
            &mut backend,
        );
        assert!(session.dashboard.auth_setup.is_none());
    }

    #[test]
    fn welcome_is_first_frame_before_any_host_or_workspace_call() {
        let session = Session::new(Dashboard::default());
        let text = frame(&session);
        assert!(text.contains("lomi"));
        assert!(text.contains("Sign in"));
        assert!(!text.contains("No workspaces"));
        assert!(!session.authenticated);
    }

    #[test]
    fn blocked_auth_poll_keeps_event_dispatch_responsive_and_does_not_overlap() {
        let mut backend = FakeBackend::new(LocalAuthPhase::Idle);
        backend.block_async = true;
        let mut session = Session::new(Dashboard::default());

        session.poll(&mut backend);
        assert_eq!(backend.async_calls, [LocalCall::LoginStatus {}]);
        assert!(!session.dispatch_key(
            KeyEvent::new(KeyCode::Char('q'), KeyModifiers::NONE),
            &mut backend
        ));
        session.poll(&mut backend);
        assert_eq!(backend.async_calls, [LocalCall::LoginStatus {}]);
        assert_eq!(backend.async_senders.len(), 1);
    }

    #[test]
    fn queued_sign_in_is_discarded_if_pending_status_returns_ready() {
        let mut backend = FakeBackend::new(LocalAuthPhase::Idle);
        backend.block_async = true;
        let mut session = Session::new(Dashboard::default());
        session.poll(&mut backend);
        assert!(session.dispatch_key(
            KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
            &mut backend
        ));

        backend.async_senders[0]
            .send(Ok(LocalResult::LoginStatus(LocalLoginStatus {
                phase: LocalAuthPhase::Ready,
                storage: LocalAuthStorage::Available,
                network: LocalAuthNetwork::Available,
                generation: DecimalU64(1),
                locked: false,
                pending_cloud_revoke: false,
                operation_id: None,
                access_expires_at: None,
                refresh_at: None,
            })))
            .unwrap();
        session.poll(&mut backend);

        assert!(session.authenticated);
        assert!(
            backend
                .async_calls
                .iter()
                .all(|call| !matches!(call, LocalCall::LoginStart(_)))
        );
    }

    #[test]
    fn unauthenticated_navigation_cannot_reach_dashboard_reads_or_mutations() {
        for phase in [
            LocalAuthPhase::Unconfigured,
            LocalAuthPhase::Idle,
            LocalAuthPhase::Initializing,
            LocalAuthPhase::AwaitingApproval,
            LocalAuthPhase::Exchanging,
            LocalAuthPhase::Registering,
            LocalAuthPhase::Locked,
            LocalAuthPhase::PendingRevoke,
            LocalAuthPhase::Unavailable,
        ] {
            let mut backend = FakeBackend::new(phase);
            let mut session = Session::new(Dashboard::default());
            session.poll(&mut backend);
            frame(&session);
            for code in [
                KeyCode::Char('a'),
                KeyCode::Char('/'),
                KeyCode::Up,
                KeyCode::Down,
                KeyCode::Char('?'),
            ] {
                assert!(
                    session.dispatch_key(KeyEvent::new(code, KeyModifiers::NONE), &mut backend)
                );
            }
            assert!(!session.handle_paste("/private/workspace"));
            assert!(
                backend
                    .calls
                    .iter()
                    .all(|call| matches!(call, LocalCall::LoginStatus {})),
                "{phase:?}: {:?}",
                backend.calls
            );
            assert!(!session.authenticated);
        }
    }

    #[test]
    fn ready_enters_dashboard_once_and_polling_does_not_reload_workspaces() {
        let mut backend = FakeBackend::new(LocalAuthPhase::Idle);
        let mut session = Session::new(Dashboard::default());
        session.poll(&mut backend);
        backend.phase = Some(LocalAuthPhase::Ready);
        assert!(session.poll(&mut backend));
        assert!(session.authenticated);
        assert!(frame(&session).contains("No workspaces"));
        assert_eq!(
            backend
                .calls
                .iter()
                .filter(|call| matches!(call, LocalCall::Workspaces {}))
                .count(),
            1
        );
        backend.calls.clear();
        session.poll(&mut backend);
        assert!(
            backend
                .calls
                .iter()
                .all(|call| matches!(call, LocalCall::LoginStatus {}))
        );
    }

    #[test]
    fn logout_revoke_lock_and_lost_host_drop_dashboard_and_its_overlays() {
        for loss in 0..4 {
            let mut backend = FakeBackend::new(LocalAuthPhase::Ready);
            let mut session = Session::new(Dashboard::default());
            session.poll(&mut backend);
            session.dashboard.help = true;
            session.dashboard.search_query = "private project".to_owned();
            match loss {
                0 => backend.phase = Some(LocalAuthPhase::Idle),
                1 => backend.pending_revoke = true,
                2 => backend.locked = true,
                _ => backend.phase = None,
            }
            backend.calls.clear();
            assert!(session.poll(&mut backend));
            assert!(!session.authenticated);
            assert!(!session.dashboard.help);
            assert!(session.dashboard.search_query.is_empty());
            let text = frame(&session);
            assert!(text.contains("lomi"));
            assert!(!text.contains("private project"));
            assert!(
                backend
                    .calls
                    .iter()
                    .all(|call| matches!(call, LocalCall::LoginStatus {}))
            );
        }
    }
}

impl Session {
    pub(super) fn new(dashboard: Dashboard) -> Self {
        Self {
            sign_in: SignIn::default(),
            dashboard,
            authenticated: false,
            configuration_scroll: 0,
            configuration_max_scroll: Cell::new(0),
            configuration_body: Cell::new(Rect::default()),
            quit_requested: false,
        }
    }

    pub(super) fn poll(&mut self, backend: &mut impl Backend) -> bool {
        let changed = self.sign_in.poll(backend);
        let ready = self.sign_in.ready();
        if ready == self.authenticated {
            return !ready && changed;
        }
        self.authenticated = ready;
        if ready {
            self.dashboard.auth_setup = None;
            self.dashboard.refresh(backend);
        } else {
            // Drop panels, transient codes, confirmations and input targets on
            // logout, revocation, or loss of the authenticated Host connection.
            self.dashboard = Dashboard::default();
        }
        true
    }

    pub(super) fn draw(&self, frame: &mut Frame) {
        if self.authenticated {
            self.dashboard.draw(frame);
        } else {
            self.sign_in.draw(frame);
            if self.dashboard.auth_setup.is_some() {
                self.draw_configuration(frame);
            }
        }
    }

    pub(super) fn dispatch_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> bool {
        if self.authenticated {
            self.dashboard.dispatch_key(key, backend)
        } else if self.dashboard.auth_setup.is_some() {
            self.configuration_key(key, backend)
        } else {
            let keep_running = self.sign_in.handle_key(key, backend);
            self.maybe_configure();
            keep_running
        }
    }

    pub(super) fn handle_mouse(&mut self, event: MouseEvent, backend: &mut impl Backend) -> bool {
        if self.authenticated {
            let changed = self.dashboard.handle_mouse(event, backend);
            self.quit_requested = self.dashboard.quit_requested;
            changed
        } else if self.dashboard.auth_setup.is_some() {
            match event.kind {
                MouseEventKind::ScrollUp => {
                    self.configuration_scroll = self.configuration_scroll.saturating_sub(3)
                }
                MouseEventKind::ScrollDown => {
                    self.configuration_scroll = self
                        .configuration_scroll
                        .saturating_add(3)
                        .min(self.configuration_max_scroll.get())
                }
                _ => {
                    if let Some(Action::Key(key)) = self.dashboard.controls.click(event) {
                        self.dashboard.controls.blur();
                        self.configuration_key(key, backend);
                    }
                }
            }
            true
        } else {
            let changed = self.sign_in.handle_mouse(event, backend);
            self.maybe_configure();
            changed
        }
    }

    pub(super) fn handle_paste(&mut self, text: &str) -> bool {
        (self.authenticated || self.dashboard.auth_setup.is_some())
            && self.dashboard.handle_paste(text)
    }

    pub(super) fn hoverable(&self, column: u16, row: u16) -> bool {
        if self.authenticated {
            self.dashboard.hoverable(column, row)
        } else if self.dashboard.auth_setup.is_some() {
            self.dashboard.controls.hoverable(column, row)
        } else {
            self.sign_in.hoverable(column, row)
        }
    }

    fn maybe_configure(&mut self) {
        if self.sign_in.take_configuration_request() {
            self.dashboard.controls.reset();
            self.configuration_scroll = 0;
            self.dashboard.begin_auth_setup();
            if self.dashboard.auth_setup.is_none() {
                if let Some(message) = self.dashboard.login_message {
                    self.sign_in.configuration_error(message);
                }
            }
        }
    }

    fn configuration_key(&mut self, mut key: KeyEvent, backend: &mut impl Backend) -> bool {
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return false;
        }
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return true;
        }
        let body = self.configuration_body.get();
        if key.code != KeyCode::Esc && (body.width < 20 || body.height < 2) {
            return true;
        }
        match key.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.dashboard.controls.cycle(key.code == KeyCode::BackTab);
                return true;
            }
            KeyCode::PageUp => {
                self.configuration_scroll = self.configuration_scroll.saturating_sub(5);
                return true;
            }
            KeyCode::PageDown => {
                self.configuration_scroll = self
                    .configuration_scroll
                    .saturating_add(5)
                    .min(self.configuration_max_scroll.get());
                return true;
            }
            KeyCode::Enter => {
                if let Some(Action::Key(action)) = self.dashboard.controls.focused() {
                    key = action;
                }
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Up | KeyCode::Down => {
                if key.code == KeyCode::Up
                    && self
                        .dashboard
                        .auth_setup
                        .as_ref()
                        .is_some_and(|draft| draft.step == AuthSetupStep::KeychainPath)
                {
                    self.dashboard.controls.blur();
                } else {
                    self.dashboard.controls.move_focus(key.code);
                }
                return true;
            }
            _ => {}
        }
        self.dashboard.handle_auth_setup_key(key, backend);
        self.configuration_scroll = 0;
        self.dashboard.controls.reset();
        if self.dashboard.auth_setup.is_none() {
            self.sign_in.poll(backend);
        }
        true
    }

    fn draw_configuration(&self, frame: &mut Frame) {
        let Some(draft) = &self.dashboard.auth_setup else {
            return;
        };
        shortcuts::dim_frame(frame);
        self.dashboard.controls.begin();
        let area = frame.area();
        let width = area.width.min(78);
        let height = area.height.min(26);
        let popup = Rect::new(
            area.x + (area.width - width) / 2,
            area.y + (area.height - height) / 2,
            width,
            height,
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BORDER))
            .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
            .title(" Configure sign in ")
            .title_alignment(Alignment::Center);
        let inner = block.inner(popup);
        frame.render_widget(Clear, popup);
        frame.render_widget(block, popup);
        let footer_height = inner.height.min(5);
        let body = Rect::new(
            inner.x,
            inner.y,
            inner.width,
            inner.height.saturating_sub(footer_height),
        );
        let footer = Rect::new(inner.x, body.bottom(), inner.width, footer_height);
        self.configuration_body.set(body);
        let paragraph =
            Paragraph::new(self.dashboard.draw_auth_setup(draft)).wrap(Wrap { trim: false });
        let max_scroll = paragraph
            .line_count(body.width)
            .saturating_sub(usize::from(body.height));
        self.configuration_max_scroll.set(max_scroll);
        frame.render_widget(
            paragraph
                .style(Style::default().fg(theme::SECONDARY))
                .scroll((
                    self.configuration_scroll
                        .min(max_scroll)
                        .min(usize::from(u16::MAX)) as u16,
                    0,
                )),
            body,
        );
        let actions: &[(&str, &str)] = match draft.step {
            AuthSetupStep::KeychainPath => &[("enter", "Continue")],
            AuthSetupStep::LinuxStorageChoice => &[("k", "Keyring"), ("p", "Protected file")],
            AuthSetupStep::ProtectedFileConsent => &[("y", "Acknowledge")],
            AuthSetupStep::Confirm => &[("y", "Save")],
        };
        self.dashboard.controls.extend(theme::render_footer(
            frame,
            footer,
            actions,
            &[("esc", "Cancel")],
        ));
        self.dashboard.controls.highlight(frame);
    }
}
