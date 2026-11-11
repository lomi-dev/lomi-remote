//! Sign-in gate shown before the workspace dashboard is available.

use super::{Backend, theme};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use lomi_remote_protocol::{
    DecimalU64, OperationId,
    ipc::{
        LocalAuthNetwork, LocalAuthPhase, LocalAuthStorage, LocalCall, LocalLoginAccepted,
        LocalLoginPresentation, LocalLoginStart, LocalLoginStatus, LocalResult,
    },
};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Paragraph, Wrap},
};
use std::{
    cell::Cell,
    sync::mpsc::{Receiver, TryRecvError},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

const PRESENTATION_POLL_INTERVAL: Duration = Duration::from_secs(1);
const START_STATUS_GRACE: Duration = Duration::from_secs(8);
const WELCOME_BUTTON_WIDTH: u16 = 22;
const DIALOG_MAX_WIDTH: u16 = 76;
const DIALOG_MAX_HEIGHT: u16 = 22;

#[derive(Debug, Clone, PartialEq, Eq)]
struct PresentationKey {
    url: String,
    expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LoginContext {
    generation: DecimalU64,
    operation_id: OperationId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthRequestKind {
    Start,
    Status,
    Presentation,
}

struct AuthRequest {
    kind: AuthRequestKind,
    context: Option<LoginContext>,
    receiver: Receiver<Result<LocalResult, &'static str>>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum BrowserState {
    #[default]
    NotOpened,
    Opening,
    Opened,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
enum Focus {
    #[default]
    Welcome,
    Primary,
    Close,
}

#[derive(Debug, Clone, Copy, Default)]
struct Targets {
    welcome: Rect,
    primary: Rect,
    close: Rect,
    dialog: Rect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrimaryAction {
    OpenBrowser,
    StartLogin,
}

/// State and drawing for the standalone sign-in gate.
#[derive(Default)]
pub(super) struct SignIn {
    status: Option<LocalLoginStatus>,
    status_error: Option<&'static str>,
    status_message: Option<&'static str>,
    login_error: Option<&'static str>,
    configuration_error: Option<&'static str>,
    modal_open: bool,
    configuration_requested: bool,
    start_requested: bool,
    start_operation_id: Option<OperationId>,
    start_accepted_at: Option<Instant>,
    active_operation_id: Option<OperationId>,
    active_generation: Option<DecimalU64>,
    auth_request: Option<AuthRequest>,
    last_completed_auth_request: Option<AuthRequestKind>,
    presentation_requested: bool,
    presentation_expired: bool,
    presentation: Option<LocalLoginPresentation>,
    presentation_key: Option<PresentationKey>,
    presentation_operation_id: Option<OperationId>,
    presentation_generation: Option<DecimalU64>,
    last_presentation_poll: Option<Instant>,
    browser_receiver: Option<Receiver<Result<(), &'static str>>>,
    browser_context: Option<LoginContext>,
    browser_attempted_for: Option<PresentationKey>,
    browser_state: BrowserState,
    modal_scroll: usize,
    focus: Focus,
    targets: Cell<Targets>,
    last_visible_state: Option<VisibleState>,
}

impl SignIn {
    /// Draw the welcome state and, after explicit sign-in, its device-code
    /// dialog. Polling and drawing never start or reveal a login by themselves.
    pub(super) fn draw(&self, frame: &mut Frame) {
        self.targets.set(Targets::default());
        theme::canvas(frame);
        let area = frame.area();
        if area.is_empty() {
            return;
        }
        self.draw_welcome(frame, area);
        if self.modal_open {
            self.draw_dialog(frame, area);
        }
    }

    /// Poll local authentication and browser results without waiting for IPC.
    pub(super) fn poll(&mut self, backend: &mut impl Backend) -> bool {
        let now = Instant::now();

        self.poll_browser_result();
        self.complete_auth_request(backend, now);

        self.expire_presentation_if_needed();

        if self.auth_request.is_none() {
            if self.start_requested {
                self.start_requested = false;
                self.issue_login_start(backend, now);
            } else {
                self.schedule_auth_poll(backend, now);
            }
        }

        let visible = self.visible_state();
        let changed = self.last_visible_state.as_ref() != Some(&visible);
        self.last_visible_state = Some(visible);
        changed
    }

    /// The dashboard is allowed only after a usable local session is observed.
    /// A still-valid access lease also preserves a session while credentials
    /// rotate; a locked, expired, or revoking session remains behind the gate.
    pub(super) fn ready(&self) -> bool {
        let Some(status) = self.status.as_ref() else {
            return false;
        };
        if self.status_error.is_some() || status.locked || status.pending_cloud_revoke {
            return false;
        }
        if status.storage == LocalAuthStorage::Locked {
            return false;
        }
        match status.phase {
            LocalAuthPhase::Ready => true,
            LocalAuthPhase::Refreshing => status
                .access_expires_at
                .is_some_and(|expires| expires.0 > unix_now_seconds()),
            _ => false,
        }
    }

    pub(super) fn needs_configuration(&self) -> bool {
        self.status.as_ref().is_some_and(|status| {
            status.phase == LocalAuthPhase::Unconfigured && !status.pending_cloud_revoke
        })
    }

    pub(super) fn take_configuration_request(&mut self) -> bool {
        std::mem::take(&mut self.configuration_requested)
    }

    pub(super) fn configuration_error(&mut self, message: &'static str) {
        self.configuration_error = Some(message);
        self.modal_open = false;
    }

    /// `false` means the user requested application exit; all other events are
    /// consumed by this screen so they cannot activate hidden dashboard items.
    pub(super) fn handle_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> bool {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('c' | 'C'))
        {
            return false;
        }
        if key.code == KeyCode::Char('q') && key.modifiers.is_empty() {
            return false;
        }

        if self.modal_open {
            return self.handle_dialog_key(key, backend);
        }

        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return true;
        }
        match key.code {
            KeyCode::Enter | KeyCode::Char(' ') => self.activate_sign_in(),
            KeyCode::Char('c' | 'C') => self.request_configuration(),
            KeyCode::Tab | KeyCode::BackTab => self.focus = Focus::Welcome,
            _ => {}
        }
        true
    }

    pub(super) fn handle_mouse(&mut self, event: MouseEvent, backend: &mut impl Backend) -> bool {
        if event.kind != MouseEventKind::Down(MouseButton::Left) || !event.modifiers.is_empty() {
            return false;
        }
        let targets = self.targets.get();
        if self.modal_open {
            if contains(targets.primary, event.column, event.row) {
                if !super::interaction::accept_pointer_key(event, targets.primary, KeyCode::Enter) {
                    return false;
                }
                self.focus = Focus::Primary;
                self.activate_primary(backend);
                return true;
            }
            if contains(targets.close, event.column, event.row) {
                if !super::interaction::accept_pointer_key(event, targets.close, KeyCode::Esc) {
                    return false;
                }
                self.focus = Focus::Close;
                self.modal_open = false;
                return true;
            }
            // Modal background clicks are consumed by the sign-in screen and
            // never forwarded to the dashboard beneath it.
            return false;
        }

        if contains(targets.welcome, event.column, event.row)
            && super::interaction::accept_pointer_key(event, targets.welcome, KeyCode::Enter)
        {
            self.focus = Focus::Welcome;
            self.activate_sign_in();
            return true;
        }
        false
    }

    pub(super) fn hoverable(&self, x: u16, y: u16) -> bool {
        let targets = self.targets.get();
        if self.modal_open {
            contains(targets.primary, x, y) || contains(targets.close, x, y)
        } else {
            contains(targets.welcome, x, y)
        }
    }

    fn handle_dialog_key(&mut self, key: KeyEvent, backend: &mut impl Backend) -> bool {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return true;
        }
        match key.code {
            KeyCode::Esc => self.modal_open = false,
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match (self.primary_action().is_some(), self.focus) {
                    (true, Focus::Primary) => Focus::Close,
                    (true, _) => Focus::Primary,
                    (false, _) => Focus::Close,
                };
            }
            KeyCode::Enter | KeyCode::Char(' ') => {
                if self.focus == Focus::Close {
                    self.modal_open = false;
                } else {
                    self.activate_primary(backend);
                }
            }
            KeyCode::Up | KeyCode::PageUp => {
                self.modal_scroll = self
                    .modal_scroll
                    .saturating_sub(if key.code == KeyCode::PageUp { 5 } else { 1 });
            }
            KeyCode::Down | KeyCode::PageDown => {
                let step = if key.code == KeyCode::PageDown { 5 } else { 1 };
                self.modal_scroll = self
                    .modal_scroll
                    .saturating_add(step)
                    .min(self.modal_max_scroll());
            }
            KeyCode::Left | KeyCode::Right => {
                if self.primary_action().is_some() {
                    self.focus = if self.focus == Focus::Primary {
                        Focus::Close
                    } else {
                        Focus::Primary
                    };
                }
            }
            _ => {}
        }
        true
    }

    fn activate_sign_in(&mut self) {
        if self.needs_configuration() {
            self.request_configuration();
            return;
        }
        if self.is_revoking() && !self.can_retry_pending_revoke() {
            self.modal_open = true;
            self.focus = Focus::Close;
            return;
        }

        if self.start_accepted_at.is_some_and(|accepted| {
            Instant::now().saturating_duration_since(accepted) < START_STATUS_GRACE
        }) {
            self.modal_open = true;
            self.focus = Focus::Close;
            return;
        }

        self.modal_open = true;
        self.modal_scroll = 0;
        self.configuration_error = None;
        if self.start_requested
            || self.start_is_pending()
            || self.start_accepted_at.is_some_and(|accepted| {
                Instant::now().saturating_duration_since(accepted) < START_STATUS_GRACE
            })
        {
            return;
        }
        if self.has_active_login() && !self.presentation_expired {
            // An already-pending enrollment is reused; LoginStart is not
            // repeated merely because the user reopened its dialog.
            self.presentation_requested = true;
            self.last_presentation_poll = None;
            self.focus = Focus::Primary;
            return;
        }

        self.clear_presentation();
        self.presentation_expired = false;
        self.presentation_requested = true;
        self.start_requested = true;
        self.start_accepted_at = None;
        self.login_error = None;
        self.status_message = Some("Starting sign in…");
        self.focus = Focus::Close;
    }

    fn request_configuration(&mut self) {
        if self.is_revoking() {
            return;
        }
        self.modal_open = false;
        self.configuration_requested = true;
    }

    fn activate_primary(&mut self, backend: &mut impl Backend) {
        match self.primary_action() {
            Some(PrimaryAction::OpenBrowser) => self.open_browser(backend, true),
            Some(PrimaryAction::StartLogin) => self.activate_sign_in(),
            None if self.presentation.is_some() => self.open_browser(backend, true),
            None => {}
        }
    }

    fn issue_login_start(&mut self, backend: &mut impl Backend, now: Instant) {
        if self.ready()
            || (self.is_revoking() && !self.can_retry_pending_revoke())
            || self.is_locked()
            || self.needs_configuration()
        {
            self.start_requested = false;
            return;
        }
        if self.has_active_login() && !self.presentation_expired {
            // Status may have completed after the explicit action was queued.
            // Reuse that enrollment instead of issuing a second LoginStart.
            self.start_operation_id = None;
            self.presentation_requested = true;
            self.last_presentation_poll = None;
            self.focus = Focus::Primary;
            return;
        }
        let operation_id = match self.start_operation_id {
            Some(operation_id) => operation_id,
            None => match OperationId::from_bytes(*uuid::Uuid::new_v4().as_bytes()) {
                Ok(operation_id) => {
                    self.start_operation_id = Some(operation_id);
                    operation_id
                }
                Err(_) => {
                    self.login_error =
                        Some("Could not create a sign-in request. Please try again.");
                    return;
                }
            },
        };
        self.status_message = Some("Starting sign in…");
        self.request_auth(
            backend,
            AuthRequestKind::Start,
            self.active_context(),
            LocalCall::LoginStart(LocalLoginStart { operation_id }),
            now,
        );
    }

    fn accept_login_start(&mut self, accepted: LocalLoginAccepted, now: Instant) {
        if self.is_revoking() {
            self.clear_presentation();
            self.presentation_requested = false;
            self.presentation_expired = false;
            self.active_operation_id = None;
            self.active_generation = None;
            self.start_operation_id = None;
            self.start_accepted_at = Some(now);
            self.login_error = None;
            self.modal_open = false;
            self.status_message = Some("Sign-in will continue when sign-out finishes.");
            return;
        }
        let accepted_context = LoginContext {
            generation: accepted.generation,
            operation_id: accepted.operation_id,
        };
        if self.active_context() != Some(accepted_context) {
            self.clear_presentation();
        }
        self.active_operation_id = Some(accepted.operation_id);
        self.active_generation = Some(accepted.generation);
        self.start_operation_id = None;
        self.start_accepted_at = Some(now);
        self.login_error = None;
        self.status_message = Some("Preparing your sign-in link…");
        self.presentation_requested = true;
        self.last_presentation_poll = None;
    }

    fn start_is_pending(&self) -> bool {
        self.auth_request
            .as_ref()
            .is_some_and(|request| request.kind == AuthRequestKind::Start)
    }

    fn request_auth(
        &mut self,
        backend: &mut impl Backend,
        kind: AuthRequestKind,
        context: Option<LoginContext>,
        call: LocalCall,
        now: Instant,
    ) {
        match backend.request_async(call) {
            Ok(receiver) => {
                self.auth_request = Some(AuthRequest {
                    kind,
                    context,
                    receiver,
                });
                // In-memory backends return an already-ready receiver. Consume
                // it now to keep their tests and previews deterministic.
                self.complete_auth_request(backend, now);
            }
            Err(error) => self.finish_auth_request(kind, context, Err(error), now, backend),
        }
    }

    fn complete_auth_request(&mut self, backend: &mut impl Backend, now: Instant) {
        let Some(request) = self.auth_request.as_ref() else {
            return;
        };
        let kind = request.kind;
        let context = request.context;
        match request.receiver.try_recv() {
            Ok(result) => {
                self.auth_request = None;
                self.finish_auth_request(kind, context, result, now, backend);
            }
            Err(TryRecvError::Disconnected) => {
                self.auth_request = None;
                self.finish_auth_request(kind, context, Err("LOCAL_REQUEST_FAILED"), now, backend);
            }
            Err(TryRecvError::Empty) => {}
        }
    }

    fn finish_auth_request(
        &mut self,
        kind: AuthRequestKind,
        context: Option<LoginContext>,
        result: Result<LocalResult, &'static str>,
        now: Instant,
        backend: &mut impl Backend,
    ) {
        self.last_completed_auth_request = Some(kind);
        match kind {
            AuthRequestKind::Start => {
                if context == self.active_context() {
                    match result {
                        Ok(LocalResult::LoginAccepted(accepted)) => {
                            // Use the accepted server operation ID and generation.
                            self.accept_login_start(accepted, now);
                        }
                        Err(error) => {
                            self.login_error = Some(login_start_error(error));
                            self.presentation_requested = false;
                            self.status_message = None;
                        }
                        _ => {
                            self.login_error = Some("The sign-in request could not be confirmed.");
                            self.presentation_requested = false;
                            self.status_message = None;
                        }
                    }
                }
            }
            AuthRequestKind::Status => {
                // A status reply is useful only for the context visible when
                // the request began. A queued explicit start remains pending
                // until this check has decided whether it is still allowed.
                if context == self.active_context() {
                    match result {
                        Ok(LocalResult::LoginStatus(status)) => self.apply_status(status, now),
                        Err(error) => {
                            self.status = None;
                            self.status_error = Some(error);
                            self.status_message = None;
                            self.clear_secrets();
                        }
                        _ => {
                            self.status = None;
                            self.status_error = Some("LOGIN_STATUS_INVALID");
                            self.status_message = None;
                            self.clear_secrets();
                        }
                    }
                }
            }
            AuthRequestKind::Presentation => {
                self.last_presentation_poll = Some(now);
                if let Some(context) = context.filter(|context| self.context_is_current(*context)) {
                    self.finish_presentation_request(result, context, backend);
                }
            }
        }
    }

    fn schedule_auth_poll(&mut self, backend: &mut impl Backend, now: Instant) {
        // The run loop calls this on its one-second tick. A busy auth slot is
        // the only throttle needed for status requests.
        let presentation_due = self.should_poll_presentation()
            && self.last_presentation_poll.is_none_or(|last| {
                now.saturating_duration_since(last) >= PRESENTATION_POLL_INTERVAL
            });

        // Alternate when both are due, so a fast presentation response cannot
        // starve status refresh and a slow status cannot starve the code.
        let poll_presentation =
            presentation_due && self.last_completed_auth_request == Some(AuthRequestKind::Status);
        if poll_presentation {
            if let Some(context) = self.active_context() {
                self.request_auth(
                    backend,
                    AuthRequestKind::Presentation,
                    Some(context),
                    LocalCall::LoginPresentation {},
                    now,
                );
            }
        } else {
            self.request_auth(
                backend,
                AuthRequestKind::Status,
                self.active_context(),
                LocalCall::LoginStatus {},
                now,
            );
        }
    }

    fn apply_status(&mut self, status: LocalLoginStatus, now: Instant) {
        let start_grace = matches!(status.phase, LocalAuthPhase::Idle | LocalAuthPhase::Locked)
            && self.start_accepted_at.is_some_and(|accepted| {
                now.saturating_duration_since(accepted) < START_STATUS_GRACE
            });
        let old_context = self.active_context();
        let presented_context = self.presentation_context();
        let previous_generation = self.status.as_ref().map(|current| current.generation);
        let new_operation_id = status.operation_id;
        let new_context = new_operation_id.map(|operation_id| LoginContext {
            generation: status.generation,
            operation_id,
        });
        let phase_is_active = matches!(
            status.phase,
            LocalAuthPhase::Initializing
                | LocalAuthPhase::AwaitingApproval
                | LocalAuthPhase::Exchanging
                | LocalAuthPhase::Registering
        );
        let operation_changed = !start_grace
            && (old_context.is_some_and(|context| Some(context.operation_id) != new_operation_id)
                || presented_context
                    .is_some_and(|context| Some(context.operation_id) != new_operation_id));
        let context_changed = !start_grace
            && (previous_generation.is_some_and(|generation| generation != status.generation)
                || old_context.is_some_and(|context| Some(context) != new_context)
                || presented_context.is_some_and(|context| Some(context) != new_context));
        let preserve_presentation_request =
            self.presentation_requested && !operation_changed && phase_is_active;
        let operation_ended = !start_grace
            && matches!(
                status.phase,
                LocalAuthPhase::Idle | LocalAuthPhase::Unconfigured | LocalAuthPhase::Locked
            );
        let unavailable = status.phase == LocalAuthPhase::Unavailable;

        self.status = Some(status);
        self.status_error = None;
        if context_changed || operation_ended || unavailable {
            self.clear_presentation();
            self.presentation_requested = preserve_presentation_request;
            self.presentation_expired = false;
            self.active_operation_id = None;
            self.active_generation = None;
            self.start_accepted_at = None;
        }
        if self
            .status
            .as_ref()
            .is_some_and(|status| status.phase != LocalAuthPhase::Unconfigured)
        {
            self.configuration_error = None;
        }

        if self.is_revoking() {
            let start_accepted_at = self.start_accepted_at;
            self.clear_secrets();
            self.start_accepted_at = start_accepted_at;
            self.start_operation_id = None;
            self.modal_open = false;
            self.login_error = None;
            self.status_message = Some(if self.can_retry_pending_revoke() {
                "Finishing sign-out. Try signing in again to reconnect."
            } else {
                "Account access is being revoked. Sign-in is unavailable until that finishes."
            });
            return;
        }
        if self.is_locked() {
            self.clear_secrets();
            self.modal_open = false;
            self.status_message = Some(
                "Credential storage is locked. Unlock it or run the setup wizard to configure storage.",
            );
            return;
        }
        if self.ready() {
            self.clear_secrets();
            self.start_operation_id = None;
            self.modal_open = false;
            self.login_error = None;
            self.status_message = None;
            self.configuration_error = None;
            return;
        }

        if let Some(status) = self.status.as_ref() {
            if phase_is_active {
                self.active_operation_id = new_operation_id;
                self.active_generation = Some(status.generation);
                self.start_operation_id = None;
                self.start_accepted_at = None;
            } else if status.phase == LocalAuthPhase::Idle {
                if start_grace {
                    self.active_operation_id = old_context.map(|context| context.operation_id);
                    self.active_generation = old_context.map(|context| context.generation);
                } else {
                    self.active_operation_id = None;
                    self.active_generation = None;
                }
            } else if status.phase == LocalAuthPhase::Unconfigured {
                self.active_operation_id = None;
                self.active_generation = None;
            } else if !start_grace {
                self.active_operation_id = None;
                self.active_generation = None;
            }
            self.status_message = match status.phase {
                LocalAuthPhase::Unconfigured => Some(
                    "Authentication is not configured. Choose Sign in to set up secure storage.",
                ),
                LocalAuthPhase::Initializing => Some("Preparing sign-in…"),
                LocalAuthPhase::AwaitingApproval => Some("Waiting for approval in your browser…"),
                LocalAuthPhase::Exchanging | LocalAuthPhase::Registering => {
                    Some("Finishing sign-in…")
                }
                LocalAuthPhase::Ready => None,
                LocalAuthPhase::Refreshing => Some("Refreshing account access…"),
                LocalAuthPhase::Locked => Some("Account access has ended. Sign in again."),
                LocalAuthPhase::PendingRevoke => Some("Account access is being revoked."),
                LocalAuthPhase::Unavailable => Some("Authentication is unavailable right now."),
                LocalAuthPhase::Idle => {
                    if self.start_accepted_at.is_some_and(|accepted| {
                        now.saturating_duration_since(accepted) < START_STATUS_GRACE
                    }) {
                        Some("Starting sign in…")
                    } else {
                        self.start_accepted_at = None;
                        self.active_operation_id = None;
                        self.presentation_requested = false;
                        self.clear_presentation();
                        Some("No sign-in is in progress. Select Sign in to try again.")
                    }
                }
            };
        }
    }

    fn should_poll_presentation(&self) -> bool {
        self.presentation_requested
            && self.presentation.is_none()
            && !self.presentation_expired
            && self.has_active_login()
            && self
                .active_context()
                .is_some_and(|context| self.context_is_current(context))
            && !self.is_revoking()
            && !self.is_locked()
    }

    fn finish_presentation_request(
        &mut self,
        result: Result<LocalResult, &'static str>,
        context: LoginContext,
        backend: &mut impl Backend,
    ) {
        match result {
            Ok(LocalResult::LoginPresentation(presentation)) => {
                if !self.context_is_current(context) {
                    return;
                }
                self.accept_presentation(presentation, backend);
            }
            Err("AUTH_UNCONFIGURED") | Err("AUTH_CONFIGURATION_MISSING") => {
                self.login_error = Some(
                    "Authentication is not configured. Choose Sign in to configure secure storage.",
                );
            }
            Err("LOGIN_PRESENTATION_UNAVAILABLE") | Err("LOGIN_UNAVAILABLE") => {
                self.status_message = Some("Waiting for your sign-in link…");
            }
            Err(_) => {
                self.status_message = Some("Waiting for your sign-in link…");
            }
            _ => {
                self.login_error = Some("The sign-in link could not be loaded.");
            }
        }
    }

    fn accept_presentation(
        &mut self,
        presentation: LocalLoginPresentation,
        backend: &mut impl Backend,
    ) {
        if presentation.expires_at.0 <= unix_now_seconds() {
            self.clear_presentation();
            self.presentation_requested = false;
            self.presentation_expired = true;
            self.login_error =
                Some("This sign-in code has expired. Start sign-in again for a new code.");
            return;
        }
        let url = presentation.verification_url.as_str();
        if crate::browser::validate_url(url).is_err() {
            // Never display or open an unverified URL.
            self.clear_presentation();
            self.presentation_requested = false;
            self.presentation_expired = true;
            self.login_error = Some("The sign-in link could not be verified.");
            return;
        }
        let key = PresentationKey {
            url: url.to_owned(),
            expires_at: presentation.expires_at.0,
        };
        let Some(operation_id) = self.active_operation_id else {
            self.login_error = Some("The sign-in operation could not be verified.");
            return;
        };
        let Some(context) = self.active_context() else {
            self.login_error = Some("The sign-in operation could not be verified.");
            return;
        };
        if !self.context_is_current(context) {
            return;
        }
        let same_presentation = self.presentation_key.as_ref() == Some(&key)
            && self.presentation_context() == Some(context);
        self.presentation = Some(presentation);
        self.presentation_key = Some(key.clone());
        self.presentation_operation_id = Some(operation_id);
        self.presentation_generation = Some(context.generation);
        self.presentation_expired = false;
        self.login_error = None;
        self.status_message = None;
        if !same_presentation {
            self.browser_receiver = None;
            self.browser_state = BrowserState::NotOpened;
            self.browser_attempted_for = None;
            self.focus = Focus::Primary;
            self.open_browser(backend, false);
        }
    }

    fn open_browser(&mut self, backend: &mut impl Backend, explicit_retry: bool) {
        let Some(context) = self.active_context() else {
            self.clear_presentation();
            self.presentation_requested = false;
            return;
        };
        if self.presentation_context() != Some(context) || !self.context_is_current(context) {
            self.clear_presentation();
            self.presentation_requested = false;
            return;
        }
        let Some(presentation) = self.presentation.as_ref() else {
            return;
        };
        if presentation.expires_at.0 <= unix_now_seconds() {
            self.expire_presentation_if_needed();
            return;
        }
        let url = presentation.verification_url.as_str();
        if crate::browser::validate_url(url).is_err() {
            self.clear_presentation();
            self.presentation_requested = false;
            self.presentation_expired = true;
            self.login_error = Some("The sign-in link could not be verified.");
            return;
        }
        let Some(key) = self.presentation_key.clone() else {
            return;
        };
        if self.browser_receiver.is_some() {
            return;
        }
        if explicit_retry {
            self.browser_attempted_for = None;
        }
        if self.browser_attempted_for.as_ref() == Some(&key) {
            return;
        }
        self.browser_attempted_for = Some(key);
        match backend.open_browser_url(url) {
            Ok(receiver) => {
                self.browser_receiver = Some(receiver);
                self.browser_context = Some(context);
                self.browser_state = BrowserState::Opening;
            }
            Err(_) => {
                self.browser_receiver = None;
                self.browser_context = None;
                self.browser_state = BrowserState::Failed;
            }
        }
    }

    fn poll_browser_result(&mut self) {
        if self
            .browser_context
            .is_some_and(|context| !self.context_is_current(context))
        {
            self.browser_receiver = None;
            self.browser_context = None;
            self.browser_state = BrowserState::NotOpened;
            return;
        }
        let result = self.browser_receiver.as_ref().map(Receiver::try_recv);
        match result {
            Some(Ok(Ok(()))) => {
                self.browser_receiver = None;
                self.browser_context = None;
                self.browser_state = BrowserState::Opened;
            }
            Some(Ok(Err(_))) | Some(Err(TryRecvError::Disconnected)) => {
                self.browser_receiver = None;
                self.browser_context = None;
                self.browser_state = BrowserState::Failed;
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
    }

    fn expire_presentation_if_needed(&mut self) {
        if self
            .presentation
            .as_ref()
            .is_some_and(|presentation| presentation.expires_at.0 <= unix_now_seconds())
        {
            self.clear_presentation();
            self.presentation_requested = false;
            self.presentation_expired = true;
            self.login_error =
                Some("This sign-in code has expired. Start sign-in again for a new code.");
        }
    }

    fn clear_presentation(&mut self) {
        self.presentation = None;
        self.presentation_key = None;
        self.presentation_operation_id = None;
        self.presentation_generation = None;
        self.browser_receiver = None;
        self.browser_context = None;
        self.browser_attempted_for = None;
        self.browser_state = BrowserState::NotOpened;
    }

    fn clear_secrets(&mut self) {
        self.clear_presentation();
        self.presentation_requested = false;
        self.presentation_expired = false;
        self.active_operation_id = None;
        self.active_generation = None;
        self.start_requested = false;
        self.start_accepted_at = None;
    }

    fn is_revoking(&self) -> bool {
        self.status.as_ref().is_some_and(|status| {
            status.pending_cloud_revoke || status.phase == LocalAuthPhase::PendingRevoke
        })
    }

    fn can_retry_pending_revoke(&self) -> bool {
        self.status.as_ref().is_some_and(|status| {
            (status.pending_cloud_revoke || status.phase == LocalAuthPhase::PendingRevoke)
                && status.network == LocalAuthNetwork::Unavailable
                && status.storage == LocalAuthStorage::Available
        })
    }

    fn is_locked(&self) -> bool {
        // `locked` is the Host's authorization gate and is expected during
        // sign-in. Only storage locking prevents access to the credential
        // provider; a revoked account (phase Locked) can explicitly sign in.
        self.status
            .as_ref()
            .is_some_and(|status| status.storage == LocalAuthStorage::Locked)
    }

    fn has_active_login(&self) -> bool {
        self.status.as_ref().is_some_and(|status| {
            matches!(
                status.phase,
                LocalAuthPhase::Initializing
                    | LocalAuthPhase::AwaitingApproval
                    | LocalAuthPhase::Exchanging
                    | LocalAuthPhase::Registering
            )
        })
    }

    fn active_context(&self) -> Option<LoginContext> {
        Some(LoginContext {
            generation: self.active_generation?,
            operation_id: self.active_operation_id?,
        })
    }

    fn presentation_context(&self) -> Option<LoginContext> {
        Some(LoginContext {
            generation: self.presentation_generation?,
            operation_id: self.presentation_operation_id?,
        })
    }

    fn context_is_current(&self, context: LoginContext) -> bool {
        self.active_context() == Some(context)
            && self.status.as_ref().is_some_and(|status| {
                status.generation == context.generation
                    && status.operation_id == Some(context.operation_id)
                    && matches!(
                        status.phase,
                        LocalAuthPhase::Initializing
                            | LocalAuthPhase::AwaitingApproval
                            | LocalAuthPhase::Exchanging
                            | LocalAuthPhase::Registering
                    )
            })
    }

    fn primary_action(&self) -> Option<PrimaryAction> {
        if self.presentation.as_ref().is_some_and(|presentation| {
            presentation.expires_at.0 > unix_now_seconds()
                && self.presentation_context() == self.active_context()
        }) {
            return Some(PrimaryAction::OpenBrowser);
        }
        if self.can_start_login() {
            Some(PrimaryAction::StartLogin)
        } else {
            None
        }
    }

    fn can_start_login(&self) -> bool {
        if self.needs_configuration()
            || (self.is_revoking() && !self.can_retry_pending_revoke())
            || self.is_locked()
        {
            return false;
        }
        if self.has_active_login() && !self.presentation_expired {
            return false;
        }
        if self.start_accepted_at.is_some_and(|accepted| {
            Instant::now().saturating_duration_since(accepted) < START_STATUS_GRACE
        }) {
            return false;
        }
        if self.status.as_ref().is_some_and(|status| {
            status.phase == LocalAuthPhase::Refreshing
                || status.storage == LocalAuthStorage::Unavailable
        }) {
            return false;
        }
        !self.start_requested && !self.start_is_pending()
    }

    fn dialog_lines(&self) -> Vec<Line<'static>> {
        let mut lines = Vec::new();
        if let Some(status) = self.status.as_ref() {
            let phase = match status.phase {
                LocalAuthPhase::Unconfigured => "Authentication is not configured yet.",
                LocalAuthPhase::Idle => "No sign-in is in progress.",
                LocalAuthPhase::Initializing => "Preparing your sign-in request…",
                LocalAuthPhase::AwaitingApproval => "Approve this sign-in in your browser.",
                LocalAuthPhase::Exchanging | LocalAuthPhase::Registering => "Finishing sign-in…",
                LocalAuthPhase::Ready => "Sign-in complete.",
                LocalAuthPhase::Refreshing => "Refreshing account access…",
                LocalAuthPhase::Locked => "Account access has ended. Sign in again.",
                LocalAuthPhase::PendingRevoke => "Account access is being revoked.",
                LocalAuthPhase::Unavailable => "Authentication is unavailable right now.",
            };
            lines.push(Line::styled(phase, Style::default().fg(theme::SECONDARY)));
        } else if let Some(error) = self.status_error {
            lines.push(Line::styled(
                status_error_message(error),
                Style::default().fg(theme::WARNING),
            ));
        }

        if let Some(presentation) = self.presentation.as_ref()
            && self.presentation_context() == self.active_context()
            && presentation.expires_at.0 > unix_now_seconds()
        {
            lines.push(Line::default());
            lines.push(Line::styled(
                "One-time code",
                Style::default().fg(theme::MUTED),
            ));
            lines.push(Line::styled(
                presentation.user_code.expose_wire().to_owned(),
                Style::default()
                    .fg(theme::ACCENT)
                    .add_modifier(Modifier::BOLD),
            ));
            lines.push(Line::default());
            lines.push(Line::styled(
                "Verification URL",
                Style::default().fg(theme::MUTED),
            ));
            lines.push(Line::styled(
                presentation.verification_url.as_str().to_owned(),
                Style::default().fg(theme::SECONDARY),
            ));
            let remaining = presentation.expires_at.0.saturating_sub(unix_now_seconds());
            lines.push(Line::styled(
                format!("Code expires in {}:{:02}.", remaining / 60, remaining % 60),
                Style::default().fg(theme::MUTED),
            ));
        }

        if let Some(message) = self.login_error {
            lines.push(Line::default());
            lines.push(Line::styled(message, Style::default().fg(theme::ERROR)));
        } else if let Some(message) = self.configuration_error {
            lines.push(Line::default());
            lines.push(Line::styled(message, Style::default().fg(theme::ERROR)));
        } else if let Some(message) = self.status_message {
            lines.push(Line::default());
            lines.push(Line::styled(message, Style::default().fg(theme::SECONDARY)));
        }

        if self.status.as_ref().is_some_and(|status| {
            status.network == lomi_remote_protocol::ipc::LocalAuthNetwork::Unavailable
        }) {
            lines.push(Line::styled(
                "The sign-in service is unavailable. The Host will retry automatically.",
                Style::default().fg(theme::WARNING),
            ));
        }

        match self.browser_state {
            BrowserState::NotOpened => {}
            BrowserState::Opening => lines.push(Line::styled(
                "Opening your browser…",
                Style::default().fg(theme::SECONDARY),
            )),
            BrowserState::Opened => lines.push(Line::styled(
                "Browser opened. Complete sign-in there.",
                Style::default().fg(theme::SUCCESS),
            )),
            BrowserState::Failed => lines.push(Line::styled(
                "Could not open a browser. Open the verification URL manually, or retry below.",
                Style::default().fg(theme::WARNING),
            )),
        }
        if lines.is_empty() {
            lines.push(Line::styled(
                "Waiting for the local Host…",
                Style::default().fg(theme::SECONDARY),
            ));
        }
        lines
    }

    fn welcome_message(&self) -> Option<&'static str> {
        if let Some(message) = self.configuration_error {
            return Some(message);
        }
        if self.is_revoking() {
            return Some(if self.can_retry_pending_revoke() {
                "Finishing sign-out. Try signing in again to reconnect."
            } else {
                "Account access is being revoked. Sign-in is unavailable until that finishes."
            });
        }
        if self.is_locked() {
            return Some("Credential storage is locked. Unlock it or run the setup wizard.");
        }
        if self.needs_configuration() {
            return Some("Choose Sign in to configure secure credential storage.");
        }
        if let Some(error) = self.status_error {
            return Some(status_error_message(error));
        }
        if let Some(status) = self.status.as_ref() {
            if status.network == lomi_remote_protocol::ipc::LocalAuthNetwork::Unavailable
                || status.phase == LocalAuthPhase::Unavailable
            {
                return Some(
                    "The sign-in service is unavailable. Check the connection and try again.",
                );
            }
            if self.has_active_login() {
                return Some("A sign-in is already in progress. Choose Sign in to continue.");
            }
        }
        self.login_error
    }

    fn visible_state(&self) -> VisibleState {
        VisibleState {
            status: self.status.clone(),
            status_error: self.status_error,
            status_message: self.status_message,
            login_error: self.login_error,
            configuration_error: self.configuration_error,
            modal_open: self.modal_open,
            configuration_requested: self.configuration_requested,
            presentation: self.presentation.clone(),
            presentation_expired: self.presentation_expired,
            browser_state: self.browser_state,
            ready: self.ready(),
            presentation_seconds_remaining: self
                .presentation
                .as_ref()
                .map(|presentation| presentation.expires_at.0.saturating_sub(unix_now_seconds())),
        }
    }

    fn draw_welcome(&self, frame: &mut Frame, area: Rect) {
        let brand_y = area.y.saturating_add(area.height.saturating_sub(4) / 2);
        let button_y = brand_y.saturating_add(2);
        let button_width = area.width.min(WELCOME_BUTTON_WIDTH);
        let button = Rect::new(
            area.x
                .saturating_add(area.width.saturating_sub(button_width) / 2),
            button_y.min(area.bottom().saturating_sub(1)),
            button_width,
            u16::from(area.height > 0),
        );
        if !button.is_empty() {
            let label = if self.can_retry_pending_revoke() {
                "Try signing in again"
            } else if self.has_active_login() && !self.presentation_expired {
                "Continue sign in"
            } else {
                "Sign in"
            };
            draw_button(frame, button, label, self.focus == Focus::Welcome);
        }
        let brand = Rect::new(area.x, brand_y, area.width, 1);
        if !brand.is_empty() {
            frame.render_widget(
                Paragraph::new(Span::styled(
                    "lomi",
                    Style::default()
                        .fg(theme::ACCENT)
                        .add_modifier(Modifier::BOLD),
                ))
                .alignment(Alignment::Center),
                brand,
            );
        }
        self.targets.set(Targets {
            welcome: button,
            ..Targets::default()
        });
        if let Some(message) = self.welcome_message()
            && area.height >= 6
        {
            let hint_y = button
                .bottom()
                .saturating_add(1)
                .min(area.bottom().saturating_sub(1));
            if hint_y < area.bottom() {
                frame.render_widget(
                    Paragraph::new(message)
                        .style(Style::default().fg(theme::MUTED))
                        .alignment(Alignment::Center)
                        .wrap(Wrap { trim: true }),
                    Rect::new(
                        area.x.saturating_add(1),
                        hint_y,
                        area.width.saturating_sub(2),
                        2,
                    ),
                );
            }
        }
        if area.height >= 2 {
            frame.render_widget(
                Paragraph::new("Enter / Space  Sign in                         q  Quit")
                    .style(Style::default().fg(theme::MUTED))
                    .alignment(Alignment::Center),
                Rect::new(area.x, area.bottom().saturating_sub(1), area.width, 1),
            );
        }
    }

    fn draw_dialog(&self, frame: &mut Frame, area: Rect) {
        let width = area.width.min(DIALOG_MAX_WIDTH);
        let height = area.height.min(DIALOG_MAX_HEIGHT);
        if width == 0 || height == 0 {
            return;
        }
        let dialog = Rect::new(
            area.x.saturating_add(area.width.saturating_sub(width) / 2),
            area.y
                .saturating_add(area.height.saturating_sub(height) / 2),
            width,
            height,
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BORDER))
            .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
            .title(Span::styled(
                " Sign in ",
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center);
        let inner = block.inner(dialog);
        frame.render_widget(Clear, dialog);
        frame.render_widget(block, dialog);
        if inner.is_empty() {
            self.targets.set(Targets {
                dialog,
                ..Targets::default()
            });
            return;
        }

        let action = self.primary_action();
        let button_rows = u16::from(inner.height > 0);
        let body_height = inner.height.saturating_sub(button_rows);
        let body = Rect::new(inner.x, inner.y, inner.width, body_height);
        let paragraph = Paragraph::new(Text::from(self.dialog_lines())).wrap(Wrap { trim: false });
        let max_scroll = paragraph
            .line_count(body.width)
            .saturating_sub(usize::from(body.height));
        let scroll = self.modal_scroll.min(max_scroll).min(usize::from(u16::MAX)) as u16;
        if !body.is_empty() {
            frame.render_widget(paragraph.scroll((scroll, 0)), body);
        }

        let mut targets = Targets {
            dialog,
            ..Targets::default()
        };
        if button_rows > 0 {
            let y = inner.bottom().saturating_sub(1);
            if action.is_some() && inner.width >= 9 {
                let primary_width = inner.width.saturating_sub(2) / 2;
                let close_width = inner.width.saturating_sub(primary_width).saturating_sub(2);
                let primary_area = Rect::new(inner.x, y, primary_width, 1);
                let close_area = Rect::new(
                    inner.x.saturating_add(primary_width).saturating_add(2),
                    y,
                    close_width,
                    1,
                );
                let primary_label = match action {
                    Some(PrimaryAction::OpenBrowser) => "Open browser",
                    Some(PrimaryAction::StartLogin) => "Try signing in again",
                    None => unreachable!(),
                };
                draw_button(
                    frame,
                    primary_area,
                    primary_label,
                    self.focus == Focus::Primary,
                );
                draw_button(frame, close_area, "Close", self.focus == Focus::Close);
                targets.primary = primary_area;
                targets.close = close_area;
            } else {
                let close_area = Rect::new(inner.x, y, inner.width, 1);
                draw_button(frame, close_area, "Close", self.focus == Focus::Close);
                targets.close = close_area;
            }
        }
        self.targets.set(targets);
    }

    fn modal_max_scroll(&self) -> usize {
        let targets = self.targets.get();
        if targets.dialog.is_empty() {
            return 0;
        }
        let height = targets.dialog.height.saturating_sub(2);
        let button_rows = u16::from(height > 0);
        let body_height = height.saturating_sub(button_rows);
        let width = targets.dialog.width.saturating_sub(2);
        Paragraph::new(Text::from(self.dialog_lines()))
            .wrap(Wrap { trim: false })
            .line_count(width)
            .saturating_sub(usize::from(body_height))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct VisibleState {
    status: Option<LocalLoginStatus>,
    status_error: Option<&'static str>,
    status_message: Option<&'static str>,
    login_error: Option<&'static str>,
    configuration_error: Option<&'static str>,
    modal_open: bool,
    configuration_requested: bool,
    presentation: Option<LocalLoginPresentation>,
    presentation_expired: bool,
    browser_state: BrowserState,
    ready: bool,
    presentation_seconds_remaining: Option<u64>,
}

fn draw_button(frame: &mut Frame, area: Rect, label: &str, focused: bool) {
    let area = area.intersection(frame.area());
    if area.is_empty() {
        return;
    }
    let style = if focused {
        Style::default()
            .fg(theme::ACCENT)
            .bg(theme::SELECTION)
            .add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(theme::SECONDARY).bg(theme::KEYCAP)
    };
    frame.render_widget(
        Paragraph::new(format!("[ {label} ]"))
            .alignment(Alignment::Center)
            .style(style),
        area,
    );
}

fn contains(area: Rect, x: u16, y: u16) -> bool {
    !area.is_empty() && area.contains((x, y).into())
}

fn unix_now_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn login_start_error(error: &'static str) -> &'static str {
    match error {
        "AUTH_UNCONFIGURED" | "AUTH_CONFIGURATION_MISSING" => {
            "Authentication is not configured. Choose Sign in to configure secure storage."
        }
        "AUTH_LOCKED" | "AUTH_STORAGE_LOCKED" => {
            "Credential storage is locked. Unlock it or run the setup wizard."
        }
        "AUTH_UNAVAILABLE" | "LOGIN_UNAVAILABLE" => {
            "Sign-in is unavailable right now. Check the connection and try again."
        }
        _ => "Could not start sign-in. Check the local Host and try again.",
    }
}

fn status_error_message(_error: &'static str) -> &'static str {
    "Can't reach the local Host for sign-in. Check that it is running and try again."
}

#[cfg(test)]
mod tests {
    use super::*;
    use lomi_remote_protocol::ipc::{LocalAuthNetwork, LocalRootPath};
    use lomi_remote_protocol::{DecimalU64, http::UserCode};
    use ratatui::{Terminal, backend::TestBackend};
    use std::sync::mpsc::{self, Receiver, SyncSender};

    #[derive(Default)]
    struct FakeBackend {
        status: Option<LocalLoginStatus>,
        status_error: Option<&'static str>,
        presentation: Option<Result<LocalLoginPresentation, &'static str>>,
        start_calls: usize,
        start_operation_ids: Vec<OperationId>,
        start_error: Option<&'static str>,
        status_calls: usize,
        presentation_calls: usize,
        opened_urls: Vec<String>,
        browser_result: Option<Result<(), &'static str>>,
    }

    impl Backend for FakeBackend {
        fn request(&mut self, call: LocalCall) -> Result<LocalResult, &'static str> {
            match call {
                LocalCall::LoginStatus {} => {
                    self.status_calls += 1;
                    if let Some(error) = self.status_error {
                        return Err(error);
                    }
                    self.status
                        .clone()
                        .map(LocalResult::LoginStatus)
                        .ok_or("STATUS_NOT_CONFIGURED")
                }
                LocalCall::LoginStart(start) => {
                    self.start_calls += 1;
                    self.start_operation_ids.push(start.operation_id);
                    if let Some(error) = self.start_error {
                        return Err(error);
                    }
                    Ok(LocalResult::LoginAccepted(LocalLoginAccepted {
                        operation_id: operation_id(2),
                        generation: DecimalU64(1),
                    }))
                }
                LocalCall::LoginPresentation {} => {
                    self.presentation_calls += 1;
                    self.presentation
                        .clone()
                        .unwrap_or(Err("LOGIN_PRESENTATION_UNAVAILABLE"))
                        .map(LocalResult::LoginPresentation)
                }
                _ => panic!("sign-in gate made an unrelated workspace or service call"),
            }
        }

        fn open_browser_url(
            &mut self,
            url: &str,
        ) -> Result<Receiver<Result<(), &'static str>>, &'static str> {
            self.opened_urls.push(url.to_owned());
            let (sender, receiver) = mpsc::channel();
            let _ = sender.send(self.browser_result.unwrap_or(Ok(())));
            Ok(receiver)
        }
    }

    #[derive(Default)]
    struct DeferredBackend {
        calls: Vec<LocalCall>,
        sender: Option<SyncSender<Result<LocalResult, &'static str>>>,
    }

    impl Backend for DeferredBackend {
        fn request(&mut self, _call: LocalCall) -> Result<LocalResult, &'static str> {
            panic!("deferred auth request must not call the blocking backend")
        }

        fn request_async(
            &mut self,
            call: LocalCall,
        ) -> Result<Receiver<Result<LocalResult, &'static str>>, &'static str> {
            self.calls.push(call);
            let (sender, receiver) = mpsc::sync_channel(1);
            self.sender = Some(sender);
            Ok(receiver)
        }
    }

    fn operation_id(seed: u8) -> OperationId {
        OperationId::from_bytes([seed; 16]).expect("nonzero operation ID")
    }

    fn status(phase: LocalAuthPhase) -> LocalLoginStatus {
        LocalLoginStatus {
            phase,
            storage: LocalAuthStorage::Available,
            network: LocalAuthNetwork::Available,
            generation: DecimalU64(1),
            locked: !matches!(phase, LocalAuthPhase::Ready | LocalAuthPhase::Refreshing),
            pending_cloud_revoke: false,
            operation_id: matches!(
                phase,
                LocalAuthPhase::Initializing
                    | LocalAuthPhase::AwaitingApproval
                    | LocalAuthPhase::Exchanging
                    | LocalAuthPhase::Registering
            )
            .then(|| operation_id(2)),
            access_expires_at: None,
            refresh_at: None,
        }
    }

    fn presentation(url: &str, expires_at: u64) -> LocalLoginPresentation {
        LocalLoginPresentation {
            user_code: UserCode::try_from("ABCD1234".to_owned()).unwrap(),
            verification_url: LocalRootPath::try_from(url.to_owned()).unwrap(),
            expires_at: DecimalU64(expires_at),
            next_poll_at: DecimalU64(unix_now_seconds()),
        }
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    fn left_click(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn text(terminal: &Terminal<TestBackend>) -> String {
        terminal
            .backend()
            .buffer()
            .content
            .iter()
            .map(|cell| cell.symbol())
            .collect()
    }

    #[test]
    fn reopening_a_starting_dialog_does_not_submit_a_second_login_intent() {
        for phase in [LocalAuthPhase::Idle, LocalAuthPhase::Locked] {
            let mut backend = FakeBackend {
                status: Some(status(phase)),
                ..FakeBackend::default()
            };
            let mut sign_in = SignIn::default();
            sign_in.poll(&mut backend);
            sign_in.handle_key(key(KeyCode::Enter), &mut backend);
            sign_in.poll(&mut backend);
            sign_in.handle_key(key(KeyCode::Esc), &mut backend);
            sign_in.handle_key(key(KeyCode::Enter), &mut backend);
            sign_in.poll(&mut backend);
            assert_eq!(backend.start_calls, 1, "{phase:?}");
        }
    }

    #[test]
    fn authorization_lock_allows_sign_in_but_locked_storage_does_not() {
        for phase in [LocalAuthPhase::Idle, LocalAuthPhase::Locked] {
            let mut backend = FakeBackend {
                status: Some(status(phase)),
                ..FakeBackend::default()
            };
            let mut sign_in = SignIn::default();
            sign_in.poll(&mut backend);
            assert!(sign_in.status.as_ref().unwrap().locked);
            assert!(!sign_in.ready());
            sign_in.handle_key(key(KeyCode::Enter), &mut backend);
            sign_in.poll(&mut backend);
            assert_eq!(backend.start_calls, 1, "{phase:?}");
        }

        let mut backend = FakeBackend {
            status: Some(LocalLoginStatus {
                storage: LocalAuthStorage::Locked,
                ..status(LocalAuthPhase::Idle)
            }),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 0);
        assert!(
            sign_in
                .welcome_message()
                .unwrap()
                .contains("Credential storage")
        );
    }

    #[test]
    fn startup_only_polls_status_and_pending_sign_in_requires_user_action() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::AwaitingApproval)),
            presentation: Some(Ok(presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ))),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();

        sign_in.poll(&mut backend);
        assert_eq!(backend.status_calls, 1);
        assert_eq!(backend.presentation_calls, 0);
        assert!(backend.opened_urls.is_empty());

        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 0, "pending login must be reused");
        assert_eq!(backend.presentation_calls, 1);
        assert_eq!(backend.opened_urls, ["https://login.example.test/device"]);
    }

    #[test]
    fn clicking_the_welcome_button_starts_once_after_the_explicit_action() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::Idle)),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| sign_in.draw(frame)).unwrap();
        let button = sign_in.targets.get().welcome;
        assert!(!button.is_empty());
        assert!(sign_in.handle_mouse(left_click(button.x + 1, button.y), &mut backend));
        assert!(sign_in.modal_open);
        assert_eq!(backend.start_calls, 0);

        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
    }

    #[test]
    fn explicit_start_uses_accepted_operation_and_opens_one_valid_presentation() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::Idle)),
            presentation: Some(Ok(presentation(
                "https://login.example.test/device?code=ABCD1234",
                unix_now_seconds() + 300,
            ))),
            browser_result: Some(Ok(())),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
        assert_eq!(
            backend.presentation_calls, 0,
            "wait for Host status to advance"
        );

        backend.status = Some(status(LocalAuthPhase::AwaitingApproval));
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
        assert_eq!(
            backend.presentation_calls, 0,
            "status and presentation share one auth slot"
        );
        sign_in.poll(&mut backend);
        assert_eq!(backend.presentation_calls, 1);
        assert_eq!(backend.opened_urls.len(), 1);
        assert_eq!(
            backend.opened_urls[0],
            "https://login.example.test/device?code=ABCD1234"
        );
        assert_eq!(
            sign_in
                .presentation
                .as_ref()
                .unwrap()
                .user_code
                .expose_wire(),
            "ABCD1234"
        );

        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Esc), &mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
        assert_eq!(backend.presentation_calls, 1);
        assert_eq!(
            backend.opened_urls.len(),
            1,
            "same URL and expiry opens once"
        );
    }

    #[test]
    fn invalid_or_expired_presentations_are_never_displayed_or_opened() {
        for (url, expires_at) in [
            ("http://login.example.test/device", unix_now_seconds() + 300),
            (
                "https://login.example.test/device",
                unix_now_seconds().saturating_sub(1),
            ),
        ] {
            let mut backend = FakeBackend {
                status: Some(status(LocalAuthPhase::AwaitingApproval)),
                presentation: Some(Ok(presentation(url, expires_at))),
                ..FakeBackend::default()
            };
            let mut sign_in = SignIn::default();
            sign_in.poll(&mut backend);
            sign_in.handle_key(key(KeyCode::Enter), &mut backend);
            sign_in.poll(&mut backend);

            assert!(sign_in.presentation.is_none());
            assert!(backend.opened_urls.is_empty());
        }
    }

    #[test]
    fn browser_failure_keeps_the_dialog_and_allows_an_explicit_retry() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::AwaitingApproval)),
            presentation: Some(Ok(presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ))),
            browser_result: Some(Err("OPEN_FAILED")),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.opened_urls.len(), 1);

        sign_in.poll(&mut backend);
        assert_eq!(sign_in.browser_state, BrowserState::Failed);
        assert!(sign_in.modal_open);
        assert_eq!(sign_in.focus, Focus::Primary);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        assert_eq!(backend.opened_urls.len(), 2);
    }

    #[test]
    fn host_loss_clears_code_and_browser_state() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::AwaitingApproval)),
            presentation: Some(Ok(presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ))),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert!(sign_in.presentation.is_some());
        assert_eq!(sign_in.browser_state, BrowserState::Opening);

        backend.status_error = Some("HOST_UNAVAILABLE");
        sign_in.poll(&mut backend);
        assert!(sign_in.presentation.is_none());
        assert!(sign_in.browser_receiver.is_none());
        assert_eq!(sign_in.browser_state, BrowserState::NotOpened);
        assert_eq!(sign_in.active_operation_id, None);
    }

    #[test]
    fn changed_or_ended_operation_invalidates_old_presentation() {
        let mut sign_in = SignIn::default();
        let now = Instant::now();
        sign_in.status = Some(status(LocalAuthPhase::AwaitingApproval));
        sign_in.active_operation_id = Some(operation_id(2));
        sign_in.active_generation = Some(DecimalU64(1));
        sign_in.presentation_requested = true;
        sign_in.accept_presentation(
            presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ),
            &mut FakeBackend::default(),
        );
        assert!(sign_in.presentation.is_some());

        sign_in.apply_status(
            LocalLoginStatus {
                operation_id: Some(operation_id(3)),
                ..status(LocalAuthPhase::AwaitingApproval)
            },
            now,
        );
        assert!(sign_in.presentation.is_none());
        assert_eq!(sign_in.active_operation_id, Some(operation_id(3)));
        assert!(!sign_in.presentation_requested);

        sign_in.presentation_requested = true;
        sign_in.active_operation_id = Some(operation_id(3));
        sign_in.active_generation = Some(DecimalU64(1));
        sign_in.accept_presentation(
            presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ),
            &mut FakeBackend::default(),
        );
        sign_in.apply_status(status(LocalAuthPhase::Idle), now);
        assert!(sign_in.presentation.is_none());
        assert!(!sign_in.presentation_requested);
    }

    #[test]
    fn same_operation_in_new_generation_clears_presentation_and_queued_browser_result() {
        let now = Instant::now();
        let mut sign_in = SignIn::default();
        sign_in.status = Some(status(LocalAuthPhase::AwaitingApproval));
        sign_in.active_operation_id = Some(operation_id(2));
        sign_in.active_generation = Some(DecimalU64(1));
        sign_in.presentation_requested = true;
        sign_in.accept_presentation(
            presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ),
            &mut FakeBackend::default(),
        );
        assert!(sign_in.presentation.is_some());
        assert!(sign_in.browser_receiver.is_some());

        sign_in.apply_status(
            LocalLoginStatus {
                generation: DecimalU64(2),
                operation_id: Some(operation_id(2)),
                ..status(LocalAuthPhase::AwaitingApproval)
            },
            now,
        );

        assert!(sign_in.presentation.is_none());
        assert!(sign_in.browser_receiver.is_none());
        assert_eq!(sign_in.browser_state, BrowserState::NotOpened);
        assert_eq!(sign_in.active_operation_id, Some(operation_id(2)));
        assert_eq!(sign_in.active_generation, Some(DecimalU64(2)));
        assert!(sign_in.presentation_requested);
        // The browser result was already queued; it cannot restore the old UI.
        sign_in.poll_browser_result();
        assert!(sign_in.presentation.is_none());
        assert_eq!(sign_in.browser_state, BrowserState::NotOpened);

        let mut backend = FakeBackend {
            status: Some(LocalLoginStatus {
                generation: DecimalU64(2),
                operation_id: Some(operation_id(2)),
                ..status(LocalAuthPhase::AwaitingApproval)
            }),
            presentation: Some(Ok(presentation(
                "https://login.example.test/new-device",
                unix_now_seconds() + 300,
            ))),
            ..FakeBackend::default()
        };
        sign_in.poll(&mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(
            sign_in
                .presentation
                .as_ref()
                .unwrap()
                .verification_url
                .as_str(),
            "https://login.example.test/new-device"
        );
    }

    #[test]
    fn late_presentation_reply_is_discarded_after_context_changes() {
        let mut sign_in = SignIn::default();
        sign_in.status = Some(status(LocalAuthPhase::AwaitingApproval));
        sign_in.active_operation_id = Some(operation_id(2));
        sign_in.active_generation = Some(DecimalU64(1));
        sign_in.presentation_requested = true;
        sign_in.last_completed_auth_request = Some(AuthRequestKind::Status);
        let mut backend = DeferredBackend::default();

        sign_in.poll(&mut backend);
        assert_eq!(backend.calls, [LocalCall::LoginPresentation {}]);
        assert!(sign_in.auth_request.is_some());

        sign_in.apply_status(
            LocalLoginStatus {
                generation: DecimalU64(2),
                operation_id: Some(operation_id(2)),
                ..status(LocalAuthPhase::AwaitingApproval)
            },
            Instant::now(),
        );
        backend
            .sender
            .take()
            .unwrap()
            .send(Ok(LocalResult::LoginPresentation(presentation(
                "https://login.example.test/old-device",
                unix_now_seconds() + 300,
            ))))
            .unwrap();

        sign_in.complete_auth_request(&mut backend, Instant::now());
        assert!(sign_in.presentation.is_none());
        assert!(sign_in.auth_request.is_none());
        assert!(
            backend.calls.len() == 1,
            "stale completion must not spawn another request"
        );
    }

    #[test]
    fn accepted_start_grace_cannot_be_started_twice_while_status_is_idle() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::Idle)),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);

        sign_in.handle_key(key(KeyCode::Esc), &mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
        assert!(sign_in.start_accepted_at.is_some());
    }

    #[test]
    fn uncertain_start_retry_reuses_the_original_operation_id() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::Idle)),
            start_error: Some("HOST_UNAVAILABLE"),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        let original_operation_id = backend.start_operation_ids[0];
        assert_eq!(sign_in.start_operation_id, Some(original_operation_id));

        sign_in.activate_sign_in();
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_operation_ids, [original_operation_id; 2]);
        assert_eq!(sign_in.start_operation_id, Some(original_operation_id));
    }

    #[test]
    fn pending_revoke_offers_only_explicit_debounced_sign_in_retry() {
        let mut pending = status(LocalAuthPhase::PendingRevoke);
        pending.pending_cloud_revoke = true;
        pending.network = LocalAuthNetwork::Unavailable;
        let mut backend = FakeBackend {
            status: Some(pending),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        assert_eq!(sign_in.primary_action(), Some(PrimaryAction::StartLogin));
        assert!(!sign_in.ready());

        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal.draw(|frame| sign_in.draw(frame)).unwrap();
        assert!(text(&terminal).contains("Try signing in again"));

        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 1);
        let first_operation = backend.start_operation_ids[0];
        assert!(sign_in.start_accepted_at.is_some());

        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(
            backend.start_calls, 1,
            "accepted retry keeps the normal debounce"
        );

        sign_in.start_accepted_at = Some(Instant::now() - START_STATUS_GRACE);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);
        assert_eq!(backend.start_calls, 2);
        assert_ne!(backend.start_operation_ids[1], first_operation);
    }

    #[test]
    fn unconfigured_auth_requests_existing_setup_without_starting_login() {
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::Unconfigured)),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        assert!(sign_in.needs_configuration());
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        assert!(sign_in.take_configuration_request());
        assert_eq!(backend.start_calls, 0);

        sign_in.configuration_error("Secure storage setup could not be started.");
        sign_in.poll(&mut backend);
        assert_eq!(
            sign_in.welcome_message(),
            Some("Secure storage setup could not be started.")
        );
        backend.status = Some(status(LocalAuthPhase::Idle));
        sign_in.poll(&mut backend);
        assert_eq!(sign_in.configuration_error, None);
    }

    #[test]
    fn ready_refreshing_session_is_preserved_but_revocation_clears_sign_in_data() {
        let mut refreshing = status(LocalAuthPhase::Refreshing);
        refreshing.access_expires_at = Some(DecimalU64(unix_now_seconds() + 60));
        let mut backend = FakeBackend {
            status: Some(refreshing),
            presentation: Some(Ok(presentation(
                "https://login.example.test/device",
                unix_now_seconds() + 300,
            ))),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        assert!(sign_in.ready());

        backend.status = Some(LocalLoginStatus {
            pending_cloud_revoke: true,
            ..status(LocalAuthPhase::PendingRevoke)
        });
        sign_in.poll(&mut backend);
        assert!(!sign_in.ready());
        assert!(sign_in.presentation.is_none());
        assert!(!sign_in.modal_open);
    }

    #[test]
    fn host_failure_is_visible_and_compact_terminals_render_without_panicking() {
        let mut backend = FakeBackend {
            status_error: Some("HOST_UNAVAILABLE"),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        assert!(sign_in.welcome_message().unwrap().contains("local Host"));

        sign_in.modal_open = true;
        let mut terminal = Terminal::new(TestBackend::new(12, 3)).unwrap();
        terminal.draw(|frame| sign_in.draw(frame)).unwrap();
        assert!(!text(&terminal).is_empty());
    }

    #[test]
    fn long_verification_urls_wrap_inside_the_dialog() {
        let long_url = format!("https://login.example.test/{}", "x".repeat(120));
        let mut backend = FakeBackend {
            status: Some(status(LocalAuthPhase::AwaitingApproval)),
            presentation: Some(Ok(presentation(&long_url, unix_now_seconds() + 300))),
            ..FakeBackend::default()
        };
        let mut sign_in = SignIn::default();
        sign_in.poll(&mut backend);
        sign_in.handle_key(key(KeyCode::Enter), &mut backend);
        sign_in.poll(&mut backend);

        let mut terminal = Terminal::new(TestBackend::new(40, 24)).unwrap();
        terminal.draw(|frame| sign_in.draw(frame)).unwrap();
        let rendered = text(&terminal);
        assert!(rendered.contains("ABCD1234"));
        assert!(rendered.contains("login.example.test"));
    }
}
