//! Devices screen (P3a.12): grants and approvals waiting for the owner, plus the banner that
//! tells the owner a device connected or asks for control. Talks to the Host's `devices.*` calls.
use super::{Backend, safe_label, shortcuts, theme};
use crate::devices::{approval_line, grant_line, mode_name, valid_code};
use crossterm::event::{KeyCode, KeyEvent};
use lomi_remote_protocol::ipc::{
    LocalCall, LocalDeviceApproval, LocalDeviceApprove, LocalDeviceGrant, LocalDeviceMode,
    LocalDeviceModeState, LocalDeviceNoticeKind, LocalDeviceRevoke, LocalDeviceTarget,
    LocalDeviceText, LocalDevices, LocalResult,
};
use ratatui::{
    Frame,
    layout::Rect,
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

#[derive(Default)]
pub(super) struct Devices {
    pub(super) open: bool,
    mode: Option<LocalDeviceMode>,
    grants: Vec<LocalDeviceGrant>,
    pending: Vec<LocalDeviceApproval>,
    /// Index over `pending` followed by `grants`.
    selected: usize,
    /// A grant waiting for the owner's yes.
    confirm_revoke: Option<LocalDeviceGrant>,
    /// Digits typed so far for an approval: the code the DEVICE shows (the Host never shows it).
    code: Option<String>,
    notice: Option<String>,
    message: Option<&'static str>,
}

impl Devices {
    fn apply(&mut self, d: LocalDevices) {
        self.mode = Some(d.mode);
        self.grants = d.grants.0;
        self.pending = d.pending.0;
        self.selected = self
            .selected
            .min((self.pending.len() + self.grants.len()).saturating_sub(1));
    }
    pub(super) fn refresh(&mut self, backend: &mut impl Backend) {
        match backend.request(LocalCall::DevicesList {}) {
            Ok(LocalResult::Devices(d)) => {
                self.message = None;
                self.apply(d);
            }
            _ => self.message = Some("Device list unavailable. The Host's tunnel is not ready."),
        }
    }
    /// Called about once a second. Returns whether the screen changed.
    pub(super) fn poll(&mut self, backend: &mut impl Backend) -> bool {
        let before = (self.pending.len(), self.notice.clone());
        if let Ok(LocalResult::DeviceNotices(notices)) =
            backend.request(LocalCall::DevicesNotices {})
        {
            if let Some(n) = notices.0.last() {
                let name = safe_label(n.device_name.as_str());
                self.notice = Some(match n.kind {
                    LocalDeviceNoticeKind::NewDevice => format!("New device connected: {name}"),
                    LocalDeviceNoticeKind::ControlRequested => {
                        format!("{name} asks for control: type the code it shows")
                    }
                    LocalDeviceNoticeKind::GrantsFull => {
                        format!("{name} was refused: all device slots are used")
                    }
                    LocalDeviceNoticeKind::RateLimited => {
                        format!("{name} was refused: too many requests")
                    }
                });
            }
            if !notices.0.is_empty() || self.open {
                self.refresh(backend);
            }
        }
        before != (self.pending.len(), self.notice.clone())
    }
    /// One line for the top of the dashboard, `None` when there is nothing to say.
    pub(super) fn banner(&self) -> Option<String> {
        let line = match self.pending.first() {
            Some(a) => format!("{}  (press i)", approval_line(a)),
            None => format!("{}  (press i)", self.notice.as_ref()?),
        };
        Some(line)
    }

    fn call(&mut self, call: LocalCall, backend: &mut impl Backend) {
        match backend.request(call) {
            Ok(LocalResult::Devices(d)) => {
                self.message = None;
                self.apply(d);
            }
            _ => {
                self.message = Some("That did not work. It may already be answered.");
                self.refresh(backend);
            }
        }
    }
    pub(super) fn handle_key(&mut self, key: KeyEvent, backend: &mut impl Backend) {
        if let Some(grant) = self.confirm_revoke.take() {
            if matches!(key.code, KeyCode::Char('y') | KeyCode::Enter) {
                self.call(
                    LocalCall::DevicesRevoke(LocalDeviceRevoke {
                        fingerprint: grant.fingerprint,
                    }),
                    backend,
                );
            }
            return;
        }
        if let Some(typed) = &mut self.code {
            match key.code {
                KeyCode::Char(c) if c.is_ascii_digit() && typed.len() < 6 => typed.push(c),
                KeyCode::Backspace => {
                    typed.pop();
                }
                KeyCode::Enter if valid_code(typed) => {
                    let code = LocalDeviceText::try_from(std::mem::take(typed));
                    self.code = None;
                    if let Ok(code) = code {
                        self.call(
                            LocalCall::DevicesApprove(LocalDeviceApprove { code }),
                            backend,
                        );
                    }
                }
                KeyCode::Esc => self.code = None,
                _ => {}
            }
            return;
        }
        let rows = self.pending.len() + self.grants.len();
        match key.code {
            KeyCode::Esc | KeyCode::Char('q' | 'i') => {
                self.open = false;
                self.notice = None;
            }
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => self.selected = (self.selected + 1).min(rows.saturating_sub(1)),
            KeyCode::Char('r') => self.refresh(backend),
            // Approving never acts on the selected row: the owner types the device's code.
            KeyCode::Char('a') if !self.pending.is_empty() => self.code = Some(String::new()),
            KeyCode::Char('x') if self.selected < self.pending.len() => {
                let target = LocalDeviceTarget {
                    circuit: self.pending[self.selected].circuit.clone(),
                };
                self.call(LocalCall::DevicesDeny(target), backend);
            }
            KeyCode::Char('v') | KeyCode::Delete if self.selected >= self.pending.len() => {
                self.confirm_revoke = self.grants.get(self.selected - self.pending.len()).cloned();
            }
            KeyCode::Char('m') => {
                let mode = match self.mode {
                    Some(LocalDeviceMode::Confirm) => LocalDeviceMode::Auto,
                    _ => LocalDeviceMode::Confirm,
                };
                match backend.request(LocalCall::DevicesModeSet(LocalDeviceModeState { mode })) {
                    Ok(LocalResult::DeviceMode(m)) => self.mode = Some(m.mode),
                    _ => self.message = Some("Mode was not changed."),
                }
            }
            _ => {}
        }
    }

    pub(super) fn draw(&self, frame: &mut Frame) {
        shortcuts::dim_frame(frame);
        let area = frame.area();
        let width = area.width.min(90);
        let height = area.height.min(22);
        let popup = Rect::new(
            area.x + area.width.saturating_sub(width) / 2,
            area.y + area.height.saturating_sub(height) / 2,
            width,
            height,
        );
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BORDER))
            .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
            .title(Span::styled(
                " Devices ",
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ));
        let inner = block.inner(popup);
        frame.render_widget(Clear, popup);
        frame.render_widget(block, popup);

        let row = |text: String, index: usize| {
            let style = if index == self.selected {
                theme::selection_style(true)
            } else {
                Style::default().fg(theme::TEXT)
            };
            Line::styled(format!(" {text}"), style)
        };
        let muted =
            |text: String| Line::styled(format!(" {text}"), Style::default().fg(theme::MUTED));
        let mut lines = vec![muted(format!(
            "Mode: {}  (m switches auto/confirm)",
            self.mode.map_or("unknown", mode_name)
        ))];
        if let Some(message) = self.message {
            lines.push(Line::styled(
                format!(" {message}"),
                Style::default().fg(theme::WARNING),
            ));
        }
        lines.push(Line::raw(""));
        lines.push(muted("Waiting for approval".to_owned()));
        if self.pending.is_empty() {
            lines.push(muted("  none".to_owned()));
        }
        for (i, a) in self.pending.iter().enumerate() {
            lines.push(row(approval_line(a), i));
        }
        lines.push(Line::raw(""));
        lines.push(muted("Devices".to_owned()));
        if self.grants.is_empty() {
            lines.push(muted("  none".to_owned()));
        }
        for (i, g) in self.grants.iter().enumerate() {
            lines.push(row(grant_line(g), self.pending.len() + i));
        }
        if let Some(typed) = &self.code {
            lines.push(Line::raw(""));
            lines.push(Line::styled(
                format!(" Code shown on the device: {typed:_<6}  (enter approves, esc cancels)"),
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ));
        }
        frame.render_widget(Paragraph::new(lines), inner);
        let hints = Rect::new(
            inner.x,
            inner.bottom().saturating_sub(1),
            inner.width,
            1.min(inner.height),
        );
        frame.render_widget(
            Paragraph::new(Line::styled(
                " a approve (type the device's code)  x deny  v revoke  m mode  r refresh  esc close",
                Style::default().fg(theme::MUTED),
            )),
            hints,
        );

        if let Some(g) = &self.confirm_revoke {
            let w = popup.width.saturating_sub(8).min(60);
            let dialog = Rect::new(
                popup.x + popup.width.saturating_sub(w) / 2,
                popup.y + popup.height / 2 - 2.min(popup.height / 2),
                w,
                5.min(popup.height),
            );
            frame.render_widget(Clear, dialog);
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(
                        format!(" Revoke {}?", safe_label(g.name.as_str())),
                        Style::default()
                            .fg(theme::TEXT)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::styled(
                        " Its tunnels close now. y revoke   any other key cancels",
                        Style::default().fg(theme::SECONDARY),
                    ),
                ])
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .border_type(BorderType::Rounded)
                        .border_style(Style::default().fg(theme::WARNING))
                        .style(Style::default().bg(theme::SURFACE)),
                ),
                dialog,
            );
        }
    }
}
