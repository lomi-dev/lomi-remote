//! Structured terminal view. No raw PTY/ANSI parser or replay queue exists here.
use crate::terminal_commands::{self as commands, Failure, LocalClient, TransportError};
use crossterm::{
    event::{
        self, DisableBracketedPaste, DisableFocusChange, EnableBracketedPaste, EnableFocusChange,
        Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers,
    },
    execute,
};
use lomi_remote_protocol::{ipc::*, rpc::*, streams::*, *};
use lomi_terminal_state::{Color as GridColor, GridPatch, Snapshot};
use ratatui::{
    Frame,
    buffer::{Buffer, CellDiffOption},
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Paragraph, Widget},
};
use std::{
    io::{self, IsTerminal},
    path::Path,
    time::{Duration, Instant},
};
const ASSEMBLY_TIME: Duration = Duration::from_secs(10);
const MAX_ASSEMBLY: usize = 8 * 1024 * 1024;
struct Initial {
    meta: TerminalSnapshotMetadata,
    chunks: SnapshotAssembly,
    bytes: Vec<u8>,
    started: Instant,
}
struct Update {
    meta: TerminalDeltaMetadata,
    chunks: DeltaAssembly,
    started: Instant,
}
enum Pending {
    Snapshot(Initial),
    Delta(Update),
}
pub struct View {
    pub context: TerminalContext,
    pub model: Option<Snapshot>,
    pub subscription: Option<SubscriptionId>,
    pub through: Option<TerminalSeq>,
    pub changed: bool,
    pub exited: bool,
    control: Option<(DecimalU64, bool)>,
    pending: Option<Pending>,
}
impl View {
    pub fn new(context: TerminalContext) -> Self {
        Self {
            context,
            model: None,
            subscription: None,
            through: None,
            changed: true,
            exited: false,
            control: None,
            pending: None,
        }
    }
    pub fn begin(&mut self, meta: TerminalSnapshotMetadata) -> Result<(), &'static str> {
        if meta.terminal != self.context || self.pending.is_some() || self.model.is_some() {
            return Err("RESYNC_REQUIRED");
        }
        let chunks = SnapshotAssembly::new(
            meta.subscription_id.clone(),
            meta.chunk_count,
            meta.total_bytes,
        )
        .map_err(|_| "RESYNC_REQUIRED")?;
        self.subscription = Some(meta.subscription_id.clone());
        self.pending = Some(Pending::Snapshot(Initial {
            meta,
            chunks,
            bytes: Vec::new(),
            started: Instant::now(),
        }));
        Ok(())
    }
    fn binding(
        &self,
        context: &TerminalContext,
        subscription: &SubscriptionId,
    ) -> Result<(), &'static str> {
        if context != &self.context || self.subscription.as_ref() != Some(subscription) {
            Err("RESYNC_REQUIRED")
        } else {
            Ok(())
        }
    }
    pub fn deadline(&self) -> Result<(), &'static str> {
        let started = match &self.pending {
            Some(Pending::Snapshot(p)) => Some(p.started),
            Some(Pending::Delta(p)) => Some(p.started),
            None => None,
        };
        if started.is_some_and(|time| time.elapsed() >= ASSEMBLY_TIME) {
            Err("ASSEMBLY_TIMEOUT")
        } else {
            Ok(())
        }
    }
    fn validate_model(&self, model: &Snapshot) -> Result<(), &'static str> {
        model.validate()?;
        if model.session_epoch.as_bytes() != &self.context.session_epoch.to_bytes()
            || model.profile != lomi_terminal_state::PROFILE
        {
            return Err("RESYNC_REQUIRED");
        }
        Ok(())
    }
    fn apply_patch(&mut self, patch: GridPatch, through: TerminalSeq) -> Result<(), &'static str> {
        if self.through != Some(TerminalSeq(patch.previous_sequence()))
            || TerminalSeq(patch.sequence()) != through
            || patch.session_epoch().as_bytes() != &self.context.session_epoch.to_bytes()
        {
            return Err("RESYNC_REQUIRED");
        }
        let previous = self.model.as_ref().ok_or("RESYNC_REQUIRED")?;
        let model = patch.apply(previous).map_err(|_| "GRID_PATCH_INVALID")?;
        self.validate_model(&model)?;
        self.model = Some(model);
        self.through = Some(through);
        self.changed = true;
        Ok(())
    }
    pub fn apply(&mut self, event: LocalStreamEvent) -> Result<(), &'static str> {
        self.deadline()?;
        let LocalStreamEvent::Terminal(frame) = event else {
            return Err("RESYNC_REQUIRED");
        };
        match frame {
            TerminalStreamFrame::SnapshotMetadata(meta) => self.begin(meta)?,
            TerminalStreamFrame::SnapshotChunk(chunk) => {
                self.binding(&chunk.terminal, &chunk.subscription_id)?;
                let Some(Pending::Snapshot(p)) = &mut self.pending else {
                    return Err("RESYNC_REQUIRED");
                };
                p.chunks
                    .push(&chunk.subscription_id, chunk.index, &chunk.bytes.0)
                    .map_err(|_| "RESYNC_REQUIRED")?;
                if chunk.bytes.0.len() > MAX_ASSEMBLY.saturating_sub(p.bytes.len()) {
                    return Err("RESYNC_REQUIRED");
                }
                p.bytes.extend(chunk.bytes.0);
            }
            TerminalStreamFrame::SnapshotComplete(complete) => {
                self.binding(&complete.terminal, &complete.subscription_id)?;
                let Some(Pending::Snapshot(p)) = self.pending.take() else {
                    return Err("RESYNC_REQUIRED");
                };
                p.chunks
                    .complete(&complete.subscription_id)
                    .map_err(|_| "RESYNC_REQUIRED")?;
                let model: Snapshot =
                    serde_json::from_slice(&p.bytes).map_err(|_| "RESYNC_REQUIRED")?;
                self.validate_model(&model)?;
                if complete.through_seq != p.meta.through_seq
                    || complete.output_offset != p.meta.output_offset
                    || model.sequence != complete.through_seq.0
                    || model.output_offset != complete.output_offset
                    || model.rows != p.meta.rows.0 as usize
                    || model.cols != p.meta.columns.0 as usize
                {
                    return Err("RESYNC_REQUIRED");
                }
                self.through = Some(complete.through_seq);
                self.model = Some(model);
                self.changed = true;
            }
            TerminalStreamFrame::DeltaMetadata(meta) => {
                self.binding(&meta.terminal, &meta.subscription_id)?;
                if self.pending.is_some() || self.model.is_none() {
                    return Err("RESYNC_REQUIRED");
                }
                let chunks =
                    DeltaAssembly::new(meta.clone(), self.through.ok_or("RESYNC_REQUIRED")?)
                        .map_err(|_| "DELTA_METADATA_INVALID")?;
                self.pending = Some(Pending::Delta(Update {
                    meta,
                    chunks,
                    started: Instant::now(),
                }));
            }
            TerminalStreamFrame::DeltaChunk(chunk) => {
                self.binding(&chunk.terminal, &chunk.subscription_id)?;
                let Some(Pending::Delta(p)) = &mut self.pending else {
                    return Err("RESYNC_REQUIRED");
                };
                p.chunks.push(&chunk).map_err(|_| "RESYNC_REQUIRED")?;
            }
            TerminalStreamFrame::DeltaComplete(complete) => {
                self.binding(&complete.terminal, &complete.subscription_id)?;
                let Some(Pending::Delta(mut p)) = self.pending.take() else {
                    return Err("RESYNC_REQUIRED");
                };
                let bytes = p
                    .chunks
                    .complete(&complete)
                    .map_err(|_| "RESYNC_REQUIRED")?;
                let patch = GridPatch::from_json(&bytes).map_err(|_| "GRID_PATCH_INVALID")?;
                if patch.previous_sequence() != p.meta.previous_seq.0 {
                    return Err("RESYNC_REQUIRED");
                }
                self.apply_patch(patch, complete.through_seq)?;
            }
            TerminalStreamFrame::Delta(delta) => {
                self.binding(&delta.terminal, &delta.subscription_id)?;
                if self.pending.is_some()
                    || self.through.and_then(|s| s.0.0.checked_add(1)) != Some(delta.seq.0.0)
                {
                    return Err("RESYNC_REQUIRED");
                }
                match delta.change {
                    TerminalChange::Grid(bytes) => self.apply_patch(
                        GridPatch::from_json(&bytes.0).map_err(|_| "GRID_PATCH_INVALID")?,
                        delta.seq,
                    )?,
                    TerminalChange::ControlChanged(control) => {
                        self.control = Some((control.lease_version, control.controlled));
                        self.through = Some(delta.seq);
                        if let Some(model) = &mut self.model {
                            model.sequence = delta.seq.0;
                        }
                        self.changed = true;
                    }
                    TerminalChange::Exit(_) => {
                        self.through = Some(delta.seq);
                        if let Some(model) = &mut self.model {
                            model.sequence = delta.seq.0;
                        }
                        self.exited = true;
                        self.changed = true;
                    }
                    TerminalChange::Resize(_) => return Err("RESYNC_REQUIRED"),
                }
            }
            TerminalStreamFrame::ResyncRequired(_) => return Err("RESYNC_REQUIRED"),
            TerminalStreamFrame::Ack(_) => return Err("RESYNC_REQUIRED"),
        }
        Ok(())
    }
}
fn color(color: &GridColor) -> Color {
    match color {
        GridColor::Default => Color::Reset,
        GridColor::Indexed { index } => Color::Indexed(*index as u8),
        GridColor::Rgb { r, g, b } => Color::Rgb(*r, *g, *b),
    }
}
pub struct Grid<'a>(pub &'a Snapshot);
impl Widget for Grid<'_> {
    fn render(self, area: Rect, buffer: &mut Buffer) {
        let model = self.0;
        let grid = if model.active == "alternate" {
            &model.alternate
        } else {
            &model.normal
        };
        for (row, line) in grid
            .lines
            .iter()
            .skip(grid.base_y)
            .take(area.height as usize)
            .enumerate()
        {
            for (column, cell) in line.cells.iter().take(area.width as usize).enumerate() {
                let target = &mut buffer[(area.x + column as u16, area.y + row as u16)];
                if cell.width == 0 {
                    target.set_diff_option(CellDiffOption::Skip);
                    continue;
                }
                if column + cell.width as usize > area.width as usize {
                    target.set_symbol(" ");
                    continue;
                }
                let mut style = Style::default().fg(color(&cell.fg)).bg(color(&cell.bg));
                for flag in &cell.flags {
                    style = match flag.as_str() {
                        "bold" => style.add_modifier(Modifier::BOLD),
                        "dim" => style.add_modifier(Modifier::DIM),
                        "italic" => style.add_modifier(Modifier::ITALIC),
                        "inverse" => style.add_modifier(Modifier::REVERSED),
                        "hidden" => style.add_modifier(Modifier::HIDDEN),
                        "strike" => style.add_modifier(Modifier::CROSSED_OUT),
                        _ => style,
                    };
                }
                if cell.underline_style != 0 {
                    style = style.add_modifier(Modifier::UNDERLINED)
                }
                let text = cell
                    .text
                    .chars()
                    .filter(|c| !c.is_control())
                    .collect::<String>();
                target
                    .set_symbol(if text.is_empty() { " " } else { &text })
                    .set_style(style);
            }
        }
    }
}
pub fn draw(frame: &mut Frame, view: &View, status: &str) {
    let [header, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(1)]).areas(frame.area());
    frame.render_widget(
        Paragraph::new(format!(
            "{}  |  F10 / Ctrl-] close view{}",
            status,
            if view.exited {
                "  |  session exited"
            } else {
                ""
            }
        )),
        header,
    );
    if let Some(model) = &view.model {
        frame.render_widget(Grid(model), body);
        let grid = if model.active == "alternate" {
            &model.alternate
        } else {
            &model.normal
        };
        if model.modes.cursor_visible
            && grid.cursor.x < body.width as usize
            && grid.cursor.y < body.height as usize
        {
            frame.set_cursor_position((
                body.x + grid.cursor.x as u16,
                body.y + grid.cursor.y as u16,
            ));
        }
    } else {
        frame.render_widget(Paragraph::new("Validating terminal snapshot..."), body);
    }
}
fn streamed_response(
    client: &mut LocalClient,
    view: &mut View,
    call: RpcCall,
) -> Result<LocalResponse, Failure> {
    let mut invalid = None;
    let response = client
        .request_with_events(
            LocalCall::Rpc(Box::new(commands::request(call))),
            &mut |event| {
                view.apply(event).map_err(|code| {
                    invalid = Some(code);
                    TransportError::InvalidFrame
                })
            },
        )
        .map_err(|_| {
            invalid.map_or_else(|| Failure::transport(None), |code| Failure::new(code, 6))
        })?;
    Ok(response)
}
fn streamed(
    client: &mut LocalClient,
    view: &mut View,
    call: RpcCall,
) -> Result<RpcResult, Failure> {
    commands::result(streamed_response(client, view, call)?, None)
}
/// Returns false only when an ordered Exit received during this ACK wait makes
/// the server's retired-subscription RESYNC_REQUIRED obsolete. No ACK success is
/// fabricated: callers must leave the acknowledged sequence unchanged.
pub fn acknowledge_rendered(
    client: &mut LocalClient,
    view: &mut View,
    through: TerminalSeq,
) -> Result<bool, Failure> {
    if view.exited || view.through != Some(through) || view.model.is_none() {
        return Err(Failure::invalid());
    }
    let subscription_id = view.subscription.clone().ok_or_else(Failure::invalid)?;
    let response = streamed_response(
        client,
        view,
        RpcCall::TerminalAck(TerminalAckParams {
            terminal: view.context.clone(),
            subscription_id,
            through_seq: through,
        }),
    )?;
    // Callback/transport failures already returned above. In particular a bad
    // Exit binding must poison transport rather than be confused with this
    // canonical remote error response.
    if view.exited
        && matches!(&response.result,Ok(LocalResult::Rpc(reply))
        if matches!(&**reply,RpcResponse::Error{error,..} if error.code()==ErrorCode::ResyncRequired))
    {
        return Ok(false);
    }
    match commands::result(response, None)? {
        RpcResult::TerminalAck(_) => Ok(true),
        _ => Err(Failure::new("INVALID_LOCAL_RESPONSE", 6)),
    }
}
struct Lease {
    wire: TerminalLeaseResult,
    expires: Instant,
    renew: Instant,
}
impl Lease {
    fn new(wire: TerminalLeaseResult, started: Instant) -> Self {
        Self {
            expires: started + Duration::from_millis(wire.expires_in_ms.get()),
            renew: started + Duration::from_secs(2),
            wire,
        }
    }
}
struct Capture;
impl Drop for Capture {
    fn drop(&mut self) {
        let _ = execute!(io::stdout(), DisableFocusChange);
        let _ = execute!(io::stdout(), DisableBracketedPaste);
    }
}
fn local_quit(key: KeyEvent) -> bool {
    key.code == KeyCode::F(10)
        || (matches!(key.code, KeyCode::Char(']' | '5'))
            && key.modifiers.contains(KeyModifiers::CONTROL))
    // Crossterm decodes the legacy Ctrl-] byte (0x1d) as Ctrl-5.
}
fn key_bytes(key: KeyEvent, model: &Snapshot) -> Option<Vec<u8>> {
    let mut bytes = match key.code {
        KeyCode::Char(ch) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            let lower = ch.to_ascii_lowercase();
            if lower.is_ascii_lowercase() {
                vec![lower as u8 - b'a' + 1]
            } else if ch == ' ' {
                vec![0]
            } else {
                return None;
            }
        }
        KeyCode::Char(ch) => {
            let mut text = [0; 4];
            ch.encode_utf8(&mut text).as_bytes().to_vec()
        }
        KeyCode::Enter => vec![b'\r'],
        KeyCode::Backspace => vec![127],
        KeyCode::Tab => vec![b'\t'],
        KeyCode::BackTab => b"\x1b[Z".to_vec(),
        KeyCode::Esc => vec![27],
        KeyCode::Up | KeyCode::Down | KeyCode::Right | KeyCode::Left => {
            let final_byte = match key.code {
                KeyCode::Up => b'A',
                KeyCode::Down => b'B',
                KeyCode::Right => b'C',
                _ => b'D',
            };
            vec![
                27,
                if model.modes.application_cursor_keys {
                    b'O'
                } else {
                    b'['
                },
                final_byte,
            ]
        }
        KeyCode::Home => b"\x1b[H".to_vec(),
        KeyCode::End => b"\x1b[F".to_vec(),
        KeyCode::Delete => b"\x1b[3~".to_vec(),
        KeyCode::Insert => b"\x1b[2~".to_vec(),
        KeyCode::PageUp => b"\x1b[5~".to_vec(),
        KeyCode::PageDown => b"\x1b[6~".to_vec(),
        _ => return None,
    };
    if key.modifiers.contains(KeyModifiers::ALT) {
        bytes.insert(0, 27)
    }
    Some(bytes)
}
fn send_input(
    client: &mut LocalClient,
    view: &mut View,
    lease: &mut Lease,
    bytes: Vec<u8>,
) -> Result<(), Failure> {
    if bytes.is_empty() || bytes.len() > 16384 {
        return Err(Failure::new("INPUT_TOO_LARGE", 2));
    }
    if Instant::now() >= lease.expires {
        return Err(Failure::new("CONTROL_EXPIRED", 4));
    }
    let submitted = bytes.len();
    let result = streamed(
        client,
        view,
        RpcCall::TerminalInput(TerminalInputParams {
            terminal: view.context.clone(),
            lease: lease.wire.lease.clone(),
            input_id: lease.wire.next_input_id,
            input_seq: lease.wire.next_input_seq,
            bytes: BoundedList(bytes),
        }),
    )
    .map_err(|error| {
        if error.code == "DAEMON_UNAVAILABLE" || error.exit == 6 {
            Failure::new("INPUT_OUTCOME_UNKNOWN_NO_REPLAY", 7)
        } else {
            error
        }
    })?;
    let RpcResult::TerminalInput(receipt) = result else {
        return Err(Failure::new("INPUT_OUTCOME_UNKNOWN_NO_REPLAY", 7));
    };
    if receipt.accepted_bytes().get() != submitted as u64 {
        return Err(Failure::new("INPUT_PARTIAL_NO_REPLAY", 7));
    }
    lease.wire.next_input_id.0 = lease
        .wire
        .next_input_id
        .0
        .checked_add(1)
        .ok_or_else(Failure::invalid)?;
    lease.wire.next_input_seq.0.0 = lease
        .wire
        .next_input_seq
        .0
        .0
        .checked_add(1)
        .ok_or_else(Failure::invalid)?;
    Ok(())
}
pub fn run(
    profile: &Path,
    workspace: WorkspaceId,
    pane: PaneId,
    control: bool,
) -> Result<(), Failure> {
    if !(io::stdin().is_terminal() && io::stdout().is_terminal()) {
        return Err(Failure::new("INTERACTIVE_TERMINAL_REQUIRED", 2));
    }
    #[cfg(target_os = "macos")]
    let mut client = commands::connect_installed_macos_host(profile)
        .map_err(|code| Failure::new(code, commands::host_failure_exit(code)))?;
    #[cfg(not(target_os = "macos"))]
    let mut client = LocalClient::connect(profile).map_err(Failure::connect)?;
    let state = commands::inspect(&mut client, workspace)?;
    let context = commands::pane(&state, pane)
        .and_then(|(_, pane)| pane.session.clone())
        .ok_or_else(|| Failure::new("SESSION_NOT_RUNNING", 4))?;
    let mut view = View::new(context.clone());
    let _restore = crate::ui::restore_guard();
    let mut terminal =
        ratatui::try_init().map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?;
    let _capture = Capture;
    execute!(io::stdout(), EnableFocusChange, EnableBracketedPaste)
        .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?;
    let result = streamed(
        &mut client,
        &mut view,
        RpcCall::TerminalAttach(TerminalReadParams {
            terminal: context.clone(),
        }),
    )?;
    let RpcResult::TerminalAttach(meta) = result else {
        return Err(Failure::new("INVALID_LOCAL_RESPONSE", 6));
    };
    view.begin(meta).map_err(|code| Failure::new(code, 6))?;
    let mut lease: Option<Lease> = None;
    let mut claim_attempted = false;
    let mut acked = None;
    let mut status = "Observer".to_owned();
    let mut resize = None;
    let mut pending_event = None;
    loop {
        view.deadline().map_err(|code| Failure::new(code, 6))?;
        let mut received = false;
        for _ in 0..16 {
            if let Some(event) = client
                .next_event(Duration::from_millis(250))
                .map_err(|_| Failure::transport(None))?
            {
                view.apply(event).map_err(|code| Failure::new(code, 6))?;
                received = true;
            } else {
                break;
            }
        }
        if let Some((version, controlled)) = view.control.take()
            && lease
                .as_ref()
                .is_some_and(|l| !controlled || l.wire.lease.version != version)
        {
            lease = None;
            status = "Observer: control revoked".to_owned();
            view.changed = true;
        }
        if view.exited {
            lease = None;
            resize = None;
            status = "Observer: session exited".to_owned();
        }
        if lease.as_ref().is_some_and(|l| Instant::now() >= l.expires) {
            lease = None;
            status = "Observer: control expired".to_owned();
            view.changed = true;
        }
        if view.changed {
            terminal
                .draw(|frame| draw(frame, &view, &status))
                .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?;
            view.changed = false;
            if let Some(through) = view.through
                && acked != Some(through)
                && !view.exited
                && acknowledge_rendered(&mut client, &mut view, through)?
            {
                acked = Some(through);
            }
        }
        // Exit may have arrived while the rendered ACK waited. Process its
        // read-only transition and final redraw before any lease/input action.
        if view.exited && view.changed {
            continue;
        }
        if control
            && !claim_attempted
            && !view.exited
            && let Some(rendered_through_seq) = acked
        {
            claim_attempted = true;
            let started = Instant::now();
            let sub = view.subscription.clone().ok_or_else(Failure::invalid)?;
            match streamed(
                &mut client,
                &mut view,
                RpcCall::TerminalClaim(TerminalClaimParams {
                    terminal: context.clone(),
                    subscription_id: sub,
                    rendered_through_seq,
                }),
            ) {
                Ok(RpcResult::TerminalClaim(wire)) => {
                    lease = Some(Lease::new(wire, started));
                    status = "Control: input and resize".to_owned();
                    let size = terminal
                        .size()
                        .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?;
                    resize = Some((size.width, size.height.saturating_sub(1), Instant::now()));
                }
                Err(error) if error.exit == 2 => status = format!("Observer: {}", error.code),
                Err(error) => return Err(error),
                _ => return Err(Failure::new("INVALID_LOCAL_RESPONSE", 6)),
            }
            view.changed = true;
        }
        if lease.as_ref().is_some_and(|l| Instant::now() >= l.renew) && !view.exited {
            let binding = lease.as_ref().unwrap().wire.lease.clone();
            let started = Instant::now();
            match streamed(
                &mut client,
                &mut view,
                RpcCall::TerminalRenew(TerminalLeaseParams {
                    terminal: context.clone(),
                    lease: binding,
                }),
            ) {
                Ok(RpcResult::TerminalRenew(wire)) => lease = Some(Lease::new(wire, started)),
                Err(error) if error.exit == 2 => {
                    lease = None;
                    status = format!("Observer: {}", error.code);
                    view.changed = true;
                }
                Err(error) => return Err(error),
                _ => return Err(Failure::new("INVALID_LOCAL_RESPONSE", 6)),
            }
        }
        if resize
            .as_ref()
            .is_some_and(|(_, _, time)| time.elapsed() >= Duration::from_millis(100))
        {
            let (columns, rows, _) = resize.take().unwrap();
            if let Some(l) = &mut lease {
                if Instant::now() >= l.expires {
                    return Err(Failure::new("CONTROL_EXPIRED", 4));
                }
                streamed(
                    &mut client,
                    &mut view,
                    RpcCall::TerminalResize(TerminalResizeParams {
                        terminal: context.clone(),
                        lease: l.wire.lease.clone(),
                        resize_seq: l.wire.next_resize_seq,
                        columns: TerminalDimension(u32::from(columns.clamp(1, 1000))),
                        rows: TerminalDimension(u32::from(rows.clamp(1, 1000))),
                    }),
                )?;
                l.wire.next_resize_seq.0.0 = l
                    .wire
                    .next_resize_seq
                    .0
                    .0
                    .checked_add(1)
                    .ok_or_else(Failure::invalid)?;
            }
        }
        if pending_event.is_none()
            && !event::poll(if received {
                Duration::ZERO
            } else {
                Duration::from_millis(250)
            })
            .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?
        {
            continue;
        }
        let event = match pending_event.take() {
            Some(event) => event,
            None => event::read().map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?,
        };
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                if local_quit(key) {
                    if let Some(l) = lease.take() {
                        let _ = streamed(
                            &mut client,
                            &mut view,
                            RpcCall::TerminalRelease(TerminalLeaseParams {
                                terminal: context.clone(),
                                lease: l.wire.lease,
                            }),
                        );
                    }
                    return Ok(());
                }
                if let (Some(l), Some(model)) = (&mut lease, &view.model)
                    && !view.exited
                    && let Some(mut bytes) = key_bytes(key, model)
                {
                    // Coalesce only currently available keys into one bounded write.
                    // No input survives this iteration or any uncertain receipt.
                    for _ in 0..127 {
                        if !event::poll(Duration::ZERO)
                            .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?
                        {
                            break;
                        }
                        let next = event::read()
                            .map_err(|_| Failure::new("TERMINAL_UI_UNAVAILABLE", 4))?;
                        if let Event::Key(next_key) = next
                            && next_key.kind == KeyEventKind::Press
                            && !local_quit(next_key)
                            && let Some(next_bytes) = key_bytes(next_key, model)
                            && bytes.len() + next_bytes.len() <= 16384
                        {
                            bytes.extend(next_bytes);
                        } else {
                            pending_event = Some(next);
                            break;
                        }
                    }
                    send_input(&mut client, &mut view, l, bytes)?;
                }
            }
            Event::Resize(columns, rows) => {
                resize = Some((columns, rows.saturating_sub(1), Instant::now()));
                view.changed = true;
            }
            Event::FocusLost => {
                if let Some(l) = lease.take() {
                    let _ = streamed(
                        &mut client,
                        &mut view,
                        RpcCall::TerminalRelease(TerminalLeaseParams {
                            terminal: context.clone(),
                            lease: l.wire.lease,
                        }),
                    );
                    status = "Observer: focus lost".to_owned();
                    view.changed = true;
                }
            }
            Event::Paste(text) => {
                if let Some(l) = &mut lease {
                    let mut bytes = text.into_bytes();
                    if view.model.as_ref().is_some_and(|m| m.modes.bracketed_paste) {
                        let mut wrapped = b"\x1b[200~".to_vec();
                        wrapped.append(&mut bytes);
                        wrapped.extend(b"\x1b[201~");
                        bytes = wrapped;
                    }
                    if bytes.is_empty() {
                        continue;
                    }
                    if bytes.len() > 16384 {
                        status = "Paste exceeds 16 KiB; nothing sent".to_owned();
                        view.changed = true;
                    } else {
                        send_input(&mut client, &mut view, l, bytes)?;
                    }
                }
            }
            _ => {}
        }
    }
}
