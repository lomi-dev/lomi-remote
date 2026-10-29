//! Experimental authoritative terminal state. Snapshots never replay bytes or reset the parser.
mod cwd;
mod patch;
pub use patch::{GRID_PATCH_FORMAT, GridPatch, GridUpdate};

use alacritty_terminal::{
    Term,
    event::{Event, EventListener, WindowSize},
    grid::{Dimensions, Grid},
    index::{Column, Line},
    term::{
        Config, Osc52, TermMode,
        cell::{Cell as EngineCell, Flags},
    },
    vte::ansi::{Color as EngineColor, CursorShape, NamedColor, Processor, Rgb},
};
use lomi_remote_protocol::{DecimalU64, SessionEpoch};
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Instant,
};
use uuid::Uuid;
fn required_option<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}
pub const PROFILE: &str = "lomi-rust-grid-v1-experimental";
pub const MAX_SNAPSHOT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_OUTPUT_CHUNK: usize = 64 * 1024;
pub const MAX_CELLS: usize = 32_768;
const MAX_REPLY_BYTES: usize = 8192;
const MAX_REPLIES: usize = 64;
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum Color {
    Default,
    Indexed { index: u16 },
    Rgb { r: u8, g: u8, b: u8 },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RgbColor {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hyperlink {
    pub id: String,
    pub uri: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Cell {
    pub text: String,
    pub width: u8,
    pub fg: Color,
    pub bg: Color,
    pub flags: Vec<String>,
    pub underline_style: u8,
    #[serde(deserialize_with = "required_option")]
    pub underline_color: Option<Color>,
    #[serde(deserialize_with = "required_option")]
    pub hyperlink: Option<Hyperlink>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Row {
    pub wrapped: bool,
    pub cells: Vec<Cell>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub x: usize,
    pub y: usize,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Buffer {
    pub lines: Vec<Row>,
    pub base_y: usize,
    pub cursor: Cursor,
    pub saved_cursor: Cursor,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Modes {
    pub application_cursor_keys: bool,
    pub application_keypad: bool,
    pub bracketed_paste: bool,
    pub insert: bool,
    pub origin: bool,
    pub wraparound: bool,
    pub send_focus: bool,
    pub cursor_visible: bool,
    pub mouse_tracking: String,
    pub mouse_encoding: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorStyle {
    pub shape: String,
    pub blinking: bool,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    rename_all = "camelCase",
    deny_unknown_fields,
    try_from = "SnapshotWire"
)]
pub struct Snapshot {
    pub profile: String,
    pub version: u8,
    pub session_epoch: Uuid,
    pub sequence: DecimalU64,
    pub output_offset: DecimalU64,
    pub rows: usize,
    pub cols: usize,
    pub active: String,
    pub normal: Buffer,
    pub alternate: Buffer,
    pub modes: Modes,
    #[serde(deserialize_with = "required_option")]
    pub title: Option<String>,
    pub cursor_style: CursorStyle,
    pub colors: Vec<Option<RgbColor>>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotWire {
    profile: String,
    version: u8,
    session_epoch: Uuid,
    sequence: DecimalU64,
    output_offset: DecimalU64,
    rows: usize,
    cols: usize,
    active: String,
    normal: Buffer,
    alternate: Buffer,
    modes: Modes,
    #[serde(deserialize_with = "required_option")]
    title: Option<String>,
    cursor_style: CursorStyle,
    colors: Vec<Option<RgbColor>>,
}
impl TryFrom<SnapshotWire> for Snapshot {
    type Error = &'static str;
    fn try_from(w: SnapshotWire) -> Result<Self, Self::Error> {
        let value = Self {
            profile: w.profile,
            version: w.version,
            session_epoch: w.session_epoch,
            sequence: w.sequence,
            output_offset: w.output_offset,
            rows: w.rows,
            cols: w.cols,
            active: w.active,
            normal: w.normal,
            alternate: w.alternate,
            modes: w.modes,
            title: w.title,
            cursor_style: w.cursor_style,
            colors: w.colors,
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, try_from = "DeltaWire")]
pub struct Delta {
    pub profile: String,
    pub version: u8,
    pub session_epoch: Uuid,
    pub previous_sequence: DecimalU64,
    pub state: Snapshot,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DeltaWire {
    profile: String,
    version: u8,
    session_epoch: Uuid,
    previous_sequence: DecimalU64,
    state: Snapshot,
}
impl TryFrom<DeltaWire> for Delta {
    type Error = &'static str;
    fn try_from(w: DeltaWire) -> Result<Self, Self::Error> {
        let value = Self {
            profile: w.profile,
            version: w.version,
            session_epoch: w.session_epoch,
            previous_sequence: w.previous_sequence,
            state: w.state,
        };
        value.validate()?;
        Ok(value)
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidDimensions,
    OutputTooLarge,
    SnapshotTooLarge,
    CounterOverflow,
    InvalidState,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostStats {
    pub dropped_replies: u64,
    pub unsupported_events: u64,
}
#[derive(Default)]
struct Replies {
    queue: VecDeque<String>,
    bytes: usize,
    stats: HostStats,
    rows: u16,
    cols: u16,
}
#[derive(Clone, Default)]
pub struct HostEventListener(Arc<Mutex<Replies>>);
impl HostEventListener {
    fn push(replies: &mut Replies, text: String) {
        if replies.queue.len() >= MAX_REPLIES || text.len() > MAX_REPLY_BYTES - replies.bytes {
            replies.stats.dropped_replies = replies.stats.dropped_replies.saturating_add(1);
        } else {
            replies.bytes += text.len();
            replies.queue.push_back(text);
        }
    }
}
impl EventListener for HostEventListener {
    fn send_event(&self, event: Event) {
        let mut r = self.0.lock().expect("reply lock");
        let reply = match event {
            Event::PtyWrite(s) => Some(s),
            Event::ColorRequest(i, f) => Some(f(default_color(i))),
            Event::TextAreaSizeRequest(f) => Some(f(WindowSize {
                num_lines: r.rows,
                num_cols: r.cols,
                cell_width: 8,
                cell_height: 16,
            })),
            Event::ClipboardLoad(..) | Event::ClipboardStore(..) => {
                r.stats.unsupported_events = r.stats.unsupported_events.saturating_add(1);
                None
            }
            _ => None,
        };
        if let Some(text) = reply {
            Self::push(&mut r, text);
        }
    }
}
fn default_color(i: usize) -> Rgb {
    let (r, g, b) = match i {
        0..=15 => {
            let v = if i & 8 != 0 { 255 } else { 170 };
            (
                if i & 1 != 0 { v } else { 0 },
                if i & 2 != 0 { v } else { 0 },
                if i & 4 != 0 { v } else { 0 },
            )
        }
        16..=231 => {
            let n = i - 16;
            let level = |n| if n == 0 { 0 } else { 55 + 40 * n as u8 };
            (level(n / 36), level(n / 6 % 6), level(n % 6))
        }
        232..=255 => {
            let n = 8 + 10 * (i - 232) as u8;
            (n, n, n)
        }
        257 => (0, 0, 0),
        _ => (229, 229, 229),
    };
    Rgb { r, g, b }
}
struct Size(usize, usize);
impl Dimensions for Size {
    fn total_lines(&self) -> usize {
        self.0
    }
    fn screen_lines(&self) -> usize {
        self.0
    }
    fn columns(&self) -> usize {
        self.1
    }
}
pub struct TerminalState {
    term: Term<HostEventListener>,
    parser: Processor,
    cwd_parser: cwd::Osc7Parser,
    working_directory: Option<String>,
    listener: HostEventListener,
    epoch: Uuid,
    sequence: u64,
    offset: u64,
    rows: usize,
    cols: usize,
    history: usize,
    faulted: bool,
}
impl TerminalState {
    pub fn new(rows: usize, cols: usize, history: usize) -> Result<Self, Error> {
        let epoch = SessionEpoch::from_bytes(*Uuid::new_v4().as_bytes())
            .map_err(|_| Error::InvalidState)?;
        Self::new_with_epoch(rows, cols, history, epoch)
    }
    /// Bind the sole parser to the same nonnil epoch as the host's persisted
    /// session descriptor. The typed epoch cannot represent nil UUIDs.
    pub fn new_with_epoch(
        rows: usize,
        cols: usize,
        history: usize,
        epoch: SessionEpoch,
    ) -> Result<Self, Error> {
        Self::check_size(rows, cols, history)?;
        let listener = HostEventListener::default();
        {
            let mut r = listener.0.lock().expect("reply lock");
            r.rows = rows as u16;
            r.cols = cols as u16;
        }
        let term = Term::new(
            Config {
                scrolling_history: history,
                kitty_keyboard: false,
                osc52: Osc52::Disabled,
                ..Config::default()
            },
            &Size(rows, cols),
            listener.clone(),
        );
        Ok(Self {
            term,
            parser: Processor::new(),
            cwd_parser: cwd::Osc7Parser::default(),
            working_directory: None,
            listener,
            epoch: Uuid::from_bytes(epoch.to_bytes()),
            sequence: 0,
            offset: 0,
            rows,
            cols,
            history,
            faulted: false,
        })
    }
    fn check_size(rows: usize, cols: usize, history: usize) -> Result<(), Error> {
        if !(2..=256).contains(&rows)
            || !(2..=512).contains(&cols)
            || history > 4096
            || rows
                .checked_mul(2)
                .and_then(|r| r.checked_add(history))
                .and_then(|r| r.checked_mul(cols))
                .is_none_or(|c| c > MAX_CELLS)
        {
            Err(Error::InvalidDimensions)
        } else {
            Ok(())
        }
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.faulted {
            return Err(Error::SnapshotTooLarge);
        }
        if bytes.len() > MAX_OUTPUT_CHUNK {
            return Err(Error::OutputTooLarge);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::CounterOverflow)?;
        let offset = self
            .offset
            .checked_add(bytes.len() as u64)
            .ok_or(Error::CounterOverflow)?;
        if let Some(path) = self.cwd_parser.advance(bytes) {
            self.working_directory = Some(path);
        }
        self.parser.advance(&mut self.term, bytes);
        self.sequence = sequence;
        self.offset = offset;
        if self.check_budget().is_err() {
            self.faulted = true;
            return Err(Error::SnapshotTooLarge);
        }
        Ok(())
    }
    /// The most recent valid Host-side OSC 7 path, when the shell has reported
    /// one. This advisory metadata never changes the terminal grid or authority.
    pub fn working_directory(&self) -> Option<&str> {
        self.working_directory.as_deref()
    }
    /// The owner must schedule this monotonic deadline even when the PTY is
    /// idle. Taking an observer snapshot must never flush the parser itself.
    pub fn sync_deadline(&self) -> Option<Instant> {
        self.parser.sync_timeout().sync_timeout()
    }
    /// Flush an expired synchronized update as one ordered host event. A true
    /// result requires publishing a delta, just like feed/resize, but accepts
    /// no new output bytes. Call from the owner timer, never from an observer.
    pub fn expire_sync(&mut self, now: Instant) -> Result<bool, Error> {
        if self.faulted {
            return Err(Error::SnapshotTooLarge);
        }
        if self.sync_deadline().is_none_or(|deadline| now < deadline) {
            return Ok(false);
        }
        let sequence = self.sequence.checked_add(1).ok_or(Error::CounterOverflow)?;
        self.parser.stop_sync(&mut self.term);
        self.sequence = sequence;
        if self.check_budget().is_err() {
            self.faulted = true;
            return Err(Error::SnapshotTooLarge);
        }
        Ok(true)
    }
    pub fn resize(&mut self, rows: usize, cols: usize) -> Result<(), Error> {
        if self.faulted {
            return Err(Error::SnapshotTooLarge);
        }
        Self::check_size(rows, cols, self.history)?;
        let sequence = self.sequence.checked_add(1).ok_or(Error::CounterOverflow)?;
        self.term.resize(Size(rows, cols));
        self.rows = rows;
        self.cols = cols;
        self.sequence = sequence;
        let mut r = self.listener.0.lock().expect("reply lock");
        r.rows = rows as u16;
        r.cols = cols as u16;
        drop(r);
        if self.check_budget().is_err() {
            self.faulted = true;
            return Err(Error::SnapshotTooLarge);
        }
        Ok(())
    }
    pub fn take_replies(&mut self) -> Vec<String> {
        let mut r = self.listener.0.lock().expect("reply lock");
        r.bytes = 0;
        r.queue.drain(..).collect()
    }
    pub fn stats(&self) -> HostStats {
        self.listener.0.lock().expect("reply lock").stats.clone()
    }
    fn check_budget(&self) -> Result<(), Error> {
        let (normal, alternate) = self.term.checkpoint_grids();
        let mut size = 0usize;
        for grid in [normal, alternate] {
            for line in -(grid.history_size() as i32)..grid.screen_lines() as i32 {
                for col in 0..grid.columns() {
                    let c = &grid[Line(line)][Column(col)];
                    size = size.saturating_add(
                        256 + c.zerowidth().map_or(0, |v| v.len() * 6)
                            + c.hyperlink()
                                .map_or(0, |h| (h.id().len() + h.uri().len()) * 6),
                    );
                    if size > MAX_SNAPSHOT_BYTES {
                        return Err(Error::SnapshotTooLarge);
                    }
                }
            }
        }
        Ok(())
    }
    pub fn snapshot(&self) -> Result<Snapshot, Error> {
        self.check_budget()?;
        let (normal, alternate) = self.term.checkpoint_grids();
        let m = *self.term.mode();
        let style = self.term.cursor_style();
        let snapshot = Snapshot {
            profile: PROFILE.into(),
            version: 1,
            session_epoch: self.epoch,
            sequence: DecimalU64(self.sequence),
            output_offset: DecimalU64(self.offset),
            rows: self.rows,
            cols: self.cols,
            active: if m.contains(TermMode::ALT_SCREEN) {
                "alternate"
            } else {
                "normal"
            }
            .into(),
            normal: buffer(normal),
            alternate: buffer(alternate),
            modes: Modes {
                application_cursor_keys: m.contains(TermMode::APP_CURSOR),
                application_keypad: m.contains(TermMode::APP_KEYPAD),
                bracketed_paste: m.contains(TermMode::BRACKETED_PASTE),
                insert: m.contains(TermMode::INSERT),
                origin: m.contains(TermMode::ORIGIN),
                wraparound: m.contains(TermMode::LINE_WRAP),
                send_focus: m.contains(TermMode::FOCUS_IN_OUT),
                cursor_visible: m.contains(TermMode::SHOW_CURSOR),
                mouse_tracking: if m.contains(TermMode::MOUSE_MOTION) {
                    "any"
                } else if m.contains(TermMode::MOUSE_DRAG) {
                    "drag"
                } else if m.contains(TermMode::MOUSE_REPORT_CLICK) {
                    "vt200"
                } else {
                    "none"
                }
                .into(),
                mouse_encoding: if m.contains(TermMode::SGR_MOUSE) {
                    "sgr"
                } else if m.contains(TermMode::UTF8_MOUSE) {
                    "utf8"
                } else {
                    "default"
                }
                .into(),
            },
            title: self.term.checkpoint_title().map(|s| project_text(s, 4096)),
            cursor_style: CursorStyle {
                shape: match style.shape {
                    CursorShape::Underline => "underline",
                    CursorShape::Beam => "bar",
                    _ => "block",
                }
                .into(),
                blinking: style.blinking,
            },
            colors: (0..269)
                .map(|i| {
                    self.term.colors()[i].map(|c| RgbColor {
                        r: c.r,
                        g: c.g,
                        b: c.b,
                    })
                })
                .collect(),
        };
        snapshot.validate().map_err(|_| Error::InvalidState)?;
        if serde_json::to_vec(&snapshot)
            .map_err(|_| Error::InvalidState)?
            .len()
            > MAX_SNAPSHOT_BYTES
        {
            return Err(Error::SnapshotTooLarge);
        }
        Ok(snapshot)
    }
    pub fn next_delta(&self, previous: &Snapshot) -> Result<Delta, Error> {
        previous.validate().map_err(|_| Error::InvalidState)?;
        if previous.session_epoch != self.epoch
            || previous.sequence.0.checked_add(1) != Some(self.sequence)
            || previous.output_offset.0 > self.offset
        {
            return Err(Error::InvalidState);
        }
        Ok(Delta {
            profile: PROFILE.into(),
            version: 1,
            session_epoch: self.epoch,
            previous_sequence: previous.sequence,
            state: self.snapshot()?,
        })
    }
}
fn color(c: EngineColor) -> Color {
    match c {
        EngineColor::Spec(c) => Color::Rgb {
            r: c.r,
            g: c.g,
            b: c.b,
        },
        EngineColor::Indexed(index) => Color::Indexed {
            index: index.into(),
        },
        EngineColor::Named(NamedColor::Foreground | NamedColor::Background) => Color::Default,
        EngineColor::Named(n) => Color::Indexed { index: n as u16 },
    }
}
// JavaScript string.length counts UTF-16 units. Rust strings cannot contain
// lone surrogates; the remaining forbidden code points match the renderer's C0/C1 policy.
fn valid_text(text: &str, max: usize) -> bool {
    text.encode_utf16().count() <= max && !text.chars().any(char::is_control)
}
fn project_text(text: &str, max: usize) -> String {
    let mut units = 0;
    text.chars()
        .filter(|c| !c.is_control())
        .take_while(|c| {
            units += c.len_utf16();
            units <= max
        })
        .collect()
}
fn valid_hyperlink(link: &Hyperlink) -> bool {
    valid_text(&link.id, 1024)
        && valid_text(&link.uri, 4096)
        && link.uri.split_once(':').is_some_and(|(scheme, _)| {
            ["http", "https", "mailto"]
                .iter()
                .any(|allowed| scheme.eq_ignore_ascii_case(allowed))
        })
        && url::Url::parse(&link.uri).is_ok()
}
fn cell(c: &EngineCell) -> Cell {
    let spacer = c.flags.contains(Flags::WIDE_CHAR_SPACER);
    let mut text = if spacer {
        String::new()
    } else {
        c.c.to_string()
    };
    if !spacer && let Some(extra) = c.zerowidth() {
        text.extend(extra);
    }
    text = project_text(&text, 128);
    let flags = [
        (Flags::BOLD, "bold"),
        (Flags::DIM, "dim"),
        (Flags::ITALIC, "italic"),
        (Flags::INVERSE, "inverse"),
        (Flags::HIDDEN, "hidden"),
        (Flags::STRIKEOUT, "strike"),
    ]
    .into_iter()
    .filter(|(flag, _)| c.flags.contains(*flag))
    .map(|(_, name)| name.into())
    .collect();
    let underline_style = [
        Flags::UNDERLINE,
        Flags::DOUBLE_UNDERLINE,
        Flags::UNDERCURL,
        Flags::DOTTED_UNDERLINE,
        Flags::DASHED_UNDERLINE,
    ]
    .iter()
    .position(|f| c.flags.contains(*f))
    .map_or(0, |i| i as u8 + 1);
    Cell {
        text,
        width: if spacer {
            0
        } else if c.flags.contains(Flags::WIDE_CHAR) {
            2
        } else {
            1
        },
        fg: color(c.fg),
        bg: color(c.bg),
        flags,
        underline_style,
        underline_color: c.underline_color().map(color),
        hyperlink: c.hyperlink().and_then(|h| {
            let link = Hyperlink {
                id: h.id().into(),
                uri: h.uri().into(),
            };
            valid_hyperlink(&link).then_some(link)
        }),
    }
}
fn buffer(grid: &Grid<EngineCell>) -> Buffer {
    let history = grid.history_size();
    let mut wrapped = false;
    let lines = (-(history as i32)..grid.screen_lines() as i32)
        .map(|line| {
            let row = &grid[Line(line)];
            let cells = (0..grid.columns())
                .map(|col| cell(&row[Column(col)]))
                .collect();
            let result = Row { wrapped, cells };
            wrapped = row[Column(grid.columns() - 1)]
                .flags
                .contains(Flags::WRAPLINE);
            result
        })
        .collect();
    let cursor = |c: &alacritty_terminal::grid::Cursor<EngineCell>| Cursor {
        x: if c.input_needs_wrap {
            grid.columns()
        } else {
            c.point.column.0
        },
        y: c.point.line.0 as usize,
    };
    Buffer {
        lines,
        base_y: history,
        cursor: cursor(&grid.cursor),
        saved_cursor: cursor(&grid.saved_cursor),
    }
}

impl Snapshot {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.profile != PROFILE || self.version != 1 {
            return Err("unsupported terminal profile");
        }
        TerminalState::check_size(self.rows, self.cols, self.normal.base_y)
            .map_err(|_| "invalid dimensions")?;
        if !["normal", "alternate"].contains(&self.active.as_str())
            || self.colors.len() != 269
            || self.colors[259..].iter().any(Option::is_some)
        {
            return Err("unsupported buffer or palette");
        }
        if !["block", "underline", "bar"].contains(&self.cursor_style.shape.as_str())
            || !["none", "x10", "vt200", "drag", "any"]
                .contains(&self.modes.mouse_tracking.as_str())
            || !["default", "utf8", "sgr"].contains(&self.modes.mouse_encoding.as_str())
        {
            return Err("invalid terminal modes");
        }
        if self
            .title
            .as_ref()
            .is_some_and(|title| !valid_text(title, 4096))
        {
            return Err("invalid title text");
        }
        for (b, alternate) in [(&self.normal, false), (&self.alternate, true)] {
            if b.lines.len() != b.base_y + self.rows
                || (alternate && b.base_y != 0)
                || b.cursor.x > self.cols
                || b.saved_cursor.x > self.cols
                || b.cursor.y >= self.rows
                || b.saved_cursor.y >= self.rows
            {
                return Err("invalid buffer geometry");
            }
            for row in &b.lines {
                if row.cells.len() != self.cols {
                    return Err("invalid row width");
                }
                for (i, c) in row.cells.iter().enumerate() {
                    if !valid_text(&c.text, 128)
                        || c.hyperlink
                            .as_ref()
                            .is_some_and(|link| !valid_hyperlink(link))
                    {
                        return Err("invalid cell text or hyperlink");
                    }
                    if c.flags
                        .iter()
                        .collect::<std::collections::BTreeSet<_>>()
                        .len()
                        != c.flags.len()
                        || c.width > 2
                        || c.underline_style > 5
                        || c.flags.iter().any(|f| {
                            ![
                                "bold", "dim", "italic", "inverse", "hidden", "strike", "blink",
                            ]
                            .contains(&f.as_str())
                        })
                    {
                        return Err("invalid cell attributes");
                    }
                    for color in [&c.fg, &c.bg].into_iter().chain(c.underline_color.iter()) {
                        if matches!(color,Color::Indexed{index} if *index>255) {
                            return Err("invalid color index");
                        }
                    }
                    if (c.width == 0
                        && (!c.text.is_empty() || i == 0 || row.cells[i - 1].width != 2))
                        || (c.width == 2 && (i + 1 >= self.cols || row.cells[i + 1].width != 0))
                    {
                        return Err("invalid wide cell");
                    }
                }
            }
        }
        Ok(())
    }
}
impl Delta {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.state.validate()?;
        if self.profile != PROFILE
            || self.version != 1
            || self.session_epoch != self.state.session_epoch
            || self.previous_sequence.0.checked_add(1) != Some(self.state.sequence.0)
        {
            return Err("invalid delta sequence");
        }
        Ok(())
    }
}
