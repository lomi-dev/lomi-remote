//! Read-only local directory browser for selecting a workspace location.

use super::{safe_label, shortcuts, theme};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const POPUP_MAX_WIDTH: u16 = 88;
const POPUP_MAX_HEIGHT: u16 = 28;
const MAX_DIRECTORIES: usize = 500;
const DOUBLE_CLICK_INTERVAL: Duration = Duration::from_millis(450);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum PickerAction {
    None,
    Cancel,
    Select(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    List,
    Cancel,
    Select,
}

#[derive(Debug)]
struct DirectoryEntry {
    label: String,
    path: PathBuf,
}

#[derive(Debug, Default)]
struct Listing {
    directories: Vec<DirectoryEntry>,
    truncated: bool,
    unreadable: bool,
}

/// A modal that browses existing local directories without modifying them.
pub(super) struct DirectoryPicker {
    current: PathBuf,
    directories: Vec<DirectoryEntry>,
    truncated: bool,
    status: Option<&'static str>,
    selected: usize,
    focus: Focus,
    scroll_offset: Cell<usize>,
    list_area: Cell<Rect>,
    cancel_area: Cell<Rect>,
    select_area: Cell<Rect>,
    last_click: Option<(usize, Instant)>,
}

impl DirectoryPicker {
    pub(super) fn new(start: PathBuf) -> Self {
        let (current, status) = match canonical_directory(&start) {
            Some(path) => (path, None),
            None => match start
                .parent()
                .and_then(parent_path)
                .and_then(|path| canonical_directory(&path))
            {
                Some(path) => (
                    path,
                    Some("Starting directory unavailable; showing its parent."),
                ),
                None => (start, Some("Starting directory is unavailable.")),
            },
        };

        let mut picker = Self {
            current,
            directories: Vec::new(),
            truncated: false,
            status,
            selected: 0,
            focus: Focus::List,
            scroll_offset: Cell::new(0),
            list_area: Cell::new(Rect::default()),
            cancel_area: Cell::new(Rect::default()),
            select_area: Cell::new(Rect::default()),
            last_click: None,
        };
        picker.reload();
        picker
    }

    pub(super) fn draw(&self, frame: &mut Frame) {
        shortcuts::dim_frame(frame);
        let area = frame.area();
        if area.is_empty() {
            self.clear_hit_areas();
            return;
        }

        let popup = centered_popup(area);
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(theme::BORDER))
            .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
            .title(Span::styled(
                " Select directory ",
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ))
            .title_alignment(Alignment::Center);
        let content = block.inner(popup);

        frame.render_widget(Clear, popup);
        frame.render_widget(block, popup);

        if content.is_empty() {
            self.clear_hit_areas();
            return;
        }

        let status = self.status.or_else(|| {
            self.truncated
                .then_some("Showing the first 500 directories in this folder.")
        });
        let button_rows = if content.width >= 36 { 1 } else { 2 };
        let visible_button_rows = button_rows.min(content.height);
        let buttons_y = content.bottom().saturating_sub(visible_button_rows);
        let status_y = if status.is_some() && buttons_y > content.y {
            Some(buttons_y - 1)
        } else {
            None
        };
        let path_y = content.y;
        let list_y = content.y.saturating_add(1);
        let list_bottom = status_y.unwrap_or(buttons_y);
        let list_height = list_bottom.saturating_sub(list_y);
        let path_area = Rect::new(content.x, path_y, content.width, 1.min(content.height));
        let list_area = Rect::new(content.x, list_y, content.width, list_height);
        self.list_area.set(list_area);

        let path = safe_label(&self.current.to_string_lossy());
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("Current: ", Style::default().fg(theme::MUTED)),
                Span::styled(path, Style::default().fg(theme::SECONDARY)),
            ])),
            path_area,
        );

        let rows = self.rows();
        let visible_count = usize::from(list_height);
        let mut offset = self.scroll_offset.get();
        if self.selected < offset {
            offset = self.selected;
        } else if visible_count > 0 && self.selected >= offset.saturating_add(visible_count) {
            offset = self
                .selected
                .saturating_add(1)
                .saturating_sub(visible_count);
        }
        let max_offset = rows.len().saturating_sub(visible_count);
        offset = offset.min(max_offset);
        self.scroll_offset.set(offset);

        for (visible_row, row) in rows.iter().skip(offset).take(visible_count).enumerate() {
            let row_area = Rect::new(
                list_area.x,
                list_area.y.saturating_add(visible_row as u16),
                list_area.width,
                1,
            );
            let row_index = offset + visible_row;
            let selected = row_index == self.selected;
            let style = if selected {
                theme::selection_style(self.focus == Focus::List)
            } else {
                Style::default().fg(theme::SECONDARY).bg(theme::SURFACE)
            };
            frame.render_widget(
                Paragraph::new(safe_label(&row.label)).style(style),
                row_area,
            );
        }

        if let (Some(status), Some(y)) = (status, status_y) {
            let style = if self.status.is_some() {
                Style::default().fg(theme::ERROR)
            } else {
                Style::default().fg(theme::WARNING)
            };
            frame.render_widget(
                Paragraph::new(safe_label(status)).style(style),
                Rect::new(content.x, y, content.width, 1),
            );
        }

        self.draw_buttons(frame, content, buttons_y, visible_button_rows);
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> PickerAction {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return PickerAction::None;
        }
        match key.code {
            KeyCode::Esc => PickerAction::Cancel,
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Cancel,
                    Focus::Cancel => Focus::Select,
                    Focus::Select => Focus::List,
                };
                PickerAction::None
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::List => Focus::Select,
                    Focus::Cancel => Focus::List,
                    Focus::Select => Focus::Cancel,
                };
                PickerAction::None
            }
            KeyCode::Up => {
                match self.focus {
                    Focus::List => self.move_selection(-1),
                    Focus::Cancel | Focus::Select => self.focus = Focus::List,
                }
                PickerAction::None
            }
            KeyCode::Down => {
                match self.focus {
                    Focus::List if self.selected + 1 >= self.row_count() => {
                        if !self.cancel_area.get().is_empty() {
                            self.focus = Focus::Cancel;
                        }
                    }
                    Focus::List => self.move_selection(1),
                    Focus::Cancel if !self.select_area.get().is_empty() => {
                        self.focus = Focus::Select;
                    }
                    Focus::Cancel | Focus::Select => {}
                }
                PickerAction::None
            }
            KeyCode::PageUp => {
                self.focus = Focus::List;
                self.move_selection(-(self.list_area.get().height.max(1) as isize));
                PickerAction::None
            }
            KeyCode::PageDown => {
                self.focus = Focus::List;
                self.move_selection(self.list_area.get().height.max(1) as isize);
                PickerAction::None
            }
            KeyCode::Home => {
                self.focus = Focus::List;
                self.selected = 0;
                self.scroll_offset.set(0);
                PickerAction::None
            }
            KeyCode::End => {
                self.focus = Focus::List;
                self.selected = self.row_count().saturating_sub(1);
                PickerAction::None
            }
            KeyCode::Left => {
                match self.focus {
                    Focus::List => self.go_parent(),
                    Focus::Select if !self.cancel_area.get().is_empty() => {
                        self.focus = Focus::Cancel;
                    }
                    Focus::Cancel | Focus::Select => {}
                }
                PickerAction::None
            }
            KeyCode::Backspace => {
                self.go_parent();
                PickerAction::None
            }
            KeyCode::Right => {
                match self.focus {
                    Focus::List => self.enter_selected(),
                    Focus::Cancel if !self.select_area.get().is_empty() => {
                        self.focus = Focus::Select;
                    }
                    Focus::Cancel | Focus::Select => {}
                }
                PickerAction::None
            }
            KeyCode::Enter => match self.focus {
                Focus::List => {
                    self.enter_selected();
                    PickerAction::None
                }
                Focus::Cancel => PickerAction::Cancel,
                Focus::Select => self.select_current(),
            },
            _ => PickerAction::None,
        }
    }

    pub(super) fn handle_mouse(&mut self, event: MouseEvent) -> PickerAction {
        match event.kind {
            MouseEventKind::ScrollUp => {
                if self
                    .list_area
                    .get()
                    .contains((event.column, event.row).into())
                {
                    self.focus = Focus::List;
                    self.move_selection(-1);
                }
                PickerAction::None
            }
            MouseEventKind::ScrollDown => {
                if self
                    .list_area
                    .get()
                    .contains((event.column, event.row).into())
                {
                    self.focus = Focus::List;
                    self.move_selection(1);
                }
                PickerAction::None
            }
            MouseEventKind::Down(MouseButton::Left) => {
                let position = (event.column, event.row);
                if self.cancel_area.get().contains(position.into()) {
                    self.last_click = None;
                    self.focus = Focus::Cancel;
                    return PickerAction::Cancel;
                }
                if self.select_area.get().contains(position.into()) {
                    self.last_click = None;
                    self.focus = Focus::Select;
                    return self.select_current();
                }
                let list_area = self.list_area.get();
                if list_area.contains(position.into()) {
                    let row_index = self
                        .scroll_offset
                        .get()
                        .saturating_add(usize::from(event.row.saturating_sub(list_area.y)));
                    if row_index < self.row_count() {
                        self.focus = Focus::List;
                        self.selected = row_index;
                        let now = Instant::now();
                        let double_click = self.last_click.is_some_and(|(previous, time)| {
                            previous == row_index
                                && now.duration_since(time) <= DOUBLE_CLICK_INTERVAL
                        });
                        self.last_click = Some((row_index, now));
                        if double_click {
                            self.last_click = None;
                            self.enter_selected();
                        }
                    }
                } else {
                    self.last_click = None;
                }
                PickerAction::None
            }
            _ => PickerAction::None,
        }
    }

    /// Whether a painted button or actual visible directory row is hoverable.
    /// Blank space in the list viewport remains an arrow-pointer target.
    pub(super) fn hoverable(&self, column: u16, row: u16) -> bool {
        let position = (column, row).into();
        if self.cancel_area.get().contains(position) || self.select_area.get().contains(position) {
            return true;
        }

        let list_area = self.list_area.get();
        if !list_area.contains(position) {
            return false;
        }
        let row_index = self
            .scroll_offset
            .get()
            .saturating_add(usize::from(row.saturating_sub(list_area.y)));
        row_index < self.row_count()
    }

    fn clear_hit_areas(&self) {
        self.list_area.set(Rect::default());
        self.cancel_area.set(Rect::default());
        self.select_area.set(Rect::default());
    }

    fn rows(&self) -> Vec<DirectoryEntry> {
        let mut rows = Vec::with_capacity(self.directories.len().saturating_add(1));
        if let Some(parent) = self.current.parent() {
            rows.push(DirectoryEntry {
                label: "..".to_owned(),
                path: parent.to_path_buf(),
            });
        }
        rows.extend(self.directories.iter().map(|entry| DirectoryEntry {
            label: entry.label.clone(),
            path: entry.path.clone(),
        }));
        rows
    }

    fn row_count(&self) -> usize {
        self.directories
            .len()
            .saturating_add(usize::from(self.current.parent().is_some()))
    }

    fn move_selection(&mut self, amount: isize) {
        let count = self.row_count();
        if count == 0 {
            self.selected = 0;
            return;
        }
        self.selected = if amount.is_negative() {
            self.selected.saturating_sub(amount.unsigned_abs())
        } else {
            self.selected.saturating_add(amount as usize).min(count - 1)
        };
    }

    fn enter_selected(&mut self) {
        let rows = self.rows();
        let Some(row) = rows.get(self.selected) else {
            return;
        };
        self.navigate(&row.path);
    }

    fn navigate(&mut self, path: &Path) {
        match canonical_directory(path) {
            Some(path) => {
                self.current = path;
                self.status = None;
                self.reload();
            }
            None => self.status = Some("This directory is unavailable."),
        }
    }

    fn go_parent(&mut self) {
        let Some(parent) = self.current.parent().map(Path::to_path_buf) else {
            return;
        };
        self.navigate(&parent);
    }

    fn select_current(&mut self) -> PickerAction {
        match canonical_directory(&self.current) {
            Some(path) if path.to_str().is_some() => PickerAction::Select(path),
            Some(_) => {
                self.status = Some("This path cannot be selected because it is not valid UTF-8.");
                PickerAction::None
            }
            None => {
                self.status = Some("This directory is unavailable.");
                PickerAction::None
            }
        }
    }

    fn reload(&mut self) {
        let listing = read_directories(&self.current);
        self.directories = listing.directories;
        self.truncated = listing.truncated;
        if listing.unreadable {
            self.status = Some("Unable to read this directory.");
        }
        if !listing.unreadable && self.status == Some("Unable to read this directory.") {
            self.status = None;
        }
        let parent_row = usize::from(self.current.parent().is_some());
        self.selected = if self.directories.is_empty() {
            0
        } else {
            parent_row
        };
        self.scroll_offset.set(0);
        self.last_click = None;
    }

    fn draw_buttons(&self, frame: &mut Frame, content: Rect, y: u16, button_rows: u16) {
        self.cancel_area.set(Rect::default());
        self.select_area.set(Rect::default());
        if button_rows == 0 || content.width == 0 {
            return;
        }

        let cancel_selected = self.focus == Focus::Cancel;
        let select_selected = self.focus == Focus::Select;
        if content.width >= 36 && button_rows == 1 {
            let gap = 2;
            let cancel_width = content.width.saturating_sub(gap) / 2;
            let select_width = content
                .width
                .saturating_sub(gap)
                .saturating_sub(cancel_width);
            let cancel_area = Rect::new(content.x, y, cancel_width, 1);
            let select_area = Rect::new(
                content.x.saturating_add(cancel_width).saturating_add(gap),
                y,
                select_width,
                1,
            );
            self.cancel_area.set(cancel_area);
            self.select_area.set(select_area);
            draw_button(frame, cancel_area, "Cancel", cancel_selected);
            draw_button(frame, select_area, "Select this directory", select_selected);
        } else {
            let cancel_area = Rect::new(content.x, y, content.width, 1);
            let select_y = y.saturating_add(1);
            let select_area = if select_y < content.bottom() {
                Rect::new(content.x, select_y, content.width, 1)
            } else {
                Rect::default()
            };
            self.cancel_area.set(cancel_area);
            self.select_area.set(select_area);
            draw_button(frame, cancel_area, "Cancel", cancel_selected);
            draw_button(frame, select_area, "Select this directory", select_selected);
        }
    }
}

fn canonical_directory(path: &Path) -> Option<PathBuf> {
    let path = fs::canonicalize(path).ok()?;
    path.is_dir().then_some(path)
}

fn parent_path(path: &Path) -> Option<PathBuf> {
    if path.as_os_str().is_empty() {
        std::env::current_dir().ok()
    } else {
        Some(path.to_path_buf())
    }
}

fn read_directories(path: &Path) -> Listing {
    let Ok(entries) = fs::read_dir(path) else {
        return Listing {
            unreadable: true,
            ..Listing::default()
        };
    };

    let mut directories = BTreeMap::<std::ffi::OsString, PathBuf>::new();
    let mut truncated = false;
    let mut unreadable = false;
    for entry in entries {
        let Ok(entry) = entry else {
            unreadable = true;
            continue;
        };
        let name = entry.file_name();
        let child_path = path.join(&name);
        // `fs::metadata` follows symlinks, allowing directory symlinks to be
        // browsed. Navigation canonicalizes the target, and listing remains
        // one level deep, so this does not recurse through symlink cycles.
        if !fs::metadata(&child_path).is_ok_and(|metadata| metadata.is_dir()) {
            continue;
        }

        if directories.len() < MAX_DIRECTORIES || directories.contains_key(&name) {
            directories.insert(name, child_path);
            continue;
        }

        truncated = true;
        if directories
            .last_key_value()
            .is_some_and(|(largest, _)| name < *largest)
        {
            directories.insert(name, child_path);
            directories.pop_last();
        }
    }

    Listing {
        directories: directories
            .into_iter()
            .map(|(name, path)| DirectoryEntry {
                label: safe_label(&name.to_string_lossy()),
                path,
            })
            .collect(),
        truncated,
        unreadable,
    }
}

fn centered_popup(area: Rect) -> Rect {
    let width = area.width.min(POPUP_MAX_WIDTH);
    let height = area.height.min(POPUP_MAX_HEIGHT);
    Rect::new(
        area.x.saturating_add(area.width.saturating_sub(width) / 2),
        area.y
            .saturating_add(area.height.saturating_sub(height) / 2),
        width,
        height,
    )
}

fn draw_button(frame: &mut Frame, area: Rect, label: &str, selected: bool) {
    if area.is_empty() {
        return;
    }
    let (background, foreground) = if selected {
        (theme::SELECTION, theme::ACCENT)
    } else {
        (theme::KEYCAP, theme::SECONDARY)
    };
    let label = safe_label(label);
    frame.render_widget(
        Paragraph::new(Span::styled(
            label,
            Style::default().fg(foreground).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .style(Style::default().bg(background)),
        area,
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::{KeyModifiers, MouseEvent};
    use ratatui::{Terminal, backend::TestBackend};
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "lomi-directory-picker-{}-{}",
                std::process::id(),
                NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).expect("create temporary test directory");
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

    #[test]
    fn lists_only_sorted_directories_with_parent_and_does_not_write() {
        let root = TempDir::new();
        fs::create_dir(root.path().join("zeta")).unwrap();
        fs::create_dir(root.path().join("alpha")).unwrap();
        fs::write(root.path().join("notes.txt"), b"unchanged").unwrap();

        let picker = DirectoryPicker::new(root.path().to_path_buf());
        let rows = picker.rows();
        let labels = rows
            .iter()
            .map(|row| row.label.as_str())
            .collect::<Vec<_>>();

        assert_eq!(labels, ["..", "alpha", "zeta"]);
        assert!(root.path().join("alpha").is_dir());
        assert_eq!(
            fs::read(root.path().join("notes.txt")).unwrap(),
            b"unchanged"
        );
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 3);
    }

    #[test]
    fn enter_navigates_and_select_returns_canonical_current_directory() {
        let root = TempDir::new();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        let mut picker = DirectoryPicker::new(root.path().to_path_buf());

        assert_eq!(picker.handle_key(key(KeyCode::Enter)), PickerAction::None);
        assert_eq!(picker.current, fs::canonicalize(&child).unwrap());
        assert_eq!(picker.handle_key(key(KeyCode::Tab)), PickerAction::None);
        assert_eq!(picker.handle_key(key(KeyCode::Tab)), PickerAction::None);
        assert_eq!(
            picker.handle_key(key(KeyCode::Enter)),
            PickerAction::Select(fs::canonicalize(&child).unwrap())
        );
    }

    #[test]
    fn cancel_key_cancels_and_backspace_returns_to_parent() {
        let root = TempDir::new();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        let mut picker = DirectoryPicker::new(child.clone());

        assert_eq!(
            picker.handle_key(key(KeyCode::Backspace)),
            PickerAction::None
        );
        assert_eq!(picker.current, fs::canonicalize(root.path()).unwrap());
        assert_eq!(picker.handle_key(key(KeyCode::Esc)), PickerAction::Cancel);
    }

    #[test]
    fn arrows_reach_buttons_from_the_last_row_without_selecting_a_directory() {
        let root = TempDir::new();
        fs::create_dir(root.path().join("child")).unwrap();
        let mut picker = DirectoryPicker::new(root.path().to_path_buf());
        picker.handle_key(key(KeyCode::End));
        let selected = picker.selected;
        let current = picker.current.clone();
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|frame| picker.draw(frame)).unwrap();

        assert_eq!(picker.handle_key(key(KeyCode::Down)), PickerAction::None);
        assert_eq!(picker.focus, Focus::Cancel);
        assert_eq!(picker.selected, selected);
        assert_eq!(picker.current, current);

        assert_eq!(picker.handle_key(key(KeyCode::Right)), PickerAction::None);
        assert_eq!(picker.focus, Focus::Select);
        assert_eq!(picker.handle_key(key(KeyCode::Right)), PickerAction::None);
        assert_eq!(picker.focus, Focus::Select);
        assert_eq!(picker.current, current);
        assert_eq!(picker.handle_key(key(KeyCode::Up)), PickerAction::None);
        assert_eq!(picker.focus, Focus::List);
        assert_eq!(picker.selected, selected);
        assert_eq!(picker.current, current);
    }

    #[test]
    fn mouse_click_selects_row_and_double_click_enters_it() {
        let root = TempDir::new();
        let child = root.path().join("child");
        fs::create_dir(&child).unwrap();
        let mut picker = DirectoryPicker::new(root.path().to_path_buf());
        let backend = TestBackend::new(100, 40);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| picker.draw(frame)).unwrap();
        let list_area = picker.list_area.get();
        let child_row = usize::from(picker.current.parent().is_some());
        let row_y = list_area.y + u16::try_from(child_row).unwrap();

        assert_eq!(
            picker.handle_mouse(mouse(
                MouseEventKind::Down(MouseButton::Left),
                list_area.x,
                row_y
            )),
            PickerAction::None
        );
        assert_eq!(picker.selected, child_row);
        assert_eq!(
            picker.handle_mouse(mouse(
                MouseEventKind::Down(MouseButton::Left),
                list_area.x,
                row_y
            )),
            PickerAction::None
        );
        assert_eq!(picker.current, fs::canonicalize(&child).unwrap());
    }

    #[test]
    fn hover_only_targets_visible_rows_and_buttons_and_clears_after_resize() {
        let root = TempDir::new();
        fs::create_dir(root.path().join("child")).unwrap();
        let picker = DirectoryPicker::new(root.path().to_path_buf());
        let mut terminal = Terminal::new(TestBackend::new(100, 40)).unwrap();
        terminal.draw(|frame| picker.draw(frame)).unwrap();

        let list_area = picker.list_area.get();
        let list_column = list_area.x;
        let first_row = list_area.y;
        let blank_row = first_row.saturating_add(picker.row_count() as u16);
        let cancel_area = picker.cancel_area.get();
        let select_area = picker.select_area.get();
        assert!(blank_row < list_area.bottom());
        assert!(picker.hoverable(list_column, first_row));
        assert!(picker.hoverable(cancel_area.x, cancel_area.y));
        assert!(picker.hoverable(select_area.x, select_area.y));
        assert!(!picker.hoverable(list_column, blank_row));
        assert_eq!(picker.focus, Focus::List);
        assert_eq!(picker.last_click, None);

        let mut small_terminal = Terminal::new(TestBackend::new(1, 1)).unwrap();
        small_terminal.draw(|frame| picker.draw(frame)).unwrap();
        assert!(!picker.hoverable(list_column, first_row));
        assert!(!picker.hoverable(cancel_area.x, cancel_area.y));
        assert!(!picker.hoverable(select_area.x, select_area.y));
        assert!(!picker.hoverable(0, 0));
    }

    #[test]
    fn invalid_start_falls_back_only_to_its_existing_parent() {
        let root = TempDir::new();
        let missing = root.path().join("missing");
        let picker = DirectoryPicker::new(missing);

        assert_eq!(picker.current, fs::canonicalize(root.path()).unwrap());
        assert!(picker.status.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn lists_directory_symlinks_but_skips_broken_and_file_symlinks() {
        use std::os::unix::fs::symlink;

        let root = TempDir::new();
        let target = root.path().join("target");
        fs::create_dir(&target).unwrap();
        fs::write(root.path().join("file"), b"file").unwrap();
        symlink(&target, root.path().join("directory-link")).unwrap();
        symlink(
            root.path().join("missing-target"),
            root.path().join("broken-link"),
        )
        .unwrap();
        symlink(root.path().join("file"), root.path().join("file-link")).unwrap();

        let picker = DirectoryPicker::new(root.path().to_path_buf());
        let labels = picker
            .rows()
            .into_iter()
            .map(|row| row.label)
            .collect::<Vec<_>>();

        assert_eq!(labels, ["..", "directory-link", "target"]);
    }
}
