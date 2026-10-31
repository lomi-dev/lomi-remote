//! Local-only workspace creation form state and rendering.

use super::interaction::accept_pointer_key;
use super::{input_character_is_unsafe, input_contains_terminal_control, safe_label, theme};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::Span,
    widgets::{Block, BorderType, Borders, Paragraph},
};
use std::{
    cell::Cell,
    path::{Path, PathBuf},
};

const FORM_MAX_WIDTH: u16 = 56;
const FORM_MAX_HEIGHT: u16 = 17;
const NAME_MAX_BYTES: usize = 255;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Name,
    Directory,
    Create,
    Cancel,
}

#[derive(Debug, Clone, Copy, Default)]
struct HitTargets {
    name: Rect,
    directory: Rect,
    create: Rect,
    cancel: Rect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HitTarget {
    Name,
    Directory,
    Create,
    Cancel,
}

/// User-entered workspace details. Submission is handled by the parent UI.
pub(super) struct WorkspaceForm {
    pub(super) name: String,
    pub(super) directory: Option<PathBuf>,
    pub(super) error: Option<&'static str>,
    focus: Focus,
    name_cursor: usize,
    last_targets: Cell<HitTargets>,
}

/// Actions the parent UI must perform after a form event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FormAction {
    None,
    Cancel,
    PickDirectory,
    Submit,
}

impl WorkspaceForm {
    pub(super) fn new() -> Self {
        Self {
            name: String::new(),
            directory: None,
            error: None,
            focus: Focus::Name,
            name_cursor: 0,
            last_targets: Cell::new(HitTargets::default()),
        }
    }

    /// Draw the centered form inside the content region supplied by the page.
    /// The parent keeps its sidebar visible by passing only the right-side area.
    pub(super) fn draw(&self, frame: &mut Frame, area: Rect, show_cursor: bool) {
        self.last_targets.set(HitTargets::default());
        if area.is_empty() {
            return;
        }

        let width = area.width.min(FORM_MAX_WIDTH);
        let height = area.height.min(FORM_MAX_HEIGHT);
        let form = Rect::new(
            area.x.saturating_add(area.width.saturating_sub(width) / 2),
            area.y
                .saturating_add(area.height.saturating_sub(height) / 2),
            width,
            height,
        );

        let full_layout = height >= FORM_MAX_HEIGHT;
        let show_description = height >= 13;
        let show_spacers = height >= 14;
        let input_height = if height >= 10 { 3 } else { 1 };
        let directory_height = if height >= 15 { 3 } else { 1 };
        let actions_height = if full_layout { 3 } else { 1 };
        let show_path = height >= 10;
        let show_error = height >= 11;

        let mut y = form.y;
        self.draw_heading(frame, Rect::new(form.x, y, form.width, 1));
        y = y.saturating_add(1);

        if show_description && y < form.bottom() {
            frame.render_widget(
                Paragraph::new("Add a local workspace to Lomi Remote.")
                    .style(Style::default().fg(theme::SECONDARY)),
                Rect::new(form.x, y, form.width, 1),
            );
            y = y.saturating_add(1);
        }
        if show_spacers {
            y = y.saturating_add(1);
        }

        if y < form.bottom() {
            frame.render_widget(
                Paragraph::new("Workspace name").style(Style::default().fg(theme::SECONDARY)),
                Rect::new(form.x, y, form.width, 1),
            );
            y = y.saturating_add(1);
        }

        let name_area = bounded_row(form, y, input_height);
        if !name_area.is_empty() {
            self.draw_name_input(frame, name_area, show_cursor);
            self.last_targets.set(HitTargets {
                name: name_area,
                ..self.last_targets.get()
            });
            y = y.saturating_add(name_area.height);
        }

        if show_spacers {
            y = y.saturating_add(1);
        }

        let directory_area = bounded_row(form, y, directory_height);
        if !directory_area.is_empty() {
            self.draw_button(
                frame,
                directory_area,
                "Select directory…",
                self.focus == Focus::Directory,
                false,
            );
            self.last_targets.set(HitTargets {
                directory: directory_area,
                ..self.last_targets.get()
            });
            y = y.saturating_add(directory_area.height);
        }

        if show_path && y < form.bottom() {
            let directory_text = self.directory.as_ref().map_or_else(
                || "No directory selected.".to_owned(),
                |path| selected_directory_label(path, usize::from(form.width)),
            );
            frame.render_widget(
                Paragraph::new(directory_text).style(Style::default().fg(
                    if self.directory.is_some() {
                        theme::SECONDARY
                    } else {
                        theme::MUTED
                    },
                )),
                Rect::new(form.x, y, form.width, 1),
            );
            y = y.saturating_add(1);
        }

        if show_error && y < form.bottom() {
            let message = self
                .error
                .map_or_else(String::new, |error| safe_label(error));
            frame.render_widget(
                Paragraph::new(message).style(Style::default().fg(theme::ERROR)),
                Rect::new(form.x, y, form.width, 1),
            );
            y = y.saturating_add(1);
        }

        if show_spacers {
            y = y.saturating_add(1);
        }

        let actions_area = bounded_row(form, y, actions_height);
        if !actions_area.is_empty() {
            self.draw_actions(frame, actions_area);
        }
    }

    pub(super) fn handle_key(&mut self, key: KeyEvent) -> FormAction {
        if key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT)
        {
            return FormAction::None;
        }
        match key.code {
            KeyCode::Esc => return FormAction::Cancel,
            KeyCode::Tab => {
                self.focus = next_focus(self.focus);
                return FormAction::None;
            }
            KeyCode::BackTab => {
                self.focus = previous_focus(self.focus);
                return FormAction::None;
            }
            _ => {}
        }

        if self.focus != Focus::Name {
            match key.code {
                KeyCode::Up => self.focus = previous_focus(self.focus),
                KeyCode::Down => self.focus = next_focus(self.focus),
                KeyCode::Left if self.focus == Focus::Cancel => self.focus = Focus::Create,
                KeyCode::Right if self.focus == Focus::Create => self.focus = Focus::Cancel,
                _ => {}
            }
            return match key.code {
                KeyCode::Enter | KeyCode::Char(' ') => self.activate_focus(),
                _ => FormAction::None,
            };
        }

        match key.code {
            KeyCode::Up => self.focus = previous_focus(self.focus),
            KeyCode::Down => self.focus = next_focus(self.focus),
            KeyCode::Left => self.move_cursor_left(),
            KeyCode::Right => self.move_cursor_right(),
            KeyCode::Home => self.name_cursor = 0,
            KeyCode::End => self.name_cursor = self.name.len(),
            KeyCode::Backspace => {
                if self.name_cursor > 0 {
                    let previous = previous_char_boundary(&self.name, self.name_cursor);
                    self.name.drain(previous..self.name_cursor);
                    self.name_cursor = previous;
                    self.error = None;
                }
            }
            KeyCode::Delete => {
                if self.name_cursor < self.name.len() {
                    let next = next_char_boundary(&self.name, self.name_cursor);
                    self.name.drain(self.name_cursor..next);
                    self.error = None;
                }
            }
            KeyCode::Enter => self.focus = Focus::Directory,
            KeyCode::Char(character)
                if !key
                    .modifiers
                    .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
            {
                self.insert_character(character);
            }
            _ => {}
        }
        FormAction::None
    }

    pub(super) fn handle_mouse(&mut self, event: MouseEvent) -> FormAction {
        if event.kind != MouseEventKind::Down(MouseButton::Left) {
            return FormAction::None;
        }
        let targets = self.last_targets.get();
        let Some(target) = [
            (HitTarget::Name, targets.name),
            (HitTarget::Directory, targets.directory),
            (HitTarget::Create, targets.create),
            (HitTarget::Cancel, targets.cancel),
        ]
        .into_iter()
        .find_map(|(target, rect)| contains(rect, event.column, event.row).then_some(target)) else {
            return FormAction::None;
        };

        match target {
            HitTarget::Name => {
                self.focus = Focus::Name;
                FormAction::None
            }
            HitTarget::Directory => {
                if !accept_pointer_key(event, targets.directory, KeyCode::Enter) {
                    return FormAction::None;
                }
                self.focus = Focus::Directory;
                FormAction::PickDirectory
            }
            HitTarget::Create => {
                if !accept_pointer_key(event, targets.create, KeyCode::Enter) {
                    return FormAction::None;
                }
                self.focus = Focus::Create;
                self.submit_or_report_error()
            }
            HitTarget::Cancel => {
                if !accept_pointer_key(event, targets.cancel, KeyCode::Esc) {
                    return FormAction::None;
                }
                self.focus = Focus::Cancel;
                FormAction::Cancel
            }
        }
    }

    /// Whether the last-painted form target should use the hand pointer.
    /// The name field and disabled Create button are intentionally excluded.
    pub(super) fn hoverable(&self, column: u16, row: u16) -> bool {
        let targets = self.last_targets.get();
        contains(targets.directory, column, row)
            || (self.is_ready() && contains(targets.create, column, row))
            || contains(targets.cancel, column, row)
    }

    pub(super) fn handle_paste(&mut self, text: &str) -> bool {
        if self.focus != Focus::Name {
            // The form consumes paste events while a button has focus.
            return true;
        }
        if input_contains_terminal_control(text) {
            self.error = Some("Paste one workspace name line without control characters.");
        } else if self.name.len().saturating_add(text.len()) > NAME_MAX_BYTES {
            self.error = Some("Workspace name limit is 255 UTF-8 bytes.");
        } else {
            self.insert_text(text);
        }
        true
    }

    pub(super) fn directory_selected(&mut self, path: PathBuf) {
        self.directory = Some(path);
        self.focus = Focus::Create;
        self.error = None;
    }

    fn draw_heading(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(
            Paragraph::new("Add workspace")
                .style(
                    Style::default()
                        .fg(theme::TEXT)
                        .add_modifier(Modifier::BOLD),
                )
                .alignment(Alignment::Center),
            area,
        );
    }

    fn draw_name_input(&self, frame: &mut Frame, area: Rect, show_cursor: bool) {
        let focused = self.focus == Focus::Name;
        let border_color = if focused {
            theme::ACCENT
        } else {
            theme::BORDER
        };
        let inner = if area.height >= 3 && area.width >= 3 {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(border_color))
                .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE));
            let inner = block.inner(area);
            frame.render_widget(block, area);
            inner
        } else {
            area
        };
        if inner.is_empty() {
            return;
        }

        let cursor = self.name_cursor.min(self.name.len());
        let (start, start_column) = visible_start(&self.name, cursor, inner.width);
        let visible = safe_label(&self.name[start..]);
        frame.render_widget(
            Paragraph::new(visible).style(
                Style::default()
                    .fg(if focused {
                        theme::TEXT
                    } else {
                        theme::SECONDARY
                    })
                    .bg(theme::SURFACE),
            ),
            inner,
        );

        if focused && show_cursor {
            let cursor_column = Span::raw(&self.name[..cursor]).width();
            let visible_cursor_column = cursor_column.saturating_sub(start_column);
            if visible_cursor_column < usize::from(inner.width) {
                frame.set_cursor_position((
                    inner.x.saturating_add(visible_cursor_column as u16),
                    inner.y,
                ));
            }
        }
    }

    fn draw_button(
        &self,
        frame: &mut Frame,
        area: Rect,
        label: &str,
        focused: bool,
        disabled: bool,
    ) {
        let color = if disabled {
            theme::MUTED
        } else if focused {
            theme::ACCENT
        } else {
            theme::BORDER
        };
        if area.height >= 3 && area.width >= 3 {
            let block = Block::default()
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(color))
                .style(
                    Style::default()
                        .fg(if disabled { theme::MUTED } else { theme::TEXT })
                        .bg(theme::SURFACE),
                );
            let inner = block.inner(area);
            frame.render_widget(block, area);
            frame.render_widget(
                Paragraph::new(label).alignment(Alignment::Center).style(
                    Style::default()
                        .fg(if disabled { theme::MUTED } else { theme::TEXT })
                        .bg(theme::SURFACE),
                ),
                inner,
            );
        } else {
            let label = if label == "Create workspace" && area.width < 18 {
                "Create"
            } else {
                label
            };
            frame.render_widget(
                Paragraph::new(label).alignment(Alignment::Center).style(
                    Style::default().fg(color).add_modifier(if focused {
                        Modifier::BOLD
                    } else {
                        Modifier::empty()
                    }),
                ),
                area,
            );
        }
    }

    fn draw_actions(&self, frame: &mut Frame, area: Rect) {
        let ready = self.is_ready();
        if area.width >= 33 && area.height >= 3 {
            let total = 33;
            let left = area.x.saturating_add(area.width.saturating_sub(total) / 2);
            let create = Rect::new(left, area.y, 20, area.height);
            let cancel = Rect::new(left.saturating_add(23), area.y, 10, area.height);
            self.draw_button(
                frame,
                create,
                "Create workspace",
                self.focus == Focus::Create,
                !ready,
            );
            self.draw_button(frame, cancel, "Cancel", self.focus == Focus::Cancel, false);
            self.last_targets.set(HitTargets {
                create,
                cancel,
                ..self.last_targets.get()
            });
            return;
        }

        if area.width < 4 {
            return;
        }
        let create_width = area.width.saturating_mul(2) / 3;
        let create = Rect::new(area.x, area.y, create_width, area.height);
        let cancel = Rect::new(
            area.x.saturating_add(create_width),
            area.y,
            area.width.saturating_sub(create_width),
            area.height,
        );
        self.draw_button(
            frame,
            create,
            "Create workspace",
            self.focus == Focus::Create,
            !ready,
        );
        self.draw_button(frame, cancel, "Cancel", self.focus == Focus::Cancel, false);
        self.last_targets.set(HitTargets {
            create,
            cancel,
            ..self.last_targets.get()
        });
    }

    fn activate_focus(&mut self) -> FormAction {
        match self.focus {
            Focus::Name => {
                self.focus = Focus::Directory;
                FormAction::None
            }
            Focus::Directory => FormAction::PickDirectory,
            Focus::Create => self.submit_or_report_error(),
            Focus::Cancel => FormAction::Cancel,
        }
    }

    fn submit_or_report_error(&mut self) -> FormAction {
        if self.name.trim().is_empty() {
            self.error = Some("Enter a workspace name.");
        } else if self.name.len() > NAME_MAX_BYTES {
            self.error = Some("Workspace name limit is 255 UTF-8 bytes.");
        } else if self.directory.is_none() {
            self.error = Some("Select a directory for this workspace.");
        } else {
            self.error = None;
            return FormAction::Submit;
        }
        FormAction::None
    }

    fn is_ready(&self) -> bool {
        !self.name.trim().is_empty()
            && self.name.len() <= NAME_MAX_BYTES
            && self.directory.is_some()
    }

    fn insert_character(&mut self, character: char) {
        if input_character_is_unsafe(character) {
            self.error = Some("Control characters are not allowed.");
        } else if self.name.len().saturating_add(character.len_utf8()) > NAME_MAX_BYTES {
            self.error = Some("Workspace name limit is 255 UTF-8 bytes.");
        } else {
            self.name.insert(self.name_cursor, character);
            self.name_cursor = self.name_cursor.saturating_add(character.len_utf8());
            self.error = None;
        }
    }

    fn insert_text(&mut self, text: &str) {
        self.name.insert_str(self.name_cursor, text);
        self.name_cursor = self.name_cursor.saturating_add(text.len());
        self.error = None;
    }

    fn move_cursor_left(&mut self) {
        self.name_cursor = previous_char_boundary(&self.name, self.name_cursor);
    }

    fn move_cursor_right(&mut self) {
        self.name_cursor = next_char_boundary(&self.name, self.name_cursor);
    }
}

fn next_focus(focus: Focus) -> Focus {
    match focus {
        Focus::Name => Focus::Directory,
        Focus::Directory => Focus::Create,
        Focus::Create => Focus::Cancel,
        Focus::Cancel => Focus::Name,
    }
}

fn previous_focus(focus: Focus) -> Focus {
    match focus {
        Focus::Name => Focus::Cancel,
        Focus::Directory => Focus::Name,
        Focus::Create => Focus::Directory,
        Focus::Cancel => Focus::Create,
    }
}

fn previous_char_boundary(text: &str, position: usize) -> usize {
    text[..position]
        .char_indices()
        .next_back()
        .map_or(0, |(index, _)| index)
}

fn next_char_boundary(text: &str, position: usize) -> usize {
    text[position..]
        .char_indices()
        .nth(1)
        .map_or(text.len(), |(index, _)| position + index)
}

fn visible_start(text: &str, cursor: usize, width: u16) -> (usize, usize) {
    let cursor = cursor.min(text.len());
    let cursor_column = Span::raw(&text[..cursor]).width();
    let earliest_column = cursor_column.saturating_sub(usize::from(width.saturating_sub(1)));
    let mut start = 0;
    let mut start_column = 0;
    for (index, character) in text.char_indices() {
        let end = index + character.len_utf8();
        if end > cursor {
            break;
        }
        let column = Span::raw(&text[..end]).width();
        if column > earliest_column {
            break;
        }
        start = end;
        start_column = column;
    }
    (start, start_column)
}

fn selected_directory_label(path: &Path, available_width: usize) -> String {
    const PREFIX: &str = "Selected: ";
    const ELLIPSIS: &str = "…";

    if available_width == 0 {
        return String::new();
    }

    // Keep the full display string until after fitting. `safe_label` bounds
    // output to 120 characters, which would otherwise remove long path tails.
    let path_text = path.display().to_string();
    let sanitized_path = sanitize_controls(&path_text);
    let full_label = format!("{PREFIX}{sanitized_path}");
    if display_width(&full_label) <= available_width && full_label.chars().count() <= 120 {
        return safe_label(&full_label);
    }

    let basename_width = path
        .file_name()
        .map(|name| display_width(&sanitize_controls(&name.to_string_lossy())))
        .unwrap_or_default();
    let prefix_width = display_width(PREFIX);
    let ellipsis_width = display_width(ELLIPSIS);
    let keep_prefix = available_width
        >= prefix_width
            .saturating_add(ellipsis_width)
            .saturating_add(basename_width)
        && PREFIX.chars().count().saturating_add(1).saturating_add(
            path.file_name()
                .map(|name| name.to_string_lossy().chars().count())
                .unwrap_or_default(),
        ) <= 120;

    let (prefix, tail_width, max_tail_chars) = if keep_prefix {
        (
            PREFIX,
            available_width.saturating_sub(prefix_width + ellipsis_width),
            120usize.saturating_sub(PREFIX.chars().count() + 1),
        )
    } else if available_width > ellipsis_width {
        (
            "",
            available_width.saturating_sub(ellipsis_width),
            120usize.saturating_sub(1),
        )
    } else {
        // A one-column area cannot show both an ellipsis and a path character.
        let tail = tail_by_columns(&sanitized_path, available_width, 120);
        return safe_label(&tail);
    };

    let tail = tail_by_columns(&sanitized_path, tail_width, max_tail_chars);
    safe_label(&format!("{prefix}{ELLIPSIS}{tail}"))
}

fn sanitize_controls(text: &str) -> String {
    text.chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .collect()
}

fn display_width(text: &str) -> usize {
    Span::raw(text).width()
}

fn tail_by_columns(text: &str, max_width: usize, max_chars: usize) -> String {
    let span = Span::raw(text);
    let graphemes = span
        .styled_graphemes(Style::default())
        .map(|grapheme| grapheme.symbol)
        .collect::<Vec<_>>();
    let mut tail = Vec::new();
    let mut width = 0usize;
    let mut character_count = 0usize;
    for grapheme in graphemes.into_iter().rev() {
        let grapheme_width = display_width(grapheme);
        let grapheme_chars = grapheme.chars().count();
        if width.saturating_add(grapheme_width) > max_width
            || character_count.saturating_add(grapheme_chars) > max_chars
        {
            break;
        }
        width = width.saturating_add(grapheme_width);
        character_count = character_count.saturating_add(grapheme_chars);
        tail.push(grapheme);
    }
    tail.into_iter().rev().collect::<Vec<_>>().concat()
}

fn bounded_row(form: Rect, y: u16, height: u16) -> Rect {
    if y >= form.bottom() {
        return Rect::default();
    }
    Rect::new(
        form.x,
        y,
        form.width,
        height.min(form.bottom().saturating_sub(y)),
    )
}

fn contains(rect: Rect, x: u16, y: u16) -> bool {
    !rect.is_empty()
        && x >= rect.x
        && x < rect.x.saturating_add(rect.width)
        && y >= rect.y
        && y < rect.y.saturating_add(rect.height)
}

#[cfg(test)]
mod tests {
    use super::{FormAction, WorkspaceForm};
    use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
    use ratatui::{Terminal, backend::TestBackend};
    use std::path::{Path, PathBuf};

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn name_input_supports_literal_shortcuts_and_utf8_byte_limit() {
        let mut form = WorkspaceForm::new();
        for character in "?q/a-é".chars() {
            assert_eq!(
                form.handle_key(key(KeyCode::Char(character))),
                FormAction::None
            );
        }
        assert_eq!(form.name, "?q/a-é");

        form.name = "é".repeat(127);
        form.name_cursor = form.name.len();
        assert_eq!(form.handle_key(key(KeyCode::Char('x'))), FormAction::None);
        assert_eq!(form.name.len(), 255);
        assert_eq!(form.error, None);
        assert_eq!(form.handle_key(key(KeyCode::Char('x'))), FormAction::None);
        assert_eq!(form.name.len(), 255);
        assert_eq!(form.error, Some("Workspace name limit is 255 UTF-8 bytes."));
    }

    #[test]
    fn directory_and_submit_actions_require_explicit_navigation() {
        let mut form = WorkspaceForm::new();
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::None);
        assert_eq!(
            form.handle_key(key(KeyCode::Enter)),
            FormAction::PickDirectory
        );

        form.name = "My workspace".to_owned();
        form.directory_selected(PathBuf::from("/tmp/project"));
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::Submit);
        assert_eq!(
            form.directory.as_deref(),
            Some(std::path::Path::new("/tmp/project"))
        );
    }

    #[test]
    fn arrows_navigate_focus_without_activating_form_actions() {
        let mut form = WorkspaceForm::new();
        form.name = "workspace".to_owned();
        form.directory = Some(PathBuf::from("/tmp"));

        assert_eq!(form.handle_key(key(KeyCode::Down)), FormAction::None);
        assert_eq!(form.focus, super::Focus::Directory);
        assert_eq!(form.handle_key(key(KeyCode::Down)), FormAction::None);
        assert_eq!(form.focus, super::Focus::Create);
        assert_eq!(form.handle_key(key(KeyCode::Right)), FormAction::None);
        assert_eq!(form.focus, super::Focus::Cancel);
        assert_eq!(form.handle_key(key(KeyCode::Left)), FormAction::None);
        assert_eq!(form.focus, super::Focus::Create);
    }

    #[test]
    fn name_left_and_right_move_the_caret_without_leaving_the_field() {
        let mut form = WorkspaceForm::new();
        form.name = "éx".to_owned();
        form.name_cursor = form.name.len();

        assert_eq!(form.handle_key(key(KeyCode::Left)), FormAction::None);
        assert_eq!(form.name_cursor, 2);
        assert_eq!(form.focus, super::Focus::Name);
        assert_eq!(form.handle_key(key(KeyCode::Right)), FormAction::None);
        assert_eq!(form.name_cursor, 3);
        assert_eq!(form.focus, super::Focus::Name);
    }

    #[test]
    fn double_clicking_create_does_not_repeat_the_custom_action() {
        let mut form = WorkspaceForm::new();
        form.name = "workspace".to_owned();
        form.directory = Some(PathBuf::from("/tmp"));
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                form.draw(frame, area, true);
            })
            .unwrap();
        let create = form.last_targets.get().create;
        let click = crossterm::event::MouseEvent {
            kind: crossterm::event::MouseEventKind::Down(crossterm::event::MouseButton::Left),
            column: create.x.saturating_add(1),
            row: create.y,
            modifiers: KeyModifiers::NONE,
        };

        assert_eq!(form.handle_mouse(click), FormAction::Submit);
        assert_eq!(form.handle_mouse(click), FormAction::None);
    }

    #[test]
    fn submit_reports_missing_fields_and_escape_cancels() {
        let mut form = WorkspaceForm::new();
        assert_eq!(form.handle_key(key(KeyCode::Tab)), FormAction::None);
        assert_eq!(form.handle_key(key(KeyCode::Tab)), FormAction::None);
        assert_eq!(form.handle_key(key(KeyCode::Enter)), FormAction::None);
        assert_eq!(form.error, Some("Enter a workspace name."));
        assert_eq!(form.handle_key(key(KeyCode::Esc)), FormAction::Cancel);
    }

    #[test]
    fn paste_rejects_terminal_controls_and_accepts_safe_text() {
        let mut form = WorkspaceForm::new();
        assert!(form.handle_paste("safe name"));
        assert_eq!(form.name, "safe name");
        assert!(form.handle_paste("unsafe\nname"));
        assert_eq!(form.name, "safe name");
        assert!(form.error.is_some());
    }

    #[test]
    fn long_directory_label_preserves_the_basename() {
        let path =
            Path::new("/private/var/folders/ab/cdefghijklmnopqrstuvw/T/workspaces/AlphaProject");
        let label = super::selected_directory_label(path, 56);
        assert!(label.starts_with("Selected: …"));
        assert!(label.ends_with("AlphaProject"));
        assert!(super::display_width(&label) <= 56);
    }

    #[test]
    fn hover_only_targets_enabled_buttons_from_the_last_paint() {
        let mut form = WorkspaceForm::new();
        let mut terminal = Terminal::new(TestBackend::new(80, 30)).unwrap();
        terminal
            .draw(|frame| {
                let area = frame.area();
                form.draw(frame, area, true);
            })
            .unwrap();

        let targets = form.last_targets.get();
        let focus = form.focus;
        assert!(!form.hoverable(targets.name.x, targets.name.y));
        assert!(form.hoverable(targets.directory.x, targets.directory.y));
        assert!(!form.hoverable(targets.create.x, targets.create.y));
        assert!(form.hoverable(targets.cancel.x, targets.cancel.y));
        assert!(!form.hoverable(12, 8));
        assert_eq!(form.focus, focus);

        form.name = "Workspace".to_owned();
        form.directory = Some(PathBuf::from("/tmp/workspace"));
        terminal
            .draw(|frame| {
                let area = frame.area();
                form.draw(frame, area, true);
            })
            .unwrap();
        let targets = form.last_targets.get();
        assert!(form.hoverable(targets.create.x, targets.create.y));

        let old_directory = targets.directory;
        let mut small_terminal = Terminal::new(TestBackend::new(1, 1)).unwrap();
        small_terminal
            .draw(|frame| {
                let area = frame.area();
                form.draw(frame, area, true);
            })
            .unwrap();
        assert!(!form.hoverable(old_directory.x, old_directory.y));
    }
}
