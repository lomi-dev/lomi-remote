//! Read-only shortcut reference drawn over the dashboard.

use super::interaction::{Action, Controls, hint_key};
use super::theme;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

const POPUP_MAX_WIDTH: u16 = 76;
const POPUP_MAX_HEIGHT: u16 = 20;

const WORKSPACE_SHORTCUTS: [(&str, &str); 6] = [
    ("↑↓", "Select workspace"),
    ("/", "Search workspaces"),
    ("a", "Add workspace"),
    ("s", "Share / unshare"),
    ("p", "Shell profiles"),
    ("r", "Refresh"),
];

const HOST_SHORTCUTS: [(&str, &str); 6] = [
    ("o", "Service"),
    ("v", "Access"),
    ("l", "Login"),
    ("g", "Doctor"),
    ("k", "Logs"),
    ("e", "Settings"),
];

const APPLICATION_SHORTCUTS: [(&str, &str); 2] =
    [("q", "Quit dashboard"), ("Ctrl+C", "Quit dashboard")];

/// Draw the shortcut dialog over the existing frame and return its maximum
/// scroll offset. The requested offset is clamped while rendering.
pub(super) fn draw(frame: &mut Frame, scroll: usize, controls: &Controls) -> usize {
    dim_frame(frame);

    let area = frame.area();
    if area.is_empty() {
        return 0;
    }

    let popup = bounds(area);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
        .title(Span::styled(
            " Shortcuts ",
            Style::default()
                .fg(theme::TEXT)
                .add_modifier(Modifier::BOLD),
        ))
        .title_alignment(Alignment::Center);
    let inner = block.inner(popup);

    frame.render_widget(Clear, popup);
    frame.render_widget(block, popup);

    let content = inset(inner, 1, 1);
    if content.is_empty() {
        return 0;
    }

    let wide = content.width >= 50;
    let content_rows: usize = if wide { 11 } else { 19 };
    let footer_rows = footer_rows(content.width);
    let body_height = content.height.saturating_sub(footer_rows);
    let max_scroll = content_rows.saturating_sub(usize::from(body_height));
    let scroll = scroll.min(max_scroll);
    let body = Rect::new(content.x, content.y, content.width, body_height);

    if wide {
        draw_wide_groups(frame, body, scroll, controls);
    } else {
        draw_stacked_groups(frame, body, scroll, controls);
    }
    draw_footer(
        frame,
        content,
        body_height,
        footer_rows,
        max_scroll > 0,
        controls,
    );

    max_scroll
}

pub(super) fn bounds(area: Rect) -> Rect {
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

fn inset(area: Rect, horizontal: u16, vertical: u16) -> Rect {
    Rect::new(
        area.x.saturating_add(horizontal),
        area.y.saturating_add(vertical),
        area.width.saturating_sub(horizontal.saturating_mul(2)),
        area.height.saturating_sub(vertical.saturating_mul(2)),
    )
}

fn footer_rows(width: u16) -> u16 {
    if width >= 40 {
        1
    } else if width >= 24 {
        2
    } else {
        3
    }
}

fn draw_wide_groups(frame: &mut Frame, body: Rect, scroll: usize, controls: &Controls) {
    let gap = 2;
    let left_width = body.width.saturating_sub(gap) / 2;
    let right_width = body.width.saturating_sub(gap).saturating_sub(left_width);
    let right_x = body.x.saturating_add(left_width).saturating_add(gap);

    draw_group(
        frame,
        body,
        scroll,
        0,
        body.x,
        left_width,
        "Workspaces",
        &WORKSPACE_SHORTCUTS,
        controls,
    );
    draw_group(
        frame,
        body,
        scroll,
        0,
        right_x,
        right_width,
        "Host",
        &HOST_SHORTCUTS,
        controls,
    );
    draw_group(
        frame,
        body,
        scroll,
        8,
        body.x,
        body.width,
        "Application",
        &APPLICATION_SHORTCUTS,
        controls,
    );
}

fn draw_stacked_groups(frame: &mut Frame, body: Rect, scroll: usize, controls: &Controls) {
    draw_group(
        frame,
        body,
        scroll,
        0,
        body.x,
        body.width,
        "Workspaces",
        &WORKSPACE_SHORTCUTS,
        controls,
    );
    draw_group(
        frame,
        body,
        scroll,
        8,
        body.x,
        body.width,
        "Host",
        &HOST_SHORTCUTS,
        controls,
    );
    draw_group(
        frame,
        body,
        scroll,
        16,
        body.x,
        body.width,
        "Application",
        &APPLICATION_SHORTCUTS,
        controls,
    );
}

fn draw_group(
    frame: &mut Frame,
    body: Rect,
    scroll: usize,
    start: usize,
    x: u16,
    width: u16,
    title: &'static str,
    shortcuts: &[(&'static str, &'static str)],
    controls: &Controls,
) {
    draw_line(
        frame,
        body,
        scroll,
        start,
        x,
        width,
        Line::styled(
            title,
            Style::default()
                .fg(theme::SECONDARY)
                .add_modifier(Modifier::BOLD),
        ),
        None,
        controls,
    );

    for (index, (key, label)) in shortcuts.iter().enumerate() {
        draw_line(
            frame,
            body,
            scroll,
            start + index + 1,
            x,
            width,
            shortcut_line(key, label),
            shortcut_action(key),
            controls,
        );
    }
}

fn shortcut_line(key: &str, label: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(
            format!(" {key} "),
            Style::default()
                .fg(theme::TEXT)
                .bg(theme::KEYCAP)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!(" {label}"), Style::default().fg(theme::SECONDARY)),
    ])
}

fn draw_line(
    frame: &mut Frame,
    body: Rect,
    scroll: usize,
    row: usize,
    x: u16,
    width: u16,
    line: Line<'static>,
    action: Option<KeyEvent>,
    controls: &Controls,
) {
    if width == 0 || row < scroll {
        return;
    }
    let visible_row = row - scroll;
    if visible_row >= usize::from(body.height) {
        return;
    }
    let area = Rect::new(x, body.y.saturating_add(visible_row as u16), width, 1);
    frame.render_widget(Paragraph::new(line), area);
    if let Some(action) = action {
        controls.add(area, Action::Key(action));
    }
}

fn draw_footer(
    frame: &mut Frame,
    content: Rect,
    body_height: u16,
    footer_rows: u16,
    can_scroll: bool,
    controls: &Controls,
) {
    let footer_y = content.y.saturating_add(body_height);
    if footer_rows == 0 || footer_y >= content.bottom() {
        return;
    }

    if content.width >= 40 {
        let mut spans = Vec::new();
        append_hint(&mut spans, "Esc", "Close");
        spans.push(Span::raw("   "));
        append_hint(&mut spans, "?", "Close");
        if can_scroll {
            spans.push(Span::raw("   "));
            append_hint(&mut spans, "↑↓", "Navigate");
        }
        render_footer_line(frame, content, footer_y, Line::from(spans));
        add_hint_target(controls, content, footer_y, 0, "Esc", "Close", KeyCode::Esc);
        let question_x = hint_width("Esc", "Close").saturating_add(3) as u16;
        add_hint_target(
            controls,
            content,
            footer_y,
            question_x,
            "?",
            "Close",
            KeyCode::Char('?'),
        );
        if can_scroll {
            let scroll_x = question_x
                .saturating_add(hint_width("?", "Close") as u16)
                .saturating_add(3);
            add_hint_target(
                controls,
                content,
                footer_y,
                scroll_x,
                "↑↓",
                "Navigate",
                KeyCode::Down,
            );
        }
    } else if content.width >= 24 {
        let mut close = Vec::new();
        append_hint(&mut close, "Esc", "Close");
        close.push(Span::raw("   "));
        append_hint(&mut close, "?", "Close");
        render_footer_line(frame, content, footer_y, Line::from(close));
        add_hint_target(controls, content, footer_y, 0, "Esc", "Close", KeyCode::Esc);
        let question_x = hint_width("Esc", "Close").saturating_add(3) as u16;
        add_hint_target(
            controls,
            content,
            footer_y,
            question_x,
            "?",
            "Close",
            KeyCode::Char('?'),
        );
        if can_scroll && footer_rows > 1 {
            let mut scroll = Vec::new();
            append_hint(&mut scroll, "↑↓", "Navigate");
            render_footer_line(
                frame,
                content,
                footer_y.saturating_add(1),
                Line::from(scroll),
            );
            add_hint_target(
                controls,
                content,
                footer_y.saturating_add(1),
                0,
                "↑↓",
                "Navigate",
                KeyCode::Down,
            );
        }
    } else {
        let mut esc = Vec::new();
        append_hint(&mut esc, "Esc", "Close");
        render_footer_line(frame, content, footer_y, Line::from(esc));
        add_hint_target(controls, content, footer_y, 0, "Esc", "Close", KeyCode::Esc);

        if footer_rows > 1 {
            let mut question = Vec::new();
            append_hint(&mut question, "?", "Close");
            render_footer_line(
                frame,
                content,
                footer_y.saturating_add(1),
                Line::from(question),
            );
            add_hint_target(
                controls,
                content,
                footer_y.saturating_add(1),
                0,
                "?",
                "Close",
                KeyCode::Char('?'),
            );
        }
        if can_scroll && footer_rows > 2 {
            let mut scroll = Vec::new();
            append_hint(&mut scroll, "↑↓", "Navigate");
            render_footer_line(
                frame,
                content,
                footer_y.saturating_add(2),
                Line::from(scroll),
            );
            add_hint_target(
                controls,
                content,
                footer_y.saturating_add(2),
                0,
                "↑↓",
                "Navigate",
                KeyCode::Down,
            );
        }
    }
}

fn shortcut_action(key: &str) -> Option<KeyEvent> {
    match key {
        "↑↓" => hint_key("Esc"),
        "Ctrl+C" => hint_key("Ctrl+C"),
        _ => hint_key(key),
    }
}

fn hint_width(key: &str, label: &str) -> usize {
    Span::raw(format!(" {key} ")).width() + Span::raw(format!(" {label}")).width()
}

fn add_hint_target(
    controls: &Controls,
    content: Rect,
    y: u16,
    x: u16,
    key: &str,
    label: &str,
    code: KeyCode,
) {
    if y >= content.bottom() || x >= content.width {
        return;
    }
    let width = hint_width(key, label).min(usize::from(content.width.saturating_sub(x))) as u16;
    if width > 0 {
        controls.key(Rect::new(content.x.saturating_add(x), y, width, 1), code);
    }
}

fn append_hint(spans: &mut Vec<Span<'static>>, key: &'static str, label: &'static str) {
    spans.push(Span::styled(
        format!(" {key} "),
        Style::default()
            .bg(theme::KEYCAP)
            .fg(theme::TEXT)
            .add_modifier(Modifier::BOLD),
    ));
    spans.push(Span::styled(
        format!(" {label}"),
        Style::default().fg(theme::MUTED),
    ));
}

fn render_footer_line(frame: &mut Frame, content: Rect, y: u16, line: Line<'static>) {
    if y < content.bottom() {
        frame.render_widget(
            Paragraph::new(line),
            Rect::new(content.x, y, content.width, 1),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use ratatui::{Terminal, backend::TestBackend};

    #[test]
    fn popup_bounds_center_and_cap_to_the_available_frame() {
        assert_eq!(bounds(Rect::new(0, 0, 100, 30)), Rect::new(12, 5, 76, 20));
        assert_eq!(bounds(Rect::new(4, 6, 20, 10)), Rect::new(4, 6, 20, 10));
    }

    #[test]
    fn visible_shortcut_rows_and_footer_hints_register_their_keys() {
        let controls = Controls::default();
        controls.begin();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, 0, &controls);
            })
            .unwrap();

        assert_eq!(
            controls.action_at(16, 8),
            Some(Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
        );
        assert_eq!(
            controls.action_at(16, 9),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('/'),
                KeyModifiers::NONE
            )))
        );
        assert_eq!(
            controls.action_at(16, 17),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('c'),
                KeyModifiers::CONTROL
            )))
        );
        assert_eq!(
            controls.action_at(29, 22),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('?'),
                KeyModifiers::NONE
            )))
        );
    }

    #[test]
    fn scrolling_registers_only_shortcut_rows_that_are_visible() {
        let controls = Controls::default();
        controls.begin();
        let mut terminal = Terminal::new(TestBackend::new(36, 24)).unwrap();
        terminal
            .draw(|frame| {
                let max_scroll = draw(frame, 5, &controls);
                assert_eq!(max_scroll, 5);
            })
            .unwrap();

        assert_eq!(
            controls.action_at(3, 4),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('p'),
                KeyModifiers::NONE
            )))
        );
        assert_eq!(
            controls.action_at(3, 5),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('r'),
                KeyModifiers::NONE
            )))
        );
    }
}

pub(super) fn dim_frame(frame: &mut Frame) {
    for cell in &mut frame.buffer_mut().content {
        cell.fg = dim_color(cell.fg, false);
        cell.bg = dim_color(cell.bg, true);
    }
}

fn dim_color(color: Color, background: bool) -> Color {
    match color {
        Color::Rgb(red, green, blue) => Color::Rgb(
            (u16::from(red) * 2 / 5) as u8,
            (u16::from(green) * 2 / 5) as u8,
            (u16::from(blue) * 2 / 5) as u8,
        ),
        Color::Black | Color::DarkGray => Color::Black,
        Color::Reset => {
            if background {
                Color::Black
            } else {
                Color::DarkGray
            }
        }
        Color::Red
        | Color::Green
        | Color::Yellow
        | Color::Blue
        | Color::Magenta
        | Color::Cyan
        | Color::Gray
        | Color::LightRed
        | Color::LightGreen
        | Color::LightYellow
        | Color::LightBlue
        | Color::LightMagenta
        | Color::LightCyan
        | Color::White
        | Color::Indexed(_) => {
            if background {
                Color::Black
            } else {
                Color::DarkGray
            }
        }
    }
}
