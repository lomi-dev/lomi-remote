//! Read-only consent copy and choices for sharing a workspace.

use super::{interaction::Controls, shortcuts, theme};
use crossterm::event::KeyCode;
use ratatui::{
    Frame,
    layout::{Alignment, Rect},
    style::{Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Clear, Paragraph},
};

const POPUP_MAX_WIDTH: u16 = 72;
const SHARE_MAX_HEIGHT: u16 = 19;
const UNSHARE_MAX_HEIGHT: u16 = 12;

/// Draw the share/unshare confirmation dialog and return the maximum vertical
/// scroll offset for its body.
pub(super) fn draw(
    frame: &mut Frame,
    name: &str,
    share: bool,
    confirm_selected: bool,
    scroll: usize,
    controls: &Controls,
) -> usize {
    shortcuts::dim_frame(frame);

    let area = frame.area();
    if area.is_empty() {
        return 0;
    }

    let popup = bounds(area, share);
    let title = if share {
        "Share workspace"
    } else {
        "Unshare workspace"
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(theme::BORDER))
        .style(Style::default().fg(theme::TEXT).bg(theme::SURFACE))
        .title(Span::styled(
            format!(" {title} "),
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

    let desired_button_rows: u16 = if content.width >= 44 { 1 } else { 2 };
    let button_rows = desired_button_rows.min(content.height);
    let gap_rows = u16::from(content.height > button_rows);
    let body_height = content
        .height
        .saturating_sub(button_rows.saturating_add(gap_rows));
    let body = Rect::new(content.x, content.y, content.width, body_height);
    let lines = body_lines(name, share, content.width);
    let max_scroll = lines.len().saturating_sub(usize::from(body.height));
    let scroll = scroll.min(max_scroll).min(usize::from(u16::MAX)) as u16;

    frame.render_widget(Paragraph::new(Text::from(lines)).scroll((scroll, 0)), body);

    let buttons_y = body.y.saturating_add(body.height).saturating_add(gap_rows);
    draw_buttons(
        frame,
        content,
        buttons_y,
        button_rows,
        share,
        confirm_selected,
        controls,
    );

    max_scroll
}

pub(super) fn bounds(area: Rect, share: bool) -> Rect {
    let width = area.width.min(POPUP_MAX_WIDTH);
    let height = area.height.min(if share {
        SHARE_MAX_HEIGHT
    } else {
        UNSHARE_MAX_HEIGHT
    });
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

fn body_lines(name: &str, share: bool, width: u16) -> Vec<Line<'static>> {
    if width == 0 {
        return Vec::new();
    }

    let question = if share {
        format!("Share “{name}” with your account?")
    } else {
        format!("Stop sharing “{name}”?")
    };
    let paragraphs = if share {
        vec![
            (
                question,
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "Desktop, browser, and mobile clients signed into your account can access this workspace. No separate device approval is required."
                    .to_owned(),
                Style::default().fg(theme::SECONDARY),
            ),
            (
                "Shared connections can view, control, create, resize, and close terminals, and read and edit project files. They can use Git status, diffs, history, staging, commits, fetch, fast-forward pull, and push."
                    .to_owned(),
                Style::default().fg(theme::SECONDARY),
            ),
            (
                "Editor buffers, chat, browser panes, plugins, and AI-controlled terminals stay private. Sharing does not start a shell."
                    .to_owned(),
                Style::default().fg(theme::SECONDARY),
            ),
        ]
    } else {
        vec![
            (
                question,
                Style::default()
                    .fg(theme::TEXT)
                    .add_modifier(Modifier::BOLD),
            ),
            (
                "Unsharing revokes remote access to this workspace."
                    .to_owned(),
                Style::default().fg(theme::SECONDARY),
            ),
            (
                "The local workspace stays available, and existing local terminal sessions are preserved."
                    .to_owned(),
                Style::default().fg(theme::SECONDARY),
            ),
        ]
    };

    let mut lines = Vec::new();
    for (index, (text, style)) in paragraphs.into_iter().enumerate() {
        if index > 0 {
            lines.push(Line::default());
        }
        lines.extend(wrap_paragraph(&text, usize::from(width), style));
    }
    lines
}

fn wrap_paragraph(text: &str, width: usize, style: Style) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    let mut line = String::new();
    let mut line_width = 0usize;

    for word in text.split_whitespace() {
        let word_width = Span::raw(word).width();
        if line_width > 0 && line_width.saturating_add(1).saturating_add(word_width) > width {
            lines.push(Line::styled(std::mem::take(&mut line), style));
            line_width = 0;
        }

        if word_width <= width {
            if line_width > 0 {
                line.push(' ');
                line_width += 1;
            }
            line.push_str(word);
            line_width = line_width.saturating_add(word_width);
            continue;
        }

        if line_width > 0 {
            lines.push(Line::styled(std::mem::take(&mut line), style));
            line_width = 0;
        }
        for grapheme in Span::raw(word).styled_graphemes(style) {
            let grapheme_width = Span::raw(grapheme.symbol).width();
            if line_width > 0 && line_width.saturating_add(grapheme_width) > width {
                lines.push(Line::styled(std::mem::take(&mut line), style));
                line_width = 0;
            }
            line.push_str(grapheme.symbol);
            line_width = line_width.saturating_add(grapheme_width);
        }
    }

    if !line.is_empty() || lines.is_empty() {
        lines.push(Line::styled(line, style));
    }
    lines
}

fn draw_buttons(
    frame: &mut Frame,
    content: Rect,
    y: u16,
    button_rows: u16,
    share: bool,
    confirm_selected: bool,
    controls: &Controls,
) {
    let confirm = if share {
        "Share workspace"
    } else {
        "Unshare workspace"
    };

    if button_rows == 1 {
        let gap = if content.width >= 44 { 2 } else { 0 };
        let cancel_width = content.width.saturating_sub(gap) / 2;
        let confirm_width = content
            .width
            .saturating_sub(gap)
            .saturating_sub(cancel_width);
        draw_button(
            frame,
            Rect::new(content.x, y, cancel_width, 1),
            "Cancel",
            !confirm_selected,
            KeyCode::Char('n'),
            content,
            controls,
        );
        draw_button(
            frame,
            Rect::new(
                content.x.saturating_add(cancel_width).saturating_add(gap),
                y,
                confirm_width,
                1,
            ),
            confirm,
            confirm_selected,
            KeyCode::Char('y'),
            content,
            controls,
        );
    } else {
        draw_button(
            frame,
            Rect::new(content.x, y, content.width, 1),
            "Cancel",
            !confirm_selected,
            KeyCode::Char('n'),
            content,
            controls,
        );
        draw_button(
            frame,
            Rect::new(content.x, y.saturating_add(1), content.width, 1),
            confirm,
            confirm_selected,
            KeyCode::Char('y'),
            content,
            controls,
        );
    }
}

fn draw_button(
    frame: &mut Frame,
    area: Rect,
    label: &str,
    selected: bool,
    key: KeyCode,
    clip: Rect,
    controls: &Controls,
) {
    let area = area.intersection(clip).intersection(frame.area());
    if area.is_empty() {
        return;
    }
    let (background, foreground) = if selected {
        (theme::SELECTION, theme::ACCENT)
    } else {
        (theme::KEYCAP, theme::SECONDARY)
    };
    let label_width = Span::raw(label).width();
    let label = if label_width.saturating_add(2) <= usize::from(area.width) {
        format!(" {label} ")
    } else {
        label.to_owned()
    };
    frame.render_widget(
        Paragraph::new(Span::styled(
            label,
            Style::default().fg(foreground).add_modifier(Modifier::BOLD),
        ))
        .alignment(Alignment::Center)
        .style(Style::default().bg(background)),
        area,
    );
    controls.key(area, key);
}

#[cfg(test)]
mod tests {
    use super::super::interaction::Action;
    use super::*;
    use crossterm::event::{KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::{Terminal, backend::TestBackend};

    fn click(column: u16, row: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::NONE,
        }
    }

    #[test]
    fn popup_bounds_center_and_cap_each_dialog_height() {
        let area = Rect::new(0, 0, 100, 30);
        assert_eq!(bounds(area, true), Rect::new(14, 5, 72, 19));
        assert_eq!(bounds(area, false), Rect::new(14, 9, 72, 12));
        assert_eq!(
            bounds(Rect::new(4, 6, 20, 10), true),
            Rect::new(4, 6, 20, 10)
        );
    }

    #[test]
    fn only_visible_buttons_register_cancel_and_confirm_keys() {
        let controls = Controls::default();
        controls.begin();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, "sample [workspace]", true, false, 0, &controls);
            })
            .unwrap();

        assert_eq!(
            controls.click(click(17, 21)),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('n'),
                KeyModifiers::NONE
            )))
        );
        assert_eq!(
            controls.click(click(52, 21)),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('y'),
                KeyModifiers::NONE
            )))
        );
        assert_eq!(controls.click(click(50, 21)), None);
    }

    #[test]
    fn unshare_confirm_target_uses_the_same_y_action() {
        let controls = Controls::default();
        controls.begin();
        let mut terminal = Terminal::new(TestBackend::new(100, 30)).unwrap();
        terminal
            .draw(|frame| {
                draw(frame, "shared", false, false, 0, &controls);
            })
            .unwrap();

        assert_eq!(
            controls.click(click(52, 18)),
            Some(Action::Key(KeyEvent::new(
                KeyCode::Char('y'),
                KeyModifiers::NONE
            )))
        );
    }
}
