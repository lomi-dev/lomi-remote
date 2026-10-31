//! Always-dark terminal colors from Lomi's built-in desktop theme.
//! Source: lomi/themes/lomi.json, common primary token and dark token block.

use super::interaction::{Action, Target, hint_key};

use ratatui::{
    Frame,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, Borders, Padding, Paragraph},
};
use std::sync::OnceLock;

pub(crate) const CANVAS: Color = Color::Rgb(0x10, 0x11, 0x14);
pub(crate) const SURFACE: Color = Color::Rgb(0x18, 0x1a, 0x1f);
pub(crate) const KEYCAP: Color = Color::Rgb(0x20, 0x23, 0x29);
pub(crate) const SIDEBAR: Color = SURFACE;
pub(crate) const TEXT: Color = Color::Rgb(0xf3, 0xf4, 0xf6);
pub(crate) const SECONDARY: Color = Color::Rgb(0xbe, 0xc3, 0xcc);
pub(crate) const MUTED: Color = Color::Rgb(0x98, 0x9f, 0xac);
pub(crate) const BORDER: Color = Color::Rgb(0x34, 0x39, 0x43);
pub(crate) const ACCENT: Color = Color::Rgb(0xc8, 0xff, 0x3d);
pub(crate) const SELECTION: Color = Color::Rgb(0x29, 0x35, 0x1c);
pub(crate) const SUCCESS: Color = Color::Rgb(0xa8, 0xd8, 0xb9);
pub(crate) const WARNING: Color = Color::Rgb(0xf1, 0xd2, 0x8a);
pub(crate) const ERROR: Color = Color::Rgb(0xf1, 0xab, 0xa8);

/// Keep the current choice visible after keyboard focus moves elsewhere.
pub(crate) fn selection_style(focused: bool) -> Style {
    Style::default()
        .fg(if focused { ACCENT } else { TEXT })
        .bg(if focused { SELECTION } else { KEYCAP })
        .add_modifier(Modifier::BOLD)
}

pub(crate) fn canvas(frame: &mut Frame) {
    frame.render_widget(
        Block::default().style(Style::default().bg(CANVAS).fg(TEXT)),
        frame.area(),
    );
}

/// Apple's Terminal ignores RGB SGR colors. Quantize only there; capable
/// terminals retain the exact desktop palette, independent of OS appearance.
pub(crate) fn finish(frame: &mut Frame) {
    static INDEXED_COLORS: OnceLock<bool> = OnceLock::new();
    if !*INDEXED_COLORS.get_or_init(|| {
        std::env::var_os("TERM_PROGRAM").is_some_and(|program| program == "Apple_Terminal")
    }) {
        return;
    }
    for cell in &mut frame.buffer_mut().content {
        cell.fg = indexed_color(cell.fg);
        cell.bg = indexed_color(cell.bg);
    }
}

fn indexed_color(color: Color) -> Color {
    let Color::Rgb(red, green, blue) = color else {
        return color;
    };
    let levels = [0u8, 95, 135, 175, 215, 255];
    let nearest = |channel: u8| {
        levels
            .iter()
            .enumerate()
            .min_by_key(|(_, level)| channel.abs_diff(**level))
            .map(|(index, value)| (index as u8, *value))
            .unwrap()
    };
    let (ri, r) = nearest(red);
    let (gi, g) = nearest(green);
    let (bi, b) = nearest(blue);
    let distance = |r: u8, g: u8, b: u8| {
        [red.abs_diff(r), green.abs_diff(g), blue.abs_diff(b)]
            .into_iter()
            .map(|delta| u32::from(delta).pow(2))
            .sum::<u32>()
    };
    // Avoid the configurable first sixteen colors: the remaining xterm cube
    // and grayscale ramp have stable values across terminal profiles.
    let mean = (u16::from(red) + u16::from(green) + u16::from(blue)) / 3;
    let gray_index = ((mean.saturating_sub(8) + 5) / 10).min(23) as u8;
    let gray = 8 + gray_index * 10;
    Color::Indexed(if distance(gray, gray, gray) <= distance(r, g, b) {
        232 + gray_index
    } else {
        16 + 36 * ri + 6 * gi + bi
    })
}

/// Retain the original one-cell content insets without visible box outlines.
pub(crate) fn panel(title: impl Into<String>, surface: Color) -> Block<'static> {
    Block::bordered()
        .style(Style::default().bg(surface).fg(SECONDARY))
        .border_style(Style::default().fg(surface))
        .title(Span::styled(
            format!(" {} ", title.into()),
            Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
        ))
}

pub(crate) fn footer() -> Block<'static> {
    Block::default()
        .borders(Borders::TOP)
        .border_style(Style::default().fg(BORDER))
        .padding(Padding::horizontal(1))
        .style(Style::default().bg(CANVAS).fg(MUTED))
}

fn hint_line(hints: &[(&str, &str)]) -> Line<'static> {
    let mut spans = Vec::new();
    for (index, (key, label)) in hints.iter().enumerate() {
        if index > 0 {
            spans.push(Span::raw("   "));
        }
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default()
                .bg(KEYCAP)
                .fg(TEXT)
                .add_modifier(Modifier::BOLD),
        ));
        spans.push(Span::styled(
            format!(" {label}"),
            Style::default().fg(MUTED),
        ));
    }
    Line::from(spans)
}

pub(crate) fn render_footer(
    frame: &mut Frame,
    area: Rect,
    primary: &[(&str, &str)],
    trailing: &[(&str, &str)],
) -> Vec<Target> {
    let block = footer();
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut targets = Vec::new();
    if inner.is_empty() {
        return targets;
    }
    let left_width = hint_line(primary).width();
    let right_width = hint_line(trailing).width();
    let gap = usize::from(!primary.is_empty() && !trailing.is_empty()) * 3;
    if left_width + gap + right_width <= usize::from(inner.width) {
        render_hint_groups(frame, inner, primary, inner.x, &mut targets);
        render_hint_groups(
            frame,
            inner,
            trailing,
            inner.right().saturating_sub(right_width as u16),
            &mut targets,
        );
    } else {
        let hints: Vec<_> = primary.iter().chain(trailing).copied().collect();
        render_hint_groups(frame, inner, &hints, inner.x, &mut targets);
    }
    targets
}

fn render_hint_groups(
    frame: &mut Frame,
    inner: Rect,
    hints: &[(&str, &str)],
    mut x: u16,
    targets: &mut Vec<Target>,
) {
    let mut y = inner.y;
    for (key, label) in hints {
        let line = hint_line(&[(*key, *label)]);
        let width = line.width().min(usize::from(inner.width)) as u16;
        if x > inner.x && x.saturating_add(width) > inner.right() {
            x = inner.x;
            y = y.saturating_add(1);
        }
        if y >= inner.bottom() {
            break;
        }
        let target = Rect::new(x, y, width, 1);
        frame.render_widget(Paragraph::new(line), target);
        if let Some(key) = hint_key(key).filter(|_| line_width_fits(key, label, inner.width)) {
            targets.push(Target {
                area: target,
                action: Action::Key(key),
            });
        }
        x = x.saturating_add(width).saturating_add(3);
    }
}

fn line_width_fits(key: &str, label: &str, width: u16) -> bool {
    hint_line(&[(key, label)]).width() <= usize::from(width)
}

fn shortcut_line(text: &str) -> Line<'static> {
    let mut spans = Vec::new();
    let mut remaining = text;
    while let Some(start) = remaining.find('[') {
        let Some(end) = remaining[start..].find(']') else {
            break;
        };
        spans.push(Span::styled(
            remaining[..start].to_owned(),
            Style::default().fg(MUTED),
        ));
        let end = start + end + 1;
        spans.push(Span::styled(
            format!(" {} ", &remaining[start + 1..end - 1]),
            Style::default().fg(TEXT).bg(KEYCAP),
        ));
        remaining = &remaining[end..];
    }
    spans.push(Span::styled(
        remaining.to_owned(),
        Style::default().fg(MUTED),
    ));
    Line::from(spans)
}

pub(crate) fn shortcuts(text: &str) -> Text<'static> {
    Text::from(text.split('\n').map(shortcut_line).collect::<Vec<_>>())
}

fn value_color(value: &str) -> Color {
    match value {
        "Ready" | "Running" | "Available" | "Enabled" | "Shared" | "Healthy" => SUCCESS,
        "Locked" | "PendingRevoke" | "Unavailable" | "Unknown" | "Starting" => WARNING,
        "Failed" | "Invalid" | "PermissionDenied" => ERROR,
        _ => TEXT,
    }
}

/// Style existing text without changing labels, values, line breaks or actions.
pub(crate) fn content(text: &str) -> Text<'static> {
    Text::from(
        text.split('\n')
            .enumerate()
            .map(|(index, line)| {
                if let Some((label, value)) = line.split_once(": ") {
                    return Line::from(vec![
                        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
                        Span::styled(value.to_owned(), Style::default().fg(value_color(value))),
                    ]);
                }
                Line::styled(
                    line.to_owned(),
                    if index == 0 {
                        Style::default().fg(TEXT).add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(SECONDARY)
                    },
                )
            })
            .collect::<Vec<_>>(),
    )
}

pub(crate) fn header(text: &str) -> Text<'static> {
    let mut styled = content(text);
    if let Some(first) = styled.lines.first_mut() {
        if let Some(rest) = text
            .lines()
            .next()
            .and_then(|line| line.strip_prefix("Lomi Remote"))
        {
            *first = Line::from(vec![
                Span::styled(
                    "Lomi Remote",
                    Style::default().fg(TEXT).add_modifier(Modifier::BOLD),
                ),
                Span::styled(rest.to_owned(), Style::default().fg(MUTED)),
            ]);
        }
    }
    styled
}
