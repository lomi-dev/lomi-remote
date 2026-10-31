//! Explicit screen targets shared by pointer and keyboard navigation.

use super::theme;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::{Frame, layout::Rect, style::Modifier};
use std::{
    cell::{Cell, RefCell},
    time::{Duration, Instant},
};

thread_local! {
    // All foreground TUI screens share the input thread. Keep a pending
    // double-click from activating a newly opened confirmation, including
    // setup steps that construct a fresh Controls value.
    static LAST_CLICK: Cell<Option<(u16, u16, Instant)>> = const { Cell::new(None) };
}

fn accept_click(event: MouseEvent, target: Target) -> bool {
    let now = Instant::now();
    LAST_CLICK.with(|last| {
        if matches!(target.action, Action::Key(_))
            && last.get().is_some_and(|(x, y, time)| {
                (target.area.contains((x, y).into())
                    || (x.abs_diff(event.column) <= 1 && y.abs_diff(event.row) <= 1))
                    && now.saturating_duration_since(time) < Duration::from_millis(450)
            })
        {
            return false;
        }
        last.set(Some((event.column, event.row, now)));
        true
    })
}

/// Apply the shared double-click guard to custom controls that activate from
/// pointer events instead of registering a `Controls` target.
pub(crate) fn accept_pointer_key(event: MouseEvent, area: Rect, code: KeyCode) -> bool {
    if event.kind != MouseEventKind::Down(MouseButton::Left)
        || !event.modifiers.is_empty()
        || area.is_empty()
        || !area.contains((event.column, event.row).into())
    {
        return false;
    }
    accept_click(
        event,
        Target {
            area,
            action: Action::Key(KeyEvent::new(code, KeyModifiers::NONE)),
        },
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Action {
    Key(KeyEvent),
    Row(usize),
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Target {
    pub area: Rect,
    pub action: Action,
}

#[derive(Default)]
pub(crate) struct Controls {
    targets: RefCell<Vec<Target>>,
    focus: Cell<Option<usize>>,
    restore_focus: Cell<Option<Action>>,
    restore_index: Cell<Option<usize>>,
}

impl Controls {
    /// Rebuild targets each frame; only the currently visible controls exist.
    pub(crate) fn begin(&self) {
        let action = self.focused();
        self.restore_index.set(self.focus.get());
        self.targets.borrow_mut().clear();
        self.focus.set(None);
        self.restore_focus.set(action);
    }

    pub(crate) fn reset(&self) {
        self.begin();
        self.blur();
    }

    pub(crate) fn blur(&self) {
        self.focus.set(None);
        self.restore_focus.set(None);
        self.restore_index.set(None);
    }

    pub(crate) fn add(&self, area: Rect, action: Action) {
        if !area.is_empty() {
            let mut targets = self.targets.borrow_mut();
            if self.restore_focus.get() == Some(action)
                && (self.focus.get().is_none() || self.restore_index.get() == Some(targets.len()))
            {
                self.focus.set(Some(targets.len()));
            }
            targets.push(Target { area, action });
        }
    }

    pub(crate) fn key(&self, area: Rect, code: KeyCode) {
        self.event(area, KeyEvent::new(code, KeyModifiers::NONE));
    }

    pub(crate) fn event(&self, area: Rect, key: KeyEvent) {
        self.add(area, Action::Key(key));
    }

    pub(crate) fn row(&self, area: Rect, index: usize) {
        self.add(area, Action::Row(index));
    }

    pub(crate) fn extend(&self, targets: impl IntoIterator<Item = Target>) {
        for target in targets {
            self.add(target.area, target.action);
        }
    }

    pub(crate) fn cycle(&self, backwards: bool) {
        self.restore_focus.set(None);
        self.restore_index.set(None);
        let count = self.targets.borrow().len();
        if count == 0 {
            self.blur();
            return;
        }
        self.focus.set(Some(
            match self.focus.get().filter(|index| *index < count) {
                None => {
                    if backwards {
                        count - 1
                    } else {
                        0
                    }
                }
                Some(0) if backwards => count - 1,
                Some(index) if backwards => index - 1,
                Some(index) => (index + 1) % count,
            },
        ));
    }

    /// Move focus to the closest visible target in one direction.
    ///
    /// The perpendicular overlap preference keeps movement within a row or
    /// column when possible. Focus movement never dispatches the target's
    /// action.
    pub(crate) fn move_focus(&self, direction: KeyCode) -> bool {
        if !matches!(
            direction,
            KeyCode::Up | KeyCode::Down | KeyCode::Left | KeyCode::Right
        ) {
            return false;
        }
        let horizontal = matches!(direction, KeyCode::Left | KeyCode::Right);
        let forward = matches!(direction, KeyCode::Down | KeyCode::Right);
        let targets = self.targets.borrow();
        if targets.is_empty() {
            return false;
        }

        let current = self.focus.get().filter(|index| *index < targets.len());
        let next = if let Some(current) = current {
            let source = targets[current].area;
            targets
                .iter()
                .enumerate()
                .filter(|(index, target)| {
                    if *index == current {
                        return false;
                    }
                    let (source_primary, target_primary) = if horizontal {
                        (center_x(source), center_x(target.area))
                    } else {
                        (center_y(source), center_y(target.area))
                    };
                    if forward {
                        target_primary > source_primary
                    } else {
                        target_primary < source_primary
                    }
                })
                .min_by_key(|(_, target)| {
                    let primary_distance = if horizontal {
                        center_x(target.area).abs_diff(center_x(source))
                    } else {
                        center_y(target.area).abs_diff(center_y(source))
                    };
                    let perpendicular_distance = if horizontal {
                        center_y(target.area).abs_diff(center_y(source))
                    } else {
                        center_x(target.area).abs_diff(center_x(source))
                    };
                    let overlaps = if horizontal {
                        vertical_overlap(source, target.area)
                    } else {
                        horizontal_overlap(source, target.area)
                    };
                    (!overlaps, primary_distance, perpendicular_distance)
                })
                .map(|(index, _)| index)
        } else {
            let key = |area: Rect| {
                if horizontal {
                    (center_x(area), center_y(area))
                } else {
                    (center_y(area), center_x(area))
                }
            };
            targets
                .iter()
                .enumerate()
                .min_by_key(|(_, target)| {
                    let (mut primary, mut secondary) = key(target.area);
                    if forward {
                        (primary, secondary)
                    } else {
                        primary = u32::MAX - primary;
                        secondary = u32::MAX - secondary;
                        (primary, secondary)
                    }
                })
                .map(|(index, _)| index)
        };

        let Some(next) = next else {
            return false;
        };
        self.focus.set(Some(next));
        self.restore_focus.set(None);
        self.restore_index.set(None);
        true
    }

    /// Focus a currently visible target with this action.
    pub(crate) fn focus_action(&self, action: Action) -> bool {
        let targets = self.targets.borrow();
        let Some(index) = targets.iter().rposition(|target| target.action == action) else {
            return false;
        };
        self.focus.set(Some(index));
        self.restore_focus.set(None);
        self.restore_index.set(None);
        true
    }

    pub(crate) fn focused(&self) -> Option<Action> {
        self.targets
            .borrow()
            .get(self.focus.get()?)
            .map(|target| target.action)
    }

    pub(crate) fn click(&self, event: MouseEvent) -> Option<Action> {
        if event.kind != MouseEventKind::Down(MouseButton::Left) || !event.modifiers.is_empty() {
            return None;
        }
        let (index, target) = self.target_at(event.column, event.row)?;
        if !accept_click(event, target) {
            return None;
        }
        self.focus.set(Some(index));
        self.restore_focus.set(None);
        self.restore_index.set(None);
        Some(target.action)
    }

    /// Whether the current topmost target should use the hand pointer.
    ///
    /// This is deliberately read-only: hover must not change focus, consume a
    /// click guard, or activate the action associated with a target.
    pub(crate) fn hoverable(&self, column: u16, row: u16) -> bool {
        self.target_at(column, row)
            .is_some_and(|(_, target)| match target.action {
                Action::Key(_) => true,
                Action::Row(index) => index != usize::MAX,
            })
    }

    fn target_at(&self, column: u16, row: u16) -> Option<(usize, Target)> {
        self.targets
            .borrow()
            .iter()
            .copied()
            .enumerate()
            .rev()
            .find(|(_, target)| target.area.contains((column, row).into()))
    }

    #[cfg(test)]
    pub(crate) fn action_at(&self, column: u16, row: u16) -> Option<Action> {
        self.target_at(column, row).map(|(_, target)| target.action)
    }

    pub(crate) fn highlight(&self, frame: &mut Frame) {
        let targets = self.targets.borrow();
        let Some(target) = self.focus.get().and_then(|index| targets.get(index)) else {
            return;
        };
        let area = target.area.intersection(frame.area());
        for y in area.y..area.bottom() {
            for x in area.x..area.right() {
                let cell = &mut frame.buffer_mut()[(x, y)];
                if !cell.symbol().trim().is_empty() {
                    cell.set_fg(theme::ACCENT);
                    cell.modifier.insert(Modifier::UNDERLINED);
                }
            }
        }
    }
}

fn center_x(area: Rect) -> u32 {
    u32::from(area.x) * 2 + u32::from(area.width)
}

fn center_y(area: Rect) -> u32 {
    u32::from(area.y) * 2 + u32::from(area.height)
}

fn horizontal_overlap(left: Rect, right: Rect) -> bool {
    left.x < right.x.saturating_add(right.width) && right.x < left.x.saturating_add(left.width)
}

fn vertical_overlap(top: Rect, bottom: Rect) -> bool {
    top.y < bottom.y.saturating_add(bottom.height) && bottom.y < top.y.saturating_add(top.height)
}

/// Parse only trusted shortcut specifications, never displayed workspace data.
pub(crate) fn hint_key(key: &str) -> Option<KeyEvent> {
    let code = match key.to_ascii_lowercase().as_str() {
        "enter" | "return" => KeyCode::Enter,
        "esc" | "escape" | "n/esc" | "n / esc" => KeyCode::Esc,
        "backspace" => KeyCode::Backspace,
        "tab" => KeyCode::Tab,
        "ctrl+c" | "ctrl-c" => {
            return Some(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
        }
        _ => {
            let mut characters = key.chars();
            let character = characters.next()?;
            if characters.next().is_some() {
                return None;
            }
            KeyCode::Char(character)
        }
    };
    Some(KeyEvent::new(code, KeyModifiers::NONE))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rebuilding_and_resizing_removes_invisible_hit_targets() {
        let controls = Controls::default();
        controls.key(Rect::new(4, 5, 10, 1), KeyCode::Char('a'));
        controls.cycle(false);
        assert!(controls.focused().is_some());
        controls.begin();
        assert!(controls.focused().is_none());
        assert!(!controls.hoverable(5, 5));
        assert!(
            controls
                .click(MouseEvent {
                    kind: MouseEventKind::Down(MouseButton::Left),
                    column: 5,
                    row: 5,
                    modifiers: KeyModifiers::NONE
                })
                .is_none()
        );
        controls.key(Rect::new(0, 0, 0, 1), KeyCode::Char('y'));
        controls.cycle(false);
        assert!(controls.focused().is_none());
    }

    #[test]
    fn focus_and_pointer_activate_the_same_explicit_action() {
        let controls = Controls::default();
        controls.row(Rect::new(1, 1, 20, 2), 7);
        controls.key(Rect::new(30, 1, 10, 1), KeyCode::Esc);
        controls.cycle(true);
        assert_eq!(
            controls.focused(),
            Some(Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE)))
        );
        let clicked = controls.click(MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 4,
            row: 2,
            modifiers: KeyModifiers::NONE,
        });
        assert_eq!(clicked, Some(Action::Row(7)));
        assert_eq!(controls.focused(), clicked);
        controls.cycle(false);
        assert!(matches!(controls.focused(), Some(Action::Key(_))));
    }

    #[test]
    fn focus_tracks_the_action_when_rows_change_and_never_switches_to_confirm() {
        let controls = Controls::default();
        controls.row(Rect::new(0, 0, 8, 1), 0);
        controls.key(Rect::new(0, 1, 8, 1), KeyCode::Esc);
        controls.cycle(true);
        let cancel = controls.focused();
        controls.begin();
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Esc);
        controls.key(Rect::new(0, 1, 8, 1), KeyCode::Char('y'));
        assert_eq!(controls.focused(), cancel);
        controls.begin();
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Char('y'));
        assert!(controls.focused().is_none());
        controls.begin();
        controls.key(Rect::new(0, 0, 8, 1), KeyCode::Esc);
        assert!(controls.focused().is_none());
    }

    #[test]
    fn hover_queries_preserve_focus_and_click_guard() {
        LAST_CLICK.with(|last| last.set(None));
        let controls = Controls::default();
        controls.key(Rect::new(1, 1, 8, 1), KeyCode::Char('a'));
        controls.row(Rect::new(1, 2, 8, 1), 7);
        controls.cycle(false);
        let focused = controls.focused();
        let click_guard = (3, 1, Instant::now());
        LAST_CLICK.with(|last| last.set(Some(click_guard)));

        assert!(controls.hoverable(3, 1));
        assert!(controls.hoverable(3, 2));
        assert!(!controls.hoverable(9, 2));
        assert_eq!(controls.focused(), focused);
        assert_eq!(LAST_CLICK.with(|last| last.get()), Some(click_guard));

        controls.row(Rect::new(1, 3, 8, 1), usize::MAX);
        assert!(!controls.hoverable(3, 3));
        assert_eq!(controls.focused(), focused);
        assert_eq!(LAST_CLICK.with(|last| last.get()), Some(click_guard));
        LAST_CLICK.with(|last| last.set(None));
    }

    #[test]
    fn double_click_does_not_accept_a_new_confirmation_even_across_screens() {
        LAST_CLICK.with(|last| last.set(None));
        let first = Controls::default();
        first.key(Rect::new(1, 1, 12, 1), KeyCode::Char('i'));
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 3,
            row: 1,
            modifiers: KeyModifiers::NONE,
        };
        assert!(first.click(click).is_some());
        let confirmation = Controls::default();
        confirmation.key(Rect::new(1, 1, 12, 1), KeyCode::Char('y'));
        assert!(confirmation.click(click).is_none());
        assert!(
            confirmation
                .click(MouseEvent { column: 4, ..click })
                .is_none()
        );
        confirmation.key(Rect::new(40, 1, 12, 1), KeyCode::Char('y'));
        assert!(
            confirmation
                .click(MouseEvent {
                    column: 44,
                    ..click
                })
                .is_some()
        );
        LAST_CLICK.with(|last| last.set(None));
    }

    #[test]
    fn directional_focus_prefers_the_same_row_and_never_activates() {
        let controls = Controls::default();
        let source = Action::Key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));
        let same_row = Action::Key(KeyEvent::new(KeyCode::Char('b'), KeyModifiers::NONE));
        let nearby_diagonal = Action::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::NONE));
        controls.key(Rect::new(1, 1, 8, 1), KeyCode::Char('a'));
        controls.key(Rect::new(12, 1, 8, 1), KeyCode::Char('b'));
        controls.key(Rect::new(9, 3, 8, 1), KeyCode::Char('c'));
        assert!(controls.focus_action(source));

        assert!(controls.move_focus(KeyCode::Right));
        assert_eq!(controls.focused(), Some(same_row));
        assert!(!controls.move_focus(KeyCode::Right));
        assert_eq!(controls.focused(), Some(same_row));
        assert_eq!(controls.focused(), Some(same_row));
        assert_ne!(controls.focused(), Some(nearby_diagonal));
    }

    #[test]
    fn directional_focus_uses_visible_targets_and_has_a_deterministic_initial_target() {
        let controls = Controls::default();
        let first = Action::Row(1);
        let last = Action::Key(KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE));
        controls.row(Rect::new(20, 2, 10, 1), 1);
        controls.key(Rect::new(20, 6, 10, 1), KeyCode::Esc);
        controls.key(Rect::new(0, 0, 0, 1), KeyCode::Char('x'));

        assert!(controls.move_focus(KeyCode::Down));
        assert_eq!(controls.focused(), Some(first));
        assert!(controls.move_focus(KeyCode::Down));
        assert_eq!(controls.focused(), Some(last));
        assert!(controls.focus_action(first));
        assert!(!controls.move_focus(KeyCode::Up));
        assert_eq!(controls.focused(), Some(first));
        assert!(!controls.focus_action(Action::Row(99)));
        assert_eq!(controls.focused(), Some(first));
    }

    #[test]
    fn custom_pointer_actions_share_the_click_guard() {
        LAST_CLICK.with(|last| last.set(None));
        let area = Rect::new(5, 6, 10, 2);
        let click = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 7,
            row: 6,
            modifiers: KeyModifiers::NONE,
        };

        assert!(accept_pointer_key(click, area, KeyCode::Enter));
        assert!(!accept_pointer_key(click, area, KeyCode::Enter));
        assert!(!accept_pointer_key(
            MouseEvent {
                modifiers: KeyModifiers::SHIFT,
                ..click
            },
            area,
            KeyCode::Enter,
        ));
        assert!(!accept_pointer_key(click, Rect::default(), KeyCode::Enter));
        LAST_CLICK.with(|last| last.set(None));
    }
}
