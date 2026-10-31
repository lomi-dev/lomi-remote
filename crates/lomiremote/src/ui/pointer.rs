//! Best-effort OSC 22 mouse pointers, separate from the text input caret.
//!
//! No capability queries are sent: Crossterm 0.29 cannot isolate OSC replies
//! from keyboard input. Unknown terminals keep their native mouse pointer.

use crossterm::event::MouseEvent;
use std::{
    cell::Cell,
    io::{self, IsTerminal, Write},
};

thread_local! {
    // Setup can open a new foreground terminal session between steps. Reuse
    // its last observed location so a redraw also updates a stationary mouse.
    static LAST_POSITION: Cell<Option<(u16, u16)>> = const { Cell::new(None) };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Shape {
    Arrow,
    Hand,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dialect {
    Css,
    X11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Profile {
    dialect: Dialect,
    tmux: bool,
}

impl Profile {
    fn command(self, shape: Option<Shape>) -> Vec<u8> {
        let command: &[u8] = match (self.dialect, shape) {
            (_, None) => b"\x1b]22;\x1b\\",
            (Dialect::Css, Some(Shape::Arrow)) => b"\x1b]22;default\x1b\\",
            (Dialect::Css, Some(Shape::Hand)) => b"\x1b]22;pointer\x1b\\",
            (Dialect::X11, Some(Shape::Arrow)) => b"\x1b]22;left_ptr\x1b\\",
            (Dialect::X11, Some(Shape::Hand)) => b"\x1b]22;hand2\x1b\\",
        };
        if !self.tmux {
            return command.to_vec();
        }
        let mut wrapped = b"\x1bPtmux;".to_vec();
        for byte in command {
            wrapped.push(*byte);
            if *byte == 0x1b {
                wrapped.push(*byte);
            }
        }
        wrapped.extend_from_slice(b"\x1b\\");
        wrapped
    }
}

fn version_at_least(version: &str, major: u32, minor: u32) -> bool {
    let mut parts = version.split('.');
    let number = |value: &str| {
        value
            .chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse::<u32>()
            .ok()
    };
    match (parts.next().and_then(number), parts.next().and_then(number)) {
        (Some(a), Some(b)) => (a, b) >= (major, minor),
        _ => false,
    }
}

fn detect_profile(is_tty: bool, env: impl Fn(&str) -> Option<String>) -> Option<Profile> {
    if !is_tty {
        return None;
    }
    let term = env("TERM").unwrap_or_default().to_ascii_lowercase();
    if matches!(term.as_str(), "dumb" | "linux" | "cons25" | "emacs") {
        return None;
    }
    let setting = env("LOMI_REMOTE_POINTER")
        .unwrap_or_else(|| "auto".to_owned())
        .to_ascii_lowercase();
    if setting == "off" || env("STY").is_some() {
        return None;
    }
    let tmux = env("TMUX").is_some();
    if let Some(dialect) = match setting.as_str() {
        "css" => Some(Dialect::Css),
        "x11" => Some(Dialect::X11),
        _ => None,
    } {
        // Explicit overrides can traverse tmux when its owner has enabled
        // allow-passthrough. Do not change that user's tmux configuration.
        return Some(Profile { dialect, tmux });
    }
    if setting != "auto" || tmux {
        return None;
    }
    let program = env("TERM_PROGRAM").unwrap_or_default().to_ascii_lowercase();
    let version = env("TERM_PROGRAM_VERSION").unwrap_or_default();
    let dialect = if program == "ghostty"
        || term == "xterm-ghostty"
        || program == "kitty"
        || term == "xterm-kitty"
        || env("KITTY_WINDOW_ID").is_some()
        || matches!(term.as_str(), "foot" | "foot-direct" | "foot-extra")
    {
        Dialect::Css
    } else if matches!(program.as_str(), "iterm.app" | "iterm2") && version_at_least(&version, 3, 5)
    {
        Dialect::X11
    } else if env("XTERM_VERSION").is_some_and(|value| {
        value
            .split(|c: char| !c.is_ascii_digit())
            .filter_map(|part| part.parse::<u32>().ok())
            .next()
            .is_some_and(|version| version >= 367)
    }) {
        Dialect::X11
    } else {
        return None;
    };
    Some(Profile {
        dialect,
        tmux: false,
    })
}

struct Output {
    profile: Option<Profile>,
    shape: Option<Shape>,
    touched: bool,
    failed: bool,
}

impl Output {
    fn new(profile: Option<Profile>) -> Self {
        Self {
            profile,
            shape: None,
            touched: false,
            failed: false,
        }
    }

    fn set(&mut self, writer: &mut impl Write, shape: Shape) {
        let Some(profile) = self.profile else {
            return;
        };
        if self.failed || self.shape == Some(shape) {
            return;
        }
        self.touched = true;
        if writer
            .write_all(&profile.command(Some(shape)))
            .and_then(|_| writer.flush())
            .is_err()
        {
            // Pointer decoration must never prevent navigation or text input.
            self.failed = true;
            return;
        }
        self.shape = Some(shape);
    }

    fn restore(&mut self, writer: &mut impl Write) {
        if !self.touched {
            return;
        }
        if let Some(profile) = self.profile {
            let _ = writer
                .write_all(&profile.command(None))
                .and_then(|_| writer.flush());
        }
        self.touched = false;
        self.shape = None;
    }
}

pub(crate) struct PointerTracker {
    output: Output,
    position: Option<(u16, u16)>,
}

impl PointerTracker {
    pub(crate) fn new() -> Self {
        let profile = detect_profile(io::stdout().is_terminal(), |key| std::env::var(key).ok());
        Self {
            output: Output::new(profile),
            position: LAST_POSITION.with(Cell::get),
        }
    }

    pub(crate) fn observe(&mut self, event: MouseEvent) {
        self.position = Some((event.column, event.row));
        LAST_POSITION.with(|last| last.set(self.position));
    }

    pub(crate) fn refresh(&mut self, hoverable: impl Fn(u16, u16) -> bool) {
        let shape = if self.position.is_some_and(|(x, y)| hoverable(x, y)) {
            Shape::Hand
        } else {
            Shape::Arrow
        };
        self.output.set(&mut io::stdout().lock(), shape);
    }

    pub(crate) fn reset(&mut self) {
        self.output.set(&mut io::stdout().lock(), Shape::Arrow);
    }
}

impl Drop for PointerTracker {
    fn drop(&mut self) {
        self.output.restore(&mut io::stdout().lock());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(entries: &[(&str, &str)], is_tty: bool) -> Option<Profile> {
        detect_profile(is_tty, |key| {
            entries
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_owned())
        })
    }

    #[test]
    fn auto_detection_uses_verified_terminal_dialects_and_versions() {
        for env in [
            vec![("TERM", "xterm-kitty")],
            vec![("TERM_PROGRAM", "ghostty")],
            vec![("TERM", "foot")],
        ] {
            assert_eq!(
                profile(&env, true),
                Some(Profile {
                    dialect: Dialect::Css,
                    tmux: false
                })
            );
        }
        assert_eq!(
            profile(
                &[
                    ("TERM_PROGRAM", "iTerm.app"),
                    ("TERM_PROGRAM_VERSION", "3.5.0")
                ],
                true
            ),
            Some(Profile {
                dialect: Dialect::X11,
                tmux: false
            })
        );
        assert!(
            profile(
                &[
                    ("TERM_PROGRAM", "iTerm.app"),
                    ("TERM_PROGRAM_VERSION", "3.4.9")
                ],
                true
            )
            .is_none()
        );
        assert_eq!(
            profile(&[("XTERM_VERSION", "XTerm(390)")], true),
            Some(Profile {
                dialect: Dialect::X11,
                tmux: false
            })
        );
        assert!(profile(&[("XTERM_VERSION", "XTerm(366)")], true).is_none());
    }

    #[test]
    fn unsupported_and_redirected_output_is_untouched() {
        for env in [
            vec![],
            vec![("TERM_PROGRAM", "Apple_Terminal")],
            vec![("WT_SESSION", "session")],
            vec![("TERM", "dumb"), ("LOMI_REMOTE_POINTER", "css")],
            vec![("TERM", "linux")],
            vec![("TERM", "xterm-kitty"), ("TMUX", "session")],
            vec![("STY", "screen"), ("LOMI_REMOTE_POINTER", "x11")],
        ] {
            assert!(profile(&env, true).is_none(), "{env:?}");
        }
        assert!(profile(&[("LOMI_REMOTE_POINTER", "css")], false).is_none());
        let mut output = Output::new(None);
        let mut bytes = Vec::new();
        output.set(&mut bytes, Shape::Hand);
        output.restore(&mut bytes);
        assert!(bytes.is_empty());
    }

    #[test]
    fn shape_updates_are_deduplicated_and_teardown_restores_the_terminal_default() {
        let mut output = Output::new(Some(Profile {
            dialect: Dialect::Css,
            tmux: false,
        }));
        let mut bytes = Vec::new();
        output.set(&mut bytes, Shape::Arrow);
        output.set(&mut bytes, Shape::Hand);
        output.set(&mut bytes, Shape::Hand);
        output.set(&mut bytes, Shape::Arrow);
        output.restore(&mut bytes);
        output.restore(&mut bytes);
        assert_eq!(
            bytes,
            b"\x1b]22;default\x1b\\\x1b]22;pointer\x1b\\\x1b]22;default\x1b\\\x1b]22;\x1b\\"
        );
    }

    #[test]
    fn x11_and_explicit_tmux_passthrough_use_their_own_encoding() {
        let legacy = Profile {
            dialect: Dialect::X11,
            tmux: false,
        };
        assert_eq!(
            legacy.command(Some(Shape::Arrow)),
            b"\x1b]22;left_ptr\x1b\\"
        );
        assert_eq!(legacy.command(Some(Shape::Hand)), b"\x1b]22;hand2\x1b\\");
        let tmux = profile(&[("TMUX", "session"), ("LOMI_REMOTE_POINTER", "css")], true).unwrap();
        assert_eq!(
            tmux.command(Some(Shape::Hand)),
            b"\x1bPtmux;\x1b\x1b]22;pointer\x1b\x1b\\\x1b\\"
        );
    }

    #[test]
    fn failed_pointer_output_does_not_keep_retrying_or_skip_cleanup() {
        struct Writer {
            attempts: usize,
        }
        impl Write for Writer {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.attempts += 1;
                Err(io::Error::other("unavailable"))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut writer = Writer { attempts: 0 };
        let mut output = Output::new(Some(Profile {
            dialect: Dialect::Css,
            tmux: false,
        }));
        output.set(&mut writer, Shape::Hand);
        output.set(&mut writer, Shape::Arrow);
        assert_eq!(writer.attempts, 1);
        output.restore(&mut writer);
        assert_eq!(writer.attempts, 2);
    }
}
