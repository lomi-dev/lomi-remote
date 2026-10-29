//! Explicit local setup; secrets are read without echo, never command arguments.
use clap::ArgMatches;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use lomi_host::{GitCredentials, git_credentials::HostGitCredentials};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
};

struct RawInput;
impl Drop for RawInput {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

fn read_field(prompt: &str, target: &mut Vec<u8>) -> Result<(), &'static str> {
    eprint!("{prompt}");
    io::stderr()
        .flush()
        .map_err(|_| "GIT_CREDENTIAL_INPUT_UNAVAILABLE")?;
    terminal::enable_raw_mode().map_err(|_| "GIT_CREDENTIAL_INPUT_UNAVAILABLE")?;
    let _raw = RawInput;
    loop {
        match event::read().map_err(|_| "GIT_CREDENTIAL_INPUT_UNAVAILABLE")? {
            Event::Key(key) if key.kind == KeyEventKind::Press => match key.code {
                KeyCode::Char('c' | 'd') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                    return Err("GIT_CREDENTIAL_INPUT_CANCELLED");
                }
                KeyCode::Esc => return Err("GIT_CREDENTIAL_INPUT_CANCELLED"),
                KeyCode::Enter if !target.is_empty() => break,
                KeyCode::Backspace => {
                    if !target.is_empty() {
                        let mut end = target.len() - 1;
                        while end > 0 && target[end] & 0xc0 == 0x80 {
                            end -= 1;
                        }
                        target[end..].fill(0);
                        target.truncate(end);
                    }
                }
                KeyCode::Char(character)
                    if !character.is_control()
                        && !key
                            .modifiers
                            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    let mut buffer = [0u8; 4];
                    let bytes = character.encode_utf8(&mut buffer).as_bytes();
                    if target.len() + bytes.len() > 8192 {
                        return Err("GIT_CREDENTIAL_INPUT_TOO_LARGE");
                    }
                    target.extend_from_slice(bytes);
                    buffer.fill(0);
                }
                _ => (),
            },
            Event::Paste(value) => {
                let mut bytes = value.into_bytes();
                let valid = target.len() + bytes.len() <= 8192
                    && !bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n'));
                if valid {
                    target.extend_from_slice(&bytes);
                }
                bytes.fill(0);
                if !valid {
                    return Err("GIT_CREDENTIAL_INPUT_INVALID");
                }
            }
            _ => (),
        }
    }
    drop(_raw);
    eprintln!();
    Ok(())
}

pub fn run(profile: &Path, args: &ArgMatches) -> u8 {
    let result = (|| -> Result<(), String> {
        let (command, args) = args.subcommand().ok_or("INVALID_ARGUMENT")?;
        if !matches!(command, "set" | "clear") {
            return Err("INVALID_ARGUMENT".into());
        }
        if !args.get_flag("confirm") {
            return Err("CONFIRMATION_REQUIRED".into());
        }
        let url = args.get_one::<String>("url").ok_or("INVALID_ARGUMENT")?;
        let configuration = crate::bootstrap::default_auth_configuration(
            args.get_one::<PathBuf>("keychain-path")
                .map(PathBuf::as_path),
            args.get_flag("ack-os-permissions-only"),
        )
        .map_err(|error| error.to_string())?;
        let storage = HostGitCredentials::new(profile.to_owned(), configuration)
            .map_err(|error| error.to_string())?;
        let credentials = if command == "set" {
            if !(io::stdin().is_terminal() && io::stderr().is_terminal()) {
                return Err("INTERACTIVE_TERMINAL_REQUIRED".into());
            }
            let mut credentials = GitCredentials {
                username: Vec::new().into(),
                password: Vec::new().into(),
            };
            read_field("Git username (hidden): ", &mut credentials.username)?;
            read_field(
                "Git password or access token (hidden): ",
                &mut credentials.password,
            )?;
            Some(credentials)
        } else {
            None
        };
        storage
            .replace(url, credentials)
            .map_err(|error| error.to_string())?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            println!("Git credential storage updated.");
            0
        }
        Err(code) => {
            eprintln!("{code}");
            4
        }
    }
}
