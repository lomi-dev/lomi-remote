//! Direct task action with Windows GUI subsystem solely to prevent console creation.
#![cfg_attr(windows, windows_subsystem = "windows")]
#[cfg(windows)]
fn main() -> std::process::ExitCode {
    use std::{ffi::OsStr, path::PathBuf, process::ExitCode};
    if lomi_platform::installation::check_current_executable().is_err() {
        return ExitCode::from(4);
    }
    let mut args = std::env::args_os().skip(1);
    let (Some(command), Some(registration), Some(installation), None) =
        (args.next(), args.next(), args.next(), args.next())
    else {
        return ExitCode::from(2);
    };
    if command != OsStr::new("--managed-logon") {
        return ExitCode::from(2);
    }
    let Some(installation) = installation
        .to_str()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
    else {
        return ExitCode::from(2);
    };
    ExitCode::from(
        if lomi_host::windows_task::run_registered(&PathBuf::from(registration), installation)
            .is_ok()
        {
            0
        } else {
            4
        },
    )
}
#[cfg(not(windows))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(3)
}
