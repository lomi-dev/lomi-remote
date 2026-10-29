pub mod attach;
pub mod bootstrap;
pub mod cli;
pub mod diagnostics;
pub mod git_credentials;
#[cfg(all(target_os = "linux", feature = "linux-setup-handoff"))]
pub mod linux_selected_install;
pub mod logs;
#[cfg(feature = "release-maintenance")]
pub mod maintenance_commands;
#[cfg(not(feature = "release-maintenance"))]
pub mod maintenance_commands {
    use clap::ArgMatches;
    use std::path::Path;

    pub fn run(_profile: &Path, _name: &str, _args: &ArgMatches) -> u8 {
        eprintln!("MAINTENANCE_RELEASE_PINS_UNAVAILABLE");
        4
    }

    pub fn dispatch_internal() -> Option<u8> {
        None
    }
}
pub mod operator;
pub mod service;
pub mod setup;
pub mod setup_entry;
pub mod setup_runtime;
pub mod setup_view;
pub mod terminal_commands;
pub mod ui;
#[cfg(windows)]
pub mod windows_service_commands;
