use clap::{Arg, ArgAction, Command, value_parser};
use std::path::PathBuf;

fn json_flag() -> Arg {
    Arg::new("json")
        .long("json")
        .help("Write versioned JSON to stdout")
        .action(ArgAction::SetTrue)
}
fn workspace_id() -> Arg {
    Arg::new("workspace-id")
        .required(true)
        .help("Host workspace UUID")
}
fn confirm_flag() -> Arg {
    Arg::new("confirm")
        .long("confirm")
        .help("Confirm the displayed destructive or access change")
        .action(ArgAction::SetTrue)
}
pub fn command() -> Command {
    Command::new("lomiremote")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Local Lomi Remote host and terminal dashboard")
        .after_help("Without a command, open the TUI when stdin and stdout are terminals.\nThe local host runs independently of the dashboard.")
        .arg(Arg::new("profile-dir").long("profile-dir").global(true).value_name("PATH").value_parser(value_parser!(PathBuf)).help("Use a local host data profile"))
        .subcommand(Command::new("version").about("Show the program version").arg(json_flag()))
        .subcommand(Command::new("status").about("Read the running host status").arg(json_flag()))
        .subcommand(Command::new("doctor").about("Read bounded host diagnostics").arg(json_flag()))
        .subcommand(Command::new("logs").about("Read structured Host diagnostics without terminal or file content")
            .arg(Arg::new("follow").long("follow").help("Follow this Host runtime until interrupted or disconnected").action(ArgAction::SetTrue))
            .arg(json_flag()))
        .subcommand(Command::new("maintenance").about("Prepare a controlled host update")
            .subcommand_required(true)
            .subcommand(Command::new("prepare").about("Read authenticated profile compatibility and live session count").arg(json_flag()))
            .subcommand(Command::new("status").about("Read the result of a Windows maintenance handoff")
                .arg(Arg::new("job-id").required(true).value_name("JOB_ID"))
                .arg(json_flag())))
        .subcommand(Command::new("update").about("Update this signed installation")
            .arg(Arg::new("release-version").long("version").value_name("X.Y.Z")
                .help("Require this exact version in signed release metadata"))
            .arg(Arg::new("check").long("check").help("Check the latest release without changing this installation")
                .action(ArgAction::SetTrue).conflicts_with_all(["release-version", "confirm"]))
            .arg(confirm_flag()).arg(json_flag()))
        .subcommand(Command::new("uninstall").about("Stop and remove this signed installation")
            .arg(Arg::new("purge").long("purge").help("Also clear allowlisted mutable Host settings and Git credentials after cloud revoke is acknowledged")
                .action(ArgAction::SetTrue))
            .arg(confirm_flag()).arg(json_flag()))
        .subcommand(Command::new("daemon").about("Manage the local host")
            .subcommand_required(true)
            .subcommand(Command::new("run").about("Run the host in the foreground")
                .arg(Arg::new("expected-host-id").long("expected-host-id").hide(true))
                .arg(Arg::new("existing-profile").long("existing-profile").hide(true).action(ArgAction::SetTrue)))
            .subcommand(Command::new("start").about("Start a detached host"))
            .subcommand(Command::new("stop").about("Request a controlled host shutdown").arg(confirm_flag())))
        .subcommand(Command::new("workspace").about("Manage host workspaces")
            .subcommand_required(true)
            .subcommand(Command::new("list").about("List registered workspaces").arg(json_flag()))
            .subcommand(Command::new("add").about("Register an existing local directory")
                .arg(Arg::new("name").long("name").required(true).value_name("NAME"))
                .arg(Arg::new("path").long("path").required(true).value_name("PATH").value_parser(value_parser!(PathBuf))))
            .subcommand(Command::new("remove").about("Remove a registration and its sessions, preserving project files").arg(workspace_id()).arg(confirm_flag()))
            .subcommand(Command::new("removal-status").about("Read a workspace removal outcome without repeating cleanup").arg(workspace_id()).arg(json_flag()))
            .subcommand(Command::new("rename").about("Rename a workspace when its current name still matches")
                .arg(workspace_id()).arg(Arg::new("expected-name").long("expected-name").required(true))
                .arg(Arg::new("name").long("name").required(true)).arg(confirm_flag()).arg(json_flag()))
            .subcommand(Command::new("share").about("Request workspace sharing").arg(workspace_id()).arg(confirm_flag())
                .arg(Arg::new("policy").long("policy").value_parser(["owner-account"]).default_value("owner-account")))
            .subcommand(Command::new("unshare").about("Revoke workspace sharing, preserving local sessions").arg(workspace_id()).arg(confirm_flag())))
        .subcommand(Command::new("auth").about("Configure host authentication explicitly")
            .subcommand_required(true)
            .subcommand(Command::new("configure")
                .arg(Arg::new("origin").long("origin").help("Explicit identity origin; omit all public endpoint flags to use this release's built-in configuration"))
                .arg(Arg::new("remote-api-origin").long("remote-api-origin").value_name("HTTPS_ORIGIN").help("Pin a trusted operator-supplied canonical HTTPS Remote API origin, distinct from the identity origin"))
                .arg(Arg::new("relay-endpoint").long("relay-endpoint").value_name("WSS_ENDPOINT").help("Pin a separately trusted operator-supplied canonical wss://host/v2/relay endpoint; no default or inference"))
                .arg(Arg::new("client-id").long("client-id"))
                .arg(Arg::new("provider").long("provider").value_parser(["protected-file", "macos-keychain", "windows-dpapi", "linux-secret-service"]))
                .arg(Arg::new("keychain-path").long("keychain-path").value_parser(value_parser!(PathBuf)))
                .arg(Arg::new("ack-os-permissions-only").long("ack-os-permissions-only").help("Acknowledge that protected-file stores plaintext protected only by OS permissions").action(ArgAction::SetTrue))
                .arg(confirm_flag()).arg(json_flag())))
        .subcommand(Command::new("git-credentials").about("Configure HTTPS Git credentials in native host secret storage")
            .subcommand_required(true)
            .subcommands(["set", "clear"].map(|name| Command::new(name)
                .arg(Arg::new("url").long("url").required(true).help("Exact HTTPS remote URL without credentials"))
                .arg(Arg::new("keychain-path").long("keychain-path").value_parser(value_parser!(PathBuf)))
                .arg(Arg::new("ack-os-permissions-only").long("ack-os-permissions-only").action(ArgAction::SetTrue))
                .arg(confirm_flag()))))
        .subcommand(Command::new("login").about("Start durable host login; the host continues after this CLI exits")
            .arg(json_flag())
            .subcommand(Command::new("status").arg(json_flag()))
            .subcommand(Command::new("code").about("Explicitly display the current user code and trusted verification URL").arg(json_flag())))
        .subcommand(Command::new("logout").about("Fence all remote sharing before attempting cloud revoke").arg(confirm_flag()).arg(json_flag()))
        .subcommand(terminal_command())
        .subcommand(setup_command())
        .subcommand(Command::new("service").about("Manage OS autostart (requires a qualified service adapter)")
            .subcommand_required(true)
            .subcommand(service_install_command())
            .subcommand(Command::new("file-security")
                .about("Manage the explicitly installed LocalSystem file security broker (Windows administrator required)")
                .subcommand_required(true)
                .subcommands(["install", "upgrade", "status", "start", "stop", "uninstall"].map(|name| {
                    let command = Command::new(name)
                        .arg(Arg::new("owner-sid").long("owner-sid").required(true).value_name("SID"));
                    if matches!(name, "install" | "upgrade") {
                        command.arg(Arg::new("confirm-system-service")
                            .long("confirm-system-service")
                            .required(true)
                            .help("Confirm installation or replacement of the automatically started per-owner LocalSystem security broker")
                            .action(ArgAction::SetTrue))
                    } else {
                        command
                    }
                })))
            .subcommands(["start","stop","restart","status","uninstall"].map(|name| {
                let command = Command::new(name);
                #[cfg(target_os = "macos")]
                let command = command
                    .arg(Arg::new("mode").long("mode").value_parser(service_mode_parser()).requires("account"))
                    .arg(Arg::new("account").long("account").value_name("NAME_OR_UID").requires("mode"));
                #[cfg(windows)]
                let command = command
                    .arg(Arg::new("account").long("account").value_name("ACCOUNT"))
                    .arg(confirm_flag());
                command
            }))
            .subcommands(windows_service_update_commands()))
}

fn windows_service_update_commands() -> Vec<Command> {
    #[cfg(windows)]
    {
        ["update", "recover", "rollback"]
            .into_iter()
            .map(|name| {
                let command = Command::new(name)
                    .arg(
                        Arg::new("account")
                            .long("account")
                            .required(true)
                            .value_name("ACCOUNT"),
                    )
                    .arg(confirm_flag());
                if name == "update" {
                    command
                        .arg(
                            Arg::new("repair-credentials")
                                .long("repair-credentials")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(release_version_arg())
                } else {
                    command
                }
            })
            .collect()
    }
    #[cfg(not(windows))]
    {
        Vec::new()
    }
}

fn service_install_command() -> Command {
    let command = Command::new("install")
        .about("Install the selected Host start mode; sharing requires separate workspace consent")
        .arg(Arg::new("mode").long("mode").required(true).value_parser(service_mode_parser()))
        .arg(Arg::new("account").long("account").required(true).value_name("NAME_OR_UID"))
        .arg(confirm_flag())
        .arg(Arg::new("confirm-service-logon-right").long("confirm-service-logon-right").action(ArgAction::SetTrue)
            .help("Explicitly authorize the selected Windows account's service logon right and credential configuration"));
    #[cfg(windows)]
    let command = command.arg(release_version_arg());
    command
}

#[cfg(windows)]
fn release_version_arg() -> Arg {
    Arg::new("release-version")
        .long("release-version")
        .value_name("VERSION")
        .help("Require the signed release metadata to name this exact product version")
}

fn setup_command() -> Command {
    Command::new("setup").about("Resume first-run account, workspace and sharing setup")
        .arg(Arg::new("non-interactive").long("non-interactive").action(ArgAction::SetTrue))
        .arg(confirm_flag())
        .arg(Arg::new("mode").long("mode").value_parser(["manual", "login", "boot"]))
        .arg(Arg::new("account").long("account").value_name("EXISTING_ACCOUNT"))
        .arg(Arg::new("create-account").long("create-account").requires("account").action(ArgAction::SetTrue)
            .help("Explicitly create a dedicated Linux account and its home; requires root and confirmation"))
        .arg(Arg::new("workspace-name").long("workspace-name"))
        .arg(Arg::new("workspace-root").long("workspace-root").value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("create-workspace").long("create-workspace").action(ArgAction::SetTrue))
        .arg(Arg::new("shell").long("shell").value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("shell-name").long("shell-name").default_value("Shell"))
        .arg(Arg::new("host-name").long("host-name").value_name("NAME")
            .help("Override the local display name for this Host"))
        .arg(Arg::new("shell-arg").long("shell-arg").action(ArgAction::Append).allow_hyphen_values(true))
        .arg(Arg::new("share").long("share").conflicts_with("local-only").action(ArgAction::SetTrue))
        .arg(Arg::new("local-only").long("local-only").action(ArgAction::SetTrue))
        .arg(Arg::new("renew-share-consent").long("renew-share-consent").action(ArgAction::SetTrue))
        .arg(Arg::new("disable-existing-share").long("disable-existing-share").action(ArgAction::SetTrue))
        .arg(Arg::new("confirm-authorization-change").long("confirm-authorization-change").action(ArgAction::SetTrue))
        .arg(Arg::new("keychain-path").long("keychain-path").value_parser(value_parser!(PathBuf)))
        .arg(Arg::new("ack-os-permissions-only").long("ack-os-permissions-only").action(ArgAction::SetTrue))
}

fn service_mode_parser() -> clap::builder::PossibleValuesParser {
    #[cfg(target_os = "macos")]
    {
        clap::builder::PossibleValuesParser::new(["manual", "login", "boot"])
    }
    #[cfg(not(target_os = "macos"))]
    {
        clap::builder::PossibleValuesParser::new(["login", "boot"])
    }
}

fn workspace_flag() -> Arg {
    Arg::new("workspace")
        .long("workspace")
        .required(true)
        .value_name("UUID")
}
fn pane_flag() -> Arg {
    Arg::new("pane")
        .long("pane")
        .required(true)
        .value_name("UUID")
}
fn profile_flag() -> Arg {
    Arg::new("profile")
        .long("profile")
        .default_value("default")
        .value_name("PROFILE_ID")
}
fn terminal_command() -> Command {
    Command::new("terminal")
        .about("Inspect, manage or attach to host-owned terminals")
        .subcommand_required(true)
        .subcommand(
            Command::new("list")
                .about("Read terminal descriptors without starting a shell")
                .arg(workspace_flag())
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("create")
                .about("Start the host-selected shell profile")
                .arg(workspace_flag())
                .arg(profile_flag())
                .arg(Arg::new("name").long("name").default_value("Terminal"))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("split")
                .about("Split a terminal pane and start a shell")
                .arg(workspace_flag())
                .arg(pane_flag())
                .arg(profile_flag())
                .arg(
                    Arg::new("axis")
                        .long("axis")
                        .value_parser(["horizontal", "vertical"])
                        .default_value("horizontal"),
                )
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("rename")
                .about("Rename a terminal tab")
                .arg(workspace_flag())
                .arg(Arg::new("tab").long("tab").required(true))
                .arg(Arg::new("name").long("name").required(true))
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("move")
                .about("Move a pane within this workspace")
                .arg(workspace_flag())
                .arg(pane_flag())
                .arg(Arg::new("target-pane").long("target-pane").required(true))
                .arg(
                    Arg::new("placement")
                        .long("placement")
                        .value_parser(["before", "after"])
                        .default_value("after"),
                )
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("close")
                .about("Close a pane, ending its running shell")
                .arg(workspace_flag())
                .arg(pane_flag())
                .arg(confirm_flag())
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("restart")
                .about("Start a fresh session for a pane")
                .arg(workspace_flag())
                .arg(pane_flag())
                .arg(profile_flag())
                .arg(confirm_flag())
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("attach")
                .about("View a running session; F10 or Ctrl-] closes the view")
                .arg(workspace_flag())
                .arg(pane_flag())
                .arg(
                    Arg::new("control")
                        .long("control")
                        .help("Claim exclusive input and resize after render ACK")
                        .action(ArgAction::SetTrue),
                ),
        )
}

#[cfg(test)]
mod tests {
    use super::command;

    #[test]
    fn update_check_is_read_only_and_excludes_maintenance_options() {
        let matches = command()
            .try_get_matches_from(["lomiremote", "update", "--check", "--json"])
            .unwrap();
        let (_, update) = matches.subcommand().unwrap();
        assert!(update.get_flag("check"));
        assert!(update.get_flag("json"));

        assert!(
            command()
                .try_get_matches_from(["lomiremote", "update", "--check", "--version", "1.2.3",])
                .is_err()
        );
        assert!(
            command()
                .try_get_matches_from(["lomiremote", "update", "--check", "--confirm"])
                .is_err()
        );
    }
}
