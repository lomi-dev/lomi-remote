//! Thin CLI boundary for explicitly selected OS service adapters.
use clap::ArgMatches;
use std::path::Path;

pub fn run(profile: &Path, args: &ArgMatches) -> u8 {
    if let Some(("file-security", file_security)) = args.subcommand() {
        #[cfg(windows)]
        {
            let Some((operation, options)) = file_security.subcommand() else {
                return 2;
            };
            let owner_sid = options.get_one::<String>("owner-sid").map(String::as_str);
            let confirm = matches!(operation, "install" | "upgrade")
                && options.get_flag("confirm-system-service");
            let Ok(executable) = std::env::current_exe() else {
                return 4;
            };
            return match lomi_platform::windows::file_security_service::run(
                operation,
                owner_sid,
                confirm,
                &executable,
            ) {
                Ok(message) => {
                    println!("{message}");
                    0
                }
                Err(error) => {
                    eprintln!("{error}");
                    use lomi_platform::windows::file_security_service::Error;
                    match error {
                        Error::Invalid => 2,
                        Error::Conflict | Error::UnsignedExecutable | Error::ProtectedPath => 5,
                        Error::Deadline => 7,
                        Error::Manager | Error::NotReady => 4,
                        Error::NotInstalled => 3,
                        Error::AdministratorRequired => 5,
                    }
                }
            };
        }
        #[cfg(not(windows))]
        {
            let _ = (profile, file_security);
            eprintln!("FILE_SECURITY_SERVICE_UNSUPPORTED_ON_THIS_PLATFORM");
            return 3;
        }
    }
    #[cfg(target_os = "linux")]
    {
        let Some((operation, options)) = args.subcommand() else {
            return 2;
        };
        let Ok(executable) = std::env::current_exe() else {
            return 4;
        };
        let mode = (operation == "install")
            .then(|| options.get_one::<String>("mode").map(String::as_str))
            .flatten();
        let account = (operation == "install")
            .then(|| options.get_one::<String>("account").map(String::as_str))
            .flatten();
        match lomi_platform::service_linux::run(profile, &executable, operation, mode, account) {
            Ok(message) => {
                println!("{message}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                use lomi_platform::service_linux::Error;
                if error == Error::Manager {
                    eprintln!(
                        "Run lomiremote --profile-dir PATH daemon run under your supervisor when systemd user/DBus is unavailable."
                    );
                }
                match error {
                    Error::Invalid => 2,
                    Error::Conflict => 5,
                    Error::Deadline => 7,
                    Error::Manager | Error::NotReady => 4,
                    Error::LingerRequired => 3,
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    {
        let Some((operation, options)) = args.subcommand() else {
            return 2;
        };
        let Ok(executable) = std::env::current_exe() else {
            return 4;
        };
        let mode = options.get_one::<String>("mode").map(String::as_str);
        let account = options.get_one::<String>("account").map(String::as_str);
        let result = if lomi_platform::service_macos::is_administrator() {
            match (mode, account) {
                (Some(mode), Some(account)) => mode.parse().and_then(|mode| {
                    lomi_platform::service_macos::run_admin_host(
                        profile,
                        &executable,
                        operation,
                        mode,
                        account,
                    )
                }),
                _ => lomi_platform::service_macos::run(
                    profile,
                    &executable,
                    operation,
                    mode,
                    account,
                ),
            }
        } else {
            lomi_platform::service_macos::run(profile, &executable, operation, mode, account)
        };
        match result {
            Ok(message) => {
                println!("{message}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                use lomi_platform::service_macos::Error;
                if error == Error::Manager {
                    eprintln!(
                        "Run lomiremote --profile-dir PATH daemon run under your supervisor when the current-user launchd domain is unavailable."
                    );
                }
                match error {
                    Error::Invalid => 2,
                    Error::Conflict => 5,
                    Error::Deadline => 7,
                    Error::Manager | Error::NotReady => 4,
                    Error::Unavailable => 4,
                    Error::Unimplemented | Error::Disabled | Error::AdministratorRequired => 3,
                }
            }
        }
    }
    #[cfg(windows)]
    {
        if let Some(exit) = crate::windows_service_commands::dispatch(profile, args) {
            return exit;
        }
        let Some((operation, options)) = args.subcommand() else {
            return 2;
        };
        let Ok(executable) = std::env::current_exe() else {
            return 4;
        };
        let mode = (operation == "install")
            .then(|| options.get_one::<String>("mode").map(String::as_str))
            .flatten();
        let account = (operation == "install")
            .then(|| options.get_one::<String>("account").map(String::as_str))
            .flatten();
        match lomi_platform::service_windows_login::selected(profile, operation, mode) {
            Ok(true) => {
                let Some(parent) = executable.parent() else {
                    return 4;
                };
                let helper = parent.join("lomiremote-host.exe");
                return match lomi_platform::service_windows_login::run(
                    profile, &helper, operation, account,
                ) {
                    Ok(message) => {
                        println!("{message}");
                        0
                    }
                    Err(error) => {
                        eprintln!("{error}");
                        login_exit(error)
                    }
                };
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("{error}");
                return login_exit(error);
            }
        }
        match lomi_platform::service_windows::run(profile, &executable, operation, mode, account) {
            Ok(message) => {
                println!("{message}");
                0
            }
            Err(error) => {
                eprintln!("{error}");
                use lomi_platform::service_windows::Error;
                match error {
                    Error::Invalid => 2,
                    Error::Conflict => 5,
                    Error::Deadline => 7,
                    Error::Manager | Error::NotReady | Error::NotInstalled => 4,
                    Error::Unimplemented
                    | Error::CredentialsRequired
                    | Error::PrivilegedAccount => 3,
                }
            }
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        let _ = (profile, args);
        eprintln!("SERVICE_ADAPTER_UNIMPLEMENTED_ON_THIS_PLATFORM");
        3
    }
}

#[cfg(windows)]
fn login_exit(error: lomi_platform::service_windows_login::Error) -> u8 {
    use lomi_platform::service_windows_login::Error;
    match error {
        Error::Invalid => 2,
        Error::Conflict => 5,
        Error::Deadline => 7,
        Error::PrivilegedAccount | Error::SessionRequired | Error::HelperMissing => 3,
        Error::Manager | Error::NotReady | Error::NotInstalled => 4,
    }
}
