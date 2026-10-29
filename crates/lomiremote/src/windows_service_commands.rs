//! Typed CLI adapter for administrator-managed Windows Host services.
//!
//! The public service command remains shared with the login-task adapter. This
//! module claims only an explicitly selected administrator Host operation, or
//! a command whose current account already has a real Boot registration.

use clap::ArgMatches;
use lomi_platform::windows::service_admin as admin;
use lomi_update_trust::TrustStore;
use std::path::Path;

const EXIT_ARGUMENTS: u8 = 2;
const EXIT_NOT_AUTHORIZED: u8 = 3;
const EXIT_UNAVAILABLE: u8 = 4;
const EXIT_CONFLICT: u8 = 5;
const EXIT_UNCERTAIN: u8 = 7;

/// Dispatch a Windows administrator-managed Host service operation.
///
/// `None` means the command belongs to the existing login-task/user-service
/// adapter. Once a Boot Host operation is identified, failures are reported
/// here and are never retried through that fallback.
pub fn dispatch(_profile: &Path, args: &ArgMatches) -> Option<u8> {
    let (operation, options) = args.subcommand()?;
    if operation == "file-security" {
        return None;
    }

    let requested_mode = value(options, "mode");
    if operation == "install" && requested_mode != Some("boot") {
        if value(options, "release-version").is_some() {
            return Some(fail(
                "WINDOWS_ADMIN_HOST_RELEASE_VERSION_REQUIRES_BOOT_MODE",
                EXIT_ARGUMENTS,
            ));
        }
        return None;
    }

    let explicit_account = value(options, "account");
    let account = match explicit_account {
        Some(account) => account.to_owned(),
        None => {
            if operation == "install" {
                return Some(fail("WINDOWS_ADMIN_HOST_ACCOUNT_REQUIRED", EXIT_ARGUMENTS));
            }
            let Ok((current_sid, current_name)) = admin::current_account() else {
                return None;
            };
            match admin::inspect(&current_name) {
                Ok(Some(status))
                    if is_registered_boot_service(&status) && status.account_sid == current_sid =>
                {
                    current_name
                }
                Ok(Some(status)) if status.account_sid == current_sid => {
                    return Some(fail("WINDOWS_ADMIN_HOST_BINDING_CONFLICT", EXIT_CONFLICT));
                }
                Ok(Some(_)) | Ok(None) => return None,
                Err(error) => return Some(report_admin_error(error)),
            }
        }
    };

    if !matches!(
        operation,
        "install"
            | "status"
            | "start"
            | "stop"
            | "restart"
            | "update"
            | "recover"
            | "rollback"
            | "uninstall"
    ) {
        return None;
    }

    Some(match operation {
        "install" => install_boot_host(&account, options),
        "status" => show_status(&account),
        "start" | "stop" | "restart" => run_service_action(operation, &account, options),
        "update" => update_boot_host(&account, options),
        "recover" => recover_boot_host(&account),
        "rollback" => rollback_boot_host(&account, options),
        "uninstall" => uninstall_boot_host(&account, options),
        _ => unreachable!(),
    })
}

fn install_boot_host(account: &str, options: &ArgMatches) -> u8 {
    let expected_version = match requested_release_version(options) {
        Ok(version) => version,
        Err(exit) => return exit,
    };
    if !flag(options, "confirm") || !flag(options, "confirm-service-logon-right") {
        return fail(
            "WINDOWS_ADMIN_HOST_INSTALL_CONFIRMATION_REQUIRED",
            EXIT_ARGUMENTS,
        );
    }
    let Some(pins) = crate::bootstrap::windows_release_pins() else {
        return fail(
            "WINDOWS_ADMIN_HOST_RELEASE_PINS_UNAVAILABLE",
            EXIT_UNAVAILABLE,
        );
    };
    let (_, canonical_account) = match admin::selected_account_identity(account) {
        Ok(identity) => identity,
        Err(error) => return report_admin_error(error),
    };
    let password =
        match lomi_platform::windows_password::prompt_service_password(&canonical_account) {
            Ok(password) => password,
            Err(error) => return report_prompt_error(error),
        };
    let mut store = match TrustStore::initialize_admin_host_for_account(account) {
        Ok(store) => store,
        Err(error) => return report_update_error(error.as_ref()),
    };
    let result = if let Some(version) = expected_version {
        store.install_or_update_admin_host_service_https_pinned_blocking(
            pins.release_origin,
            pins.primary_target,
            pins.helper_target,
            pins.platform,
            account,
            Some(password),
            Some(version),
        )
    } else {
        store.install_or_update_admin_host_service_https_blocking(
            pins.release_origin,
            pins.primary_target,
            pins.helper_target,
            pins.platform,
            account,
            Some(password),
        )
    };
    match result {
        Ok(outcome) => {
            print_status(&outcome.status);
            0
        }
        Err(error) => report_update_error(error.as_ref()),
    }
}

fn show_status(account: &str) -> u8 {
    match admin::inspect(account) {
        Ok(Some(status)) if status.mode == "boot" => {
            print_status(&status);
            0
        }
        Ok(Some(_)) => fail("WINDOWS_ADMIN_HOST_BINDING_CONFLICT", EXIT_CONFLICT),
        Ok(None) => fail("WINDOWS_ADMIN_HOST_SERVICE_NOT_INSTALLED", EXIT_ARGUMENTS),
        Err(error) => report_admin_error(error),
    }
}

fn run_service_action(operation: &str, account: &str, options: &ArgMatches) -> u8 {
    if matches!(operation, "stop" | "restart") && !flag(options, "confirm") {
        return fail(
            "WINDOWS_ADMIN_HOST_ACTION_CONFIRMATION_REQUIRED",
            EXIT_ARGUMENTS,
        );
    }
    match admin::run(operation, account, None, None) {
        Ok(summary) => {
            // This native summary contains only fixed state labels and
            // booleans; it does not include paths, SID, or credentials.
            println!("{summary}");
            0
        }
        Err(error) => report_admin_error(error),
    }
}

fn update_boot_host(account: &str, options: &ArgMatches) -> u8 {
    let expected_version = match requested_release_version(options) {
        Ok(version) => version,
        Err(exit) => return exit,
    };
    if !flag(options, "confirm") {
        return fail(
            "WINDOWS_ADMIN_HOST_UPDATE_CONFIRMATION_REQUIRED",
            EXIT_ARGUMENTS,
        );
    }
    let Some(pins) = crate::bootstrap::windows_release_pins() else {
        return fail(
            "WINDOWS_ADMIN_HOST_RELEASE_PINS_UNAVAILABLE",
            EXIT_UNAVAILABLE,
        );
    };
    let repair_requested = flag(options, "repair-credentials");
    let mut store = match TrustStore::open_admin_host_for_account(account) {
        Ok(store) => store,
        Err(error) => return report_update_error(error.as_ref()),
    };
    let password = if repair_requested {
        let (_, canonical_account) = match admin::selected_account_identity(account) {
            Ok(identity) => identity,
            Err(error) => return report_admin_error(error),
        };
        match lomi_platform::windows_password::prompt_service_password(&canonical_account) {
            Ok(password) => Some(password),
            Err(error) => return report_prompt_error(error),
        }
    } else {
        None
    };

    let result = if let Some(version) = expected_version {
        store.install_or_update_admin_host_service_https_pinned_blocking(
            pins.release_origin,
            pins.primary_target,
            pins.helper_target,
            pins.platform,
            account,
            password,
            Some(version),
        )
    } else {
        store.install_or_update_admin_host_service_https_blocking(
            pins.release_origin,
            pins.primary_target,
            pins.helper_target,
            pins.platform,
            account,
            password,
        )
    };
    match result {
        Ok(outcome) => {
            print_status(&outcome.status);
            0
        }
        Err(error) => report_update_error(error.as_ref()),
    }
}

fn requested_release_version(options: &ArgMatches) -> Result<Option<&str>, u8> {
    match value(options, "release-version") {
        None => Ok(None),
        Some(version) if !version.is_empty() && version == env!("CARGO_PKG_VERSION") => {
            Ok(Some(version))
        }
        Some(_) => Err(fail(
            "WINDOWS_ADMIN_HOST_RELEASE_VERSION_MISMATCH",
            EXIT_ARGUMENTS,
        )),
    }
}

fn recover_boot_host(account: &str) -> u8 {
    let mut store = match TrustStore::open_admin_host_for_account(account) {
        Ok(store) => store,
        Err(error) => return report_update_error(error.as_ref()),
    };
    match store.recover_admin_host_service(account) {
        Ok(outcome) => {
            print_status(&outcome.status);
            0
        }
        Err(error) => report_update_error(error.as_ref()),
    }
}

fn rollback_boot_host(account: &str, options: &ArgMatches) -> u8 {
    if !flag(options, "confirm") {
        return fail(
            "WINDOWS_ADMIN_HOST_ROLLBACK_CONFIRMATION_REQUIRED",
            EXIT_ARGUMENTS,
        );
    }
    let mut store = match TrustStore::open_admin_host_for_account(account) {
        Ok(store) => store,
        Err(error) => return report_update_error(error.as_ref()),
    };
    match store.rollback_admin_host_service(account) {
        Ok(outcome) => {
            print_status(&outcome.status);
            0
        }
        Err(error) => report_update_error(error.as_ref()),
    }
}

fn uninstall_boot_host(account: &str, options: &ArgMatches) -> u8 {
    if !flag(options, "confirm") {
        return fail(
            "WINDOWS_ADMIN_HOST_UNINSTALL_CONFIRMATION_REQUIRED",
            EXIT_ARGUMENTS,
        );
    }
    let mut store = match TrustStore::open_admin_host_for_account(account) {
        Ok(store) => store,
        Err(error) => return report_update_error(error.as_ref()),
    };
    match store.uninstall_admin_host_service(account) {
        Ok(removed) => {
            println!("WINDOWS_ADMIN_HOST_UNINSTALLED removed_objects={removed}");
            0
        }
        Err(error) => report_update_error(error.as_ref()),
    }
}

fn is_registered_boot_service(status: &admin::AdminServiceStatus) -> bool {
    status.registered && status.mode == "boot"
}

fn print_status(status: &admin::AdminServiceStatus) {
    println!(
        "WINDOWS_ADMIN_HOST_SERVICE mode=boot registered={} phase={} running={} ready={} autostart={}",
        status.registered, status.phase, status.running, status.ready, status.autostart
    );
}

fn report_admin_error(error: admin::Error) -> u8 {
    let (code, exit) = match error {
        admin::Error::Invalid => ("WINDOWS_ADMIN_HOST_INVALID_CONFIGURATION", EXIT_ARGUMENTS),
        admin::Error::Conflict => ("WINDOWS_ADMIN_HOST_OWNERSHIP_CONFLICT", EXIT_CONFLICT),
        admin::Error::AdministratorRequired => {
            ("WINDOWS_ADMINISTRATOR_REQUIRED", EXIT_NOT_AUTHORIZED)
        }
        admin::Error::AccountNotOrdinary => (
            "WINDOWS_ADMIN_HOST_DEDICATED_ACCOUNT_REQUIRED",
            EXIT_NOT_AUTHORIZED,
        ),
        admin::Error::CredentialsRequired => (
            "WINDOWS_ADMIN_HOST_CREDENTIALS_OR_LOGON_RIGHT_REQUIRED",
            EXIT_NOT_AUTHORIZED,
        ),
        admin::Error::NotInstalled => (
            "WINDOWS_ADMIN_HOST_SERVICE_NOT_INSTALLED",
            EXIT_NOT_AUTHORIZED,
        ),
        admin::Error::Manager => ("WINDOWS_ADMIN_HOST_MANAGER_UNAVAILABLE", EXIT_UNAVAILABLE),
        admin::Error::NotReady => ("WINDOWS_ADMIN_HOST_NOT_READY", EXIT_UNAVAILABLE),
        admin::Error::Deadline => ("WINDOWS_ADMIN_HOST_OPERATION_UNCERTAIN", EXIT_UNCERTAIN),
        admin::Error::ProtectedImageRequired => (
            "WINDOWS_ADMIN_HOST_VERIFIED_IMAGE_REQUIRED",
            EXIT_NOT_AUTHORIZED,
        ),
    };
    fail(code, exit)
}

fn report_prompt_error(error: lomi_platform::windows_password::PromptError) -> u8 {
    let (code, exit) = match error {
        lomi_platform::windows_password::PromptError::ConsoleRequired
        | lomi_platform::windows_password::PromptError::ConsoleUnavailable => (
            "WINDOWS_ADMIN_HOST_PASSWORD_CONSOLE_REQUIRED",
            EXIT_NOT_AUTHORIZED,
        ),
        lomi_platform::windows_password::PromptError::ConsoleModeRestore => (
            "WINDOWS_ADMIN_HOST_PASSWORD_CONSOLE_RESTORE_FAILED",
            EXIT_UNAVAILABLE,
        ),
        lomi_platform::windows_password::PromptError::Cancelled => (
            "WINDOWS_ADMIN_HOST_PASSWORD_PROMPT_CANCELLED",
            EXIT_NOT_AUTHORIZED,
        ),
        lomi_platform::windows_password::PromptError::PromptBusy
        | lomi_platform::windows_password::PromptError::ConsoleIo => (
            "WINDOWS_ADMIN_HOST_PASSWORD_PROMPT_FAILED",
            EXIT_UNAVAILABLE,
        ),
        lomi_platform::windows_password::PromptError::InvalidAccountLabel
        | lomi_platform::windows_password::PromptError::PasswordTooLong
        | lomi_platform::windows_password::PromptError::InvalidPassword
        | lomi_platform::windows_password::PromptError::CredentialRejected => {
            ("WINDOWS_ADMIN_HOST_PASSWORD_INVALID", EXIT_NOT_AUTHORIZED)
        }
    };
    fail(code, exit)
}

fn report_update_error(error: &(dyn std::error::Error + 'static)) -> u8 {
    if let Some(error) = error.downcast_ref::<admin::Error>() {
        return report_admin_error(*error);
    }
    if let Some(error) = error.downcast_ref::<lomi_platform::windows_password::PromptError>() {
        return report_prompt_error(*error);
    }
    fail(
        "WINDOWS_ADMIN_HOST_UPDATER_OPERATION_FAILED",
        EXIT_UNAVAILABLE,
    )
}

fn value<'a>(options: &'a ArgMatches, name: &str) -> Option<&'a str> {
    options
        .try_get_one::<String>(name)
        .ok()
        .flatten()
        .map(String::as_str)
}

fn flag(options: &ArgMatches, name: &str) -> bool {
    options
        .try_get_one::<bool>(name)
        .ok()
        .flatten()
        .copied()
        .unwrap_or(false)
}

fn fail(code: &str, exit: u8) -> u8 {
    eprintln!("{code}");
    exit
}
