use lomi_platform::service_macos::{self as service, AdminHostIdentityBinding, AdminHostMode};
use lomi_remote_protocol::OperationId;
use std::{
    io,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
    time::Duration,
};
use uuid::Uuid;

const WARNING_GRACE: Duration = Duration::from_secs(20);
const INTERNAL_DEADLINE_BUDGET: u64 = 119;

fn request_error(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn parse_mode(value: &str) -> io::Result<AdminHostMode> {
    value
        .parse()
        .map_err(|_| request_error("admin Host mode must be exactly manual, login, or boot"))
}

fn parse_purge(value: &str) -> io::Result<bool> {
    match value {
        "0" => Ok(false),
        "1" => Ok(true),
        _ => Err(request_error("purge must be exactly 0 or 1")),
    }
}

fn native_platform() -> Option<&'static str> {
    #[cfg(target_arch = "aarch64")]
    return Some("macos-aarch64");
    #[cfg(target_arch = "x86_64")]
    return Some("macos-x86_64");
    #[allow(unreachable_code)]
    None
}

fn monotonic_deadline_after(seconds: u64) -> io::Result<u128> {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let current_seconds = u128::try_from(now.tv_sec)
        .map_err(|_| io::Error::other("monotonic clock returned a negative timestamp"))?;
    let nanoseconds = u128::try_from(now.tv_nsec)
        .ok()
        .filter(|value| *value < 1_000_000_000)
        .ok_or_else(|| io::Error::other("monotonic clock returned an invalid timestamp"))?;
    let current = current_seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(|| io::Error::other("monotonic maintenance deadline overflowed"))?;
    let budget = u128::from(seconds)
        .checked_mul(1_000_000_000)
        .ok_or_else(|| io::Error::other("monotonic maintenance deadline overflowed"))?;
    current
        .checked_add(budget)
        .ok_or_else(|| io::Error::other("monotonic maintenance deadline overflowed"))
}

fn read_binding(
    profile: &Path,
    executable: &Path,
    account: &str,
    mode: AdminHostMode,
) -> lomi_update_trust::Result<AdminHostIdentityBinding> {
    service::read_admin_host_identity_binding(profile, executable, account, mode)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
}

fn inspect_active(
    profile: &Path,
    executable: &Path,
    account: &str,
    mode: AdminHostMode,
) -> lomi_update_trust::Result<bool> {
    service::inspect_admin_host_active(profile, executable, account, mode)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
}

/// Uninstall a selected administrator-managed Host through its verified native
/// maintenance protocol. On success, `exec` replaces this updater process.
pub(super) fn run(args: &[String]) -> lomi_update_trust::Result<()> {
    if !service::is_administrator() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "admin Host uninstall requires an explicit root invocation",
        )
        .into());
    }
    if args.len() != 6 {
        return Err(request_error(
            "usage: uninstall-admin-host PROFILE_DIR INSTALL_DIR PLATFORM ACCOUNT MODE PURGE",
        )
        .into());
    }

    let profile = PathBuf::from(&args[0]);
    let install_dir = PathBuf::from(&args[1]);
    let platform = args[2].as_str();
    let account = args[3].as_str();
    let mode = parse_mode(&args[4])?;
    let purge = parse_purge(&args[5])?;
    if native_platform() != Some(platform) {
        return Err(request_error("platform does not match this native updater").into());
    }

    let expected_install = lomi_update_trust::admin_boot_install_path(account)?;
    if install_dir != expected_install {
        return Err(request_error(
            "admin Host uninstall requires the exact selected-account install directory",
        )
        .into());
    }
    lomi_update_trust::validate_admin_boot_install_directory(&install_dir)?;
    let executable = install_dir.join("lomiremote");
    lomi_update_trust::verify_admin_installed_maintenance_cli(&install_dir, platform)?;
    let binding = read_binding(&profile, &executable, account, mode)?;
    let initially_active = inspect_active(&profile, &executable, account, mode)?;

    eprintln!(
        "Lomi Remote administrator-managed uninstall will stop the selected account Host if it is running. Save work; continuing in {} seconds. Press Ctrl-C to cancel.",
        WARNING_GRACE.as_secs()
    );
    thread::sleep(WARNING_GRACE);

    // Recheck the activated image and the native owner projection after the
    // user-facing grace period. Abort if the Host's active state changed.
    lomi_update_trust::validate_admin_boot_install_directory(&install_dir)?;
    lomi_update_trust::verify_admin_installed_maintenance_cli(&install_dir, platform)?;
    let current_binding = read_binding(&profile, &executable, account, mode)?;
    if current_binding != binding {
        return Err(
            io::Error::other("admin Host identity changed during uninstall grace period").into(),
        );
    }
    let currently_active = inspect_active(&profile, &executable, account, mode)?;
    if currently_active != initially_active {
        return Err(
            io::Error::other("admin Host activity changed during uninstall grace period").into(),
        );
    }

    let operation_id = OperationId::from_bytes(*Uuid::new_v4().as_bytes())
        .map_err(|_| io::Error::other("could not mint a maintenance operation ID"))?;
    let deadline = monotonic_deadline_after(INTERNAL_DEADLINE_BUDGET)?;
    let mut command = Command::new(&executable);
    command
        .current_dir("/")
        .arg("--internal-maintenance-macos-v1")
        .arg("uninstall")
        .arg(&profile)
        .arg(account)
        .arg(mode.as_str())
        .arg(String::from(binding.host_id()))
        .arg(String::from(binding.profile_id()))
        .arg(String::from(operation_id))
        .arg(deadline.to_string())
        .arg("-")
        .arg(if purge { "1" } else { "0" })
        .arg(if currently_active { "1" } else { "0" })
        .arg("0");

    let error = command.exec();
    Err(io::Error::new(
        error.kind(),
        format!("could not hand off to the verified installed Host CLI: {error}"),
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::{native_platform, parse_mode, parse_purge};
    use lomi_platform::service_macos::AdminHostMode;

    #[test]
    fn parses_only_the_closed_mode_and_purge_values() {
        assert_eq!(parse_mode("manual").unwrap(), AdminHostMode::Manual);
        assert_eq!(parse_mode("login").unwrap(), AdminHostMode::Login);
        assert_eq!(parse_mode("boot").unwrap(), AdminHostMode::Boot);
        for value in ["", "Manual", "other"] {
            assert!(parse_mode(value).is_err());
        }

        assert!(!parse_purge("0").unwrap());
        assert!(parse_purge("1").unwrap());
        for value in ["", "true", "01", "2"] {
            assert!(parse_purge(value).is_err());
        }
    }

    #[test]
    fn updater_platform_is_fixed_to_its_native_macos_target() {
        assert!(matches!(
            (std::env::consts::ARCH, native_platform()),
            ("aarch64", Some("macos-aarch64")) | ("x86_64", Some("macos-x86_64"))
        ));
    }
}
