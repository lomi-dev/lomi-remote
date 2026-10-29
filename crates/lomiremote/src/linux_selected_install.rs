//! Linux-only root-to-selected-account release handoff for first setup.
//!
//! The privileged parent copies its already-running image into a sealed
//! root-owned memfd before dropping to the selected account. This continuation
//! installs only the target and coordinates embedded in the signed release;
//! it never accepts an origin, target, platform, profile, or install path from
//! the internal command line.

use std::{
    env, fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{DirBuilderExt, MetadataExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Command, ExitCode},
};

struct LinuxSetupRelease {
    origin: &'static str,
    target_name: &'static str,
    platform: &'static str,
}

mod compiled {
    include!(concat!(env!("OUT_DIR"), "/linux_setup_release.rs"));
}

const HANDOFF_ARGUMENT: &str = "--internal-linux-selected-install";
const MAX_HANDOFF_ARGUMENTS: usize = 128;
const MAX_HANDOFF_ARGUMENT_BYTES: usize = 128 * 1024;

/// Dispatch the closed internal command before the generic executable-path
/// activation barrier. The command is accepted only from the root-created
/// sealed memfd after setup_context verifies its ownership, seals, and identity
/// with `/proc/self/exe`.
pub fn dispatch() -> Option<ExitCode> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    if args.first().is_none_or(|arg| arg != HANDOFF_ARGUMENT) {
        return None;
    }
    Some(run_handoff(&args))
}

fn run_handoff(args: &[std::ffi::OsString]) -> ExitCode {
    if args.len() < 3 || args[2] != "--" || args.len() > MAX_HANDOFF_ARGUMENTS + 3 {
        return ExitCode::from(2);
    }
    let Some(fd_text) = args[1].to_str() else {
        return ExitCode::from(2);
    };
    let Ok(fd) = fd_text.parse::<i32>() else {
        return ExitCode::from(2);
    };
    if fd < 3 || fd.to_string() != fd_text {
        return ExitCode::from(2);
    }
    let original = &args[3..];
    let argument_bytes = original.iter().try_fold(0usize, |sum, arg| {
        sum.checked_add(arg.as_os_str().as_bytes().len())
    });
    if original.len() > MAX_HANDOFF_ARGUMENTS
        || argument_bytes.is_none_or(|sum| sum > MAX_HANDOFF_ARGUMENT_BYTES)
    {
        return ExitCode::from(2);
    }
    if lomi_platform::setup_context::validate_sealed_selected_executable(fd).is_err() {
        eprintln!("SELECTED_SETUP_HANDOFF_INVALID");
        return ExitCode::from(4);
    }
    if !is_setup_invocation(original) {
        eprintln!("SELECTED_SETUP_HANDOFF_INVALID");
        return ExitCode::from(2);
    }
    match ensure_selected_release(original) {
        Ok(executable) => {
            let error = Command::new(executable).args(original).exec();
            let _ = error;
            eprintln!("SELECTED_SETUP_EXEC_FAILED");
            ExitCode::from(4)
        }
        Err(code) => {
            eprintln!("{code}");
            ExitCode::from(4)
        }
    }
}

fn is_setup_invocation(args: &[std::ffi::OsString]) -> bool {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("lomiremote".into());
    argv.extend(args.iter().cloned());
    crate::cli::command()
        .try_get_matches_from(argv)
        .is_ok_and(|matches| matches.subcommand_name() == Some("setup"))
}

fn selected_profile(args: &[std::ffi::OsString]) -> Result<PathBuf, &'static str> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push("lomiremote".into());
    argv.extend(args.iter().cloned());
    let matches = crate::cli::command()
        .try_get_matches_from(argv)
        .map_err(|_| "SELECTED_SETUP_ARGUMENTS_INVALID")?;
    matches
        .get_one::<PathBuf>("profile-dir")
        .cloned()
        .or_else(lomi_platform::default_profile)
        .filter(|path| path.is_absolute())
        .ok_or("SELECTED_SETUP_PROFILE_UNAVAILABLE")
}

fn ensure_selected_release(original_args: &[std::ffi::OsString]) -> Result<PathBuf, &'static str> {
    let release = compiled::LINUX_SETUP_RELEASE.ok_or("SELECTED_SETUP_RELEASE_NOT_EMBEDDED")?;
    let account = lomi_platform::setup_context::select_current_account()
        .map_err(|_| "SELECTED_SETUP_ACCOUNT_UNAVAILABLE")?;
    let home = account.home();
    if !home.is_absolute()
        || home == Path::new("/")
        || env::var_os("HOME").as_deref() != Some(home.as_os_str())
        || env::var_os("XDG_DATA_HOME").is_some()
    {
        return Err("SELECTED_SETUP_ACCOUNT_UNAVAILABLE");
    }
    let profile = selected_profile(original_args)?;
    let install = home.join(".local/lib/lomiremote");
    ensure_private_install_directory(&install)?;
    lomi_update_trust::validate_install_directory(&install)
        .map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")?;

    // Existing active installations are re-executed by the parent without
    // entering this path. A pending journal here is ambiguous: the signed
    // installer owns managed-service stop, recovery, and prior-running-state
    // reconciliation. Never stop an existing service from plain setup.
    if lomi_update_trust::release_recovery_pending(&install)
        .map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")?
    {
        return Err("SELECTED_SETUP_RELEASE_RECOVERY_REQUIRED");
    }

    let trust = install.join("trust");
    let mut store = match fs::symlink_metadata(&trust) {
        Ok(_) => lomi_update_trust::TrustStore::open_embedded(&trust)
            .map_err(|_| "SELECTED_SETUP_TRUST_STATE_INVALID")?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            match lomi_update_trust::validate_active_release(&profile, &install, release.platform) {
                Ok(None) => {}
                Ok(Some(_)) => return Err("SELECTED_SETUP_TRUST_STATE_MISSING"),
                Err(_) => return Err("SELECTED_SETUP_INSTALL_STATE_INVALID"),
            }
            let uid = account
                .unix()
                .ok_or("SELECTED_SETUP_ACCOUNT_UNAVAILABLE")?
                .uid();
            require_fresh_install_directory(&install, uid)?;
            match lomi_update_trust::TrustStore::initialize_embedded(&trust) {
                Ok(store) => store,
                Err(_) => lomi_update_trust::TrustStore::open_embedded(&trust)
                    .map_err(|_| "SELECTED_SETUP_TRUST_INITIALIZATION_INCOMPLETE")?,
            }
        }
        Err(_) => return Err("SELECTED_SETUP_TRUST_STATE_INVALID"),
    };

    if let Some(executable) =
        lomi_update_trust::validate_active_release(&profile, &install, release.platform)
            .map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")?
    {
        return Ok(executable);
    }

    store
        .install_release_https_pinned_auto_schema_blocking(
            release.origin,
            release.target_name,
            &profile,
            &install,
            release.platform,
            Some(env!("CARGO_PKG_VERSION")),
        )
        .map_err(|_| "SELECTED_SETUP_SIGNED_RELEASE_UNAVAILABLE")?;
    lomi_update_trust::validate_active_release(&profile, &install, release.platform)
        .map_err(|_| "SELECTED_SETUP_ACTIVATION_INVALID")?
        .ok_or("SELECTED_SETUP_ACTIVATION_MISSING")
}

fn ensure_private_install_directory(path: &Path) -> Result<(), &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let parent = path.parent().ok_or("SELECTED_SETUP_INSTALL_UNAVAILABLE")?;
            fs::create_dir_all(parent).map_err(|_| "SELECTED_SETUP_INSTALL_UNAVAILABLE")?;
            fs::DirBuilder::new()
                .mode(0o700)
                .create(path)
                .map_err(|_| "SELECTED_SETUP_INSTALL_UNAVAILABLE")?;
        }
        Err(_) => return Err("SELECTED_SETUP_INSTALL_UNAVAILABLE"),
    }
    Ok(())
}

fn require_fresh_install_directory(path: &Path, owner_uid: u32) -> Result<(), &'static str> {
    for entry in fs::read_dir(path).map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")? {
        let entry = entry.map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")?;
        if entry.file_name() != ".activation.lock" {
            return Err("SELECTED_SETUP_INSTALL_STATE_INVALID");
        }
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|_| "SELECTED_SETUP_INSTALL_STATE_INVALID")?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != owner_uid
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err("SELECTED_SETUP_INSTALL_STATE_INVALID");
        }
    }
    Ok(())
}
