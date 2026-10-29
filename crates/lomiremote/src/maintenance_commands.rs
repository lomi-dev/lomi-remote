//! Local lifecycle commands for the currently installed, signed Host.
//!
//! This module never accepts release origins, target names, install paths,
//! credentials, or service identities from the command line. The only release
//! authority comes from the pins embedded by the release build.

use clap::ArgMatches;
use lomi_remote_protocol::{HostId, LocalIpcVersion, OperationId, ipc::IpcProfileId, ipc::*};
use std::{
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

mod update_check;

#[cfg(target_os = "macos")]
mod macos_uninstall;

const GRACE: Duration = Duration::from_secs(20);
const LOGOUT_ACK_TIMEOUT: Duration = Duration::from_secs(30);
const LOGOUT_ACK_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[cfg(unix)]
type LocalClient = lomi_platform::unix::LocalClient;
#[cfg(windows)]
type LocalClient = lomi_platform::windows::LocalClient;

#[derive(Clone, Copy)]
enum Action {
    Update,
    Uninstall,
}

#[derive(Clone, Copy)]
struct Identity {
    host: HostId,
    profile: IpcProfileId,
}

struct Context {
    profile: PathBuf,
    install: PathBuf,
    executable: PathBuf,
    identity: Identity,
    active_terminals: u64,
    host_running: bool,
    binding: lomi_platform::service_observation::ServiceBinding,
    service: lomi_platform::service_observation::ServiceObservation,
    #[cfg(windows)]
    owner_outcome: Option<lomi_platform::windows::maintenance::OwnerOutcome>,
}

#[derive(Clone, Copy)]
struct Failure {
    code: &'static str,
    exit: u8,
}

impl Failure {
    const fn unavailable() -> Self {
        Self {
            code: "MAINTENANCE_UNAVAILABLE",
            exit: 4,
        }
    }

    const fn invalid() -> Self {
        Self {
            code: "INVALID_ARGUMENT",
            exit: 2,
        }
    }

    const fn identity() -> Self {
        Self {
            code: "HOST_IDENTITY_MISMATCH",
            exit: 5,
        }
    }

    const fn uncertain() -> Self {
        Self {
            code: "MAINTENANCE_OUTCOME_UNCERTAIN",
            exit: 7,
        }
    }
}

pub fn run(profile: &Path, name: &str, args: &ArgMatches) -> u8 {
    if is_update_check(name, args) {
        return update_check::run(args.get_flag("json"));
    }
    #[cfg(target_os = "macos")]
    if matches!(name, "update" | "uninstall")
        && let Some(code) = run_macos_protected(name, profile, args)
    {
        return code;
    }
    #[cfg(windows)]
    if matches!(name, "update" | "uninstall")
        && let Some(code) = run_windows_registered_boot(name, args)
    {
        return code;
    }
    match name {
        "update" => run_update(profile, args),
        "uninstall" => run_uninstall(profile, args),
        "maintenance" => run_maintenance_status(profile, args),
        _ => 2,
    }
}

fn is_update_check(name: &str, args: &ArgMatches) -> bool {
    name == "update" && args.get_flag("check")
}

/// Internal maintenance dispatch runs before the ordinary activation startup
/// barrier so a trusted maintenance command can recover an interrupted update.
pub fn dispatch_internal() -> Option<u8> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args
        .first()
        .is_some_and(|arg| arg == "--internal-maintenance-macos-v1")
    {
        #[cfg(target_os = "macos")]
        return Some(run_macos_root_handoff(&args[1..]));
        #[cfg(not(target_os = "macos"))]
        return Some(2);
    }
    #[cfg(target_os = "macos")]
    if let Some(code) = macos_uninstall::dispatch_owner(&args) {
        return Some(code);
    }
    #[cfg(windows)]
    if args
        .first()
        .is_some_and(|arg| arg == "--internal-maintenance-worker-v1")
    {
        return Some(run_windows_worker(&args[1..]));
    }
    #[cfg(windows)]
    if args
        .first()
        .is_some_and(|arg| arg == "--internal-maintenance-owner-v1")
    {
        return Some(run_windows_owner_worker(&args[1..]));
    }
    #[cfg(windows)]
    if args
        .first()
        .is_some_and(|arg| arg == "--internal-maintenance-empty-worker-v1")
    {
        return Some(run_windows_empty_worker(&args[1..]));
    }
    None
}

#[cfg(target_os = "macos")]
fn run_macos_protected(name: &str, profile: &Path, args: &ArgMatches) -> Option<u8> {
    if lomi_platform::service_macos::is_administrator() {
        // Protected administrator operations enter through the closed
        // owner-selected handoff below; a root CLI invocation has no owner
        // profile authority of its own.
        return None;
    }
    let executable = match std::env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(executable) => executable,
        Err(_) => return Some(report(Failure::unavailable(), args.get_flag("json"))),
    };
    let binding = match macos_uninstall::lookup_owner_binding(profile, &executable) {
        Ok(Some(binding)) => binding,
        Ok(None) => return None,
        Err(error) => return Some(report(error, args.get_flag("json"))),
    };
    if !crate::bootstrap::maintenance_release_pins()
        .is_some_and(|pins| pins.platform == current_platform() && pins.native_signer.is_some())
    {
        return Some(report(Failure::unavailable(), args.get_flag("json")));
    }
    let observation = match macos_uninstall::prepare_owner(profile, &executable, &binding) {
        Ok(observation) => observation,
        Err(error) => return Some(report(error, args.get_flag("json"))),
    };
    if let Err(error) =
        confirm_and_wait(args.get_flag("confirm"), name, observation.active_terminals)
    {
        return Some(report(error, args.get_flag("json")));
    }
    let operation_id = match OperationId::from_bytes(*Uuid::new_v4().as_bytes()) {
        Ok(operation_id) => operation_id,
        Err(_) => return Some(report(Failure::unavailable(), args.get_flag("json"))),
    };
    let deadline = match macos_uninstall::Deadline::after(MAX_MAINTENANCE_WAIT) {
        Ok(deadline) => deadline,
        Err(error) => return Some(report(error, args.get_flag("json"))),
    };
    let version = args
        .get_one::<String>("release-version")
        .map(String::as_str);
    let purge = name == "uninstall" && args.get_flag("purge");
    let mode = macos_mode_argument(binding.mode());
    let json = args.get_flag("json");
    let mut command = std::process::Command::new("/usr/bin/sudo");
    command
        .arg("-H")
        .arg("--")
        .arg(&executable)
        .arg("--internal-maintenance-macos-v1")
        .arg(name)
        .arg(profile)
        .arg(binding.account())
        .arg(mode)
        .arg(String::from(binding.host_id()))
        .arg(String::from(binding.profile_id()))
        .arg(String::from(operation_id))
        .arg(deadline.argument())
        .arg(version.unwrap_or("-"))
        .arg(if purge { "1" } else { "0" })
        .arg(if observation.host_running { "1" } else { "0" })
        .arg(if json { "1" } else { "0" })
        .stdin(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::piped());
    let output = match command.output() {
        Ok(output) => output,
        Err(_) => return Some(report(Failure::unavailable(), json)),
    };
    if std::io::stdout()
        .write_all(&output.stdout)
        .and_then(|()| std::io::stdout().flush())
        .is_err()
    {
        return Some(4);
    }
    let code = output
        .status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(Failure::uncertain().exit);
    if json && output.stdout.is_empty() {
        return Some(report(Failure::unavailable(), true));
    }
    Some(code)
}

#[cfg(target_os = "macos")]
const MAX_MAINTENANCE_WAIT: Duration = Duration::from_secs(120);

#[cfg(target_os = "macos")]
fn macos_mode_argument(mode: lomi_platform::service_macos::AdminHostMode) -> &'static str {
    match mode {
        lomi_platform::service_macos::AdminHostMode::Manual => "manual",
        lomi_platform::service_macos::AdminHostMode::Login => "login",
        lomi_platform::service_macos::AdminHostMode::Boot => "boot",
    }
}

fn run_update(profile: &Path, args: &ArgMatches) -> u8 {
    let expected_version = args
        .get_one::<String>("release-version")
        .map(String::as_str);
    match prepare_context(profile) {
        Ok(context) => {
            if let Err(error) =
                confirm_and_wait(args.get_flag("confirm"), "update", context.active_terminals)
            {
                return report(error, args.get_flag("json"));
            }
            #[cfg(windows)]
            {
                let Some(release) = windows_release_pins() else {
                    return report(Failure::unavailable(), args.get_flag("json"));
                };
                return windows_begin(
                    &context.profile,
                    &context.install,
                    &context.executable,
                    context.identity.host,
                    context.identity.profile,
                    context.binding.mode,
                    context.host_running,
                    context.active_terminals,
                    release,
                    lomi_platform::windows::maintenance::Action::Update {
                        expected_version: expected_version.map(str::to_owned),
                    },
                    args.get_flag("json"),
                );
            }
            #[cfg(target_os = "macos")]
            match maybe_handoff_macos(&context, Action::Update, expected_version, false) {
                Ok(Some(code)) => return code,
                Ok(None) => {}
                Err(error) => return report(error, args.get_flag("json")),
            }
            report_result(
                update(&context, expected_version),
                "update",
                expected_version.unwrap_or("latest verified"),
                args.get_flag("json"),
            )
        }
        Err(error) => report(error, args.get_flag("json")),
    }
}

fn run_uninstall(profile: &Path, args: &ArgMatches) -> u8 {
    if matches!(
        lomi_host::inspect_setup(profile),
        lomi_host::SetupInspection::MissingDatabase
    ) {
        return run_uninitialized_uninstall(profile, args);
    }
    match prepare_context(profile) {
        Ok(context) => {
            if let Err(error) = confirm_and_wait(
                args.get_flag("confirm"),
                "uninstall",
                context.active_terminals,
            ) {
                return report(error, args.get_flag("json"));
            }
            #[cfg(windows)]
            {
                let Some(release) = windows_release_pins() else {
                    return report(Failure::unavailable(), args.get_flag("json"));
                };
                return windows_begin(
                    &context.profile,
                    &context.install,
                    &context.executable,
                    context.identity.host,
                    context.identity.profile,
                    context.binding.mode,
                    context.host_running,
                    context.active_terminals,
                    release,
                    lomi_platform::windows::maintenance::Action::Uninstall {
                        purge: args.get_flag("purge"),
                    },
                    args.get_flag("json"),
                );
            }
            #[cfg(target_os = "macos")]
            match maybe_handoff_macos(&context, Action::Uninstall, None, args.get_flag("purge")) {
                Ok(Some(code)) => return code,
                Ok(None) => {}
                Err(error) => return report(error, args.get_flag("json")),
            }
            report_result(
                uninstall(&context, args.get_flag("purge")),
                "uninstall",
                "",
                args.get_flag("json"),
            )
        }
        Err(error) => report(error, args.get_flag("json")),
    }
}

fn run_uninitialized_uninstall(profile: &Path, args: &ArgMatches) -> u8 {
    let json = args.get_flag("json");
    let Some(pins) = crate::bootstrap::maintenance_release_pins() else {
        return report(Failure::unavailable(), json);
    };
    if pins.platform != current_platform() {
        return report(Failure::identity(), json);
    }
    let profile = match profile.canonicalize() {
        Ok(profile) if profile.is_dir() && profile != Path::new("/") => profile,
        _ => return report(Failure::unavailable(), json),
    };
    let executable = match std::env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(path) => path,
        Err(_) => return report(Failure::unavailable(), json),
    };
    let Some(install) = executable.parent() else {
        return report(Failure::identity(), json);
    };
    let install = match install.canonicalize() {
        Ok(path) if executable.parent() == Some(path.as_path()) => path,
        _ => return report(Failure::identity(), json),
    };
    if lomi_update_trust::validate_install_directory(&install).is_err() {
        return report(Failure::identity(), json);
    }
    if validate_empty_host_registration(&profile, &executable).is_err() {
        return report(Failure::identity(), json);
    }
    if let Err(error) = confirm_and_wait(args.get_flag("confirm"), "uninstall", 0) {
        return report(error, json);
    }
    let proof = match lomi_platform::empty_profile::EmptyHostProfile::acquire(&profile) {
        Ok(proof) => proof,
        Err(_) => {
            return report(
                Failure {
                    code: "PROFILE_STATE_REQUIRES_RECOVERY",
                    exit: 5,
                },
                json,
            );
        }
    };
    if proof.recheck().is_err() || validate_empty_host_registration(&profile, &executable).is_err()
    {
        return report(Failure::identity(), json);
    }

    #[cfg(windows)]
    {
        let Some(release) = windows_release_pins() else {
            return report(Failure::unavailable(), json);
        };
        return match lomi_platform::windows::maintenance::begin_empty_uninstall(
            &proof,
            &install,
            &executable,
            release,
        ) {
            Ok(acceptance) => report_empty_uninstall_acceptance(
                acceptance,
                &profile,
                &install,
                args.get_flag("purge"),
                json,
            ),
            Err(lomi_platform::windows::maintenance::Error::Permission) => report(
                Failure {
                    code: "MAINTENANCE_PERMISSION_DENIED",
                    exit: 5,
                },
                json,
            ),
            Err(_) => report(Failure::uncertain(), json),
        };
    }
    #[cfg(unix)]
    {
        match lomi_update_trust::uninstall_uninitialized_release(&proof, &install) {
            Ok(removed) => report_empty_uninstall_complete(removed, args.get_flag("purge"), json),
            Err(_) => report(Failure::uncertain(), json),
        }
    }
}

fn validate_empty_host_registration(profile: &Path, executable: &Path) -> Result<(), Failure> {
    #[cfg(target_os = "macos")]
    if !matches!(
        lomi_platform::service_macos::lookup_admin_host_identity_binding(profile, executable),
        Ok(lomi_platform::service_macos::AdminHostIdentityLookup::NotManaged)
    ) {
        return Err(Failure::identity());
    }
    let binding = current_service_binding(profile, executable)?;
    if binding.mode != lomi_platform::service_observation::ServiceMode::Manual
        || binding.profile != profile
        || binding.executable != executable
    {
        return Err(Failure::identity());
    }
    let service = lomi_platform::service_observation::inspect(&binding);
    if service.binding != lomi_platform::service_observation::BindingState::Matches
        || service.registration != lomi_platform::service_observation::RegistrationState::Missing
        || matches!(
            service.runtime,
            lomi_platform::service_observation::RuntimeState::Running
                | lomi_platform::service_observation::RuntimeState::Starting
        )
    {
        return Err(Failure::identity());
    }
    Ok(())
}

fn run_maintenance_status(profile: &Path, args: &ArgMatches) -> u8 {
    #[cfg(windows)]
    {
        let Some(("status", status)) = args.subcommand() else {
            return report(Failure::invalid(), false);
        };
        let Some(job_id) = status.get_one::<String>("job-id") else {
            return report(Failure::invalid(), status.get_flag("json"));
        };
        return lomi_platform::windows::maintenance::status(
            profile,
            job_id,
            status.get_flag("json"),
        );
    }
    #[cfg(not(windows))]
    {
        let _ = (profile, args);
        report(Failure::unavailable(), false)
    }
}

#[cfg(windows)]
fn windows_release_pins() -> Option<lomi_platform::windows::maintenance::ReleasePins> {
    let pins = crate::bootstrap::maintenance_release_pins()?;
    Some(lomi_platform::windows::maintenance::ReleasePins {
        origin: pins.origin.to_owned(),
        primary_target: pins.primary_target.to_owned(),
        helper_target: Some(pins.helper_target?.to_owned()),
        platform: pins.platform.to_owned(),
        signer_thumbprint: pins.native_signer?.to_owned(),
        root_sha256: lomi_update_trust::embedded_root_sha256().ok()?.to_owned(),
    })
}

#[cfg(windows)]
fn run_windows_registered_boot(name: &str, args: &ArgMatches) -> Option<u8> {
    use lomi_platform::windows::service_admin::Error as AdminError;
    let binding =
        match lomi_platform::windows::service_admin::registered_boot_host_for_current_executable() {
            Ok(Some(binding)) => binding,
            Ok(None) => return None,
            Err(AdminError::AdministratorRequired) => {
                eprintln!(
                    "ADMINISTRATOR_REQUIRED: run this exact signed Boot Host command from an elevated Administrator terminal. The selected Host owner remains the account bound to the protected service registration."
                );
                return Some(report(
                    Failure {
                        code: "ADMINISTRATOR_REQUIRED",
                        exit: 5,
                    },
                    args.get_flag("json"),
                ));
            }
            Err(_) => return Some(report(Failure::identity(), args.get_flag("json"))),
        };
    match name {
        "update" => Some(run_windows_boot_update(&binding, args)),
        "uninstall" => Some(run_windows_boot_uninstall(&binding, args)),
        _ => None,
    }
}

#[cfg(windows)]
fn run_windows_boot_update(
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
    args: &ArgMatches,
) -> u8 {
    if let Err(error) = confirm_and_wait_boot(args.get_flag("confirm"), "update") {
        return report(error, args.get_flag("json"));
    }
    let Some(release) = windows_release_pins() else {
        return report(Failure::unavailable(), args.get_flag("json"));
    };
    match lomi_platform::windows::maintenance::begin_boot(
        binding,
        release,
        lomi_platform::windows::maintenance::Action::Update {
            expected_version: args
                .get_one::<String>("release-version")
                .map(String::as_str)
                .map(str::to_owned),
        },
        None,
    ) {
        Ok(acceptance) => report_windows_acceptance(acceptance, args.get_flag("json")),
        Err(_) => report(Failure::uncertain(), args.get_flag("json")),
    }
}

#[cfg(windows)]
fn run_windows_boot_uninstall(
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
    args: &ArgMatches,
) -> u8 {
    if let Err(error) = confirm_and_wait_boot(args.get_flag("confirm"), "uninstall") {
        return report(error, args.get_flag("json"));
    }

    let Some(release) = windows_release_pins() else {
        return report(Failure::unavailable(), args.get_flag("json"));
    };
    let owner = match lomi_platform::setup_context::select_windows_account(binding.account()) {
        Ok(owner) => owner,
        Err(_) => return report(Failure::identity(), args.get_flag("json")),
    };
    let Some(owner_windows) = owner.windows() else {
        return report(Failure::identity(), args.get_flag("json"));
    };
    if owner_windows.sid() != binding.account_sid()
        || owner_windows.home().join(".lomiRemote") != binding.profile()
    {
        return report(Failure::identity(), args.get_flag("json"));
    }
    let credential =
        match lomi_platform::windows_password::prompt_logon_credential(binding.account()) {
            Ok(credential) => credential,
            Err(_) => {
                return report(
                    Failure {
                        code: "OWNER_CREDENTIAL_REQUIRED",
                        exit: 5,
                    },
                    args.get_flag("json"),
                );
            }
        };
    let owner_binding = binding.clone();
    let release_for_phases = release.clone();
    let run_owner = move |executable: &std::path::Path, job_id: &str| {
        let arguments = [
            std::ffi::OsString::from("--internal-maintenance-owner-v1"),
            std::ffi::OsString::from(job_id),
        ];
        let status = lomi_platform::setup_context::reexec_windows_as_selected(
            &owner,
            &credential,
            executable,
            &arguments,
        )
        .map_err(|_| lomi_platform::windows::maintenance::Error::Uncertain)?;
        match status.code() {
            Some(0) => Ok(lomi_platform::windows::maintenance::OwnerOutcome::Complete),
            Some(12) => Ok(lomi_platform::windows::maintenance::OwnerOutcome::RevocationPending),
            Some(13) => Ok(lomi_platform::windows::maintenance::OwnerOutcome::CleanupUncertain),
            _ => Err(lomi_platform::windows::maintenance::Error::Uncertain),
        }
    };
    let continuation = Box::new(move |job_id: &str| {
        let first = run_owner(owner_binding.executable(), job_id);
        if lomi_platform::windows::service_admin::registered_boot_host_needs_stop(&owner_binding)
            .map_err(|_| lomi_platform::windows::maintenance::Error::Uncertain)?
        {
            let stopped = lomi_platform::service_observation::control(
                &windows_boot_service_binding(&owner_binding),
                lomi_platform::service_observation::ServiceAction::Stop,
            )
            .map_err(|_| lomi_platform::windows::maintenance::Error::Uncertain)?;
            if stopped.runtime != lomi_platform::service_observation::RuntimeState::Stopped {
                return Err(lomi_platform::windows::maintenance::Error::Uncertain);
            }
        }
        let first = first?;
        lomi_platform::windows::maintenance::complete_owner_phase(
            &owner_binding,
            job_id,
            &release_for_phases,
            lomi_platform::windows::maintenance::OwnerPhase::FenceAndStop,
            first,
        )
        .map_err(|_| lomi_platform::windows::maintenance::Error::Uncertain)?;
        Ok(first)
    });
    match lomi_platform::windows::maintenance::begin_boot(
        binding,
        release,
        lomi_platform::windows::maintenance::Action::Uninstall {
            purge: args.get_flag("purge"),
        },
        Some(continuation),
    ) {
        Ok(acceptance) => report_windows_acceptance(acceptance, args.get_flag("json")),
        Err(_) => report(Failure::uncertain(), args.get_flag("json")),
    }
}

#[cfg(windows)]
fn confirm_and_wait_boot(explicit: bool, action: &str) -> Result<(), Failure> {
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if !explicit {
        if !interactive {
            return Err(Failure {
                code: "CONFIRMATION_REQUIRED",
                exit: 2,
            });
        }
        eprint!("Confirm {action} of this administrator-managed Lomi Remote Host? [y/N] ");
        io::stderr().flush().map_err(|_| Failure::unavailable())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|_| Failure::unavailable())?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Failure {
                code: "MAINTENANCE_CANCELLED",
                exit: 2,
            });
        }
    }
    if interactive {
        eprintln!(
            "The Host will stop. The elevated operator cannot read the owner's live terminal count; assume active sessions may be interrupted. Save work. Continuing in {} seconds. Press Ctrl-C to cancel.",
            GRACE.as_secs()
        );
    }
    thread::sleep(GRACE);
    Ok(())
}

#[cfg(windows)]
fn report_windows_acceptance(
    acceptance: lomi_platform::windows::maintenance::JobAcceptance,
    json: bool,
) -> u8 {
    let boot_status = acceptance
        .status_executable
        .as_ref()
        .zip(acceptance.status_profile.as_ref())
        .map(|(worker, profile)| {
            let worker = worker.to_string_lossy().into_owned();
            let profile = profile.to_string_lossy().into_owned();
            let quote = |value: &str| format!("'{}'", value.replace('\'', "''"));
            let arguments = vec![
                "--profile-dir".to_owned(),
                profile.clone(),
                "maintenance".to_owned(),
                "status".to_owned(),
                acceptance.job_id.clone(),
            ];
            let command = format!(
                "& {} --profile-dir {} maintenance status {}",
                quote(&worker),
                quote(&profile),
                quote(&acceptance.job_id),
            );
            (worker, arguments, command)
        });
    if json {
        let mut payload = serde_json::json!({
            "version": LocalIpcVersion::CURRENT,
            "operation": "maintenance",
            "jobId": acceptance.job_id,
            "state": acceptance.state,
        });
        if let Some((worker, arguments, command)) = boot_status.as_ref() {
            let Some(object) = payload.as_object_mut() else {
                return 4;
            };
            object.insert("statusExecutable".to_owned(), serde_json::json!(worker));
            object.insert("statusArguments".to_owned(), serde_json::json!(arguments));
            object.insert("statusCommand".to_owned(), serde_json::json!(command));
        }
        if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
            return 4;
        }
        println!();
    } else {
        if let Some((_, _, command)) = boot_status.as_ref() {
            println!(
                "Maintenance job {} was {:?}; query the durable result with PowerShell: {}",
                acceptance.job_id, acceptance.state, command
            );
        } else {
            println!(
                "Maintenance job {} was {:?}; query `lomiremote maintenance status {}` for the durable result.",
                acceptance.job_id, acceptance.state, acceptance.job_id
            );
        }
    }
    match acceptance.state {
        lomi_platform::windows::maintenance::JobState::Accepted => 0,
        lomi_platform::windows::maintenance::JobState::Uncertain => 7,
        _ => 4,
    }
}

#[cfg(windows)]
fn report_empty_uninstall_acceptance(
    acceptance: lomi_platform::windows::maintenance::JobAcceptance,
    profile: &Path,
    install: &Path,
    purge_requested: bool,
    json: bool,
) -> u8 {
    let worker = install
        .join(".lomi-maintenance-v1")
        .join(format!("job-{}", acceptance.job_id))
        .join("worker.exe");
    let status_args = [
        "--profile-dir".to_owned(),
        profile.to_string_lossy().into_owned(),
        "maintenance".to_owned(),
        "status".to_owned(),
        acceptance.job_id.clone(),
    ];
    let quote_powershell = |value: &str| format!("'{}'", value.replace('\'', "''"));
    let status_command = format!(
        "& {} --profile-dir {} maintenance status {}",
        quote_powershell(&worker.to_string_lossy()),
        quote_powershell(&profile.to_string_lossy()),
        quote_powershell(&acceptance.job_id),
    );
    if json {
        let payload = serde_json::json!({
            "version": LocalIpcVersion::CURRENT,
            "operation": "uninstall",
            "profileKind": "empty_reservation",
            "jobId": acceptance.job_id,
            "state": acceptance.state,
            "purgeRequested": purge_requested,
            "purge": "no_mutable_host_data",
            "statusCommand": status_command,
            "statusExecutable": worker,
            "statusArguments": status_args,
        });
        if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
            return 4;
        }
        println!();
    } else {
        println!(
            "Fresh-profile uninstall job {} was {:?}. No Host data existed to purge.",
            acceptance.job_id, acceptance.state
        );
        println!("Check the durable removal result in PowerShell with: {status_command}");
    }
    match acceptance.state {
        lomi_platform::windows::maintenance::JobState::Accepted => 0,
        lomi_platform::windows::maintenance::JobState::Uncertain => 7,
        _ => 4,
    }
}

#[cfg(unix)]
fn report_empty_uninstall_complete(removed: usize, purge_requested: bool, json: bool) -> u8 {
    if json {
        let payload = serde_json::json!({
            "version": LocalIpcVersion::CURRENT,
            "operation": "uninstall",
            "profileKind": "empty_reservation",
            "removedReleaseObjects": removed,
            "purgeRequested": purge_requested,
            "purge": "no_mutable_host_data",
            "state": "completed",
        });
        if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
            return 4;
        }
        println!();
    } else {
        println!("Removed the signed installation. No Host data existed to purge.");
    }
    0
}

#[cfg(windows)]
fn windows_boot_service_binding(
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
) -> lomi_platform::service_observation::ServiceBinding {
    lomi_platform::service_observation::ServiceBinding {
        account: lomi_platform::service_observation::ServiceAccount::Windows {
            sid: binding.account_sid().to_owned(),
            name: binding.account().to_owned(),
        },
        mode: lomi_platform::service_observation::ServiceMode::Boot,
        profile: binding.profile().to_path_buf(),
        executable: binding.executable().to_path_buf(),
    }
}

#[cfg(windows)]
fn windows_boot_context(
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
    owner_outcome: Option<lomi_platform::windows::maintenance::OwnerOutcome>,
) -> Context {
    Context {
        profile: binding.profile().to_path_buf(),
        install: binding.install().to_path_buf(),
        executable: binding.executable().to_path_buf(),
        identity: Identity {
            host: binding.identity().host_id,
            profile: binding.identity().profile_id,
        },
        active_terminals: 0,
        host_running: binding.running(),
        binding: windows_boot_service_binding(binding),
        service: lomi_platform::service_observation::inspect(&windows_boot_service_binding(
            binding,
        )),
        owner_outcome,
    }
}

#[cfg(windows)]
fn windows_begin(
    profile: &Path,
    install: &Path,
    executable: &Path,
    host_id: HostId,
    profile_id: IpcProfileId,
    mode: lomi_platform::service_observation::ServiceMode,
    was_running: bool,
    active_terminals: u64,
    release: lomi_platform::windows::maintenance::ReleasePins,
    action: lomi_platform::windows::maintenance::Action,
    json: bool,
) -> u8 {
    match lomi_platform::windows::maintenance::begin(
        profile,
        install,
        executable,
        host_id,
        profile_id,
        mode,
        was_running,
        active_terminals,
        release,
        action,
    ) {
        Ok(acceptance) => {
            if json {
                let payload = serde_json::json!({
                    "version": LocalIpcVersion::CURRENT,
                    "operation": "maintenance",
                    "jobId": acceptance.job_id,
                    "state": acceptance.state,
                });
                if serde_json::to_writer(std::io::stdout().lock(), &payload).is_err() {
                    return 4;
                }
                println!();
            } else {
                println!(
                    "Maintenance job {} was {:?}; query `lomiremote maintenance status {}` for the durable result.",
                    acceptance.job_id, acceptance.state, acceptance.job_id
                );
            }
            match acceptance.state {
                lomi_platform::windows::maintenance::JobState::Accepted => 0,
                lomi_platform::windows::maintenance::JobState::Uncertain => 7,
                _ => 4,
            }
        }
        Err(_) => report(Failure::uncertain(), json),
    }
}

#[cfg(windows)]
fn run_windows_worker(args: &[std::ffi::OsString]) -> u8 {
    if !(args.len() == 1 || args.len() == 2) {
        return 2;
    }
    let Some(job_id) = args[0].to_str() else {
        return 2;
    };
    let claim = match args.len() {
        1 => lomi_platform::windows::maintenance::claim_boot_worker(job_id),
        2 => lomi_platform::windows::maintenance::claim_worker(Path::new(&args[1]), job_id),
        _ => unreachable!(),
    };
    let mut job = match claim {
        Ok(job) => job,
        Err(_) => return 7,
    };
    if lomi_platform::windows::maintenance::mark_running(&mut job).is_err() {
        return 7;
    }
    let context = match prepare_windows_worker_context(&job) {
        Ok(context) => context,
        Err(_) => {
            return finish_windows_job(
                &mut job,
                lomi_platform::windows::maintenance::JobState::Failed,
                "WORKER_IDENTITY_REVALIDATION_FAILED",
                5,
            );
        }
    };
    let action = job.action().clone();
    let result = match action {
        lomi_platform::windows::maintenance::Action::Update { expected_version } => (|| {
            recover_if_pending(&context)?;
            let context =
                if job.mode().ok() == Some(lomi_platform::service_observation::ServiceMode::Boot) {
                    let release = job.release().clone();
                    job.refresh_boot_binding_after_recovery(&release)
                        .map_err(|_| Failure::identity())?;
                    prepare_windows_worker_context(&job)?
                } else {
                    prepare_windows_worker_context(&job)?
                };
            update_after_recovery(&context, expected_version.as_deref())
        })(),
        lomi_platform::windows::maintenance::Action::Uninstall { purge } => (|| {
            if job.mode().ok() == Some(lomi_platform::service_observation::ServiceMode::Boot) {
                return run_windows_boot_uninstall_worker(&mut job, context, purge);
            }
            let revocation_pending = match context.owner_outcome {
                Some(lomi_platform::windows::maintenance::OwnerOutcome::Complete) => false,
                Some(lomi_platform::windows::maintenance::OwnerOutcome::RevocationPending) => true,
                Some(lomi_platform::windows::maintenance::OwnerOutcome::CleanupUncertain) => {
                    return Err(Failure::uncertain());
                }
                Some(
                    lomi_platform::windows::maintenance::OwnerOutcome::Pending
                    | lomi_platform::windows::maintenance::OwnerOutcome::NotRequired,
                ) => return Err(Failure::uncertain()),
                None => fence_and_stop_for_uninstall(&context)?,
            };
            recover_if_pending(&context)?;
            let context = prepare_windows_worker_context(&job)?;
            uninstall_after_recovery(&context, purge, Some(revocation_pending))
        })(),
    };
    match result {
        Ok(()) => finish_windows_job(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Completed,
            "COMPLETED",
            0,
        ),
        Err(error)
            if error.code == "PURGE_INCOMPLETE_REVOCATION_PENDING"
                || error.code == "UNINSTALL_REVOCATION_PENDING" =>
        {
            finish_windows_job(
                &mut job,
                lomi_platform::windows::maintenance::JobState::RevocationPending,
                error.code,
                7,
            )
        }
        Err(error) => finish_windows_job(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Uncertain,
            error.code,
            error.exit.max(7),
        ),
    }
}

#[cfg(windows)]
fn run_windows_boot_uninstall_worker(
    job: &mut lomi_platform::windows::maintenance::WorkerJob,
    context: Context,
    purge: bool,
) -> Result<(), Failure> {
    use lomi_platform::windows::maintenance::{OwnerOutcome, OwnerPhase};

    let phase = job.owner_phase();
    let owner_outcome = job.owner_outcome();
    let (revocation_pending, purge_after_recovery) = match (phase, owner_outcome, purge) {
        (Some(OwnerPhase::PurgeAfterRecovery), Some(OwnerOutcome::Pending), true) => (false, true),
        (Some(OwnerPhase::Complete), Some(OwnerOutcome::RevocationPending), _) => (true, false),
        (Some(OwnerPhase::Complete), Some(OwnerOutcome::Complete), false) => (false, false),
        (Some(OwnerPhase::Complete), Some(OwnerOutcome::Complete), true) => (false, false),
        (_, Some(OwnerOutcome::CleanupUncertain), _) => {
            return Err(Failure::uncertain());
        }
        _ => return Err(Failure::uncertain()),
    };

    let binding = job
        .verified_boot_binding()
        .map_err(|_| Failure::identity())?;
    stop_boot_host(&context, &binding)?;
    recover_if_pending(&context)?;
    let release = job.release().clone();
    let binding = job
        .refresh_boot_binding_after_recovery(&release)
        .map_err(|_| Failure::identity())?;
    let mut context = prepare_windows_worker_context(job)?;
    // Recovery may publish a new CLI/helper pair and may honor its old resume
    // flag. Use the refreshed sealed binding to stop and join that exact pair.
    stop_boot_host(&context, &binding)?;

    if purge_after_recovery {
        let outcome = run_windows_owner_purge_phase(job, &binding, &release)?;
        match outcome {
            OwnerOutcome::Complete => context.owner_outcome = Some(OwnerOutcome::Complete),
            OwnerOutcome::RevocationPending => {
                return Err(Failure {
                    code: "PURGE_INCOMPLETE_REVOCATION_PENDING",
                    exit: 7,
                });
            }
            OwnerOutcome::CleanupUncertain => {
                return Err(Failure {
                    code: "PURGE_CLEANUP_UNCERTAIN",
                    exit: 7,
                });
            }
            OwnerOutcome::Pending | OwnerOutcome::NotRequired => {
                return Err(Failure::uncertain());
            }
        }
    }

    uninstall_after_recovery(&context, purge, Some(revocation_pending))
}

#[cfg(windows)]
fn stop_boot_host(
    context: &Context,
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
) -> Result<(), Failure> {
    if !lomi_platform::windows::service_admin::registered_boot_host_needs_stop(binding)
        .map_err(|_| Failure::identity())?
    {
        return Ok(());
    }
    let stopped = lomi_platform::service_observation::control(
        &context.binding,
        lomi_platform::service_observation::ServiceAction::Stop,
    )
    .map_err(|_| Failure::uncertain())?;
    if stopped.runtime != lomi_platform::service_observation::RuntimeState::Stopped {
        return Err(Failure::uncertain());
    }
    Ok(())
}

#[cfg(windows)]
fn run_windows_owner_purge_phase(
    job: &lomi_platform::windows::maintenance::WorkerJob,
    binding: &lomi_platform::windows::service_admin::RegisteredBootHost,
    release: &lomi_platform::windows::maintenance::ReleasePins,
) -> Result<lomi_platform::windows::maintenance::OwnerOutcome, Failure> {
    let _console =
        lomi_platform::windows_password::attach_prompt_console().map_err(|_| Failure {
            code: "OWNER_CREDENTIAL_CONSOLE_REQUIRED",
            exit: 5,
        })?;
    let owner = lomi_platform::setup_context::select_windows_account(binding.account())
        .map_err(|_| Failure::identity())?;
    let Some(owner_windows) = owner.windows() else {
        return Err(Failure::identity());
    };
    if owner_windows.sid() != binding.account_sid()
        || owner_windows.home().join(".lomiRemote") != binding.profile()
    {
        return Err(Failure::identity());
    }
    let credential = lomi_platform::windows_password::prompt_logon_credential(binding.account())
        .map_err(|_| Failure {
            code: "OWNER_CREDENTIAL_REQUIRED",
            exit: 5,
        })?;
    let arguments = [
        std::ffi::OsString::from("--internal-maintenance-owner-v1"),
        std::ffi::OsString::from(job.job_id()),
    ];
    let status = lomi_platform::setup_context::reexec_windows_as_selected(
        &owner,
        &credential,
        binding.executable(),
        &arguments,
    )
    .map_err(|_| Failure::uncertain())?;
    let outcome = match status.code() {
        Some(0) => lomi_platform::windows::maintenance::OwnerOutcome::Complete,
        Some(12) => lomi_platform::windows::maintenance::OwnerOutcome::RevocationPending,
        Some(13) => lomi_platform::windows::maintenance::OwnerOutcome::CleanupUncertain,
        _ => return Err(Failure::uncertain()),
    };
    lomi_platform::windows::maintenance::complete_owner_phase(
        binding,
        job.job_id(),
        release,
        lomi_platform::windows::maintenance::OwnerPhase::PurgeAfterRecovery,
        outcome,
    )
    .map_err(|_| Failure::uncertain())?;
    Ok(outcome)
}

#[cfg(windows)]
fn run_windows_empty_worker(args: &[std::ffi::OsString]) -> u8 {
    if args.len() != 1 {
        return 2;
    }
    let Some(job_id) = args[0].to_str() else {
        return 2;
    };
    let mut job = match lomi_platform::windows::maintenance::claim_empty_worker(job_id) {
        Ok(job) => job,
        Err(_) => return 7,
    };
    if lomi_platform::windows::maintenance::mark_empty_worker_running(&mut job).is_err() {
        return 7;
    }
    let Some(expected_release) = windows_release_pins() else {
        let _ = lomi_platform::windows::maintenance::finish_empty_worker(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Uncertain,
            "RELEASE_PINS_UNAVAILABLE",
        );
        return 7;
    };
    if job.release() != &expected_release {
        let _ = lomi_platform::windows::maintenance::finish_empty_worker(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Uncertain,
            "RELEASE_PINS_CHANGED",
        );
        return 7;
    }
    if job.check_install_current().is_err() {
        let _ = lomi_platform::windows::maintenance::finish_empty_worker(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Uncertain,
            "INSTALL_OBJECT_CHANGED_BEFORE_REMOVAL",
        );
        return 7;
    }
    if validate_empty_host_registration(job.profile(), job.active_executable()).is_err() {
        let _ = lomi_platform::windows::maintenance::finish_empty_worker(
            &mut job,
            lomi_platform::windows::maintenance::JobState::Uncertain,
            "HOST_REGISTRATION_APPEARED",
        );
        return 7;
    }
    let removed = lomi_update_trust::uninstall_uninitialized_release(
        match job.proof() {
            Ok(proof) => proof,
            Err(_) => return 7,
        },
        job.install(),
    );
    match removed {
        Ok(_) => {
            if lomi_platform::windows::maintenance::finish_empty_worker(
                &mut job,
                lomi_platform::windows::maintenance::JobState::Completed,
                "UNINSTALL_COMPLETED",
            )
            .is_ok()
            {
                0
            } else {
                7
            }
        }
        Err(_) => {
            let _ = lomi_platform::windows::maintenance::finish_empty_worker(
                &mut job,
                lomi_platform::windows::maintenance::JobState::Uncertain,
                "UNINSTALL_OUTCOME_UNCERTAIN",
            );
            7
        }
    }
}

#[cfg(windows)]
fn run_windows_owner_worker(args: &[std::ffi::OsString]) -> u8 {
    if args.len() != 1 {
        return 2;
    }
    let Some(job_id) = args[0].to_str() else {
        return 2;
    };
    let Some(release) = windows_release_pins() else {
        return 5;
    };
    let request =
        match lomi_platform::windows::maintenance::claim_owner_continuation(job_id, &release) {
            Ok(request) => request,
            Err(_) => return 5,
        };
    if request.phase() == lomi_platform::windows::maintenance::OwnerPhase::PurgeAfterRecovery {
        if !request.purge() {
            return 5;
        }
        return match lomi_host::purge_host_profile(
            request.profile(),
            request.identity().0,
            request.identity().1,
            request.operation_id(),
        ) {
            Ok(lomi_host::ProfilePurgeOutcome::Complete) => 0,
            Ok(lomi_host::ProfilePurgeOutcome::RevocationPending) => 12,
            Ok(lomi_host::ProfilePurgeOutcome::CleanupUncertain) | Err(_) => 13,
        };
    }
    if request.phase() != lomi_platform::windows::maintenance::OwnerPhase::FenceAndStop {
        return 5;
    }
    let (host_id, profile_id) = request.identity();
    let mut client = match connect(request.profile()) {
        Ok(client) => client,
        Err(_) => {
            match lomi_host::fence_maintenance_profile(request.profile(), host_id, profile_id) {
                Ok(observation)
                    if observation.identity.host_id == host_id
                        && observation.identity.profile_id == profile_id
                        && observation.remote_locked =>
                {
                    return if observation.pending_cloud_revoke {
                        12
                    } else {
                        0
                    };
                }
                Err(lomi_host::ProfilePurgeError::Busy) => match connect(request.profile()) {
                    Ok(client) => client,
                    Err(_) => return 7,
                },
                _ => return 7,
            }
        }
    };
    let discovery = client.discovery().clone();
    if discovery.host_id != host_id || discovery.profile_id != profile_id {
        return 5;
    }
    let response = match client.request(LocalCall::MaintenancePrepare(LocalOperatorIntent {
        operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
    })) {
        Ok(response) => response,
        Err(_) => return 7,
    };
    let LocalResult::MaintenanceStatus(prepared) = (match response.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if prepared.host_id != discovery.host_id || prepared.runtime_id != discovery.runtime_id {
        return 5;
    }
    let logout_deadline = Instant::now() + LOGOUT_ACK_TIMEOUT;
    let response = match request_before_deadline(
        &mut client,
        LocalCall::Logout(LocalOperatorIntent {
            operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
        }),
        logout_deadline,
    ) {
        Ok(response) => response,
        Err(()) => return 7,
    };
    let LocalResult::LoginStatus(status) = (match response.result {
        Ok(result) => result,
        Err(_) => return 7,
    }) else {
        return 7;
    };
    if !status.locked {
        return 7;
    }
    let pending = status.pending_cloud_revoke
        && !wait_for_logout_ack(
            &mut client,
            Identity {
                host: host_id,
                profile: profile_id,
            },
            status.generation.0,
            logout_deadline,
        );
    drop(client);

    let stopped = lomi_platform::service_observation::control(
        request.binding(),
        lomi_platform::service_observation::ServiceAction::Stop,
    );
    if stopped.is_err()
        || !matches!(
            stopped.as_ref().map(|value| value.runtime),
            Ok(lomi_platform::service_observation::RuntimeState::Stopped)
        )
    {
        return 7;
    }
    if pending {
        return 12;
    }
    0
}

#[cfg(windows)]
fn finish_windows_job(
    job: &mut lomi_platform::windows::maintenance::WorkerJob,
    state: lomi_platform::windows::maintenance::JobState,
    code: &'static str,
    exit: u8,
) -> u8 {
    if lomi_platform::windows::maintenance::finish_worker(job, state, code).is_ok() {
        exit
    } else {
        7
    }
}

#[cfg(windows)]
fn prepare_windows_worker_context(
    job: &lomi_platform::windows::maintenance::WorkerJob,
) -> Result<Context, Failure> {
    use lomi_platform::{
        service_observation::{BindingState, RegistrationState, RuntimeState, ServiceAccount},
        setup_context,
    };
    let pins = windows_release_pins().ok_or(Failure::identity())?;
    if &pins != job.release() {
        return Err(Failure::identity());
    }
    let profile = job.profile().to_path_buf();
    let install = job.install().to_path_buf();
    let executable = job.active_executable().to_path_buf();
    if executable.parent() != Some(install.as_path()) {
        return Err(Failure::identity());
    }
    let identity = Identity {
        host: job.host_id().map_err(|_| Failure::identity())?,
        profile: job.profile_id().map_err(|_| Failure::identity())?,
    };
    if job.mode().map_err(|_| Failure::identity())?
        == lomi_platform::service_observation::ServiceMode::Boot
    {
        let (operator_sid, _) = lomi_platform::windows::service_admin::current_account()
            .map_err(|_| Failure::identity())?;
        if operator_sid != job.operator_sid() {
            return Err(Failure::identity());
        }
        let binding = job
            .verified_boot_binding()
            .map_err(|_| Failure::identity())?;
        if binding.account() != job.owner_account().ok_or(Failure::identity())?
            || binding.profile() != profile
            || binding.install() != install
            || binding.identity().host_id != identity.host
            || binding.identity().profile_id != identity.profile
            || binding.signer_thumbprint() != pins.signer_thumbprint
        {
            return Err(Failure::identity());
        }
        let binding = windows_boot_service_binding(&binding);
        let service = lomi_platform::service_observation::inspect(&binding);
        if service.binding != lomi_platform::service_observation::BindingState::Matches
            || matches!(
                service.registration,
                lomi_platform::service_observation::RegistrationState::Invalid
                    | lomi_platform::service_observation::RegistrationState::Unavailable
            )
        {
            return Err(Failure::identity());
        }
        let trust = lomi_update_trust::TrustStore::open_admin_host_for_account(
            job.owner_account().ok_or(Failure::identity())?,
        )
        .map_err(|_| Failure::identity())?;
        if trust
            .admin_host_install_path()
            .map_err(|_| Failure::identity())?
            != install
        {
            return Err(Failure::identity());
        }
        let host_running = match job.action() {
            lomi_platform::windows::maintenance::Action::Uninstall { .. } => false,
            lomi_platform::windows::maintenance::Action::Update { .. } => job.was_running(),
        };
        return Ok(Context {
            profile,
            install,
            executable,
            identity,
            active_terminals: job.active_terminals(),
            host_running,
            binding,
            service,
            owner_outcome: job.owner_outcome(),
        });
    }
    let selected = setup_context::select_current_account().map_err(|_| Failure::identity())?;
    let selected = selected.windows().ok_or(Failure::identity())?;
    if selected.sid() != job.account_sid() {
        return Err(Failure::identity());
    }
    let mut maintenance_profile_busy = false;
    match lomi_host::inspect_setup(&profile) {
        lomi_host::SetupInspection::Ready(observation)
            if observation.identity.host_id == identity.host
                && observation.identity.profile_id == identity.profile => {}
        lomi_host::SetupInspection::OwnerRunning => {}
        lomi_host::SetupInspection::NeedsRecovery => {
            match lomi_host::inspect_maintenance_profile(&profile) {
                Ok(observation)
                    if observation.identity.host_id == identity.host
                        && observation.identity.profile_id == identity.profile => {}
                Ok(_) => return Err(Failure::identity()),
                Err(lomi_host::ProfilePurgeError::Busy) => maintenance_profile_busy = true,
                Err(_) => return Err(Failure::identity()),
            }
        }
        _ => return Err(Failure::identity()),
    }
    let binding = lomi_platform::service_observation::current_binding(
        &profile,
        &executable,
        job.mode().map_err(|_| Failure::identity())?,
    )
    .map_err(|_| Failure::identity())?;
    let ServiceAccount::Windows { sid, .. } = &binding.account else {
        return Err(Failure::identity());
    };
    if sid != job.account_sid()
        || binding.mode != job.mode().map_err(|_| Failure::identity())?
        || binding.profile != profile
        || binding.executable.parent() != Some(install.as_path())
    {
        return Err(Failure::identity());
    }
    if binding.mode == lomi_platform::service_observation::ServiceMode::Boot {
        let ServiceAccount::Windows { name, .. } = &binding.account else {
            return Err(Failure::identity());
        };
        let trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
            .map_err(|_| Failure::identity())?;
        if trust
            .admin_host_install_path()
            .map_err(|_| Failure::identity())?
            != install
        {
            return Err(Failure::identity());
        }
        let registration = lomi_platform::windows::service_admin::inspect(name)
            .map_err(|_| Failure::identity())?
            .ok_or(Failure::identity())?;
        if !registration.registered
            || registration.account_sid != *sid
            || registration.profile != profile
            || registration.executable != binding.executable
            || registration.mode != "boot"
            || registration.host_id != Some(identity.host)
            || registration.profile_id != Some(identity.profile)
        {
            return Err(Failure::identity());
        }
    } else {
        lomi_update_trust::validate_install_directory(&install).map_err(|_| Failure::identity())?;
    }
    let service = lomi_platform::service_observation::inspect(&binding);
    if service.binding != BindingState::Matches
        || matches!(
            service.registration,
            RegistrationState::Invalid | RegistrationState::Unavailable
        )
    {
        return Err(Failure::identity());
    }
    let live = connect(&profile).ok();
    let host_running = if let Some(mut client) = live {
        let discovery = client.discovery().clone();
        if discovery.host_id != identity.host || discovery.profile_id != identity.profile {
            return Err(Failure::identity());
        }
        let response = client
            .request(LocalCall::MaintenancePrepare(LocalOperatorIntent {
                operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
            }))
            .map_err(|_| Failure::uncertain())?;
        let LocalResult::MaintenanceStatus(maintenance) =
            response.result.map_err(|_| Failure::uncertain())?
        else {
            return Err(Failure::identity());
        };
        if maintenance.host_id != identity.host || maintenance.runtime_id != discovery.runtime_id {
            return Err(Failure::identity());
        }
        true
    } else {
        if maintenance_profile_busy
            || matches!(
                service.runtime,
                RuntimeState::Running | RuntimeState::Starting
            )
            || matches!(
                lomi_host::inspect_setup(&profile),
                lomi_host::SetupInspection::OwnerRunning
            )
        {
            return Err(Failure::uncertain());
        }
        false
    };
    Ok(Context {
        profile,
        install,
        executable,
        identity,
        active_terminals: job.active_terminals(),
        host_running,
        binding,
        service,
        #[cfg(windows)]
        owner_outcome: None,
    })
}

fn prepare_context(profile: &Path) -> Result<Context, Failure> {
    let pins = crate::bootstrap::maintenance_release_pins().ok_or(Failure::unavailable())?;
    if pins.platform != current_platform() {
        return Err(Failure::identity());
    }
    let profile = profile.canonicalize().map_err(|_| Failure::unavailable())?;
    if !profile.is_dir() || profile == Path::new("/") {
        return Err(Failure::unavailable());
    }
    let executable = std::env::current_exe()
        .and_then(|path| path.canonicalize())
        .map_err(|_| Failure::unavailable())?;
    let install = executable
        .parent()
        .ok_or(Failure::unavailable())?
        .canonicalize()
        .map_err(|_| Failure::unavailable())?;
    if executable.parent() != Some(install.as_path()) {
        return Err(Failure::identity());
    }
    let binding = current_service_binding(&profile, &executable)?;
    #[cfg(target_os = "macos")]
    let mac_admin_install = matches!(
        lomi_platform::service_macos::lookup_admin_host_identity_binding(&profile, &executable)
            .map_err(|_| Failure::identity())?,
        lomi_platform::service_macos::AdminHostIdentityLookup::Present(_)
    );
    #[cfg(not(target_os = "macos"))]
    let mac_admin_install = false;
    #[cfg(windows)]
    let windows_admin_install =
        binding.mode == lomi_platform::service_observation::ServiceMode::Boot;
    #[cfg(not(windows))]
    let windows_admin_install = false;
    if mac_admin_install {
        #[cfg(target_os = "macos")]
        lomi_update_trust::validate_admin_boot_install_directory(&install)
            .map_err(|_| Failure::identity())?;
    } else if windows_admin_install {
        #[cfg(windows)]
        {
            let lomi_platform::service_observation::ServiceAccount::Windows { name, .. } =
                &binding.account
            else {
                return Err(Failure::identity());
            };
            let trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
                .map_err(|_| Failure::identity())?;
            let protected_install = trust
                .admin_host_install_path()
                .map_err(|_| Failure::identity())?;
            if protected_install != install {
                return Err(Failure::identity());
            }
        }
    } else {
        lomi_update_trust::validate_install_directory(&install).map_err(|_| Failure::identity())?;
    }

    let inspection = lomi_host::inspect_setup(&profile);
    let inspected_identity = match &inspection {
        lomi_host::SetupInspection::Ready(observation) => Some(Identity {
            host: observation.identity.host_id,
            profile: observation.identity.profile_id,
        }),
        lomi_host::SetupInspection::OwnerRunning => None,
        lomi_host::SetupInspection::NeedsRecovery => {
            match lomi_host::inspect_maintenance_profile(&profile) {
                Ok(observation) => Some(Identity {
                    host: observation.identity.host_id,
                    profile: observation.identity.profile_id,
                }),
                Err(lomi_host::ProfilePurgeError::Busy) => None,
                Err(_) => return Err(Failure::uncertain()),
            }
        }
        _ => return Err(Failure::unavailable()),
    };
    if binding.profile != profile
        || binding
            .executable
            .canonicalize()
            .ok()
            .and_then(|path| path.parent().map(Path::to_path_buf))
            .as_deref()
            != Some(install.as_path())
    {
        return Err(Failure::identity());
    }
    let service = lomi_platform::service_observation::inspect(&binding);
    if matches!(
        service.registration,
        lomi_platform::service_observation::RegistrationState::Invalid
            | lomi_platform::service_observation::RegistrationState::Unavailable
    ) || service.binding != lomi_platform::service_observation::BindingState::Matches
    {
        return Err(Failure::identity());
    }

    let live = connect(&profile).ok();
    let (identity, active_terminals, host_running) = match live {
        Some(mut client) => {
            let discovery = client.discovery().clone();
            if inspected_identity.is_some_and(|current| {
                current.host != discovery.host_id || current.profile != discovery.profile_id
            }) {
                return Err(Failure::identity());
            }
            let response = client
                .request(LocalCall::MaintenancePrepare(LocalOperatorIntent {
                    operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
                }))
                .map_err(|_| Failure::unavailable())?;
            let LocalResult::MaintenanceStatus(maintenance) =
                response.result.map_err(|_| Failure::unavailable())?
            else {
                return Err(Failure::unavailable());
            };
            if maintenance.host_id != discovery.host_id
                || maintenance.runtime_id != discovery.runtime_id
            {
                return Err(Failure::identity());
            }
            (
                Identity {
                    host: discovery.host_id,
                    profile: discovery.profile_id,
                },
                maintenance.active_terminals.0,
                true,
            )
        }
        None => {
            if matches!(&inspection, lomi_host::SetupInspection::OwnerRunning)
                || (matches!(&inspection, lomi_host::SetupInspection::NeedsRecovery)
                    && inspected_identity.is_none())
            {
                return Err(Failure::unavailable());
            }
            (inspected_identity.ok_or(Failure::unavailable())?, 0, false)
        }
    };
    Ok(Context {
        profile,
        install,
        executable,
        identity,
        active_terminals,
        host_running,
        binding,
        service,
        #[cfg(windows)]
        owner_outcome: None,
    })
}

fn current_service_binding(
    profile: &Path,
    executable: &Path,
) -> Result<lomi_platform::service_observation::ServiceBinding, Failure> {
    #[cfg(target_os = "macos")]
    if lomi_platform::service_macos::is_administrator() {
        use lomi_platform::service_macos::{AdminHostIdentityLookup, AdminHostMode};
        if let AdminHostIdentityLookup::Present(admin) =
            lomi_platform::service_macos::lookup_admin_host_identity_binding(profile, executable)
                .map_err(|_| Failure::identity())?
        {
            let selected = lomi_platform::setup_context::select_unix_account(admin.account())
                .map_err(|_| Failure::identity())?;
            let account = selected.unix().ok_or(Failure::identity())?;
            if account.uid() != admin.account_uid() {
                return Err(Failure::identity());
            }
            let mode = match admin.mode() {
                AdminHostMode::Manual => lomi_platform::service_observation::ServiceMode::Manual,
                AdminHostMode::Login => lomi_platform::service_observation::ServiceMode::Login,
                AdminHostMode::Boot => lomi_platform::service_observation::ServiceMode::Boot,
            };
            return Ok(lomi_platform::service_observation::ServiceBinding {
                account: lomi_platform::service_observation::ServiceAccount::Unix {
                    uid: account.uid(),
                    gid: account.gid(),
                    name: account.name().to_owned(),
                },
                mode,
                profile: profile.to_path_buf(),
                executable: executable.to_path_buf(),
            });
        }
    }
    lomi_platform::service_observation::current_binding(
        profile,
        executable,
        lomi_platform::service_observation::ServiceMode::Manual,
    )
    .map_err(|_| Failure::identity())
}

fn connect(profile: &Path) -> Result<LocalClient, Failure> {
    #[cfg(target_os = "macos")]
    {
        return crate::terminal_commands::connect_installed_macos_host(profile)
            .map_err(|_| Failure::unavailable());
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        return LocalClient::connect(profile).map_err(|_| Failure::unavailable());
    }
    #[cfg(windows)]
    {
        LocalClient::connect(profile).map_err(|_| Failure::unavailable())
    }
}

fn confirm_and_wait(explicit: bool, action: &str, active_terminals: u64) -> Result<(), Failure> {
    let interactive = io::stdin().is_terminal() && io::stdout().is_terminal();
    if !explicit {
        if !interactive {
            return Err(Failure {
                code: "CONFIRMATION_REQUIRED",
                exit: 2,
            });
        }
        eprint!("Confirm {action} of this Lomi Remote installation? [y/N] ");
        io::stderr().flush().map_err(|_| Failure::unavailable())?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|_| Failure::unavailable())?;
        if !matches!(answer.trim(), "y" | "Y" | "yes" | "YES") {
            return Err(Failure {
                code: "MAINTENANCE_CANCELLED",
                exit: 2,
            });
        }
    }
    if interactive {
        eprintln!(
            "Lomi Remote {action} will stop the Host. Active terminals: {active_terminals}. Save your work; continuing in {} seconds. Press Ctrl-C to cancel.",
            GRACE.as_secs()
        );
    }
    thread::sleep(GRACE);
    Ok(())
}

fn update(context: &Context, expected_version: Option<&str>) -> Result<(), Failure> {
    recover_if_pending(context)?;
    let context = revalidate_refreshed_context(context, prepare_context(&context.profile)?)?;
    update_after_recovery(&context, expected_version)
}

fn revalidate_refreshed_context(expected: &Context, observed: Context) -> Result<Context, Failure> {
    if observed.identity.host != expected.identity.host
        || observed.identity.profile != expected.identity.profile
        || observed.profile != expected.profile
        || observed.install != expected.install
        || observed.executable != expected.executable
        || observed.binding != expected.binding
    {
        return Err(Failure::identity());
    }
    Ok(observed)
}

fn update_after_recovery(context: &Context, expected_version: Option<&str>) -> Result<(), Failure> {
    #[cfg(target_os = "macos")]
    if let Some(binding) = macos_admin_binding(context)? {
        let mut trust =
            lomi_update_trust::TrustStore::open_embedded(&context.install.join("trust"))
                .map_err(|_| Failure::identity())?;
        trust
            .install_release_admin_host_https_pinned_blocking(
                crate::bootstrap::maintenance_release_pins()
                    .ok_or(Failure::unavailable())?
                    .origin,
                crate::bootstrap::maintenance_release_pins()
                    .ok_or(Failure::unavailable())?
                    .primary_target,
                &context.profile,
                &context.install,
                current_platform(),
                None,
                binding.account(),
                binding.mode(),
                expected_version,
            )
            .map_err(|_| Failure::uncertain())?;
        return Ok(());
    }

    #[cfg(windows)]
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Boot {
        let lomi_platform::service_observation::ServiceAccount::Windows { name, .. } =
            &context.binding.account
        else {
            return Err(Failure::identity());
        };
        let pins = crate::bootstrap::maintenance_release_pins().ok_or(Failure::unavailable())?;
        let mut trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
            .map_err(|_| Failure::identity())?;
        trust
            .install_or_update_admin_host_service_https_pinned_blocking(
                pins.origin,
                pins.primary_target,
                pins.helper_target.ok_or(Failure::identity())?,
                pins.platform,
                name,
                None,
                expected_version,
            )
            .map_err(|_| Failure::uncertain())?;
        return Ok(());
    }

    #[cfg(not(target_os = "macos"))]
    stop_if_running(context)?;
    #[cfg(target_os = "macos")]
    if macos_admin_binding(context)?.is_none() {
        stop_if_running(context)?;
    }

    let result = install_public_release(context, expected_version);
    match result {
        Ok(()) => {
            #[cfg(not(target_os = "macos"))]
            if restore_if_was_running(context).is_err() {
                return rollback_after_failed_health(context);
            }
            #[cfg(target_os = "macos")]
            if macos_admin_binding(context)?.is_none() && restore_if_was_running(context).is_err() {
                return rollback_after_failed_health(context);
            }
            Ok(())
        }
        Err(error) => {
            if !release_recovery_pending(context)? {
                #[cfg(not(target_os = "macos"))]
                let _ = restore_if_was_running(context);
                #[cfg(target_os = "macos")]
                if macos_admin_binding(context)?.is_none() {
                    let _ = restore_if_was_running(context);
                }
            }
            Err(error)
        }
    }
}

fn rollback_after_failed_health(context: &Context) -> Result<(), Failure> {
    let recovery_required = Failure {
        code: "UPDATE_HEALTH_CHECK_FAILED_RECOVERY_REQUIRED",
        exit: 7,
    };
    // A failed readiness call can leave a child/service partially running.
    // Do not replace its executable until the native owner barrier proves
    // that the exact profile is stopped. No logout/consent reset is involved.
    stop_and_observe_generic_host(context).map_err(|_| recovery_required)?;
    let trust = lomi_update_trust::TrustStore::open_embedded(&context.install.join("trust"))
        .map_err(|_| recovery_required)?;
    #[cfg(windows)]
    let rollback = trust.rollback_activation_pair_auto_schema(
        &context.profile,
        &context.install,
        current_platform(),
    );
    #[cfg(unix)]
    let rollback = trust.rollback_activation_auto_schema(
        &context.profile,
        &context.install,
        current_platform(),
    );
    // This checks the actual schema under the owner lock against the signed
    // prior target. An incompatible migration is never silently downgraded.
    rollback.map_err(|_| recovery_required)?;
    if restore_if_was_running(context).is_err() {
        let _ = stop_and_observe_generic_host(context);
        return Err(recovery_required);
    }
    Err(Failure {
        code: "UPDATE_HEALTH_CHECK_FAILED_ROLLED_BACK",
        exit: 7,
    })
}

/// Stop a partial or ready ordinary Host, then positively observe the actual
/// existing profile under its native owner lock. Endpoint disappearance alone
/// is not proof that cleanup and the owner lifetime have finished.
fn stop_and_observe_generic_host(
    context: &Context,
) -> Result<lomi_host::MaintenanceProfileObservation, Failure> {
    use lomi_platform::service_observation::{RuntimeState, ServiceAction, ServiceMode};
    if context.binding.mode == ServiceMode::Manual {
        match lomi_host::inspect_maintenance_profile(&context.profile) {
            Ok(observation) => return validate_stopped_observation(context, observation),
            Err(lomi_host::ProfilePurgeError::Busy) => {
                let client = connect(&context.profile)?;
                if client.discovery().host_id != context.identity.host
                    || client.discovery().profile_id != context.identity.profile
                {
                    return Err(Failure::identity());
                }
                drop(client);
                lomi_host::stop_bound(&context.profile, context.identity.host)
                    .map_err(|_| Failure::uncertain())?;
            }
            Err(_) => return Err(Failure::uncertain()),
        }
    } else {
        let observation =
            lomi_platform::service_observation::control(&context.binding, ServiceAction::Stop)
                .map_err(|_| Failure::uncertain())?;
        if observation.runtime != RuntimeState::Stopped {
            return Err(Failure::uncertain());
        }
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match lomi_host::inspect_maintenance_profile(&context.profile) {
            Ok(observation) => return validate_stopped_observation(context, observation),
            Err(lomi_host::ProfilePurgeError::Busy) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return Err(Failure::uncertain()),
        }
    }
}

fn validate_stopped_observation(
    context: &Context,
    observation: lomi_host::MaintenanceProfileObservation,
) -> Result<lomi_host::MaintenanceProfileObservation, Failure> {
    if observation.identity.host_id != context.identity.host
        || observation.identity.profile_id != context.identity.profile
    {
        return Err(Failure::identity());
    }
    Ok(observation)
}

fn install_public_release(
    context: &Context,
    expected_version: Option<&str>,
) -> Result<(), Failure> {
    let pins = crate::bootstrap::maintenance_release_pins().ok_or(Failure::unavailable())?;
    let mut trust = lomi_update_trust::TrustStore::open_embedded(&context.install.join("trust"))
        .map_err(|_| Failure::identity())?;
    #[cfg(windows)]
    {
        let helper = pins.helper_target.ok_or(Failure::identity())?;
        trust
            .install_release_pair_https_pinned_auto_schema_blocking(
                pins.origin,
                pins.primary_target,
                helper,
                &context.profile,
                &context.install,
                pins.platform,
                expected_version,
            )
            .map_err(|_| Failure::uncertain())?;
    }
    #[cfg(not(windows))]
    {
        trust
            .install_release_https_pinned_auto_schema_blocking(
                pins.origin,
                pins.primary_target,
                &context.profile,
                &context.install,
                pins.platform,
                expected_version,
            )
            .map_err(|_| Failure::uncertain())?;
    }
    Ok(())
}

fn stop_if_running(context: &Context) -> Result<(), Failure> {
    if !context.host_running {
        return Ok(());
    }
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        lomi_host::stop_bound(&context.profile, context.identity.host)
            .map_err(|_| Failure::uncertain())
    } else {
        let stopped = lomi_platform::service_observation::control(
            &context.binding,
            lomi_platform::service_observation::ServiceAction::Stop,
        )
        .map_err(|_| Failure::uncertain())?;
        if stopped.runtime != lomi_platform::service_observation::RuntimeState::Stopped {
            return Err(Failure::uncertain());
        }
        Ok(())
    }
}

fn restore_if_was_running(context: &Context) -> Result<(), Failure> {
    if !context.host_running {
        return Ok(());
    }
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        lomi_host::start_identity_bound(
            &context.executable,
            &context.profile,
            &lomi_host_store_identity(context),
        )
        .map_err(|_| Failure::uncertain())
    } else {
        let started = lomi_platform::service_observation::control(
            &context.binding,
            lomi_platform::service_observation::ServiceAction::Start,
        )
        .map_err(|_| Failure::uncertain())?;
        if started.runtime != lomi_platform::service_observation::RuntimeState::Running {
            return Err(Failure::uncertain());
        }
        verify_started_identity(context)
    }
}

fn verify_started_identity(context: &Context) -> Result<(), Failure> {
    let client = wait_connect(&context.profile)?;
    let discovery = client.discovery();
    if discovery.host_id != context.identity.host
        || discovery.profile_id != context.identity.profile
    {
        return Err(Failure::identity());
    }
    Ok(())
}

fn lomi_host_store_identity(context: &Context) -> lomi_host::Identity {
    lomi_host::Identity {
        host_id: context.identity.host,
        profile_id: context.identity.profile,
    }
}

fn uninstall(context: &Context, purge: bool) -> Result<(), Failure> {
    let revocation_pending = fence_and_stop_for_uninstall(context)?;
    recover_if_pending(context)?;
    let context = revalidate_refreshed_context(context, prepare_context(&context.profile)?)?;
    uninstall_after_recovery(&context, purge, Some(revocation_pending))
}

fn fence_and_stop_for_uninstall(context: &Context) -> Result<bool, Failure> {
    let revocation_pending = revoke_host(context)?;
    if context.host_running {
        stop_if_running(context)?;
    }
    Ok(revocation_pending)
}

fn uninstall_after_recovery(
    context: &Context,
    purge: bool,
    preflight_revocation_pending: Option<bool>,
) -> Result<(), Failure> {
    let operation_id =
        OperationId::from_bytes(*Uuid::new_v4().as_bytes()).map_err(|_| Failure::unavailable())?;
    #[cfg(windows)]
    let owner_outcome = context.owner_outcome;
    #[cfg(not(windows))]
    let owner_outcome: Option<()> = None;
    let mut revocation_pending = match preflight_revocation_pending {
        Some(pending) => pending,
        None => {
            #[cfg(windows)]
            if let Some(outcome) = owner_outcome {
                outcome == lomi_platform::windows::maintenance::OwnerOutcome::RevocationPending
            } else {
                revoke_host(context)?
            }
            #[cfg(not(windows))]
            {
                let _ = owner_outcome;
                revoke_host(context)?
            }
        }
    };
    #[cfg(not(target_os = "macos"))]
    stop_if_running(context)?;
    #[cfg(target_os = "macos")]
    if macos_admin_binding(context)?.is_none() {
        stop_if_running(context)?;
    }

    // The stopped/crash path first persisted a local fence, then recovered
    // activation without starting through its barrier. Only now may a bounded
    // temporary runtime settle that existing revoke. Boot Windows uses its
    // separately selected-owner worker instead of accessing private storage
    // from this administrator coordinator.
    #[cfg(windows)]
    if owner_outcome.is_none() {
        revocation_pending = settle_stopped_revoke(context)?;
    }
    #[cfg(not(windows))]
    if {
        #[cfg(target_os = "macos")]
        {
            macos_admin_binding(context)?.is_none()
        }
        #[cfg(not(target_os = "macos"))]
        {
            true
        }
    } {
        revocation_pending = settle_stopped_revoke(context)?;
    }

    #[cfg(windows)]
    match owner_outcome {
        Some(lomi_platform::windows::maintenance::OwnerOutcome::CleanupUncertain) => {
            return Err(Failure {
                code: "PURGE_CLEANUP_UNCERTAIN",
                exit: 7,
            });
        }
        Some(
            lomi_platform::windows::maintenance::OwnerOutcome::Pending
            | lomi_platform::windows::maintenance::OwnerOutcome::NotRequired,
        ) => return Err(Failure::uncertain()),
        _ => {}
    }

    if purge && !revocation_pending {
        #[cfg(windows)]
        match owner_outcome {
            Some(lomi_platform::windows::maintenance::OwnerOutcome::Complete) => {}
            Some(lomi_platform::windows::maintenance::OwnerOutcome::RevocationPending) => {
                return Err(Failure {
                    code: "PURGE_INCOMPLETE_REVOCATION_PENDING",
                    exit: 7,
                });
            }
            Some(lomi_platform::windows::maintenance::OwnerOutcome::Pending)
            | Some(lomi_platform::windows::maintenance::OwnerOutcome::NotRequired) => {
                return Err(Failure::uncertain());
            }
            None => {
                revocation_pending |= purge_profile(context, operation_id)?;
            }
        }
        #[cfg(not(windows))]
        {
            revocation_pending |= purge_profile(context, operation_id)?;
        }
    }

    #[cfg(target_os = "macos")]
    if let Some(binding) = macos_admin_binding(context)? {
        lomi_update_trust::uninstall_admin_host_release(
            &context.profile,
            &context.install,
            binding.account(),
            binding.mode(),
        )
        .map_err(|_| Failure::uncertain())?;
    } else {
        uninstall_generic(context)?;
    }
    #[cfg(not(target_os = "macos"))]
    uninstall_generic(context)?;

    if purge {
        if revocation_pending {
            return Err(Failure {
                code: "PURGE_INCOMPLETE_REVOCATION_PENDING",
                exit: 7,
            });
        }
        // The requested purge has already completed before the service or
        // release image is removed.
    }
    if revocation_pending {
        return Err(Failure {
            code: "UNINSTALL_REVOCATION_PENDING",
            exit: 7,
        });
    }
    Ok(())
}

fn settle_stopped_revoke(context: &Context) -> Result<bool, Failure> {
    stop_and_observe_generic_host(context)?;
    // This is the idempotent local fence, not another Logout request. It also
    // cancels a login intent that could have been saved before a crash.
    let fence = lomi_host::fence_maintenance_profile(
        &context.profile,
        context.identity.host,
        context.identity.profile,
    )
    .map_err(|_| Failure::uncertain())?;
    validate_stopped_observation(context, fence.clone())?;
    if !fence.remote_locked {
        return Err(Failure::uncertain());
    }
    if !fence.pending_cloud_revoke {
        return Ok(false);
    }

    let start = if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        lomi_host::start_identity_bound(
            &context.executable,
            &context.profile,
            &lomi_host_store_identity(context),
        )
        .map_err(|_| ())
    } else {
        lomi_platform::service_observation::control(
            &context.binding,
            lomi_platform::service_observation::ServiceAction::Start,
        )
        .map_err(|_| ())
        .and_then(|status| {
            (status.runtime == lomi_platform::service_observation::RuntimeState::Running)
                .then_some(())
                .ok_or(())
        })
    };
    if start.is_ok() {
        if let Ok(mut client) = connect(&context.profile) {
            let deadline = Instant::now() + LOGOUT_ACK_TIMEOUT;
            // No repeat of Logout, creation of login intent, or sharing consent.
            // Even if the ACK response is lost, the final stopped Store read
            // below can prove it without resubmitting a mutation.
            let _ = wait_for_logout_ack(
                &mut client,
                context.identity,
                fence.authorization_generation,
                deadline,
            );
        }
    }
    // This executes on every post-start path, including failed readiness.
    stop_and_observe_generic_host(context)?;
    // A local operator could have begun a fresh login after the ACK but
    // before the temporary runtime stopped. Cancel that distinct intent and
    // retain its revoke obligation, without starting another worker/replay.
    let observed = lomi_host::fence_maintenance_profile(
        &context.profile,
        context.identity.host,
        context.identity.profile,
    )
    .map_err(|_| Failure::uncertain())?;
    let observed = validate_stopped_observation(context, observed)?;
    if !observed.remote_locked {
        return Err(Failure::uncertain());
    }
    Ok(observed.pending_cloud_revoke)
}

fn revoke_host(context: &Context) -> Result<bool, Failure> {
    if !context.host_running {
        match lomi_host::fence_maintenance_profile(
            &context.profile,
            context.identity.host,
            context.identity.profile,
        ) {
            Ok(observation) => {
                if observation.identity.host_id != context.identity.host
                    || observation.identity.profile_id != context.identity.profile
                    || !observation.remote_locked
                {
                    return Err(Failure::identity());
                }
                return Ok(observation.pending_cloud_revoke);
            }
            Err(lomi_host::ProfilePurgeError::Busy) => {
                // A live Host may have acquired the owner lock after service
                // observation. Query that exact runtime over authenticated
                // IPC; never start a replacement without its logout fence.
                return revoke_host_live(context, true);
            }
            Err(_) => return Err(Failure::uncertain()),
        }
    }
    revoke_host_live(context, false)
}

fn revoke_host_live(context: &Context, stop_after: bool) -> Result<bool, Failure> {
    let mut client = connect(&context.profile)?;
    let discovery = client.discovery().clone();
    if discovery.host_id != context.identity.host
        || discovery.profile_id != context.identity.profile
    {
        return Err(Failure::identity());
    }
    let deadline = Instant::now() + LOGOUT_ACK_TIMEOUT;
    let response = request_before_deadline(
        &mut client,
        LocalCall::Logout(LocalOperatorIntent {
            operator_intent: lomi_remote_protocol::rpc::Confirmed::Confirmed,
        }),
        deadline,
    )
    .map_err(|_| Failure::uncertain())?;
    let LocalResult::LoginStatus(status) = response.result.map_err(|_| Failure::uncertain())?
    else {
        return Err(Failure::uncertain());
    };
    if !status.locked {
        return Err(Failure::uncertain());
    }
    let pending = status.pending_cloud_revoke
        && !wait_for_logout_ack(&mut client, context.identity, status.generation.0, deadline);
    drop(client);
    if stop_after {
        stop_if_running(&Context {
            host_running: true,
            service: context.service.clone(),
            #[cfg(windows)]
            owner_outcome: context.owner_outcome,
            ..clone_context(context)
        })?;
    }
    Ok(pending)
}

fn request_before_deadline(
    client: &mut LocalClient,
    call: LocalCall,
    deadline: Instant,
) -> Result<LocalResponse, ()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(());
    }
    #[cfg(windows)]
    {
        client.request_with_timeout(call, remaining).map_err(|_| ())
    }
    #[cfg(unix)]
    {
        if remaining < lomi_platform::unix::REQUEST_TIMEOUT {
            return Err(());
        }
        client.request(call).map_err(|_| ())
    }
}

/// Poll only the read-only status call after the single committed Logout.
/// A timeout or identity/generation change remains pending; it never repeats
/// Logout or treats a lost response as cloud acknowledgment.
fn wait_for_logout_ack(
    client: &mut LocalClient,
    identity: Identity,
    generation: u64,
    deadline: Instant,
) -> bool {
    loop {
        if Instant::now() >= deadline {
            return false;
        }
        let response = match request_before_deadline(client, LocalCall::LoginStatus {}, deadline) {
            Ok(response) => response,
            Err(()) => return false,
        };
        if response.result.is_err() {
            return false;
        }
        let Ok(LocalResult::LoginStatus(status)) = response.result else {
            return false;
        };
        let discovery = client.discovery();
        if discovery.host_id != identity.host
            || discovery.profile_id != identity.profile
            || status.generation.0 != generation
            || !status.locked
        {
            return false;
        }
        if !status.pending_cloud_revoke {
            return true;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return false;
        }
        thread::sleep(LOGOUT_ACK_POLL_INTERVAL.min(remaining));
    }
}

fn purge_profile(context: &Context, operation_id: OperationId) -> Result<bool, Failure> {
    match lomi_host::purge_host_profile(
        &context.profile,
        context.identity.host,
        context.identity.profile,
        operation_id,
    )
    .map_err(|_| Failure::uncertain())?
    {
        lomi_host::ProfilePurgeOutcome::Complete => Ok(false),
        lomi_host::ProfilePurgeOutcome::RevocationPending => Ok(true),
        lomi_host::ProfilePurgeOutcome::CleanupUncertain => Err(Failure {
            code: "PURGE_CLEANUP_UNCERTAIN",
            exit: 7,
        }),
    }
}

fn clone_context(context: &Context) -> Context {
    Context {
        profile: context.profile.clone(),
        install: context.install.clone(),
        executable: context.executable.clone(),
        identity: context.identity,
        active_terminals: context.active_terminals,
        host_running: context.host_running,
        binding: context.binding.clone(),
        service: context.service.clone(),
        #[cfg(windows)]
        owner_outcome: context.owner_outcome,
    }
}

fn wait_connect(profile: &Path) -> Result<LocalClient, Failure> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(client) = connect(profile) {
            return Ok(client);
        }
        if std::time::Instant::now() >= deadline {
            return Err(Failure::uncertain());
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn uninstall_generic(context: &Context) -> Result<(), Failure> {
    #[cfg(windows)]
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Boot {
        let lomi_platform::service_observation::ServiceAccount::Windows { name, .. } =
            &context.binding.account
        else {
            return Err(Failure::identity());
        };
        let mut trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
            .map_err(|_| Failure::identity())?;
        trust
            .uninstall_admin_host_service(name)
            .map_err(|_| Failure::uncertain())?;
        return Ok(());
    }
    if context.binding.mode != lomi_platform::service_observation::ServiceMode::Manual
        && context.service.registration
            == lomi_platform::service_observation::RegistrationState::Present
    {
        lomi_platform::service_observation::control(
            &context.binding,
            lomi_platform::service_observation::ServiceAction::Uninstall,
        )
        .map_err(|_| Failure::uncertain())?;
    }
    lomi_update_trust::uninstall_release(&context.profile, &context.install)
        .map_err(|_| Failure::uncertain())?;
    Ok(())
}

fn release_recovery_pending(context: &Context) -> Result<bool, Failure> {
    #[cfg(target_os = "macos")]
    if macos_admin_binding(context)?.is_some() {
        return lomi_update_trust::admin_host_release_recovery_pending(&context.install)
            .map_err(|_| Failure::identity());
    }
    #[cfg(windows)]
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Boot {
        let lomi_platform::service_observation::ServiceAccount::Windows { name, .. } =
            &context.binding.account
        else {
            return Err(Failure::identity());
        };
        let trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
            .map_err(|_| Failure::identity())?;
        let activation_pending = trust
            .admin_host_activation_recovery_pending()
            .map_err(|_| Failure::identity())?;
        let service_pending = lomi_platform::windows::service_admin::inspect(name)
            .map_err(|_| Failure::identity())?
            .is_some_and(|status| {
                status.phase == "updating"
                    || (status.phase == "starting" && status.resume_after_update)
            });
        return Ok(activation_pending || service_pending);
    }
    lomi_update_trust::release_recovery_pending(&context.install).map_err(|_| Failure::identity())
}

fn recover_if_pending(context: &Context) -> Result<(), Failure> {
    #[cfg(windows)]
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Boot {
        let lomi_platform::service_observation::ServiceAccount::Windows { name, .. } =
            &context.binding.account
        else {
            return Err(Failure::identity());
        };
        let pins = crate::bootstrap::maintenance_release_pins().ok_or(Failure::unavailable())?;
        let mut trust = lomi_update_trust::TrustStore::open_admin_host_for_account(name)
            .map_err(|_| Failure::identity())?;
        trust
            .recover_admin_host_maintenance(name, pins.platform)
            .map_err(|_| Failure::uncertain())?;
        return Ok(());
    }
    if !release_recovery_pending(context)? {
        return Ok(());
    }
    let pins = crate::bootstrap::maintenance_release_pins().ok_or(Failure::unavailable())?;
    #[cfg(target_os = "macos")]
    if let Some(binding) = macos_admin_binding(context)? {
        lomi_update_trust::recover_interrupted_admin_host_release(
            &context.profile,
            &context.install,
            pins.platform,
            binding.account(),
            binding.mode(),
        )
        .map_err(|_| Failure::uncertain())?;
        return Ok(());
    }
    lomi_update_trust::recover_interrupted_release(
        &context.profile,
        &context.install,
        pins.platform,
    )
    .map_err(|_| Failure::uncertain())?;
    Ok(())
}

fn report_result(result: Result<(), Failure>, operation: &str, version: &str, json: bool) -> u8 {
    match result {
        Ok(()) => {
            if json {
                let value = serde_json::json!({
                    "version": LocalIpcVersion::CURRENT,
                    "operation": operation,
                    "state": "completed",
                    "releaseVersion": if version.is_empty() { None } else { Some(version) },
                });
                if serde_json::to_writer(io::stdout().lock(), &value).is_err() {
                    return 4;
                }
                println!();
            } else {
                println!("Lomi Remote {operation} completed.");
            }
            0
        }
        Err(error) => report(error, json),
    }
}

fn report(error: Failure, json: bool) -> u8 {
    if json {
        let value = serde_json::json!({
            "version": LocalIpcVersion::CURRENT,
            "error": { "code": error.code },
        });
        if serde_json::to_writer(io::stdout().lock(), &value).is_err() {
            return 4;
        }
        println!();
    }
    eprintln!("{}", error.code);
    if matches!(
        error.code,
        "UNINSTALL_REVOCATION_PENDING" | "PURGE_INCOMPLETE_REVOCATION_PENDING"
    ) {
        eprintln!(
            "The Host was fenced locally and the pending cloud revoke was retained. Revoke this Host from the account controls. After acknowledgment, obtain and verify the signed Lomi Remote bundle, reinstall it for this Host profile, then run `lomiremote uninstall --purge --confirm` to finish local cleanup."
        );
    }
    if error.code == "UPDATE_HEALTH_CHECK_FAILED_RECOVERY_REQUIRED" {
        eprintln!(
            "A healthy Host could not be confirmed. Keep this profile, its migration backups and update trust state. Recover with a verified signed release compatible with the current database schema. If a domain backup must be restored, first confirm the Host is stopped and follow the checked domain-restore procedure; do not copy an older database over current authorization or update trust state."
        );
    }
    if error.code == "UPDATE_HEALTH_CHECK_FAILED_ROLLED_BACK" {
        eprintln!(
            "The new Host failed readiness. The previous signed, schema-compatible release was restored and its prior running state was confirmed."
        );
    }
    error.exit
}

fn current_platform() -> &'static str {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    return "linux-x86_64";
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    return "linux-aarch64";
    #[cfg(all(target_os = "macos", target_arch = "x86_64"))]
    return "macos-x86_64";
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    return "macos-aarch64";
    #[cfg(all(windows, target_arch = "x86_64"))]
    return "windows-x86_64";
    #[cfg(all(windows, target_arch = "aarch64"))]
    return "windows-aarch64";
    #[allow(unreachable_code)]
    "unsupported"
}

#[cfg(target_os = "macos")]
fn macos_admin_binding(
    context: &Context,
) -> Result<Option<lomi_platform::service_macos::AdminHostIdentityBinding>, Failure> {
    use lomi_platform::service_macos::AdminHostIdentityLookup;
    match lomi_platform::service_macos::lookup_admin_host_identity_binding(
        &context.profile,
        &context.executable,
    )
    .map_err(|_| Failure::identity())?
    {
        AdminHostIdentityLookup::NotManaged => Ok(None),
        AdminHostIdentityLookup::Missing => Err(Failure::identity()),
        AdminHostIdentityLookup::Present(binding) => {
            if binding.profile() != context.profile
                || binding.host_id() != context.identity.host
                || binding.profile_id() != context.identity.profile
            {
                return Err(Failure::identity());
            }
            Ok(Some(binding))
        }
    }
}

#[cfg(target_os = "macos")]
fn maybe_handoff_macos(
    context: &Context,
    action: Action,
    version: Option<&str>,
    purge: bool,
) -> Result<Option<u8>, Failure> {
    let Some(_binding) = macos_admin_binding(context)? else {
        return Ok(None);
    };
    if lomi_platform::service_macos::is_administrator() {
        return Ok(None);
    }
    let executable = context.executable.as_os_str();
    let mut command = std::process::Command::new("/usr/bin/sudo");
    command
        .arg("-H")
        .arg("--")
        .arg(executable)
        .arg("--internal-maintenance-macos-v1")
        .arg(match action {
            Action::Update => "update",
            Action::Uninstall => "uninstall",
        })
        .arg(&context.profile);
    if let Some(version) = version {
        command.arg(version);
    }
    if purge {
        command.arg("purge");
    }
    let status = command.status().map_err(|_| Failure::unavailable())?;
    Ok(Some(
        status
            .code()
            .and_then(|code| u8::try_from(code).ok())
            .unwrap_or(7),
    ))
}

#[cfg(target_os = "macos")]
fn run_macos_root_handoff(args: &[std::ffi::OsString]) -> u8 {
    if !lomi_platform::service_macos::is_administrator() {
        return 5;
    }
    let Some(action) = args.first().and_then(|value| value.to_str()) else {
        return 2;
    };
    if !matches!(action, "update" | "uninstall") || args.len() != 12 {
        return 2;
    }
    let json = match args[11].to_str() {
        Some("0") => false,
        Some("1") => true,
        _ => return 2,
    };
    let profile = PathBuf::from(&args[1]);
    let Some(account) = args[2].to_str() else {
        return report(Failure::invalid(), json);
    };
    let Some(mode) = args[3].to_str().and_then(parse_macos_mode_argument) else {
        return report(Failure::invalid(), json);
    };
    let Ok(expected_host) = HostId::try_from(args[4].to_string_lossy().into_owned()) else {
        return report(Failure::invalid(), json);
    };
    let Ok(expected_profile) = IpcProfileId::try_from(args[5].to_string_lossy().into_owned())
    else {
        return report(Failure::invalid(), json);
    };
    let Ok(operation_id) = OperationId::try_from(args[6].to_string_lossy().into_owned()) else {
        return report(Failure::invalid(), json);
    };
    let deadline = match macos_uninstall::Deadline::parse_absolute(&args[7].to_string_lossy()) {
        Ok(deadline) => deadline,
        Err(error) => return report(error, json),
    };
    let expected_version = match args[8].to_str() {
        Some("-") => None,
        Some(version) if !version.is_empty() => Some(version),
        _ => return report(Failure::invalid(), json),
    };
    let purge = match args[9].to_str() {
        Some("0") => false,
        Some("1") => true,
        _ => return report(Failure::invalid(), json),
    };
    let was_running = match args[10].to_str() {
        Some("0") => false,
        Some("1") => true,
        _ => return report(Failure::invalid(), json),
    };
    if (action == "update" && purge) || (action == "uninstall" && expected_version.is_some()) {
        return report(Failure::invalid(), json);
    }
    let executable = match std::env::current_exe().and_then(|path| path.canonicalize()) {
        Ok(executable) => executable,
        Err(_) => return report(Failure::identity(), json),
    };
    let binding = match macos_uninstall::read_root_binding(&profile, &executable, account, mode) {
        Ok(binding)
            if binding.host_id() == expected_host && binding.profile_id() == expected_profile =>
        {
            binding
        }
        _ => return report(Failure::identity(), json),
    };
    if lomi_update_trust::validate_admin_boot_install_directory(
        binding.executable().parent().unwrap_or(Path::new("/")),
    )
    .is_err()
    {
        return report(Failure::identity(), json);
    }
    let pins = match crate::bootstrap::maintenance_release_pins() {
        Some(pins) if pins.platform == current_platform() && pins.native_signer.is_some() => pins,
        _ => return report(Failure::unavailable(), json),
    };
    if lomi_platform::process::initialize_child_ownership().is_err() {
        return report(Failure::unavailable(), json);
    }
    let result = match action {
        "update" => run_macos_root_update(
            &binding,
            &pins,
            expected_version,
            was_running,
            operation_id,
            deadline,
        ),
        "uninstall" => {
            run_macos_root_uninstall(&binding, &pins, purge, was_running, operation_id, deadline)
        }
        _ => unreachable!(),
    };
    if action == "update" {
        report_result(
            result,
            "update",
            expected_version.unwrap_or("latest verified"),
            json,
        )
    } else {
        report_result(result, "uninstall", "", json)
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_mode_argument(value: &str) -> Option<lomi_platform::service_macos::AdminHostMode> {
    use lomi_platform::service_macos::AdminHostMode;
    match value {
        "manual" => Some(AdminHostMode::Manual),
        "login" => Some(AdminHostMode::Login),
        "boot" => Some(AdminHostMode::Boot),
        _ => None,
    }
}

#[cfg(target_os = "macos")]
fn run_macos_root_update(
    binding: &macos_uninstall::RootBinding,
    pins: &crate::bootstrap::MaintenanceReleasePins,
    expected_version: Option<&str>,
    was_running: bool,
    operation_id: OperationId,
    deadline: macos_uninstall::Deadline,
) -> Result<(), Failure> {
    let context = macos_root_context(binding)?;
    if context.binding.mode != lomi_platform::service_observation::ServiceMode::Manual {
        match (was_running, context.service.runtime) {
            (true, lomi_platform::service_observation::RuntimeState::Running)
            | (false, lomi_platform::service_observation::RuntimeState::Stopped) => {}
            _ => return Err(Failure::uncertain()),
        }
    }
    if was_running
        && context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual
    {
        let stopped = macos_uninstall::run_owner_phase_as_selected(
            binding,
            macos_uninstall::OwnerPhase::StopManualForUpdate,
            operation_id,
            deadline,
        )
        .map_err(|_| Failure::uncertain())?;
        if stopped != 0 {
            return Err(Failure::uncertain());
        }
    } else if context.binding.mode != lomi_platform::service_observation::ServiceMode::Manual {
        stop_managed_host(&context)?;
    }
    let recovery = lomi_update_trust::recover_interrupted_admin_host_release(
        &context.profile,
        &context.install,
        pins.platform,
        binding.account(),
        binding.mode(),
    );
    if context.binding.mode != lomi_platform::service_observation::ServiceMode::Manual {
        stop_managed_host(&context)?;
    }
    recovery.map_err(|_| Failure::uncertain())?;
    let mut trust = lomi_update_trust::TrustStore::open_embedded(&context.install.join("trust"))
        .map_err(|_| Failure::identity())?;
    let install_result = trust.install_release_admin_host_https_pinned_blocking(
        pins.origin,
        pins.primary_target,
        &context.profile,
        &context.install,
        pins.platform,
        None,
        binding.account(),
        binding.mode(),
        expected_version,
    );
    drop(trust);
    if install_result.is_err() {
        // An updater error after its activation boundary is uncertain. Keep
        // the Host stopped for signed recovery instead of starting an image
        // whose commit point was not reported to this caller.
        return Err(Failure::uncertain());
    }
    if was_running {
        if restore_macos_host_after_update(binding, &context, operation_id).is_err() {
            if stop_macos_host_after_update(binding, &context, operation_id).is_err() {
                return Err(update_health_recovery_required());
            }
            let rollback =
                lomi_update_trust::TrustStore::open_embedded(&context.install.join("trust"))
                    .and_then(|trust| {
                        trust.rollback_admin_host_activation(
                            &context.profile,
                            &context.install,
                            pins.platform,
                            None,
                            binding.account(),
                            binding.mode(),
                        )
                    });
            if rollback.is_err() {
                let _ = stop_macos_host_after_update(binding, &context, operation_id);
                return Err(update_health_recovery_required());
            }
            if restore_macos_host_after_update(binding, &context, operation_id).is_err() {
                let _ = stop_macos_host_after_update(binding, &context, operation_id);
                return Err(update_health_recovery_required());
            }
            return Err(Failure {
                code: "UPDATE_HEALTH_CHECK_FAILED_ROLLED_BACK",
                exit: 7,
            });
        }
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restore_macos_host_after_update(
    binding: &macos_uninstall::RootBinding,
    context: &Context,
    operation_id: OperationId,
) -> Result<(), Failure> {
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        let restore_deadline = macos_uninstall::Deadline::after(MAX_MAINTENANCE_WAIT)?;
        let result = macos_uninstall::run_owner_phase_as_selected(
            binding,
            macos_uninstall::OwnerPhase::StartManual { was_running: true },
            operation_id,
            restore_deadline,
        )
        .map_err(|_| Failure::uncertain())?;
        if result != 0 {
            return Err(Failure::uncertain());
        }
    } else {
        start_managed_host(context)?;
    }
    match macos_uninstall::health_as_selected(
        binding,
        operation_id,
        macos_uninstall::Deadline::after(MAX_MAINTENANCE_WAIT)?,
    )? {
        macos_uninstall::OwnerHealth::Running => Ok(()),
        macos_uninstall::OwnerHealth::Stopped => Err(Failure::uncertain()),
    }
}

#[cfg(target_os = "macos")]
fn stop_macos_host_after_update(
    binding: &macos_uninstall::RootBinding,
    context: &Context,
    operation_id: OperationId,
) -> Result<(), Failure> {
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        let stop_deadline = macos_uninstall::Deadline::after(MAX_MAINTENANCE_WAIT)?;
        let result = macos_uninstall::run_owner_phase_as_selected(
            binding,
            macos_uninstall::OwnerPhase::StopManualForUpdate,
            operation_id,
            stop_deadline,
        )
        .map_err(|_| Failure::uncertain())?;
        if result != 0 {
            return Err(Failure::uncertain());
        }
    } else {
        stop_managed_host(context)?;
    }
    match macos_uninstall::health_as_selected(
        binding,
        operation_id,
        macos_uninstall::Deadline::after(MAX_MAINTENANCE_WAIT)?,
    )? {
        macos_uninstall::OwnerHealth::Stopped => Ok(()),
        macos_uninstall::OwnerHealth::Running => Err(Failure::uncertain()),
    }
}

#[cfg(target_os = "macos")]
fn update_health_recovery_required() -> Failure {
    Failure {
        code: "UPDATE_HEALTH_CHECK_FAILED_RECOVERY_REQUIRED",
        exit: 7,
    }
}

#[cfg(target_os = "macos")]
fn run_macos_root_uninstall(
    binding: &macos_uninstall::RootBinding,
    pins: &crate::bootstrap::MaintenanceReleasePins,
    purge: bool,
    _was_running: bool,
    operation_id: OperationId,
    deadline: macos_uninstall::Deadline,
) -> Result<(), Failure> {
    use lomi_platform::service_observation::{RuntimeState, ServiceAction, ServiceMode};
    use macos_uninstall::OwnerPhase;

    let context = macos_root_context(binding)?;
    let phase = macos_uninstall::run_owner_phase_as_selected(
        binding,
        OwnerPhase::FenceAndLogout,
        operation_id,
        deadline,
    )
    .map_err(|_| Failure::uncertain())?;
    match phase {
        0 | 14 | 12 => {}
        _ => return Err(Failure::uncertain()),
    }

    // The fence is durable before recovery. Recover while every managed
    // runtime is stopped so an interrupted activation cannot block the
    // temporary Host used to finish a pending cloud revoke.
    if context.binding.mode != ServiceMode::Manual {
        stop_managed_host(&context)?;
    }
    lomi_update_trust::recover_interrupted_admin_host_release(
        &context.profile,
        &context.install,
        pins.platform,
        binding.account(),
        binding.mode(),
    )
    .map_err(|_| Failure::uncertain())?;
    if context.binding.mode != ServiceMode::Manual {
        stop_managed_host(&context)?;
    }

    if phase == 14 {
        if context.binding.mode == ServiceMode::Manual {
            let outcome = macos_uninstall::run_owner_phase_as_selected(
                binding,
                OwnerPhase::StartManualWaitAck,
                operation_id,
                deadline,
            )
            .map_err(|_| Failure::uncertain())?;
            match outcome {
                0 | 12 => {}
                _ => return Err(Failure::uncertain()),
            }
        } else {
            let started =
                lomi_platform::service_observation::control(&context.binding, ServiceAction::Start);
            if !matches!(
                started.as_ref().map(|status| status.runtime),
                Ok(RuntimeState::Running)
            ) {
                if stop_managed_host(&context).is_err() {
                    return Err(Failure::uncertain());
                }
                return Err(Failure::uncertain());
            }
            let outcome = macos_uninstall::run_owner_phase_as_selected(
                binding,
                OwnerPhase::WaitAck,
                operation_id,
                deadline,
            );
            stop_managed_host(&context)?;
            match outcome.map_err(|_| Failure::uncertain())? {
                0 | 12 => {}
                _ => return Err(Failure::uncertain()),
            }
        }
    }
    if context.binding.mode != ServiceMode::Manual {
        stop_managed_host(&context)?;
    }
    let final_fence =
        macos_uninstall::refence_after_ack_as_selected(binding, operation_id, deadline)
            .map_err(|_| Failure::uncertain())?;
    let revocation_pending = match final_fence {
        macos_uninstall::OwnerRefenceOutcome::Complete => false,
        macos_uninstall::OwnerRefenceOutcome::RevocationPending => true,
    };
    if purge && !revocation_pending {
        let outcome = macos_uninstall::run_owner_phase_as_selected(
            binding,
            OwnerPhase::PurgeAfterRecovery,
            operation_id,
            deadline,
        )
        .map_err(|_| Failure::uncertain())?;
        if outcome != 0 {
            return Err(Failure {
                code: if outcome == 12 {
                    "PURGE_INCOMPLETE_REVOCATION_PENDING"
                } else {
                    "PURGE_CLEANUP_UNCERTAIN"
                },
                exit: 7,
            });
        }
    }
    lomi_update_trust::uninstall_admin_host_release(
        &context.profile,
        &context.install,
        binding.account(),
        binding.mode(),
    )
    .map_err(|_| Failure::uncertain())?;
    if revocation_pending {
        Err(Failure {
            code: if purge {
                "PURGE_INCOMPLETE_REVOCATION_PENDING"
            } else {
                "UNINSTALL_REVOCATION_PENDING"
            },
            exit: 7,
        })
    } else {
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn macos_root_context(binding: &macos_uninstall::RootBinding) -> Result<Context, Failure> {
    let executable = binding.executable().to_path_buf();
    let install = executable
        .parent()
        .ok_or(Failure::identity())?
        .to_path_buf();
    let service_binding = binding.service_binding()?;
    if service_binding.profile != binding.profile() || service_binding.executable != executable {
        return Err(Failure::identity());
    }
    let service = lomi_platform::service_observation::inspect(&service_binding);
    if service.binding != lomi_platform::service_observation::BindingState::Matches
        || matches!(
            service.registration,
            lomi_platform::service_observation::RegistrationState::Invalid
                | lomi_platform::service_observation::RegistrationState::Unavailable
        )
    {
        return Err(Failure::identity());
    }
    Ok(Context {
        profile: binding.profile().to_path_buf(),
        install,
        executable,
        identity: Identity {
            host: binding.host_id(),
            profile: binding.profile_id(),
        },
        active_terminals: 0,
        host_running: service.runtime == lomi_platform::service_observation::RuntimeState::Running,
        binding: service_binding,
        service,
        #[cfg(windows)]
        owner_outcome: None,
    })
}

#[cfg(target_os = "macos")]
fn stop_managed_host(context: &Context) -> Result<(), Failure> {
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        return Err(Failure::identity());
    }
    let current = lomi_platform::service_observation::inspect(&context.binding);
    if current.binding != lomi_platform::service_observation::BindingState::Matches
        || matches!(
            current.registration,
            lomi_platform::service_observation::RegistrationState::Invalid
                | lomi_platform::service_observation::RegistrationState::Unavailable
        )
    {
        return Err(Failure::identity());
    }
    if current.runtime == lomi_platform::service_observation::RuntimeState::Stopped {
        return Ok(());
    }
    if !matches!(
        current.runtime,
        lomi_platform::service_observation::RuntimeState::Running
            | lomi_platform::service_observation::RuntimeState::Starting
    ) {
        return Err(Failure::uncertain());
    }
    let status = lomi_platform::service_observation::control(
        &context.binding,
        lomi_platform::service_observation::ServiceAction::Stop,
    )
    .map_err(|_| Failure::uncertain())?;
    if status.runtime != lomi_platform::service_observation::RuntimeState::Stopped {
        return Err(Failure::uncertain());
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn start_managed_host(context: &Context) -> Result<(), Failure> {
    if context.binding.mode == lomi_platform::service_observation::ServiceMode::Manual {
        return Err(Failure::identity());
    }
    let status = lomi_platform::service_observation::control(
        &context.binding,
        lomi_platform::service_observation::ServiceAction::Start,
    )
    .map_err(|_| Failure::uncertain())?;
    if status.runtime != lomi_platform::service_observation::RuntimeState::Running {
        return Err(Failure::uncertain());
    }
    Ok(())
}
