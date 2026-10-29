//! Pair the selected account's system Host LaunchDaemon with its root custody
//! LaunchDaemon. All lifecycle calls run under `BootMaintenanceGuard` so the
//! account owner lock and LaunchDaemon adapter lock remain pinned.

use super::{Error, Result, boot::BootMaintenanceGuard, custody};
use serde::{Deserialize, Serialize};
use std::{
    io::{self, Read},
    os::fd::AsRawFd,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const HELPER_LIMIT: usize = 16 * 1024;
const HELPER_DEADLINE: Duration = Duration::from_secs(55);
const MANAGER_DEADLINE: Duration = Duration::from_secs(10);
const ADMIN_STATUS_ARGUMENT: &str = "--internal-privileged-pty-admin-status";
const ADMIN_DRAIN_ARGUMENT: &str = "--internal-privileged-pty-admin-drain";

#[derive(Debug)]
pub(super) struct MaintenanceState {
    had_registration: bool,
    custodian_was_running: bool,
    host_was_running: bool,
    owner_uid: u32,
    profile_path: std::path::PathBuf,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminStatusResponse {
    version: u32,
    state: String,
    registration_key: String,
    request_id: String,
    runtime_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdminDrainResponse {
    version: u32,
    state: String,
    registration_key: String,
    request_id: String,
    runtime_id: String,
    drained_generation_count: u32,
    drained_set_sha256: String,
}

#[derive(Debug, Clone, Copy)]
struct JobObservation {
    running: bool,
}

/// Stop root custody admission after the account Host has already stopped.
/// The broker must positively prove every PTY generation clean before its job
/// can be booted out. An absent job is accepted only with the durable receipt
/// checked by `verify_privileged_custodian_drained`.
pub(super) fn begin_maintenance(guard: &BootMaintenanceGuard) -> Result<MaintenanceState> {
    let host_was_running = guard.service_was_running();
    let registration = custody::read_optional_privileged_custodian(guard)?;
    let Some(registration) = registration else {
        if guard.has_service_registration() || host_was_running {
            return Err(Error::Conflict);
        }
        return Ok(MaintenanceState {
            had_registration: false,
            custodian_was_running: false,
            host_was_running: false,
            owner_uid: guard.owner_uid(),
            profile_path: guard.profile_path().to_path_buf(),
        });
    };
    let observed = observe_job(&registration)?;
    let custodian_was_running = observed.is_some_and(|job| job.running);
    if host_was_running && !custodian_was_running {
        return Err(Error::Conflict);
    }
    drain_and_bootout(guard, &registration, observed)?;
    Ok(MaintenanceState {
        had_registration: true,
        custodian_was_running,
        host_was_running,
        owner_uid: guard.owner_uid(),
        profile_path: guard.profile_path().to_path_buf(),
    })
}

/// Refresh the root registration for the current verified executable. The
/// custodian and Host return only to the state appropriate for this operation.
pub(super) fn finish_maintenance(
    guard: &BootMaintenanceGuard,
    state: MaintenanceState,
) -> Result<()> {
    if guard.owner_uid() != state.owner_uid || guard.profile_path() != state.profile_path {
        return Err(Error::Conflict);
    }
    if !state.had_registration {
        if state.host_was_running {
            return Err(Error::Conflict);
        }
        return Ok(());
    }
    let registration = custody::install_privileged_custodian(guard)?;
    if state.custodian_was_running {
        start_registered(guard, &registration)?;
    } else if state.host_was_running {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// Explicit service installation creates and starts root custody before the
/// selected-account Host registration can be started.
pub(super) fn install_and_start(guard: &BootMaintenanceGuard) -> Result<()> {
    match custody::read_optional_privileged_custodian(guard)? {
        Some(registration) => {
            let observed = observe_job(&registration)?;
            drain_and_bootout(guard, &registration, observed)?;
        }
        None if guard.has_service_registration() => return Err(Error::Conflict),
        None => {}
    }
    let registration = custody::install_privileged_custodian(guard)?;
    start_registered(guard, &registration)
}

/// Ensure the root broker is ready before the account Host is bootstrapped.
pub(super) fn ensure_ready_for_host(guard: &BootMaintenanceGuard) -> Result<()> {
    let registration =
        custody::read_optional_privileged_custodian(guard)?.ok_or(Error::Conflict)?;
    custody::validate_privileged_custodian(guard, &registration)?;
    start_registered(guard, &registration)
}

/// Drain and remove only the matching custody registration after the selected
/// account Host has stopped.
pub(super) fn uninstall(guard: &BootMaintenanceGuard) -> Result<()> {
    let Some(registration) = custody::read_optional_privileged_custodian(guard)? else {
        if guard.has_service_registration() {
            return Err(Error::Conflict);
        }
        return Ok(());
    };
    let observed = observe_job(&registration)?;
    drain_and_bootout(guard, &registration, observed)?;
    custody::uninstall_privileged_custodian(guard)
}

/// Return exact root-broker readiness for service status. This deliberately
/// does not auto-install or fall back to the ordinary account Host.
pub(super) fn is_ready(guard: &BootMaintenanceGuard) -> Result<bool> {
    let Some(registration) = custody::read_optional_privileged_custodian(guard)? else {
        return Ok(false);
    };
    custody::validate_privileged_custodian(guard, &registration)?;
    is_registration_ready(&registration)
}

pub(super) fn is_ready_for_identity(
    profile: &std::path::Path,
    executable: &std::path::Path,
    selected_account: &str,
) -> Result<bool> {
    let binding = super::boot::custody_binding_for_identity(profile, executable, selected_account)?;
    let Some(registration) = custody::read_optional_for_binding(&binding)? else {
        return Ok(false);
    };
    custody::validate_for_binding(&registration, &binding)?;
    is_registration_ready(&registration)
}

fn is_registration_ready(registration: &custody::PrivilegedCustodianRegistration) -> Result<bool> {
    let Some(job) = observe_job(&registration)? else {
        return Ok(false);
    };
    if !job.running {
        return Ok(false);
    }
    admin_status(&registration).map(|_| true)
}

fn start_registered(
    guard: &BootMaintenanceGuard,
    registration: &custody::PrivilegedCustodianRegistration,
) -> Result<()> {
    custody::validate_privileged_custodian(guard, registration)?;
    let target = launch_target(registration);
    let plist = registration.launch_daemon_plist_path();
    match observe_job(registration)? {
        None => super::required(&["bootstrap", "system", plist.to_str().ok_or(Error::Invalid)?])?,
        Some(observation) if !observation.running => super::required(&["kickstart", &target])?,
        Some(_) => {}
    }
    let deadline = Instant::now() + MANAGER_DEADLINE;
    loop {
        match observe_job(registration)? {
            Some(observation) if observation.running => break,
            Some(_) => {}
            None => return Err(Error::NotReady),
        }
        if Instant::now() >= deadline {
            return Err(Error::NotReady);
        }
        thread::sleep(Duration::from_millis(50));
    }
    admin_status(registration)?;
    custody::validate_privileged_custodian(guard, registration)
}

fn drain_and_bootout(
    guard: &BootMaintenanceGuard,
    registration: &custody::PrivilegedCustodianRegistration,
    observed: Option<JobObservation>,
) -> Result<()> {
    let mut _offline_drain = None;
    if observed.is_some_and(|job| job.running) {
        custody::repair_privileged_custodian_publication(guard, registration)?;
        custody::validate_privileged_custodian(guard, registration)?;
        let response = admin_drain(registration)?;
        let receipt = custody::verify_privileged_custodian_drained(registration)?;
        if receipt.runtime_id() != response.runtime_id
            || receipt.request_id() != response.request_id
            || receipt.drained_generation_count() != response.drained_generation_count
            || receipt.drained_set_sha256() != response.drained_set_sha256
        {
            return Err(Error::Conflict);
        }
    } else {
        // Job/PID absence does not establish PTY retirement; only the durable
        // generation receipt can authorize an update or removal.
        if custody::verify_privileged_custodian_drained(registration).is_err() {
            _offline_drain = Some(custody::certify_offline_privileged_custodian_drained(
                guard,
                registration,
            )?);
        }
        custody::verify_privileged_custodian_drained(registration)?;
    }
    if observed.is_some() {
        let target = launch_target(registration);
        super::required(&["bootout", &target])?;
        let deadline = Instant::now() + MANAGER_DEADLINE;
        loop {
            if observe_job(registration)?.is_none() {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            thread::sleep(Duration::from_millis(50));
        }
        custody::verify_privileged_custodian_drained(registration)?;
    }
    Ok(())
}

fn admin_status(
    registration: &custody::PrivilegedCustodianRegistration,
) -> Result<AdminStatusResponse> {
    let response: AdminStatusResponse = run_helper(registration, ADMIN_STATUS_ARGUMENT)?;
    if response.version != 1
        || response.state != "ready"
        || response.registration_key != registration.registration_key()
        || !valid_uuid(&response.request_id)
        || !valid_uuid(&response.runtime_id)
    {
        return Err(Error::NotReady);
    }
    Ok(response)
}

fn admin_drain(
    registration: &custody::PrivilegedCustodianRegistration,
) -> Result<AdminDrainResponse> {
    let response: AdminDrainResponse = run_helper(registration, ADMIN_DRAIN_ARGUMENT)?;
    if response.version != 1
        || response.state != "drained"
        || response.registration_key != registration.registration_key()
        || !valid_uuid(&response.request_id)
        || !valid_uuid(&response.runtime_id)
        || !valid_lower_sha256(&response.drained_set_sha256)
    {
        return Err(Error::Conflict);
    }
    Ok(response)
}

fn run_helper<T: for<'de> Deserialize<'de> + Serialize>(
    registration: &custody::PrivilegedCustodianRegistration,
    operation: &str,
) -> Result<T> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    if !matches!(operation, ADMIN_STATUS_ARGUMENT | ADMIN_DRAIN_ARGUMENT) {
        return Err(Error::Invalid);
    }
    let mut command = Command::new(registration.executable_path());
    command
        .arg(operation)
        .arg(registration.registration_path())
        .current_dir("/")
        .env_clear()
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let output = bounded_helper(&mut command, HELPER_DEADLINE)?;
    let body = output.strip_suffix(b"\n").ok_or(Error::NotReady)?;
    if body.is_empty() || body.contains(&b'\n') || body.contains(&b'\r') {
        return Err(Error::NotReady);
    }
    let value: T = serde_json::from_slice(body).map_err(|_| Error::NotReady)?;
    let canonical_value = serde_json::to_value(&value).map_err(|_| Error::NotReady)?;
    let mut canonical = serde_json::to_vec(&canonical_value).map_err(|_| Error::NotReady)?;
    canonical.push(b'\n');
    if canonical != output {
        return Err(Error::NotReady);
    }
    Ok(value)
}

fn bounded_helper(command: &mut Command, timeout: Duration) -> Result<Vec<u8>> {
    crate::process::require_child_ownership().map_err(|_| Error::Manager)?;
    let mut child = command.spawn().map_err(|_| Error::Manager)?;
    let mut stdout = child.stdout.take().ok_or(Error::Manager)?;
    let mut stderr = child.stderr.take().ok_or(Error::Manager)?;
    let mut reaped = false;
    let result = (|| {
        for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
            {
                return Err(Error::Manager);
            }
        }
        let deadline = Instant::now() + timeout;
        let mut output = Vec::new();
        let mut errors = Vec::new();
        loop {
            read_available(&mut stdout, &mut output)?;
            read_available(&mut stderr, &mut errors)?;
            if output.len() > HELPER_LIMIT || errors.len() > HELPER_LIMIT {
                return Err(Error::Manager);
            }
            if let Some(status) = child.try_wait().map_err(|_| Error::Manager)? {
                reaped = true;
                drain_available(&mut stdout, &mut output)?;
                drain_available(&mut stderr, &mut errors)?;
                if output.len() > HELPER_LIMIT || !errors.is_empty() || !status.success() {
                    return Err(Error::NotReady);
                }
                return Ok(output);
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            thread::sleep(Duration::from_millis(10));
        }
    })();
    if !reaped {
        if crate::process::require_unreaped_child(&child).is_err() {
            return Err(Error::Deadline);
        }
        if result.is_err() {
            child.kill().map_err(|_| Error::Deadline)?;
        }
        let cleanup_deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) if Instant::now() < cleanup_deadline => {
                    thread::sleep(Duration::from_millis(10));
                }
                _ => return Err(Error::Deadline),
            }
        }
    }
    result
}

fn read_available(reader: &mut impl Read, output: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0u8; 4096];
    match reader.read(&mut buffer) {
        Ok(count) => output.extend_from_slice(&buffer[..count]),
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
        Err(_) => return Err(Error::Manager),
    }
    Ok(())
}

fn drain_available(reader: &mut impl Read, output: &mut Vec<u8>) -> Result<()> {
    let mut buffer = [0u8; 4096];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(()),
            Ok(count) => output.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
            Err(_) => return Err(Error::Manager),
        }
    }
}

fn observe_job(
    registration: &custody::PrivilegedCustodianRegistration,
) -> Result<Option<JobObservation>> {
    let target = launch_target(registration);
    let plist = registration
        .launch_daemon_plist_path()
        .to_str()
        .ok_or(Error::Invalid)?
        .to_owned();
    let executable = registration
        .executable_path()
        .to_str()
        .ok_or(Error::Invalid)?
        .to_owned();
    let registration_path = registration
        .registration_path()
        .to_str()
        .ok_or(Error::Invalid)?
        .to_owned();
    super::manager(&["print", &target])?
        .map(|text| parse_job_observation(&text, &target, &plist, &executable, &registration_path))
        .transpose()
}

fn parse_job_observation(
    text: &str,
    target: &str,
    plist: &str,
    executable: &str,
    registration_path: &str,
) -> Result<JobObservation> {
    if text.lines().last() != Some("}")
        || text
            .lines()
            .skip(1)
            .any(|line| !line.is_empty() && !line.starts_with('\t') && line != "}")
    {
        return Err(Error::Conflict);
    }
    let mut lines = text.lines();
    if lines.next() != Some(format!("{target} = {{").as_str()) {
        return Err(Error::Conflict);
    }
    let (mut seen_path, mut seen_program, mut seen_args) = (false, false, false);
    let mut seen_pid = false;
    let mut pid = None;
    let mut state = None;
    while let Some(line) = lines.next() {
        if line.starts_with("\t\t") {
            continue;
        }
        if let Some(value) = line.strip_prefix("\tpath = ") {
            if seen_path || value != plist {
                return Err(Error::Conflict);
            }
            seen_path = true;
        } else if let Some(value) = line.strip_prefix("\tprogram = ") {
            if seen_program || value != executable {
                return Err(Error::Conflict);
            }
            seen_program = true;
        } else if line == "\targuments = {" {
            if seen_args {
                return Err(Error::Conflict);
            }
            seen_args = true;
            for argument in [
                executable,
                "--internal-privileged-pty-broker",
                registration_path,
            ] {
                if lines.next() != Some(format!("\t\t{argument}").as_str()) {
                    return Err(Error::Conflict);
                }
            }
            if lines.next() != Some("\t}") {
                return Err(Error::Conflict);
            }
        } else if let Some(value) = line.strip_prefix("\tpid = ") {
            if seen_pid || !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(Error::Conflict);
            }
            seen_pid = true;
            let parsed = value.parse::<u32>().map_err(|_| Error::Conflict)?;
            if parsed == 0 || parsed > i32::MAX as u32 {
                return Err(Error::Conflict);
            }
            pid = Some(parsed);
        } else if let Some(value) = line.strip_prefix("\tstate = ") {
            if state.replace(value).is_some()
                || !matches!(
                    value,
                    "running" | "not running" | "waiting" | "spawn scheduled" | "SIGTERMed"
                )
            {
                return Err(Error::Conflict);
            }
        }
    }
    if !seen_path || !seen_program || !seen_args || state.is_none() {
        return Err(Error::Conflict);
    }
    let running = state == Some("running");
    if running != pid.is_some() || seen_pid != pid.is_some() {
        return Err(Error::Conflict);
    }
    Ok(JobObservation { running })
}

fn launch_target(registration: &custody::PrivilegedCustodianRegistration) -> String {
    format!("system/{}", registration.launch_daemon_label())
}

fn valid_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|uuid| !uuid.is_nil() && uuid.to_string() == value)
}

fn valid_lower_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
