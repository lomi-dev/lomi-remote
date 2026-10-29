//! Read-only, independently verifiable witnesses that a saved host process
//! incarnation has stopped. This module never signals, kills, or starts a
//! process. It intentionally does not bind process identity to an executable
//! path: renaming an executable does not retire its running process.

use serde::{Deserialize, Serialize};
use std::{error::Error, fmt};

const WITNESS_VERSION: u32 = 2;
const MAX_WITNESS_JSON: usize = 4 * 1024;
const MAX_RETIREMENT_JSON: usize = 8 * 1024;

/// A persistable identity for the current host process incarnation.
///
/// Fields are private so ordinary Rust callers can only obtain a value by
/// capturing the current process or by decoding a persisted strict wire value.
/// Decoded values are validated again before they can establish retirement.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoExecHostProcessWitness {
    version: u32,
    platform: Platform,
    machine_id: String,
    pid: u32,
    boot_id: Option<String>,
    process_birth: String,
    pid_namespace: Option<String>,
    #[serde(default)]
    time_namespace: Option<String>,
}

impl NoExecHostProcessWitness {
    /// Capture this process without retaining or comparing its executable path.
    pub fn capture_current() -> Result<Self, NoExecProcessError> {
        capture_current()
    }

    /// Verify that this exact process incarnation has terminated.
    ///
    /// A live matching incarnation returns [`NoExecProcessError::NotRetired`].
    /// Ambiguous identity, access, or kernel-query results return
    /// [`NoExecProcessError::Unknown`]. Neither case is treated as retirement.
    pub fn verify_retired(&self) -> Result<NoExecHostProcessRetirement, NoExecProcessError> {
        self.validate()?;
        verify_retired(self)
    }

    /// Encode the strict witness in deterministic field order for durable
    /// storage and later verification.
    pub fn canonical_json(&self) -> Result<String, NoExecProcessError> {
        self.validate()?;
        let json = serde_json::to_string(self).map_err(|_| NoExecProcessError::Unknown)?;
        if json.len() > MAX_WITNESS_JSON {
            return Err(NoExecProcessError::InvalidWitness);
        }
        Ok(json)
    }

    fn validate(&self) -> Result<(), NoExecProcessError> {
        if self.version != WITNESS_VERSION
            || self.pid == 0
            || self.machine_id.is_empty()
            || self.machine_id.len() > 64
            || self.process_birth.is_empty()
            || self.process_birth.len() > 128
        {
            return Err(NoExecProcessError::InvalidWitness);
        }

        match self.platform {
            Platform::Linux => {
                if self.pid > i32::MAX as u32
                    || !valid_hex(&self.machine_id, 32)
                    || !self.boot_id.as_deref().is_some_and(valid_uuid)
                    || !self
                        .pid_namespace
                        .as_deref()
                        .is_some_and(valid_pid_namespace)
                    || !self
                        .time_namespace
                        .as_deref()
                        .is_some_and(valid_time_namespace)
                    || !self.process_birth.bytes().all(|byte| byte.is_ascii_digit())
                    || self
                        .process_birth
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value != 0)
                        .is_none()
                {
                    return Err(NoExecProcessError::InvalidWitness);
                }
            }
            Platform::MacOs => {
                if self.pid > i32::MAX as u32
                    || !valid_hex(&self.machine_id, 32)
                    || !self.boot_id.as_deref().is_some_and(valid_uuid)
                    || self.pid_namespace.is_some()
                    || self.time_namespace.is_some()
                    || !self.process_birth.bytes().all(|byte| byte.is_ascii_digit())
                    || self
                        .process_birth
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value != 0)
                        .is_none()
                {
                    return Err(NoExecProcessError::InvalidWitness);
                }
            }
            Platform::Windows => {
                if !valid_uuid(&self.machine_id)
                    || self.boot_id.is_some()
                    || self.pid_namespace.is_some()
                    || self.time_namespace.is_some()
                    || !self.process_birth.bytes().all(|byte| byte.is_ascii_digit())
                    || self
                        .process_birth
                        .parse::<u64>()
                        .ok()
                        .filter(|value| *value != 0)
                        .is_none()
                {
                    return Err(NoExecProcessError::InvalidWitness);
                }
            }
        }
        Ok(())
    }
}

/// A locally generated retirement receipt. It cannot be deserialized or
/// constructed by callers; its canonical JSON binds the original witness to
/// the positive OS observation that retired it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NoExecHostProcessRetirement {
    version: u32,
    witness: NoExecHostProcessWitness,
    reason: RetirementReason,
    observed_machine_id: String,
    observed_boot_id: Option<String>,
    observed_pid_namespace: Option<String>,
    observed_process_birth: Option<String>,
}

impl NoExecHostProcessRetirement {
    /// A different verified boot of the same OS installation retires every
    /// process in the old kernel. Ordinary PID absence or incarnation changes
    /// deliberately do not establish that a process's descendants are gone.
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    pub fn proves_kernel_restart_for(&self, witness: &NoExecHostProcessWitness) -> bool {
        self.witness == *witness
            && self.reason == RetirementReason::BootChanged
            && self.observed_machine_id == witness.machine_id
            && self
                .observed_boot_id
                .as_ref()
                .zip(witness.boot_id.as_ref())
                .is_some_and(|(current, previous)| current != previous)
    }
    /// Deterministic, bounded JSON suitable as the exact input to a caller's
    /// durable digest. The JSON itself does not claim custody or operation
    /// completion; it records only this process-incarnation observation.
    pub fn canonical_json(&self) -> Result<String, NoExecProcessError> {
        let json = serde_json::to_string(self).map_err(|_| NoExecProcessError::Unknown)?;
        if json.len() > MAX_RETIREMENT_JSON {
            return Err(NoExecProcessError::Unknown);
        }
        Ok(json)
    }
}

/// Fixed, non-sensitive diagnostics for unavailable or ambiguous observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoExecProcessError {
    Unsupported,
    InvalidWitness,
    NotRetired,
    Unknown,
}

impl fmt::Display for NoExecProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Unsupported => "Host process retirement verification is unavailable",
            Self::InvalidWitness => "Host process witness is invalid",
            Self::NotRetired => "Host process incarnation is still present",
            Self::Unknown => "Host process retirement could not be established",
        })
    }
}

impl Error for NoExecProcessError {}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum Platform {
    Linux,
    #[serde(rename = "macos")]
    MacOs,
    Windows,
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
enum RetirementReason {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    BootChanged,
    PidAbsent,
    #[cfg(target_os = "windows")]
    ProcessTerminated,
    PidIncarnationChanged,
}

fn retirement(
    witness: &NoExecHostProcessWitness,
    reason: RetirementReason,
    observed_machine_id: String,
    observed_boot_id: Option<String>,
    observed_pid_namespace: Option<String>,
    observed_process_birth: Option<String>,
) -> NoExecHostProcessRetirement {
    NoExecHostProcessRetirement {
        version: 1,
        witness: witness.clone(),
        reason,
        observed_machine_id,
        observed_boot_id,
        observed_pid_namespace,
        observed_process_birth,
    }
}

fn valid_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value
            .bytes()
            .any(|byte| byte.is_ascii_hexdigit() && byte != b'0')
        && value.bytes().enumerate().all(|(index, byte)| {
            if matches!(index, 8 | 13 | 18 | 23) {
                byte == b'-'
            } else {
                byte.is_ascii_hexdigit()
            }
        })
}

fn valid_pid_namespace(value: &str) -> bool {
    value
        .strip_prefix("pid:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value != 0)
}

fn valid_time_namespace(value: &str) -> bool {
    value
        .strip_prefix("time:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
        .is_some_and(|value| value != 0)
}

#[cfg(target_os = "linux")]
fn capture_current() -> Result<NoExecHostProcessWitness, NoExecProcessError> {
    linux_require_current_proc_view()?;
    let machine_id = linux_machine_id()?;
    let boot_id = linux_boot_id()?;
    let pid_namespace = linux_pid_namespace()?;
    let time_namespace = linux_time_namespace()?;
    let pid = std::process::id();
    let (birth, state) = linux_process_stat(pid).map_err(|_| NoExecProcessError::Unknown)?;
    if matches!(state, 'Z' | 'X') {
        return Err(NoExecProcessError::Unknown);
    }
    let witness = NoExecHostProcessWitness {
        version: WITNESS_VERSION,
        platform: Platform::Linux,
        machine_id,
        pid,
        boot_id: Some(boot_id),
        process_birth: birth,
        pid_namespace: Some(pid_namespace),
        time_namespace: Some(time_namespace),
    };
    witness.validate()?;
    Ok(witness)
}

#[cfg(target_os = "linux")]
fn verify_retired(
    witness: &NoExecHostProcessWitness,
) -> Result<NoExecHostProcessRetirement, NoExecProcessError> {
    if witness.platform != Platform::Linux {
        return Err(NoExecProcessError::Unknown);
    }
    linux_require_current_proc_view()?;
    let machine_id = linux_machine_id()?;
    if machine_id != witness.machine_id {
        return Err(NoExecProcessError::Unknown);
    }
    let boot_id = linux_boot_id()?;
    if witness.boot_id.as_deref() != Some(boot_id.as_str()) {
        return Ok(retirement(
            witness,
            RetirementReason::BootChanged,
            machine_id,
            Some(boot_id),
            None,
            None,
        ));
    }
    let pid_namespace = linux_pid_namespace()?;
    if witness.pid_namespace.as_deref() != Some(pid_namespace.as_str()) {
        return Err(NoExecProcessError::Unknown);
    }
    let time_namespace = linux_time_namespace()?;
    if witness.time_namespace.as_deref() != Some(time_namespace.as_str()) {
        return Err(NoExecProcessError::Unknown);
    }

    match linux_process_stat(witness.pid) {
        Ok((birth, _state)) if birth != witness.process_birth => Ok(retirement(
            witness,
            RetirementReason::PidIncarnationChanged,
            machine_id,
            Some(boot_id),
            Some(pid_namespace),
            Some(birth),
        )),
        Ok((_birth, _state)) => Err(NoExecProcessError::NotRetired),
        Err(LinuxProcError::NotFound) => match linux_pid_exists(witness.pid) {
            Ok(false) => Ok(retirement(
                witness,
                RetirementReason::PidAbsent,
                machine_id,
                Some(boot_id),
                Some(pid_namespace),
                None,
            )),
            Ok(true) | Err(()) => Err(NoExecProcessError::Unknown),
        },
        Err(LinuxProcError::Unknown) => Err(NoExecProcessError::Unknown),
    }
}

#[cfg(target_os = "linux")]
fn linux_machine_id() -> Result<String, NoExecProcessError> {
    let value = read_bounded("/etc/machine-id", 64)?;
    let text = std::str::from_utf8(&value).map_err(|_| NoExecProcessError::Unknown)?;
    let text = text.trim_end_matches(['\r', '\n']);
    if !valid_hex(text, 32) {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(text.to_ascii_lowercase())
}

#[cfg(target_os = "linux")]
fn linux_boot_id() -> Result<String, NoExecProcessError> {
    let value = read_bounded("/proc/sys/kernel/random/boot_id", 64)?;
    let text = std::str::from_utf8(&value).map_err(|_| NoExecProcessError::Unknown)?;
    let text = text.trim_end_matches(['\r', '\n']);
    if !valid_uuid(text) {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(text.to_ascii_lowercase())
}

#[cfg(target_os = "linux")]
fn linux_pid_namespace() -> Result<String, NoExecProcessError> {
    let path = std::fs::read_link("/proc/self/ns/pid").map_err(|_| NoExecProcessError::Unknown)?;
    let value = path.to_str().ok_or(NoExecProcessError::Unknown)?;
    if !valid_pid_namespace(value) || value.len() > 64 {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn linux_time_namespace() -> Result<String, NoExecProcessError> {
    let path = std::fs::read_link("/proc/self/ns/time").map_err(|_| NoExecProcessError::Unknown)?;
    let value = path.to_str().ok_or(NoExecProcessError::Unknown)?;
    if !valid_time_namespace(value) || value.len() > 64 {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(value.to_owned())
}

#[cfg(target_os = "linux")]
fn linux_require_current_proc_view() -> Result<(), NoExecProcessError> {
    let pid = std::process::id();
    let stat = read_bounded("/proc/self/stat", 16 * 1024)?;
    let stat_text = std::str::from_utf8(&stat).map_err(|_| NoExecProcessError::Unknown)?;
    let stat_pid = stat_text
        .split_ascii_whitespace()
        .next()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(NoExecProcessError::Unknown)?;
    if stat_pid != pid {
        return Err(NoExecProcessError::Unknown);
    }

    let status = read_bounded("/proc/self/status", 64 * 1024)?;
    let status_text = std::str::from_utf8(&status).map_err(|_| NoExecProcessError::Unknown)?;
    let mut nspid = None;
    for line in status_text.lines() {
        if let Some(value) = line.strip_prefix("NSpid:") {
            if nspid.is_some() {
                return Err(NoExecProcessError::Unknown);
            }
            let pids: Vec<u32> = value
                .split_ascii_whitespace()
                .map(|part| {
                    if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                        return Err(NoExecProcessError::Unknown);
                    }
                    part.parse::<u32>().map_err(|_| NoExecProcessError::Unknown)
                })
                .collect::<Result<_, _>>()?;
            nspid = Some(pids);
        }
    }
    match nspid {
        Some(pids) if pids.len() == 1 && pids[0] == pid => Ok(()),
        _ => Err(NoExecProcessError::Unknown),
    }
}

#[cfg(target_os = "linux")]
fn read_bounded(path: &str, maximum: usize) -> Result<Vec<u8>, NoExecProcessError> {
    use std::io::Read;
    let file = std::fs::File::open(path).map_err(|_| NoExecProcessError::Unknown)?;
    let mut bytes = Vec::with_capacity(maximum.min(128));
    file.take((maximum + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| NoExecProcessError::Unknown)?;
    if bytes.len() > maximum {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(bytes)
}

#[cfg(target_os = "linux")]
enum LinuxProcError {
    NotFound,
    Unknown,
}

#[cfg(target_os = "linux")]
fn linux_process_stat(pid: u32) -> Result<(String, char), LinuxProcError> {
    use std::io::Read;
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(LinuxProcError::Unknown);
    }
    let path = format!("/proc/{pid}/stat");
    let mut file = match std::fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LinuxProcError::NotFound);
        }
        Err(_) => return Err(LinuxProcError::Unknown),
    };
    const MAX_STAT: usize = 16 * 1024;
    let mut bytes = Vec::with_capacity(1024);
    file.by_ref()
        .take((MAX_STAT + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| LinuxProcError::Unknown)?;
    if bytes.len() > MAX_STAT {
        return Err(LinuxProcError::Unknown);
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| LinuxProcError::Unknown)?;
    let reported_pid = text
        .split_ascii_whitespace()
        .next()
        .filter(|value| value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u32>().ok())
        .ok_or(LinuxProcError::Unknown)?;
    if reported_pid != pid {
        return Err(LinuxProcError::Unknown);
    }
    // comm is parenthesized but may itself contain spaces and right parens;
    // the last right paren is the only safe boundary before field 3.
    let close = text.rfind(')').ok_or(LinuxProcError::Unknown)?;
    let fields: Vec<&str> = text[close + 1..].split_ascii_whitespace().collect();
    if fields.len() <= 19 || fields[0].len() != 1 {
        return Err(LinuxProcError::Unknown);
    }
    let state = fields[0].chars().next().ok_or(LinuxProcError::Unknown)?;
    let start_time = fields[19];
    if start_time.is_empty() || !start_time.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(LinuxProcError::Unknown);
    }
    let birth = start_time
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or(LinuxProcError::Unknown)?
        .to_string();
    Ok((birth, state))
}

#[cfg(target_os = "linux")]
fn linux_pid_exists(pid: u32) -> Result<bool, ()> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(());
    }
    let result = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if result == 0 {
        return Ok(true);
    }
    match std::io::Error::last_os_error().raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        // EPERM and all other failures are ambiguity, never evidence of death.
        _ => Err(()),
    }
}

#[cfg(target_os = "macos")]
fn capture_current() -> Result<NoExecHostProcessWitness, NoExecProcessError> {
    let machine_id = mac_machine_id()?;
    let boot_id = mac_boot_id()?;
    let pid = std::process::id();
    let birth = mac_process_birth(pid).map_err(|_| NoExecProcessError::Unknown)?;
    let witness = NoExecHostProcessWitness {
        version: WITNESS_VERSION,
        platform: Platform::MacOs,
        machine_id,
        pid,
        boot_id: Some(boot_id),
        process_birth: birth,
        pid_namespace: None,
        time_namespace: None,
    };
    witness.validate()?;
    Ok(witness)
}

#[cfg(target_os = "macos")]
fn verify_retired(
    witness: &NoExecHostProcessWitness,
) -> Result<NoExecHostProcessRetirement, NoExecProcessError> {
    if witness.platform != Platform::MacOs {
        return Err(NoExecProcessError::Unknown);
    }
    let machine_id = mac_machine_id()?;
    if machine_id != witness.machine_id {
        return Err(NoExecProcessError::Unknown);
    }
    let boot_id = mac_boot_id()?;
    if witness.boot_id.as_deref() != Some(boot_id.as_str()) {
        return Ok(retirement(
            witness,
            RetirementReason::BootChanged,
            machine_id,
            Some(boot_id),
            None,
            None,
        ));
    }

    match mac_process_birth(witness.pid) {
        Ok(birth) if birth != witness.process_birth => Ok(retirement(
            witness,
            RetirementReason::PidIncarnationChanged,
            machine_id,
            Some(boot_id),
            None,
            Some(birth),
        )),
        Ok(_birth) => Err(NoExecProcessError::NotRetired),
        Err(()) if mac_pid_absent(witness.pid) => Ok(retirement(
            witness,
            RetirementReason::PidAbsent,
            machine_id,
            Some(boot_id),
            None,
            None,
        )),
        Err(()) => Err(NoExecProcessError::Unknown),
    }
}

#[cfg(target_os = "macos")]
fn mac_machine_id() -> Result<String, NoExecProcessError> {
    use std::ffi::c_int;
    unsafe extern "C" {
        fn gethostuuid(uuid: *mut u8, timeout: *const libc::timespec) -> c_int;
    }
    let timeout = libc::timespec {
        tv_sec: 1,
        tv_nsec: 0,
    };
    let mut uuid = [0u8; 16];
    if unsafe { gethostuuid(uuid.as_mut_ptr(), &timeout) } != 0
        || uuid.iter().all(|byte| *byte == 0)
    {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(hex(&uuid))
}

#[cfg(target_os = "macos")]
fn mac_boot_id() -> Result<String, NoExecProcessError> {
    use std::ffi::{CStr, c_char, c_int, c_void};
    unsafe extern "C" {
        fn sysctlbyname(
            name: *const c_char,
            output: *mut c_void,
            size: *mut usize,
            input: *mut c_void,
            input_size: usize,
        ) -> c_int;
    }
    let mut bytes = [0u8; 128];
    let mut size = bytes.len();
    if unsafe {
        sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            bytes.as_mut_ptr().cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || size == 0
        || size > bytes.len()
    {
        return Err(NoExecProcessError::Unknown);
    }
    let value = CStr::from_bytes_until_nul(&bytes[..size])
        .map_err(|_| NoExecProcessError::Unknown)?
        .to_str()
        .map_err(|_| NoExecProcessError::Unknown)?
        .to_ascii_lowercase();
    if !valid_uuid(&value) {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(value)
}

#[cfg(target_os = "macos")]
fn mac_process_birth(pid: u32) -> Result<String, ()> {
    use std::ffi::{c_int, c_void};
    #[repr(C)]
    #[derive(Default)]
    struct Usage {
        _uuid: [u8; 16],
        counters: [u64; 10],
    }
    unsafe extern "C" {
        fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *mut c_void) -> c_int;
    }
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(());
    }
    let mut usage = Usage::default();
    if unsafe { proc_pid_rusage(pid as c_int, 0, (&mut usage as *mut Usage).cast()) } != 0
        || usage.counters[8] == 0
    {
        return Err(());
    }
    Ok(usage.counters[8].to_string())
}

#[cfg(target_os = "macos")]
fn mac_pid_absent(pid: u32) -> bool {
    pid > 0
        && pid <= i32::MAX as u32
        && unsafe { libc::kill(pid as libc::pid_t, 0) } == -1
        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
}

#[cfg(target_os = "windows")]
fn capture_current() -> Result<NoExecHostProcessWitness, NoExecProcessError> {
    let machine_id = windows_machine_id()?;
    let pid = std::process::id();
    let process_birth = windows_process_birth(pid)?;
    let witness = NoExecHostProcessWitness {
        version: WITNESS_VERSION,
        platform: Platform::Windows,
        machine_id,
        pid,
        boot_id: None,
        process_birth,
        pid_namespace: None,
        time_namespace: None,
    };
    witness.validate()?;
    Ok(witness)
}

#[cfg(target_os = "windows")]
fn verify_retired(
    witness: &NoExecHostProcessWitness,
) -> Result<NoExecHostProcessRetirement, NoExecProcessError> {
    use windows_sys::Win32::{
        Foundation::{ERROR_INVALID_PARAMETER, GetLastError, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{
            OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
            WaitForSingleObject,
        },
    };

    if witness.platform != Platform::Windows {
        return Err(NoExecProcessError::Unknown);
    }
    let machine_id = windows_machine_id()?;
    if machine_id != witness.machine_id {
        return Err(NoExecProcessError::Unknown);
    }
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
            0,
            witness.pid,
        )
    };
    if handle.is_null() {
        if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            return Ok(retirement(
                witness,
                RetirementReason::PidAbsent,
                machine_id,
                None,
                None,
                None,
            ));
        }
        return Err(NoExecProcessError::Unknown);
    }
    let process = WindowsProcessHandle(handle);
    let wait = unsafe { WaitForSingleObject(process.0, 0) };
    if wait == WAIT_OBJECT_0 {
        return Ok(retirement(
            witness,
            RetirementReason::ProcessTerminated,
            machine_id,
            None,
            None,
            None,
        ));
    }
    if wait != WAIT_TIMEOUT {
        return Err(NoExecProcessError::Unknown);
    }
    let birth = windows_process_birth_from_handle(process.0)?;
    if birth != witness.process_birth {
        return Ok(retirement(
            witness,
            RetirementReason::PidIncarnationChanged,
            machine_id,
            None,
            None,
            Some(birth),
        ));
    }
    let final_wait = unsafe { WaitForSingleObject(process.0, 0) };
    if final_wait == WAIT_OBJECT_0 {
        return Ok(retirement(
            witness,
            RetirementReason::ProcessTerminated,
            machine_id,
            None,
            None,
            Some(birth),
        ));
    }
    if final_wait != WAIT_TIMEOUT {
        return Err(NoExecProcessError::Unknown);
    }
    Err(NoExecProcessError::NotRetired)
}

#[cfg(target_os = "windows")]
fn windows_machine_id() -> Result<String, NoExecProcessError> {
    use windows_sys::Win32::{
        Foundation::ERROR_SUCCESS,
        System::Registry::{
            HKEY_LOCAL_MACHINE, REG_SZ, RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
        },
    };
    const MAX_UNITS: usize = 128;
    let subkey = wide("SOFTWARE\\Microsoft\\Cryptography");
    let value = wide("MachineGuid");
    let mut buffer = [0u16; MAX_UNITS];
    let mut value_type = 0;
    let mut byte_count = (buffer.len() * std::mem::size_of::<u16>()) as u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            subkey.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_SUBKEY_WOW6464KEY,
            &mut value_type,
            buffer.as_mut_ptr().cast(),
            &mut byte_count,
        )
    };
    if status != ERROR_SUCCESS
        || value_type != REG_SZ
        || byte_count as usize > buffer.len() * std::mem::size_of::<u16>()
        || byte_count as usize % std::mem::size_of::<u16>() != 0
    {
        return Err(NoExecProcessError::Unknown);
    }
    let units = &buffer[..(byte_count as usize / 2)];
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(units.len());
    if units[end..].iter().any(|unit| *unit != 0) {
        return Err(NoExecProcessError::Unknown);
    }
    let value = String::from_utf16(&units[..end]).map_err(|_| NoExecProcessError::Unknown)?;
    let value = value.to_ascii_lowercase();
    if !valid_uuid(&value) {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(value)
}

#[cfg(target_os = "windows")]
fn windows_process_birth(pid: u32) -> Result<String, NoExecProcessError> {
    use windows_sys::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION};
    if pid == 0 {
        return Err(NoExecProcessError::Unknown);
    }
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return Err(NoExecProcessError::Unknown);
    }
    let process = WindowsProcessHandle(handle);
    windows_process_birth_from_handle(process.0)
}

#[cfg(target_os = "windows")]
fn windows_process_birth_from_handle(
    process: windows_sys::Win32::Foundation::HANDLE,
) -> Result<String, NoExecProcessError> {
    use windows_sys::Win32::{Foundation::FILETIME, System::Threading::GetProcessTimes};
    let mut created = FILETIME::default();
    let mut exited = FILETIME::default();
    let mut kernel = FILETIME::default();
    let mut user = FILETIME::default();
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(NoExecProcessError::Unknown);
    }
    let birth = ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64;
    if birth == 0 {
        return Err(NoExecProcessError::Unknown);
    }
    Ok(birth.to_string())
}

#[cfg(target_os = "windows")]
struct WindowsProcessHandle(windows_sys::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
impl Drop for WindowsProcessHandle {
    fn drop(&mut self) {
        unsafe {
            windows_sys::Win32::Foundation::CloseHandle(self.0);
        }
    }
}

#[cfg(target_os = "windows")]
fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "macos")]
fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn capture_current() -> Result<NoExecHostProcessWitness, NoExecProcessError> {
    Err(NoExecProcessError::Unsupported)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn verify_retired(
    _witness: &NoExecHostProcessWitness,
) -> Result<NoExecHostProcessRetirement, NoExecProcessError> {
    Err(NoExecProcessError::Unsupported)
}
