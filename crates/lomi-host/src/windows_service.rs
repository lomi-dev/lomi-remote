//! SCM entry point for the actual host, running entirely as the SCM account.
//!
//! This module does not install services or change account credentials. The
//! retained IPC connection uses the normal exact-SID policy, without impersonation.
use crate::HostError;
use lomi_platform::windows::LocalClient;
use lomi_remote_protocol::{RuntimeId, ipc::*, rpc::Confirmed};
use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult, ServiceStatusHandle},
    service_dispatcher,
};

const START_TIMEOUT: Duration = Duration::from_secs(30);
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(50);
struct Configuration {
    name: OsString,
    profile: PathBuf,
    executable: PathBuf,
    expected_identity: Option<lomi_platform::windows::service_admin::AdminHostIdentity>,
}
static CONFIGURATION: OnceLock<Configuration> = OnceLock::new();
static FAILED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "scm-fixture")]
static EXPIRE_STOP_DEADLINE: AtomicBool = AtomicBool::new(false);

/// Native fixture only: expire the next real SCM stop's deadline. Defaults off.
#[cfg(feature = "scm-fixture")]
pub fn fixture_expire_stop_deadline() {
    EXPIRE_STOP_DEADLINE.store(true, Ordering::Release);
}
define_windows_service!(ffi_service_main, service_main);

/// Enter the SCM dispatcher before argument parsing or any interactive UI.
/// The service manager must pass the explicit, account-owned absolute profile.
pub fn dispatch(name: OsString, profile: PathBuf) -> Result<(), HostError> {
    if name.is_empty()
        || name.to_string_lossy().chars().any(char::is_control)
        || !profile.is_absolute()
    {
        return Err(HostError::InvalidProfile);
    }
    let service_name = name.to_str().ok_or(HostError::InvalidProfile)?;
    let executable = std::env::current_exe().map_err(|_| HostError::Unavailable)?;
    let expected_identity = lomi_platform::windows::service_admin::validate_host_dispatch(
        service_name,
        &profile,
        &executable,
    )
    .map_err(|_| HostError::InvalidProfile)?;
    CONFIGURATION
        .set(Configuration {
            name,
            profile,
            executable,
            expected_identity,
        })
        .map_err(|_| HostError::Busy)?;
    service_dispatcher::start(&CONFIGURATION.get().unwrap().name, ffi_service_main)
        .map_err(|_| HostError::Unavailable)?;
    if FAILED.load(Ordering::Acquire) {
        Err(HostError::Cleanup)
    } else {
        Ok(())
    }
}

fn status(
    handle: ServiceStatusHandle,
    state: ServiceState,
    checkpoint: u32,
    failed: bool,
) -> Result<(), HostError> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(u32::from(failed)),
            checkpoint,
            wait_hint: if matches!(
                state,
                ServiceState::StartPending | ServiceState::StopPending
            ) {
                Duration::from_secs(15)
            } else {
                Duration::ZERO
            },
            process_id: None,
        })
        .map_err(|_| HostError::Unavailable)
}

fn service_main(_arguments: Vec<OsString>) {
    let Some(configuration) = CONFIGURATION.get() else {
        FAILED.store(true, Ordering::Release);
        return;
    };
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let handle =
        match service_control_handler::register(&configuration.name, move |control| match control {
            ServiceControl::Stop => {
                signal.store(true, Ordering::Release);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(handle) => handle,
            Err(_) => {
                FAILED.store(true, Ordering::Release);
                return;
            }
        };
    let result = owner(&configuration.profile, &stop, handle);
    FAILED.store(result.is_err(), Ordering::Release);
    let _ = status(handle, ServiceState::Stopped, 0, result.is_err());
}

// Terminate the owning process on a deadline, closing its PTY Job handles.
// Never report successful cleanup from a timeout or detach a live host thread.
fn incomplete() -> ! {
    // Publishing Stopped here can release the dispatcher before exit(1), and
    // can suppress SCM crash recovery. Fail the owning process while pending.
    FAILED.store(true, Ordering::Release);
    std::process::exit(1)
}

fn remaining(deadline: Instant) -> Duration {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        incomplete();
    }
    remaining
}

fn owner(profile: &Path, stop: &AtomicBool, handle: ServiceStatusHandle) -> Result<(), HostError> {
    status(handle, ServiceState::StartPending, 1, false)?;
    let (ready_tx, ready_rx) = mpsc::sync_channel(1);
    let profile_owned = profile.to_owned();
    let host = thread::Builder::new()
        .name("lomi-service-host".to_owned())
        .spawn(move || {
            let ready = |runtime| {
                let _ = ready_tx.try_send(runtime);
                Ok(())
            };
            match CONFIGURATION
                .get()
                .and_then(|configuration| configuration.expected_identity)
            {
                Some(identity) => crate::unix::run_with_ready_existing_identity(
                    &profile_owned,
                    &lomi_host_store::Identity {
                        host_id: identity.host_id,
                        profile_id: identity.profile_id,
                    },
                    ready,
                ),
                None => crate::unix::run_with_ready_existing(&profile_owned, ready),
            }
        })
        .map_err(|_| HostError::Unavailable)?;
    let deadline = Instant::now() + START_TIMEOUT;
    let mut expected: Option<RuntimeId> = None;
    let mut checkpoint = 1u32;
    let mut last_checkpoint = Instant::now();
    let mut client = loop {
        if host.is_finished() {
            // Even a clean unexpected exit before readiness is a failed start.
            let _ = host.join();
            return Err(HostError::Unavailable);
        }
        if Instant::now() >= deadline {
            incomplete();
        }
        if expected.is_none() {
            expected = ready_rx.try_recv().ok();
        }
        if let Some(runtime) = expected {
            let timeout = remaining(deadline).min(Duration::from_millis(200));
            if let Ok(mut client) = LocalClient::connect_with_timeout(profile, timeout) {
                let timeout = remaining(deadline).min(lomi_platform::windows::REQUEST_TIMEOUT);
                if client.discovery().runtime_id == runtime
                    && matches!(client.request_with_timeout(LocalCall::Status {}, timeout), Ok(response)
                        if matches!(&response.result, Ok(LocalResult::Status(status)) if status.runtime_id == runtime))
                {
                    remaining(deadline);
                    break client;
                }
            }
            remaining(deadline);
        }
        if last_checkpoint.elapsed() >= Duration::from_secs(1) {
            checkpoint = checkpoint.saturating_add(1);
            if status(handle, ServiceState::StartPending, checkpoint, false).is_err() {
                incomplete();
            }
            last_checkpoint = Instant::now();
        }
        thread::sleep(POLL);
    };
    remaining(deadline);
    let reporting_failed = status(handle, ServiceState::Running, 0, false).is_err();
    let dispatch_valid = !reporting_failed
        && CONFIGURATION.get().is_some_and(|configuration| {
            configuration.name.to_str().is_some_and(|name| {
                lomi_platform::windows::service_admin::validate_host_running(
                    name,
                    profile,
                    &configuration.executable,
                )
                .is_ok()
            })
        });
    if reporting_failed || !dispatch_valid {
        // A failed SCM identity check uses the same bounded host stop path;
        // never leave an unvalidated runtime owning the profile endpoint.
        stop.store(true, Ordering::Release);
    }
    while !stop.load(Ordering::Acquire) && !host.is_finished() {
        thread::sleep(POLL);
    }
    status(handle, ServiceState::StopPending, 1, false).unwrap_or_else(|_| incomplete());
    let intentional = stop.load(Ordering::Acquire);
    let deadline = Instant::now() + STOP_TIMEOUT;
    #[cfg(feature = "scm-fixture")]
    let deadline = if EXPIRE_STOP_DEADLINE.swap(false, Ordering::AcqRel) {
        Instant::now()
    } else {
        deadline
    };
    remaining(deadline);
    let mut requested = false;
    if !host.is_finished() && Some(client.discovery().runtime_id) == expected {
        requested = matches!(
            client.request_with_timeout(LocalCall::DaemonStop(LocalOperatorIntent {
                operator_intent: Confirmed::Confirmed,
            }), remaining(deadline).min(lomi_platform::windows::REQUEST_TIMEOUT)),
            Ok(response) if matches!(response.result, Ok(LocalResult::Stopping {}))
        );
    }
    remaining(deadline);
    drop(client);
    checkpoint = 1;
    last_checkpoint = Instant::now();
    while !host.is_finished() {
        if Instant::now() >= deadline {
            incomplete();
        }
        if last_checkpoint.elapsed() >= Duration::from_secs(1) {
            checkpoint = checkpoint.saturating_add(1);
            status(handle, ServiceState::StopPending, checkpoint, false)
                .unwrap_or_else(|_| incomplete());
            last_checkpoint = Instant::now();
        }
        thread::sleep(POLL);
    }
    // run() returns only after IPC workers, terminal Jobs, store, and endpoint
    // have all been cleaned up. A vanished descriptor alone is insufficient.
    let cleaned = host.join().map_err(|_| HostError::Cleanup)?;
    cleaned?;
    if intentional && requested && !reporting_failed && dispatch_valid {
        Ok(())
    } else {
        Err(HostError::Unavailable)
    }
}
