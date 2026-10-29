mod child;
mod ipc;
mod native;
mod session;
mod state;
use native::*;
use session::{Observation, Session};
use state::Config;
use std::{
    ffi::OsString,
    io,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
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
static CONFIG: OnceLock<Config> = OnceLock::new();
static FAILED: AtomicBool = AtomicBool::new(false);
define_windows_service!(ffi_service_main, service_main);
fn status(handle: ServiceStatusHandle, state: ServiceState, code: u32) -> Result<()> {
    handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: if state == ServiceState::Running {
                ServiceControlAccept::STOP
            } else {
                ServiceControlAccept::empty()
            },
            exit_code: ServiceExitCode::Win32(code),
            checkpoint: if state == ServiceState::StopPending {
                1
            } else {
                0
            },
            wait_hint: Duration::from_secs(7),
            process_id: None,
        })
        .map_err(|_| denied("SCM status"))
}
fn service_main(_arguments: Vec<OsString>) {
    let Some(config) = CONFIG.get() else {
        FAILED.store(true, Ordering::SeqCst);
        return;
    };
    let stop = Arc::new(AtomicBool::new(false));
    let signal = stop.clone();
    let handle =
        match service_control_handler::register(config.name(), move |control| match control {
            ServiceControl::Stop => {
                signal.store(true, Ordering::SeqCst);
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }) {
            Ok(handle) => handle,
            Err(_) => {
                FAILED.store(true, Ordering::SeqCst);
                return;
            }
        };
    let result = owner(config, &stop, handle);
    let code = u32::from(result.is_err());
    FAILED.store(code != 0, Ordering::SeqCst);
    let _ = status(handle, ServiceState::Stopped, code);
}
fn owner(config: &Config, stop: &AtomicBool, handle: ServiceStatusHandle) -> Result<()> {
    if !local_service()? || session_id()? != 0 {
        return Err(denied("requires LocalService session zero"));
    }
    config.validate_directory()?;
    let lock_path = config.directory.join("owner.lock");
    let _lock = match state::open_regular(&lock_path, true, true, true) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            state::open_regular(&lock_path, true, false, true)?
        }
        Err(error) => return Err(error),
    };
    let stage = |label: &str| -> Result<()> {
        state::atomic_file(&config.directory, "startup-status.json", &serde_json::to_vec(
            &serde_json::json!({"localService":true,"sessionId":0,"rootTrustValid":true,"stage":label,"qualified":false})
        ).map_err(|_|denied("startup stage encode"))?)
    };
    stage("dpapi")?;
    let dpapi_reopened = state::dpapi(config)?;
    stage("descriptor")?;
    let previous = state::previous(config)?;
    stage("pipe")?;
    let endpoint = ipc::Endpoint::new(config)?;
    let mut session: Option<Session> = None;
    let owner_epoch = uuid::Uuid::new_v4().to_string();
    status(handle, ServiceState::Running, 0)?;
    stage("running")?;
    let result = (|| {
        while !stop.load(Ordering::SeqCst) {
            if let Some(session) = &session
                && session.observation()?.failed
            {
                return Err(denied("output/model bound or unexpected reply"));
            }
            if !endpoint.connect()? {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            let request = endpoint.request(stop);
            let command_ok = match request.as_deref() {
                Ok("status") => true,
                Ok("start") if session.is_none() => {
                    session = Some(Session::start(config)?);
                    true
                }
                #[cfg(feature = "fixture-test-hooks")]
                Ok("close-fault") => {
                    if let Some(current) = &mut session {
                        session::close_guard_probe(current)?;
                        true
                    } else {
                        false
                    }
                }
                Ok(command @ ("resize" | "after-detach" | "ctrl-c" | "exit")) => {
                    if let Some(current) = &mut session {
                        current.send(command).is_ok()
                    } else {
                        false
                    }
                }
                _ => false,
            };
            let observation = session
                .as_ref()
                .map(|s| s.observation())
                .transpose()?
                .unwrap_or_default();
            let active = session
                .as_ref()
                .map(|s| s.active())
                .transpose()?
                .unwrap_or(0);
            let response = serde_json::json!({
                "ok": command_ok, "qualified": false, "nativeFixture": true,
                "ownerEpoch": owner_epoch, "sessionEpoch": session.as_ref().map(|s|s.epoch.as_str()),
                "previousEpoch": previous, "oldSessionLost": previous.is_some() && session.is_none(),
                "childPid": session.as_ref().and_then(|s|s.pid()), "jobActiveProcesses": active,
                "localService": true, "sessionId": 0, "dpapiDecrypted": true,
                "dpapiReopened": dpapi_reopened, "inputReplayed": false, "observation": observation,
            });
            let mut bytes = serde_json::to_vec(&response).map_err(|_| denied("response encode"))?;
            bytes.push(b'\n');
            let _ = endpoint.respond(&bytes, stop);
            endpoint.disconnect();
        }
        Ok(())
    })();
    let _ = status(
        handle,
        ServiceState::StopPending,
        u32::from(result.is_err()),
    );
    let cleanup = if let Some(session) = &mut session {
        session.shutdown()
    } else {
        Ok(())
    };
    let observation: Observation = session
        .as_ref()
        .map(|s| s.observation())
        .transpose()?
        .unwrap_or_default();
    let evidence = serde_json::json!({"qualified":false,"stopReceived":stop.load(Ordering::SeqCst),
        "cleanupComplete":cleanup.is_ok(),"jobEmpty":session.as_ref().map(|s|s.active().ok() == Some(0)).unwrap_or(true),
        "dpapiDecrypted":true,"dpapiReopened":dpapi_reopened,"sessionId":0,"localService":true,
        "ownerEpoch":owner_epoch,"observation":observation});
    state::atomic_file(
        &config.directory,
        "last-stop.json",
        &serde_json::to_vec(&evidence).map_err(|_| denied("evidence encode"))?,
    )?;
    cleanup?;
    result
}
pub fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 2 && args[1] == "synthetic-child" {
        return child::child();
    }
    if args.len() == 2 && args[1] == "synthetic-worker" {
        return child::worker();
    }
    if args.len() < 4 {
        return Err(denied(
            "usage: service|client|decrypt-negative|owner-probe UUID OPERATOR_SID [command]",
        ));
    }
    let config = Config::new(&args[2], &args[3])?;
    match args[1].as_str() {
        "service" if args.len() == 4 => {
            let name = config.name();
            CONFIG
                .set(config)
                .map_err(|_| denied("duplicate configuration"))?;
            service_dispatcher::start(name, ffi_service_main)
                .map_err(|_| denied("SCM dispatcher"))?;
            if FAILED.load(Ordering::SeqCst) {
                return Err(denied("service failed"));
            }
            Ok(())
        }
        "client" if args.len() == 5 => ipc::client(&config, &args[4], Duration::ZERO, false),
        #[cfg(feature = "fixture-test-hooks")]
        "delayed-client" if args.len() == 5 => {
            ipc::client(&config, &args[4], Duration::from_millis(400), false)
        }
        #[cfg(feature = "fixture-test-hooks")]
        "hold-client" if args.len() == 5 => ipc::client(&config, &args[4], Duration::ZERO, true),
        #[cfg(feature = "fixture-test-hooks")]
        "trust-probe" if args.len() == 4 => {
            use std::path::Path;
            let parent = Path::new(r"C:\ProgramData\LomiWindowsFixture");
            let validation = config.validate_directory();
            let value = serde_json::json!({
                "directoryTrustValid":validation.is_ok(),
                "programDataOwnerTrusted":check_owner(Path::new(r"C:\ProgramData"), &["S-1-5-18","S-1-5-32-544"]).is_ok(),
                "programDataReplacementRightsSafe":no_untrusted_parent_delete(Path::new(r"C:\ProgramData")).is_ok(),
                "parentOwnerTrusted":check_owner(parent, &["S-1-5-32-544"]).is_ok(),
                "parentAclMatches":check_directory_acl(parent,&Security::new("D:P(A;OICI;FA;;;SY)(A;;0x1200a9;;;LS)(A;OICI;FA;;;BA)")?).is_ok(),
                "rootAclMatches":check_directory_acl(&config.directory,&config.directory_security()?).is_ok(),
                "errorClass":validation.as_ref().err().map(|e|format!("{:?}",e.kind())),"qualified":false
            });
            println!("{}", value);
            validation
        }
        #[cfg(feature = "fixture-test-hooks")]
        "read-startup" if args.len() == 4 => {
            config.validate_directory()?;
            let bytes = state::read_bounded(&config.directory.join("startup-status.json"))?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| denied("invalid startup status"))?;
            println!("{}", value);
            Ok(())
        }
        #[cfg(feature = "fixture-test-hooks")]
        "security-probe" if args.len() == 4 => {
            config.validate_directory()?;
            let _lock =
                state::open_regular(&config.directory.join("owner.lock"), true, false, true)?;
            ipc::squatted_server_probe(&config)
        }
        #[cfg(feature = "fixture-test-hooks")]
        "fault-close-probe" if args.len() == 4 => {
            ipc::client(&config, "close-fault", Duration::ZERO, false)
        }
        "decrypt-negative" if args.len() == 4 => {
            config.validate_directory()?;
            // File readability is checked first: access denied must not masquerade
            // as proof of DPAPI account isolation.
            let _ = state::read_bounded(&config.directory.join("dpapi.bin"))?;
            if state::decrypt_synthetic(&config.directory.join("dpapi.bin")).is_ok() {
                return Err(denied("cross-account decrypt unexpectedly succeeded"));
            }
            println!(
                "{{\"ciphertextReadable\":true,\"crossAccountDecryptRejected\":true,\"qualified\":false}}"
            );
            Ok(())
        }
        "owner-probe" if args.len() == 4 => {
            config.validate_directory()?;
            match state::open_regular(&config.directory.join("owner.lock"), true, false, true) {
                Err(error) if matches!(error.raw_os_error(), Some(32 | 33)) => {
                    println!("{{\"secondOwnerRejected\":true,\"qualified\":false}}");
                    Ok(())
                }
                Err(error) => Err(error),
                Ok(_) => Err(denied("owner lock unexpectedly available")),
            }
        }
        "read-stop" if args.len() == 4 => {
            config.validate_directory()?;
            let bytes = state::read_bounded(&config.directory.join("last-stop.json"))?;
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).map_err(|_| denied("invalid evidence"))?;
            println!("{}", value);
            Ok(())
        }
        _ => Err(denied("invalid fixture mode")),
    }
}
