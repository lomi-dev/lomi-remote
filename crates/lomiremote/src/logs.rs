//! Read-only diagnostic following on one authenticated Host runtime connection.
use std::path::Path;

#[cfg(any(unix, windows))]
pub fn run(profile: &Path, follow: bool, json: bool) -> u8 {
    #[cfg(unix)]
    use lomi_platform::unix::Error;
    #[cfg(all(unix, not(target_os = "macos")))]
    use lomi_platform::unix::LocalClient;
    #[cfg(windows)]
    use lomi_platform::windows::{Error, LocalClient};
    use lomi_remote_protocol::{
        DecimalU64,
        ipc::{LocalCall, LocalDiagnosticLogsRead, LocalResult},
    };
    use std::io::{self, Write};

    fn native_error(error: Error) -> (&'static str, u8) {
        match error {
            Error::PermissionDenied => ("LOCAL_PERMISSION_DENIED", 5),
            Error::Io(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
                ("LOCAL_PERMISSION_DENIED", 5)
            }
            Error::Incompatible => ("UPDATE_REQUIRED", 6),
            Error::InvalidFrame => ("DIAGNOSTIC_LOG_RESPONSE_INVALID", 6),
            Error::InvalidProfile | Error::InvalidEndpoint => ("INVALID_LOCAL_PROFILE", 5),
            _ => ("DAEMON_UNAVAILABLE", 4),
        }
    }
    let connected = {
        #[cfg(target_os = "macos")]
        {
            crate::terminal_commands::connect_installed_macos_host(profile).map_err(|code| {
                match code {
                    "UPDATE_REQUIRED" => (code, 6),
                    "LOCAL_PERMISSION_DENIED" | "INVALID_LOCAL_PROFILE" => (code, 5),
                    _ => (code, 4),
                }
            })
        }
        #[cfg(not(target_os = "macos"))]
        {
            LocalClient::connect(profile).map_err(native_error)
        }
    };
    let mut client = match connected {
        Ok(client) => client,
        Err((code, exit)) => return failure(code, exit, json),
    };
    let host_id = client.discovery().host_id;
    let runtime_id = client.discovery().runtime_id;
    let mut cursor = None;
    let mut first = true;
    let mut pages = 0;
    loop {
        let response = match client.request(LocalCall::DiagnosticLogs(LocalDiagnosticLogsRead {
            after_sequence: cursor.map(DecimalU64),
            limit: 128,
        })) {
            Ok(response) => response,
            Err(error) => {
                let (code, exit) = native_error(error);
                return failure(code, exit, json);
            }
        };
        let page = match response.result {
            Ok(LocalResult::DiagnosticLogs(page)) => page,
            Err(lomi_remote_protocol::ipc::LocalError::VersionMismatch) => {
                return failure("UPDATE_REQUIRED", 6, json);
            }
            Err(lomi_remote_protocol::ipc::LocalError::PermissionDenied) => {
                return failure("LOCAL_PERMISSION_DENIED", 5, json);
            }
            Err(_) => return failure("DIAGNOSTIC_LOGS_UNAVAILABLE", 4, json),
            _ => return failure("DIAGNOSTIC_LOG_RESPONSE_INVALID", 6, json),
        };
        if !page.available {
            return failure("DIAGNOSTIC_LOGS_UNAVAILABLE", 4, json);
        }
        if cursor.is_some_and(|old| page.next_cursor.0 < old)
            || page
                .entries
                .0
                .windows(2)
                .any(|pair| pair[0].sequence >= pair[1].sequence)
            || page.entries.0.iter().any(|entry| {
                entry.sequence.0 == 0
                    || cursor.is_some_and(|old| entry.sequence.0 <= old)
                    || entry.sequence > page.next_cursor
            })
            || (page.truncated && page.next_cursor.0 <= cursor.unwrap_or(0))
        {
            return failure("DIAGNOSTIC_LOG_RESPONSE_INVALID", 6, json);
        }
        if first || !page.entries.0.is_empty() || page.truncated {
            let mut output = io::stdout().lock();
            let written = if json {
                serde_json::to_writer(
                    &mut output,
                    &serde_json::json!({
                        "version": 1, "hostId": host_id, "runtimeId": runtime_id,
                        "logs": &page,
                    }),
                )
                .map_err(io::Error::other)
                .and_then(|_| writeln!(output))
            } else {
                (|| -> io::Result<()> {
                    if first && page.entries.0.is_empty() {
                        writeln!(output, "No retained diagnostic entries.")?;
                    }
                    for entry in &page.entries.0 {
                        // Every field is a number or a closed protocol enum.
                        writeln!(
                            output,
                            "{}  {}  {:?}  {:?}  {:?}",
                            entry.sequence.0,
                            entry.unix_time_ms.map_or_else(
                                || "unknown-time".to_owned(),
                                |time| time.0.to_string()
                            ),
                            entry.severity,
                            entry.component,
                            entry.code
                        )?;
                    }
                    Ok(())
                })()
            };
            if written.and_then(|_| output.flush()).is_err() {
                return 4;
            }
        }
        first = false;
        cursor = Some(page.next_cursor.0);
        pages += 1;
        // The Host retains 256 entries; bound a snapshot/burst to two pages.
        // Continuous producers cannot turn plain `logs` into a follow command.
        if page.truncated && pages < 2 {
            continue;
        }
        if !follow {
            return 0;
        }
        // Reuse this exact authenticated connection. A restart/disconnect ends
        // the command instead of silently adopting another runtime's cursor.
        std::thread::sleep(std::time::Duration::from_secs(1));
        pages = 0;
    }
}

#[cfg(not(any(unix, windows)))]
pub fn run(_profile: &Path, _follow: bool, json: bool) -> u8 {
    failure("UNSUPPORTED_LOCAL_OPERATION", 3, json)
}

fn failure(code: &'static str, exit: u8, json: bool) -> u8 {
    if json {
        use std::io::Write;
        let mut output = std::io::stdout().lock();
        let _ = serde_json::to_writer(
            &mut output,
            &serde_json::json!({"version": 1, "error": code}),
        )
        .and_then(|_| writeln!(output).map_err(serde_json::Error::io));
    } else {
        eprintln!("{code}");
    }
    exit
}
