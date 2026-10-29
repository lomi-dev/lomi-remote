//! Synthetic subprocess harness for supervisor crash tests.
#[cfg(unix)]
fn main() {
    use lomi_remote_protocol::{SessionEpoch, TerminalSessionId};
    use lomi_terminal::{SpawnProfile, TerminalService};
    let root = std::env::var_os("LOMI_PTY_FIXTURE_ROOT").map(std::path::PathBuf::from);
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--internal-pty-worker"))
    {
        if std::env::args_os().nth(2).as_deref()
            == Some(std::ffi::OsStr::new("--test-owned-worker-crash"))
        {
            use std::process::{Command, Stdio};
            struct Owned(std::process::Child);
            impl Drop for Owned {
                fn drop(&mut self) {
                    let _ = self.0.kill();
                    let _ = self.0.wait();
                }
            }
            let root = root.unwrap();
            let mut worker = Owned(
                Command::new(std::env::current_exe().unwrap())
                    .arg("--internal-pty-worker")
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            // Only the owned inner worker retains this lifetime endpoint.
            unsafe {
                libc::close(0);
            }
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            while !root.join("flood.ready").exists() {
                assert!(std::time::Instant::now() < deadline);
                std::thread::sleep(std::time::Duration::from_millis(1));
            }
            worker.0.kill().unwrap();
            worker.0.wait().unwrap();
            std::fs::write(root.join("worker.killed"), b"done").unwrap();
            return;
        }
        if let Some(root) = root {
            std::fs::write(root.join("worker.pid"), std::process::id().to_string()).unwrap();
            if std::env::var_os("LOMI_PTY_FIXTURE_DELAY").is_some() {
                std::thread::sleep(std::time::Duration::from_secs(4));
            }
        }
        if std::env::var_os("LOMI_PTY_FIXTURE_IGNORE_CHLD").is_some() {
            // Inject inherited SIG_IGN into the worker alone, preserving the
            // fixture owner's independent std::Child reaping responsibility.
            unsafe {
                libc::signal(libc::SIGCHLD, libc::SIG_IGN);
            }
        }
        std::process::exit(lomi_terminal::internal_pty_worker());
    }
    let root = root.unwrap();
    let service = TerminalService::with_worker(std::env::current_exe().unwrap());
    let mode = std::env::args().nth(1).unwrap_or_default();
    let script = if mode == "detached" {
        // Linux-only ownership proof: double fork/session escape and ignore HUP.
        "echo $$ > shell.pid; python3 -c 'import os,signal,time; p=os.fork(); (os._exit(0) if p else None); os.setsid(); signal.signal(signal.SIGHUP, signal.SIG_IGN); open(\"escaped.pid\",\"w\").write(str(os.getpid())); time.sleep(20)' & sleep 20 & echo $! > background.pid; wait"
    } else {
        "echo $$ > shell.pid; sleep 20 & echo $! > background.pid; sleep 20 | cat & echo $! > pipeline.pid; sh -c 'echo $$ > foreground.pid; exec sleep 20'"
    };
    let executable = std::env::var_os("LOMI_PTY_FIXTURE_SHELL")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| "/bin/sh".into());
    let mut args = Vec::new();
    if mode == "interactive" {
        match executable.file_name().and_then(|name| name.to_str()) {
            Some("bash") => args.extend(["--noprofile".into(), "--norc".into()]),
            Some("zsh") => args.push("-f".into()),
            _ => {}
        }
        args.push("-i".into());
    }
    args.extend(["-c".into(), script.into()]);
    let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
    service
        .spawn(
            id,
            SessionEpoch::from_bytes([2; 16]).unwrap(),
            &SpawnProfile {
                executable,
                args,
                cwd: root.clone(),
                environment: vec![
                    ("PATH".into(), "/usr/bin:/bin:/usr/local/bin".into()),
                    ("HOME".into(), root.to_str().unwrap().into()),
                    ("ZDOTDIR".into(), root.to_str().unwrap().into()),
                ],
                shell_integration: None,
                rows: 10,
                cols: 40,
                history: 0,
            },
        )
        .unwrap();
    std::fs::write(root.join("ready"), b"ready").unwrap();
    if mode == "stop" {
        service.stop(id).unwrap();
        return;
    }
    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}
#[cfg(not(unix))]
fn main() {}
