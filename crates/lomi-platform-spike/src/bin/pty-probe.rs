//! Native-session E0 smoke probe. No service installation or renderer.
#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!(
        "not_run: this synthetic shell/IPC fixture is macOS-only; Linux/Windows require native harnesses"
    );
    std::process::exit(2);
}
#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    macos::run()
}
#[cfg(target_os = "macos")]
mod macos {
    use portable_pty::{CommandBuilder, PtySize, native_pty_system};
    use std::{
        io::{Read, Write},
        os::unix::net::{UnixListener, UnixStream},
        process::Command,
        sync::mpsc,
        thread,
        time::{Duration, Instant},
    };

    struct ChildGuard {
        child: Box<dyn portable_pty::Child + Send + Sync>,
        process_group: libc::pid_t,
        armed: bool,
    }
    impl ChildGuard {
        fn new(mut child: Box<dyn portable_pty::Child + Send + Sync>) -> std::io::Result<Self> {
            // portable-pty's native macOS spawn establishes a dedicated session
            // before exec. Capture that owned group once, before any wait/reap.
            let process_group = child
                .process_id()
                .and_then(|pid| i32::try_from(pid).ok())
                .filter(|pid| *pid > 0);
            let Some(process_group) = process_group else {
                let _ = child.kill();
                let _ = child.wait();
                return Err(std::io::Error::other(
                    "native PTY child has no process group ID",
                ));
            };
            Ok(Self {
                child,
                process_group,
                armed: true,
            })
        }
        fn finish(
            &mut self,
            status: portable_pty::ExitStatus,
            worker: i32,
        ) -> Result<(), &'static str> {
            if !status.success() {
                return Err("shell exit failed");
            }
            if unsafe { libc::kill(worker, 0) } != -1
                || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                return Err("background worker survived shell cleanup");
            }
            self.armed = false;
            Ok(())
        }
    }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if !self.armed {
                return;
            }
            // The stored owned group remains available after the shell is
            // reaped, so failed completion checks still terminate its workers.
            // Never discover or adopt a process group from the worker's PID.
            unsafe {
                libc::kill(-self.process_group, libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    fn until(
        rx: &mpsc::Receiver<Vec<u8>>,
        expected: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut output = Vec::new();
        while !output.windows(expected.len()).any(|part| part == expected) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            output.extend(rx.recv_timeout(remaining)?);
            if output.len() > 65536 {
                return Err("fixture output exceeded bound".into());
            }
        }
        Ok(output)
    }
    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let args: Vec<_> = std::env::args_os().collect();
        if args.get(1).is_some_and(|arg| arg == "--client") {
            let mut socket = UnixStream::connect(args.get(2).ok_or("missing client socket")?)?;
            socket.set_read_timeout(Some(Duration::from_secs(5)))?;
            let mut ready = [0; 5];
            socket.read_exact(&mut ready)?;
            if ready != *b"ready" {
                return Err("invalid fixture response".into());
            }
            return Ok(());
        }
        let temporary = tempfile::tempdir()?;
        let cwd = temporary.path().canonicalize()?;
        let socket_path = cwd.join("client.sock");
        let listener = UnixListener::bind(&socket_path)?;
        listener.set_nonblocking(true)?;
        let pair = native_pty_system().openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        let mut command = CommandBuilder::new("/bin/sh");
        command.args([
            "-f",
            "-c",
            r#"
            /bin/sleep 120 & worker=$!
            trap 'kill "$worker"; wait "$worker" 2>/dev/null; printf "CTRL_C_OK\n"; exit 0' INT
            printf '\033]7;file://localhost%s\007\nCHILD_PID:%s\nREADY\n' "$PWD" "$worker"
            while IFS= read -r command; do
                case "$command" in
                    size) /bin/stty size ;;
                    after_detach) printf 'DETACHED_OK\n' ;;
                esac
            done
        "#,
        ]);
        command.cwd(&cwd);
        command.env_clear();
        command.env("HOME", &cwd);
        command.env("PATH", "/usr/bin:/bin");
        command.env("LC_ALL", "C");
        command.env("TERM", "xterm-256color");
        let mut child = ChildGuard::new(pair.slave.spawn_command(command)?)?;
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader()?;
        let mut writer = pair.master.take_writer()?;
        let (send, receive) = mpsc::sync_channel(32);
        let reader_thread = thread::spawn(move || {
            let mut buffer = [0; 2048];
            while let Ok(size) = reader.read(&mut buffer) {
                if size == 0 || send.send(buffer[..size].to_vec()).is_err() {
                    break;
                }
            }
        });
        let initial = until(&receive, b"READY\r\n")?;
        let expected_osc = format!("\u{1b}]7;file://localhost{}\u{7}", cwd.display());
        let initial_text = String::from_utf8(initial)?;
        if !initial_text.contains(&expected_osc) {
            return Err("OSC7 CWD missing".into());
        }
        let worker: i32 = initial_text
            .split("CHILD_PID:")
            .nth(1)
            .ok_or("worker PID missing")?
            .split_whitespace()
            .next()
            .ok_or("worker PID empty")?
            .parse()?;
        println!("passed: renderer-free PTY output and OSC7 CWD");
        let mut client = Command::new(std::env::current_exe()?)
            .args(["--client"])
            .arg(&socket_path)
            .env_clear()
            .env("HOME", &cwd)
            .env("PATH", "/usr/bin:/bin")
            .env("LC_ALL", "C")
            .spawn()?;
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(error) => {
                    let _ = client.kill();
                    let _ = client.wait();
                    return Err(error.into());
                }
            }
        };
        socket.write_all(b"ready")?;
        drop(socket);
        // This is an actual separate client process, disconnected before the
        // PTY command below. It never owns the master or shell lifetime.
        while client.try_wait()?.is_none() {
            if Instant::now() >= deadline {
                let _ = client.kill();
                let _ = client.wait();
                return Err("client timeout".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        if !client.wait()?.success() {
            return Err("fixture client failed".into());
        }
        if child.child.try_wait()?.is_some() {
            return Err("PTY exited with client".into());
        }
        writer.write_all(b"after_detach\n")?;
        writer.flush()?;
        until(&receive, b"DETACHED_OK\r\n")?;
        println!("passed: PTY survives separate IPC client process disconnect");
        pair.master.resize(PtySize {
            rows: 37,
            cols: 101,
            pixel_width: 0,
            pixel_height: 0,
        })?;
        writer.write_all(b"size\n")?;
        writer.flush()?;
        until(&receive, b"37 101\r\n")?;
        println!("passed: resize observed by native stty");
        writer.write_all(&[3])?;
        writer.flush()?;
        until(&receive, b"CTRL_C_OK\r\n")?;
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.child.try_wait()? {
                child.finish(status, worker)?;
                break;
            }
            if Instant::now() >= deadline {
                return Err("shell cleanup timeout".into());
            }
            thread::sleep(Duration::from_millis(5));
        }
        drop(writer);
        drop(pair.master);
        drop(receive);
        reader_thread.join().map_err(|_| "reader panicked")?;
        println!("passed: Ctrl-C, shell exit, background child reap");
        println!(
            "not_run: launchd, logout/boot, locked storage, systemd linger, Windows SCM/ConPTY"
        );
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn failed_completion_kills_worker_after_shell_has_been_reaped() {
            for exit_code in [0, 7] {
                let temporary = tempfile::tempdir().unwrap();
                let pair = native_pty_system().openpty(PtySize::default()).unwrap();
                let mut command = CommandBuilder::new("/bin/sh");
                command.args(["-f", "-c", &format!(
                    "trap '' HUP; /bin/sleep 120 & printf '%s' \"$!\" > worker.pid; exit {exit_code}"
                )]);
                command.cwd(temporary.path());
                command.env_clear();
                command.env("PATH", "/usr/bin:/bin");
                command.env("HOME", temporary.path());
                let mut guard =
                    ChildGuard::new(pair.slave.spawn_command(command).unwrap()).unwrap();
                drop(pair.slave);
                let original_group = guard.process_group;
                let deadline = Instant::now() + Duration::from_secs(5);
                let status = loop {
                    if let Some(status) = guard.child.try_wait().unwrap() {
                        break status;
                    }
                    assert!(Instant::now() < deadline, "fixture shell did not exit");
                    thread::sleep(Duration::from_millis(5));
                };
                let worker: i32 = std::fs::read_to_string(temporary.path().join("worker.pid"))
                    .unwrap()
                    .parse()
                    .unwrap();
                assert_eq!(
                    unsafe { libc::kill(worker, 0) },
                    0,
                    "fixture worker must survive shell"
                );
                assert_eq!(guard.process_group, original_group);
                assert_eq!(
                    guard.finish(status, worker),
                    Err(if exit_code == 0 {
                        "background worker survived shell cleanup"
                    } else {
                        "shell exit failed"
                    })
                );
                assert!(guard.armed, "failed completion must preserve cleanup");
                drop(guard);
                let deadline = Instant::now() + Duration::from_secs(5);
                loop {
                    if unsafe { libc::kill(worker, 0) } == -1
                        && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
                    {
                        break;
                    }
                    assert!(Instant::now() < deadline, "worker survived failure cleanup");
                    thread::sleep(Duration::from_millis(5));
                }
                drop(pair.master);
            }
        }
    }
}
