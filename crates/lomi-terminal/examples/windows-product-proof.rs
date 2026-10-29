#[cfg(not(windows))]
fn main() {}
#[cfg(windows)]
fn main() {
    if let Err(error) = proof::run() {
        eprintln!("{error}");
        std::process::exit(1)
    }
}
#[cfg(windows)]
mod proof {
    use lomi_remote_protocol::{ConsumerAuthorizationId, SessionEpoch, TerminalSessionId};
    use lomi_terminal::*;
    use lomi_terminal_state::Snapshot;
    use std::time::{Duration, Instant};
    type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
    fn must<T>(value: lomi_terminal::Result<T>) -> Result<T> {
        value.map_err(|e| {
            #[cfg(feature = "windows-pty-proof-hooks")]
            let stage = lomi_windows_pty::proof_hooks::last_service_failure();
            #[cfg(not(feature = "windows-pty-proof-hooks"))]
            let stage = 0;
            format!("synthetic service operation {e:?} stage {stage}").into()
        })
    }
    fn require(value: bool) -> Result<()> {
        if value {
            Ok(())
        } else {
            Err("synthetic service assertion".into())
        }
    }
    fn visible(snapshot: &Snapshot) -> String {
        snapshot
            .normal
            .lines
            .iter()
            .flat_map(|r| r.cells.iter().map(|c| c.text.as_str()))
            .collect()
    }
    fn wait(
        service: &TerminalService,
        id: TerminalSessionId,
        epoch: SessionEpoch,
        marker: &str,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(4);
        while Instant::now() < deadline {
            if visible(&must(service.snapshot(id, epoch))?).contains(marker) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Err("synthetic service output deadline".into())
    }
    pub fn run() -> Result<()> {
        require(lomi_windows_pty::prepare_host_control().is_ok())?;
        let executable = std::env::current_exe()?
            .parent()
            .ok_or("fixture directory")?
            .parent()
            .ok_or("fixture directory")?
            .join("pty-proof.exe");
        let profile = SpawnProfile {
            executable,
            args: vec!["child".into()],
            cwd: std::env::current_dir()?,
            environment: vec![],
            shell_integration: None,
            rows: 24,
            cols: 80,
            history: 8,
        };
        let service = TerminalService::new();
        let id = TerminalSessionId::from_bytes([1; 16]).unwrap();
        let epoch = SessionEpoch::from_bytes([2; 16]).unwrap();
        require(
            service.spawn_with_checks(id, epoch, &profile, || false, || Ok(()))
                == Err(Error::SpawnFailed),
        )?;
        must(service.spawn(id, epoch, &profile))?;
        wait(&service, id, epoch, "PRODUCT_READY")?;
        let owner =
            AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([3; 16]).unwrap());
        let observer =
            AuthenticatedConnection::new(ConsumerAuthorizationId::from_bytes([4; 16]).unwrap());
        let attachment = must(service.attach(id, epoch, &owner))?;
        must(attachment.acknowledge(&owner, attachment.snapshot.sequence.0))?;
        let lease = must(service.claim(id, epoch, &owner))?;
        let second = must(service.attach(id, epoch, &observer))?;
        must(second.acknowledge(&observer, second.snapshot.sequence.0))?;
        require(service.claim(id, epoch, &observer) == Err(Error::ControlRequired))?;
        require(
            service.input(id, epoch, &observer, &lease, 1, 1, b"ping\r\n", || true)
                == Err(Error::ControlRequired),
        )?;
        println!("SERVICE_PHASE_first-input");
        let receipt = must(service.input(id, epoch, &owner, &lease, 1, 1, b"ping\r\n", || true))?;
        require(receipt.outcome == InputOutcome::Accepted)?;
        require(
            must(
                service.input(id, epoch, &owner, &lease, 1, 1, b"ping\r\n", || {
                    panic!("duplicate fence")
                }),
            )? == receipt,
        )?;
        wait(&service, id, epoch, "PRODUCT_PONG")?;
        require(attachment.try_next().is_some() && second.try_next().is_some())?;
        println!("SERVICE_PHASE_resize");
        must(service.resize(id, epoch, &owner, &lease, 1, 37, 101, || true))?;
        // A geometry checkpoint can exceed the existing 1 MiB observer queue.
        // Recover through a fresh acknowledged snapshot and a fresh lease.
        let (_resynced, lease) = if attachment.resync_required() {
            let resumed = must(service.attach(id, epoch, &owner))?;
            must(resumed.acknowledge(&owner, resumed.snapshot.sequence.0))?;
            let lease = must(service.claim(id, epoch, &owner))?;
            (Some(resumed), lease)
        } else {
            (None, lease)
        };
        println!("SERVICE_PHASE_size-input");
        must(service.input(id, epoch, &owner, &lease, 2, 2, b"size\r\n", || true))?;
        wait(&service, id, epoch, "PRODUCT_SIZE")?;
        let snapshot = must(service.snapshot(id, epoch))?;
        require(snapshot.rows == 37 && snapshot.cols == 101)?;
        println!("SERVICE_PHASE_exit-input");
        must(service.input(id, epoch, &owner, &lease, 3, 3, b"exit\r\n", || true))?;
        let deadline = Instant::now() + Duration::from_secs(4);
        while must(service.exited_sessions())?.is_empty() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        require(must(service.exited_sessions())?.len() == 1)?;
        must(service.stop(id))?;
        println!("SERVICE_PHASE_ctrl-session");
        let id = TerminalSessionId::from_bytes([5; 16]).unwrap();
        must(service.spawn(id, epoch, &profile))?;
        wait(&service, id, epoch, "PRODUCT_READY")?;
        let attachment = must(service.attach(id, epoch, &owner))?;
        must(attachment.acknowledge(&owner, attachment.snapshot.sequence.0))?;
        let lease = must(service.claim(id, epoch, &owner))?;
        println!("SERVICE_PHASE_ctrl-input");
        must(service.input(id, epoch, &owner, &lease, 1, 1, &[3], || true))?;
        wait(&service, id, epoch, "PRODUCT_CTRL")?;
        must(service.shutdown())?;
        #[cfg(feature = "windows-pty-proof-hooks")]
        for fault in 0..2 {
            println!("SERVICE_PHASE_FAULT_{fault}");
            let id = TerminalSessionId::from_bytes([6 + fault; 16]).unwrap();
            must(service.spawn(id, epoch, &profile))?;
            wait(&service, id, epoch, "PRODUCT_READY")?;
            let view = must(service.attach(id, epoch, &owner))?;
            must(view.acknowledge(&owner, view.snapshot.sequence.0))?;
            let lease = must(service.claim(id, epoch, &owner))?;
            if fault == 0 {
                lomi_windows_pty::proof_hooks::fail_next_close_thread();
            } else {
                lomi_windows_pty::proof_hooks::fail_next_io_drain();
            }
            must(service.input(id, epoch, &owner, &lease, 1, 1, b"exit\r\n", || true))?;
            let deadline = Instant::now() + Duration::from_secs(4);
            loop {
                match service.exited_sessions() {
                    Err(Error::CleanupFailed) => break,
                    Ok(exits) => require(exits.is_empty())?,
                    _ => return Err("unexpected cleanup readiness".into()),
                }
                require(Instant::now() < deadline)?;
                std::thread::sleep(Duration::from_millis(5));
            }
            // Retry succeeds through the retained owner; no normal exit was
            // eligible for durable reconciliation while cleanup was uncertain.
            must(service.stop(id))?;
        }
        #[cfg(feature = "windows-pty-proof-hooks")]
        {
            println!("SERVICE_PHASE_FINAL_RACE");
            let id = TerminalSessionId::from_bytes([9; 16]).unwrap();
            let mut final_profile = profile.clone();
            final_profile.args = vec!["final-child".into()];
            final_profile.rows = 56;
            final_profile.cols = 128;
            final_profile.history = 0;
            must(service.spawn(id, epoch, &final_profile))?;
            wait(&service, id, epoch, "PRODUCT_FINAL_READY")?;
            let view = must(service.attach(id, epoch, &owner))?;
            must(view.acknowledge(&owner, view.snapshot.sequence.0))?;
            let lease = must(service.claim(id, epoch, &owner))?;
            require(!std::path::Path::new("synthetic-read-timeout-paused").exists())?;
            lomi_windows_pty::proof_hooks::delay_next_read_timeout();
            must(service.input(id, epoch, &owner, &lease, 1, 1, b"final\r\n", || true))?;
            let deadline = Instant::now() + Duration::from_secs(5);
            while must(service.exited_sessions())?.is_empty() {
                require(Instant::now() < deadline)?;
                std::thread::sleep(Duration::from_millis(5));
            }
            println!("SERVICE_PHASE_FINAL_RACE_CHECK");
            require(lomi_windows_pty::proof_hooks::raced_read_completion_observed())?;
            let snapshot = must(service.snapshot(id, epoch))?;
            println!("SERVICE_PHASE_FINAL_MARKER_CHECK");
            require(visible(&snapshot).contains("PRODUCT_FINAL_END"))?;
            println!("SERVICE_PHASE_FINAL_BYTES_CHECK");
            require(must(service.stats(id))?.output_bytes >= 17000)?;
            must(service.stop(id))?;
        }
        println!("PRODUCT_TERMINAL_SERVICE_PASS");
        Ok(())
    }
}
