//! Native ConPTY/Job adapter. The shared service owns the sole Rust model.
use super::*;
use std::io::Read;
enum Cleanup {
    Pending,
    Confirmed,
    Failed,
}
pub(super) struct Pty {
    native: lomi_windows_pty::Pty,
    cleanup: Cleanup,
    uncertain_output: bool,
}
impl Pty {
    pub(super) fn spawn(
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
    ) -> Result<(Self, Box<dyn Read + Send>)> {
        let profile = lomi_windows_pty::TrustedSpawnProfile {
            executable: profile.executable.clone(),
            args: profile.args.iter().map(Into::into).collect(),
            cwd: profile.cwd.clone(),
            environment: profile
                .environment
                .iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            rows: profile.rows,
            cols: profile.cols,
        };
        let mut pty =
            lomi_windows_pty::Pty::spawn(profile, before_spawn).map_err(|error| match error {
                lomi_windows_pty::Error::InvalidProfile => Error::InvalidArgument,
                lomi_windows_pty::Error::ResourceExhausted => Error::ResourceExhausted,
                lomi_windows_pty::Error::SpawnFailed => Error::SpawnFailed,
                _ => Error::SpawnOutcomeUnknown,
            })?;
        let reader = pty.take_reader().ok_or(Error::SpawnOutcomeUnknown)?;
        Ok((
            Self {
                native: pty,
                cleanup: Cleanup::Pending,
                uncertain_output: false,
            },
            Box::new(reader),
        ))
    }
    fn leader_exited(&self) -> bool {
        self.native.exit().map_or(true, |exit| exit.is_some())
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.native.write(bytes).map_err(|error| {
            std::io::Error::from(match error {
                lomi_windows_pty::Error::Deadline => std::io::ErrorKind::TimedOut,
                _ => std::io::ErrorKind::BrokenPipe,
            })
        })
    }
    pub(super) fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        let result = self.native.resize(rows, cols);
        if result.is_err() {
            self.final_output_unknown(1);
        }
        result.map_err(|_| Error::StateFailed)
    }
    pub(super) fn cleanup_ready(&self) -> Result<bool> {
        match self.cleanup {
            Cleanup::Pending => Ok(false),
            Cleanup::Confirmed => Ok(true),
            Cleanup::Failed => Err(Error::CleanupFailed),
        }
    }
    fn begin_natural_shutdown(&mut self) -> Result<()> {
        self.native
            .begin_shutdown()
            .inspect_err(|_| {
                self.cleanup = Cleanup::Failed;
                #[cfg(feature = "windows-pty-proof-hooks")]
                lomi_windows_pty::proof_hooks::record_service_failure(8);
            })
            .map_err(|_| Error::CleanupFailed)
    }
    fn finish_natural_shutdown(&mut self) -> Result<bool> {
        match self.native.poll_shutdown() {
            Ok(true) => {
                self.cleanup = Cleanup::Confirmed;
                Ok(true)
            }
            Ok(false) => Ok(false),
            Err(_) => {
                self.cleanup = Cleanup::Failed;
                #[cfg(feature = "windows-pty-proof-hooks")]
                lomi_windows_pty::proof_hooks::record_service_failure(9);
                Err(Error::CleanupFailed)
            }
        }
    }
    fn final_output_unknown(&mut self, _reason: u32) {
        #[cfg(feature = "windows-pty-proof-hooks")]
        lomi_windows_pty::proof_hooks::record_service_failure(_reason);
        self.uncertain_output = true;
        self.cleanup = Cleanup::Failed;
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        let result = self.native.shutdown();
        if self.uncertain_output {
            self.cleanup = Cleanup::Failed;
            return Err(Error::CleanupFailed);
        }
        match result {
            Ok(()) => {
                self.cleanup = Cleanup::Confirmed;
                Ok(())
            }
            Err(_) => {
                self.cleanup = Cleanup::Failed;
                Err(Error::CleanupFailed)
            }
        }
    }
}
fn finish(core: &mut Core) {
    if core.exited {
        return;
    }
    core.revoke();
    if core.model.feed(&[]).is_ok()
        && let Ok(snapshot) = core.model.snapshot()
    {
        core.last = snapshot;
    }
    core.exited = true;
    core.exited_at.get_or_insert_with(Instant::now);
    core.publish(
        TerminalEvent::Exited {
            sequence: core.last.sequence.0,
        },
        128,
    );
}
fn replies(core: &mut Core, stopping: &AtomicBool) -> Result<()> {
    if core.model.stats().dropped_replies != 0 {
        return Err(Error::StateFailed);
    }
    let deadline = Instant::now() + WRITE_DEADLINE;
    for reply in core.model.take_replies() {
        let mut written = 0;
        while written < reply.len() {
            if stopping.load(Ordering::Acquire) || Instant::now() >= deadline {
                return Err(Error::StateFailed);
            }
            match core.pty.write(&reply.as_bytes()[written..]) {
                Ok(0) => return Err(Error::SessionExited),
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1))
                }
                Err(_) => return Err(Error::SessionExited),
            }
        }
        core.stats.host_replies = core.stats.host_replies.saturating_add(1);
    }
    Ok(())
}
pub(super) fn pump(
    shared: Arc<Mutex<Core>>,
    stopping: Arc<AtomicBool>,
    mut reader: Box<dyn Read + Send>,
) {
    let mut bytes = [0; 8192];
    let mut draining: Option<(Instant, usize)> = None;
    let mut eof = false;
    while !stopping.load(Ordering::Acquire) {
        let read = if eof { Ok(0) } else { reader.read(&mut bytes) };
        let Ok(mut core) = shared.lock() else { break };
        if core.exited || core.pty.uncertain_output {
            break;
        }
        let expired = core.model.expire_sync(Instant::now());
        if expired.is_err() || (expired == Ok(true) && core.state_changed().is_err()) {
            core.pty.final_output_unknown(2);
            break;
        }
        match read {
            Ok(0) => eof = true,
            Ok(count) => {
                if let Some((deadline, total)) = &mut draining {
                    *total += count;
                    if *total > 1024 * 1024 || Instant::now() >= *deadline {
                        core.pty.final_output_unknown(3);
                        break;
                    }
                }
                core.stats.output_bytes = core.stats.output_bytes.saturating_add(count as u64);
                if core.model.feed(&bytes[..count]).is_err() || core.state_changed().is_err() {
                    core.pty.final_output_unknown(4);
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(_) => {
                core.pty.final_output_unknown(5);
                break;
            }
        }
        if draining.is_none() && (eof || core.pty.leader_exited()) {
            // Close can emit more output or wait for its output pipe to drain.
            // Keep this Reader alive; never hand natural output to a discard drain.
            if core.pty.begin_natural_shutdown().is_err() {
                break;
            }
            core.closing = true;
            core.revoke();
            draining = Some((Instant::now() + Duration::from_secs(3), 0));
        }
        if let Some((deadline, _)) = draining {
            if Instant::now() >= deadline {
                core.pty.final_output_unknown(6);
                break;
            }
            // No child remains to consume terminal replies after Job cleanup.
            let _ = core.model.take_replies();
            if eof {
                match core.pty.finish_natural_shutdown() {
                    Ok(true) => {
                        finish(&mut core);
                        break;
                    }
                    Ok(false) => (),
                    Err(_) => break,
                }
            }
        } else if replies(&mut core, &stopping).is_err() {
            core.pty.final_output_unknown(7);
            break;
        }
        if core
            .lease
            .as_ref()
            .is_some_and(|lease| Instant::now() >= lease.expires)
        {
            core.revoke();
        }
        drop(core);
        thread::sleep(Duration::from_millis(2));
    }
    drop(reader);
    let mut core = shared.lock().unwrap_or_else(|p| p.into_inner());
    finish(&mut core);
    // A failed natural close remains visibly failed until the owner explicitly
    // retries. Output failure still performs best-effort resource cleanup, but
    // can never turn the incomplete final model into a confirmed normal exit.
    if !matches!(core.pty.cleanup, Cleanup::Failed) || core.pty.uncertain_output {
        let _ = core.pty.stop();
    }
}
