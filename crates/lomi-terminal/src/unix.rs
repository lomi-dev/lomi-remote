use super::*;
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use std::io::{Read, Write};

fn preserves_child_status() -> bool {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    unsafe {
        libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) == 0
            && action.sa_sigaction == libc::SIG_DFL
            && action.sa_flags & libc::SA_NOCLDWAIT == 0
    }
}
fn owns_unreaped_child(pid: libc::pid_t) -> bool {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    // A zero result with no pending exit still proves this is our live child.
    // WNOWAIT preserves an already-exited child's identity instead of reaping.
    unsafe {
        libc::waitid(
            libc::P_PID,
            pid as _,
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        ) == 0
    }
}
/// Only the dedicated group created by portable-pty is owned. Keep its leader
/// unreaped until the final group signal, preventing PID/group-ID reuse.
struct ChildGuard {
    child: Box<dyn Child + Send + Sync>,
    group: libc::pid_t,
    armed: bool,
    signalled: bool,
    numeric_cleanup: bool,
}
impl ChildGuard {
    fn new(
        child: Box<dyn Child + Send + Sync>,
        numeric_cleanup: bool,
    ) -> std::result::Result<Self, Box<dyn Child + Send + Sync>> {
        let Some(group) = child
            .process_id()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
        else {
            return Err(child);
        };
        // Pinned portable-pty 0.9 performs checked setsid in pre_exec before
        // reporting successful spawn. Darwin getpgid only finds live processes,
        // so it can return ESRCH for our already-exited but unreaped leader.
        // Prove kernel child ownership without reaping; retain the established
        // original group identity even after its leader has exited.
        if !preserves_child_status() || !owns_unreaped_child(group) {
            return Err(child);
        }
        Ok(Self {
            child,
            group,
            armed: true,
            signalled: false,
            numeric_cleanup,
        })
    }
    fn signal(&mut self) -> Result<()> {
        if !self.armed || self.signalled {
            return Ok(());
        }
        if !self.numeric_cleanup {
            return Err(Error::CleanupFailed);
        }
        self.signal_group(libc::SIGKILL)?;
        self.signalled = true;
        Ok(())
    }
    fn signal_group(&self, requested: libc::c_int) -> Result<()> {
        if !self.numeric_cleanup {
            return Err(Error::CleanupFailed);
        }
        let signal = unsafe { libc::kill(-self.group, requested) };
        if signal < 0 {
            let error = std::io::Error::last_os_error().raw_os_error();
            let harmless = error == Some(libc::ESRCH);
            #[cfg(target_os = "macos")]
            let harmless = if error == Some(libc::EPERM) {
                !group_has_live_members(self.group)?
            } else {
                harmless
            };
            if !harmless {
                return Err(Error::CleanupFailed);
            }
        }
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        if !self.armed {
            return Ok(());
        }
        if !self.numeric_cleanup {
            return if self
                .child
                .try_wait()
                .map_err(|_| Error::CleanupFailed)?
                .is_some()
            {
                self.armed = false;
                Ok(())
            } else {
                Err(Error::CleanupFailed)
            };
        }
        self.signal()?;
        let _ = self.child.kill();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self
                .child
                .try_wait()
                .map_err(|_| Error::CleanupFailed)?
                .is_some()
            {
                self.armed = false;
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(Error::CleanupFailed);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }
}
// Darwin returns EPERM for some groups consisting only of zombies. Inspect
// numeric process-group membership/state; never turn a live-member signal error
// into successful cleanup. Fixed storage fails closed if the list is truncated.
#[cfg(target_os = "macos")]
fn group_has_live_members(group: libc::pid_t) -> Result<bool> {
    let mut pids = [0i32; 4096];
    let capacity = std::mem::size_of_val(&pids) as i32;
    // PROC_PGRP_ONLY=2 is defined by Apple's sys/proc_info.h.
    let bytes = unsafe { libc::proc_listpids(2, group as u32, pids.as_mut_ptr().cast(), capacity) };
    if bytes <= 0 || bytes >= capacity {
        return Err(Error::CleanupFailed);
    }
    for pid in pids
        .into_iter()
        .take(bytes as usize / std::mem::size_of::<i32>())
        .filter(|p| *p > 0)
    {
        let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
        let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
        let copied = unsafe {
            libc::proc_pidinfo(
                pid,
                libc::PROC_PIDTBSDINFO,
                0,
                info.as_mut_ptr().cast(),
                size,
            )
        };
        if copied != size {
            if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                continue;
            }
            return Err(Error::CleanupFailed);
        }
        let info = unsafe { info.assume_init() };
        if info.pbi_pgid == group as u32 && info.pbi_status != libc::SZOMB {
            return Ok(true);
        }
    }
    Ok(false)
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
pub(super) struct Pty {
    master: Option<Box<dyn MasterPty + Send>>,
    writer: Option<Box<dyn Write + Send>>,
    child: Option<ChildGuard>,
    worker: Option<supervisor::Worker>,
    remote_master: Option<std::fs::File>,
}
impl Pty {
    pub(super) fn spawn(
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
    ) -> Result<(Self, Box<dyn Read + Send>)> {
        let mut pty = Self::acquire(profile, before_spawn, false)?;
        let master = pty.master.as_ref().expect("owned master");
        let fd = master.as_raw_fd().ok_or(Error::SpawnOutcomeUnknown)?;
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::SpawnOutcomeUnknown);
        }
        let reader = master
            .try_clone_reader()
            .map_err(|_| Error::SpawnOutcomeUnknown)?;
        let writer = match master.take_writer() {
            Ok(writer) => writer,
            Err(_) => {
                drop(reader);
                return Err(Error::SpawnOutcomeUnknown);
            }
        };
        pty.writer = Some(writer);
        Ok((pty, reader))
    }
    pub(super) fn acquire(
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
        persistent_cleanup: bool,
    ) -> Result<Self> {
        Self::acquire_inner(profile, before_spawn, persistent_cleanup, true, None)
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    pub(super) fn acquire_coalition(
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
    ) -> Result<Self> {
        Self::acquire_inner(profile, before_spawn, true, false, None)
    }

    fn acquire_inner(
        profile: &SpawnProfile,
        before_spawn: impl FnOnce() -> bool,
        persistent_cleanup: bool,
        numeric_cleanup: bool,
        exec_failed: Option<&mut bool>,
    ) -> Result<Self> {
        if !profile.executable.is_absolute() || !profile.cwd.is_absolute() {
            return Err(Error::InvalidArgument);
        }
        // Never start a child whose status could auto-reap and invalidate its
        // PID/group pin. Production workers establish this disposition first.
        if !preserves_child_status() {
            return Err(Error::SpawnFailed);
        }
        let pair = native_pty_system()
            .openpty(size(profile.rows, profile.cols))
            .map_err(|_| Error::SpawnFailed)?;
        let mut command = CommandBuilder::new(&profile.executable);
        command.args(&profile.args);
        command.cwd(&profile.cwd);
        command.env_clear();
        for (name, value) in &profile.environment {
            command.env(name, value);
        }
        if !before_spawn() {
            return Err(Error::SpawnFailed);
        }
        let raw_child = pair.slave.spawn_command(command).map_err(|_| {
            // This exact pinned portable-pty -> std::Command::spawn error
            // proves user executable never ran and exec-failure child was
            // reaped by std. NEVER set for any post-spawn/guard/setup error.
            if let Some(exec_failed) = exec_failed {
                *exec_failed = true;
            }
            Error::SpawnFailed
        })?;
        let child = match ChildGuard::new(raw_child, numeric_cleanup) {
            Ok(child) => child,
            Err(mut child) => {
                // No proven dedicated group: kill only the owned handle. Close
                // both PTY ends before waiting (required for Darwin reaping).
                let pinned = child
                    .process_id()
                    .and_then(|pid| i32::try_from(pid).ok())
                    .filter(|pid| *pid > 0)
                    .is_some_and(owns_unreaped_child);
                if numeric_cleanup && pinned && preserves_child_status() {
                    let _ = child.kill();
                }
                drop(pair);
                let deadline = Instant::now() + Duration::from_secs(2);
                while (persistent_cleanup && numeric_cleanup) || Instant::now() < deadline {
                    if child.try_wait().ok().flatten().is_some() {
                        break;
                    }
                    thread::sleep(Duration::from_millis(2));
                }
                return Err(Error::SpawnOutcomeUnknown);
            }
        };
        drop(pair.slave);
        // Establish the owning PTY guard before any fallible post-exec setup.
        let pty = Self {
            master: Some(pair.master),
            writer: None,
            child: Some(child),
            worker: None,
            remote_master: None,
        };
        Ok(pty)
    }
    pub(super) fn from_worker(
        master: std::fs::File,
        worker: supervisor::Worker,
    ) -> Result<(Self, Box<dyn Read + Send>)> {
        let reader = master.try_clone().map_err(|_| Error::SpawnOutcomeUnknown)?;
        let writer = master.try_clone().map_err(|_| Error::SpawnOutcomeUnknown)?;
        Ok((
            Self {
                master: None,
                writer: Some(Box::new(writer)),
                child: None,
                worker: Some(worker),
                remote_master: Some(master),
            },
            Box::new(reader),
        ))
    }
    pub(super) fn worker_fd(&self) -> std::os::fd::RawFd {
        self.master.as_ref().unwrap().as_raw_fd().unwrap()
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    pub(super) fn dispose_coalition_pty(&mut self) {
        self.writer.take();
        self.master.take();
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-coalition-cleanup"))]
    pub(super) fn reap_coalition_leader(&mut self) -> Result<bool> {
        let child = self.child.as_mut().ok_or(Error::CleanupFailed)?;
        if !child.armed {
            return Ok(true);
        }
        if child
            .child
            .try_wait()
            .map_err(|_| Error::CleanupFailed)?
            .is_some()
        {
            child.armed = false;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    pub(super) fn leader_exited(&self) -> bool {
        let Some(child) = &self.child else {
            return false;
        };
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        // Observe without reaping, retaining the original group identity.
        unsafe {
            libc::waitid(
                libc::P_PID,
                child.group as _,
                &mut info,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            ) == 0
                && info.si_pid() != 0
        }
    }
    pub(super) fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.writer
            .as_mut()
            .ok_or(std::io::ErrorKind::BrokenPipe)?
            .write(bytes)
    }
    pub(super) fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        if let Some(master) = &self.remote_master {
            use std::os::fd::AsRawFd;
            let winsize = libc::winsize {
                ws_row: rows,
                ws_col: cols,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            return if unsafe { libc::ioctl(master.as_raw_fd(), libc::TIOCSWINSZ, &winsize) } == 0 {
                Ok(())
            } else {
                Err(Error::StateFailed)
            };
        }
        self.master
            .as_ref()
            .ok_or(Error::SessionExited)?
            .resize(size(rows, cols))
            .map_err(|_| Error::StateFailed)
    }
    pub(super) fn cleanup_ready(&self) -> Result<bool> {
        self.worker
            .as_ref()
            .map_or(Ok(true), supervisor::Worker::finished)
    }
    pub(super) fn worker_finished(&self) -> Result<bool> {
        self.worker
            .as_ref()
            .map_or(Ok(false), supervisor::Worker::finished)
    }
    #[cfg(all(target_os = "macos", feature = "experimental-macos-session-cleanup"))]
    pub(super) fn worker_group(&self) -> libc::pid_t {
        self.child.as_ref().unwrap().group
    }
    pub(super) fn final_worker_signal(&mut self) -> Result<()> {
        self.child.as_mut().unwrap().signal()
    }

    pub(super) fn reap_worker_leader(&mut self) -> Result<()> {
        self.child.as_mut().unwrap().stop()
    }
    pub(super) fn begin_worker_shutdown(&mut self) -> Result<()> {
        let graceful = if let Some(child) = &self.child {
            // The owned leader remains unreaped, pinning this original group.
            // Give an ordinary interactive shell a chance to HUP its job groups
            // before the final SIGKILL; no discovered numeric group is signalled.
            child
                .signal_group(libc::SIGHUP)
                .and_then(|_| child.signal_group(libc::SIGCONT))
        } else {
            Ok(())
        };
        self.writer.take();
        self.master.take();
        graceful
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        if let Some(worker) = &mut self.worker {
            self.writer.take();
            self.remote_master.take();
            return worker.stop();
        }
        let child = self.child.as_mut().expect("direct child");
        let signal = child.signal();
        // Interactive Darwin PTYs can defer child status while their master is
        // still open. The reader has been dropped by pump before reaching here.
        self.writer.take();
        self.master.take();
        let reaped = child.stop();
        signal.and(reaped)
    }
}
impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}
fn size(rows: u16, cols: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
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
    // A cleanup ACK may coexist with a surviving slave writer on macOS. Bound
    // final output after ACK so that writer cannot retain the model/control.
    let mut final_drain: Option<(Instant, usize)> = None;
    const FINAL_DRAIN_BYTES: usize = 256 * 1024;
    while !stopping.load(Ordering::Acquire) {
        let read = reader.read(&mut bytes);
        let Ok(mut core) = shared.lock() else {
            break;
        };
        if core.exited {
            break;
        }
        match core.pty.worker_finished() {
            Err(_) => {
                core.closing = true;
                core.revoke();
                finish(&mut core);
                break;
            }
            Ok(true) if final_drain.is_none() => {
                core.closing = true;
                core.revoke();
                final_drain = Some((Instant::now() + WRITE_DEADLINE, FINAL_DRAIN_BYTES));
            }
            Ok(_) => {}
        }
        if final_drain
            .is_some_and(|(deadline, remaining)| Instant::now() >= deadline || remaining == 0)
        {
            finish(&mut core);
            break;
        }
        let expired = core.model.expire_sync(Instant::now());
        if expired.is_err() || (expired == Ok(true) && core.state_changed().is_err()) {
            finish(&mut core);
            break;
        }
        match read {
            Ok(0) => {
                finish(&mut core);
                break;
            }
            Ok(count) => {
                if let Some((_, remaining)) = &mut final_drain {
                    *remaining = remaining.saturating_sub(count);
                }
                core.stats.output_bytes = core.stats.output_bytes.saturating_add(count as u64);
                if core.model.feed(&bytes[..count]).is_err() || core.state_changed().is_err() {
                    finish(&mut core);
                    break;
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if final_drain.is_some() {
                    finish(&mut core);
                    break;
                }
            }
            Err(error) if error.raw_os_error() == Some(libc::EIO) => {
                finish(&mut core);
                break;
            }
            Err(_) => {
                finish(&mut core);
                break;
            }
        }
        if final_drain.is_none() && replies(&mut core, &stopping).is_err() {
            finish(&mut core);
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
    let _ = core.pty.stop();
}
