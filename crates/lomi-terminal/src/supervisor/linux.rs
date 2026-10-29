//! Linux adopted-child cleanup. /proc supplies candidates, never ownership proof.
use super::*;
pub(super) fn reap_descendants() -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
        let result =
            unsafe { libc::waitid(libc::P_ALL, 0, &mut info, libc::WEXITED | libc::WNOHANG) };
        if result < 0 {
            return if io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                Ok(())
            } else {
                Err(Error::CleanupFailed)
            };
        }
        if unsafe { info.si_pid() } != 0 {
            continue;
        }
        let entries = std::fs::read_dir("/proc").map_err(|_| Error::CleanupFailed)?;
        for entry in entries {
            let entry = entry.map_err(|_| Error::CleanupFailed)?;
            let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<libc::pid_t>().ok())
                .filter(|p| *p > 0)
            else {
                continue;
            };
            let Ok(stat) = std::fs::read_to_string(entry.path().join("stat")) else {
                continue;
            };
            let Some(fields) = stat.rsplit_once(')').map(|(_, suffix)| suffix) else {
                continue;
            };
            let parent = fields
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u32>().ok());
            if parent != Some(std::process::id()) {
                continue;
            }
            // A single reaper owns this process. An owned child cannot have its
            // PID reused until we reap it. Recheck through the kernel before
            // opening a pidfd, and only signal through that retained handle.
            let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
            if unsafe {
                libc::waitid(
                    libc::P_PID,
                    pid as _,
                    &mut info,
                    libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
                )
            } < 0
            {
                continue;
            }
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) } as RawFd;
            if fd < 0 {
                return Err(Error::CleanupFailed);
            }
            let handle = unsafe { File::from_raw_fd(fd) };
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    handle.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH) {
                return Err(Error::CleanupFailed);
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(5));
    }
}
