//! Unix child identity prerequisites for the standalone host and its helpers.
//!
//! No competing reaper may collect a caller's private `Child`. Native callers
//! must not change SIGCHLD concurrently with ownership checks or signals.
use std::{io, process::Child};

/// Call once at standalone entry, before creating any children or threads.
/// Shared libraries must validate the disposition instead of changing it.
pub fn initialize_child_ownership() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    unsafe { libc::sigemptyset(&mut action.sa_mask) };
    if unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Check the actual kernel action, including auto-reap flags, without mutation.
pub fn require_child_ownership() -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if action.sa_sigaction != libc::SIG_DFL || action.sa_flags & libc::SA_NOCLDWAIT != 0 {
        return Err(io::Error::other("Child retention requires default SIGCHLD"));
    }
    Ok(())
}

/// Confirm that the private child is still unreaped immediately before a signal.
/// This never polls/reaps it; the retained identity cannot be reused during a
/// grace period. A lost identity is an error, never authority to signal a PID.
pub fn require_unreaped_child(child: &Child) -> io::Result<()> {
    require_child_ownership()?;
    let pid = child.id();
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    let mut status: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            pid,
            &mut status,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
