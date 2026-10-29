//! Experimental SDK-visible libproc SPI. Audit tokens bind signals to process
//! identity; numeric PIDs are used only for bounded candidate discovery/queries.
use super::*;
use std::sync::OnceLock;
const CANDIDATES: usize = 8192;
const TASK_AUDIT_TOKEN: libc::task_flavor_t = 15;
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct AuditToken {
    values: [u32; 8],
}
type Signal = unsafe extern "C" fn(*mut AuditToken, libc::c_int) -> libc::c_int;
unsafe extern "C" {
    fn task_name_for_pid(
        task: libc::mach_port_t,
        pid: libc::pid_t,
        name: *mut libc::mach_port_t,
    ) -> libc::kern_return_t;
    fn mach_port_deallocate(
        task: libc::mach_port_t,
        name: libc::mach_port_t,
    ) -> libc::kern_return_t;
}
// libc recommends a separate Mach crate; retain the existing pinned dependency
// and keep that crate-level deprecation isolated to this unchanged OS API.
#[allow(deprecated)]
fn self_task() -> libc::mach_port_t {
    unsafe { libc::mach_task_self() }
}
fn signal_api() -> Option<Signal> {
    static API: OnceLock<Option<Signal>> = OnceLock::new();
    *API.get_or_init(|| {
        let symbol =
            unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
        if symbol.is_null() {
            None
        } else {
            Some(unsafe { std::mem::transmute::<*mut libc::c_void, Signal>(symbol) })
        }
    })
}
pub(super) fn available() -> bool {
    signal_api().is_some()
}
struct TaskName(libc::mach_port_t);
impl Drop for TaskName {
    fn drop(&mut self) {
        if self.0 != 0 {
            unsafe {
                mach_port_deallocate(self_task(), self.0);
            }
        }
    }
}
impl TaskName {
    fn close(mut self) -> Result<()> {
        let result = unsafe { mach_port_deallocate(self_task(), self.0) };
        self.0 = 0;
        if result == libc::KERN_SUCCESS {
            Ok(())
        } else {
            Err(Error::CleanupFailed)
        }
    }
}
fn token(pid: libc::pid_t) -> Result<AuditToken> {
    let mut name = 0;
    let result = unsafe { task_name_for_pid(self_task(), pid, &mut name) };
    let port = TaskName(name);
    if result != libc::KERN_SUCCESS || name == 0 {
        return Err(Error::CleanupFailed);
    }
    let mut token = AuditToken::default();
    let mut count = 8;
    let result = unsafe {
        libc::task_info(
            name,
            TASK_AUDIT_TOKEN,
            token.values.as_mut_ptr().cast(),
            &mut count,
        )
    };
    port.close()?;
    if result != libc::KERN_SUCCESS
        || count != 8
        || token.values[1] != unsafe { libc::geteuid() } as u32
        || token.values[5] != pid as u32
    {
        return Err(Error::CleanupFailed);
    }
    Ok(token)
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
struct Identity {
    pid: i32,
    state: i32,
    seconds: i64,
    micros: i32,
    uid: u32,
    exiting: i32,
    padding: i32,
}
unsafe extern "C" {
    fn lomi_macos_process_snapshot(
        output: *mut Identity,
        capacity: usize,
        written: *mut usize,
    ) -> libc::c_int;
}
fn snapshot() -> Result<Vec<Identity>> {
    let mut identities = vec![Identity::default(); CANDIDATES];
    let mut written = 0;
    let result = unsafe {
        lomi_macos_process_snapshot(identities.as_mut_ptr(), identities.len(), &mut written)
    };
    if result != 0 || written == 0 || written >= CANDIDATES {
        return Err(Error::CleanupFailed);
    }
    identities.truncate(written);
    if identities.iter().any(|identity| {
        identity.pid > 0 && (identity.seconds <= 0 || !(0..1_000_000).contains(&identity.micros))
    }) {
        return Err(Error::CleanupFailed);
    }
    identities.sort_unstable_by_key(|identity| identity.pid);
    if identities.windows(2).any(|pair| pair[0].pid == pair[1].pid) {
        return Err(Error::CleanupFailed);
    }
    Ok(identities)
}
fn same_identity(left: &Identity, right: &Identity) -> bool {
    left.pid == right.pid
        && left.seconds == right.seconds
        && left.micros == right.micros
        && left.uid == right.uid
}
fn current_identity(pid: libc::pid_t) -> Result<Identity> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::uninit();
    let size = std::mem::size_of::<libc::proc_bsdinfo>() as i32;
    if unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size,
        )
    } != size
    {
        return Err(Error::CleanupFailed);
    }
    let info = unsafe { info.assume_init() };
    Ok(Identity {
        pid: info.pbi_pid as i32,
        state: info.pbi_status as i32,
        seconds: info.pbi_start_tvsec as i64,
        micros: info.pbi_start_tvusec as i32,
        uid: info.pbi_uid as u32,
        exiting: 0,
        padding: 0,
    })
}
fn is_session_member(candidate: &Identity, session: libc::pid_t) -> Result<bool> {
    if candidate.pid <= 0
        || candidate.pid == session
        || candidate.uid != unsafe { libc::geteuid() } as u32
        || candidate.state == libc::SZOMB as i32
        || candidate.exiting != 0
    {
        return Ok(false);
    }
    let sid = unsafe { libc::getsid(candidate.pid) };
    if sid >= 0 {
        return Ok(sid == session);
    }
    // KERN_PROC_ALL can retain a process entry after it has begun exiting.
    // ESRCH plus a failed or changed birth-identity query means this snapshot
    // entry is stale; if the same identity remains queryable, preserve unknown.
    let current = current_identity(candidate.pid);
    if current
        .as_ref()
        .map_or(true, |current| !same_identity(candidate, current))
    {
        return Ok(false);
    }
    Err(Error::CleanupFailed)
}
pub(super) fn cleanup_session(session: libc::pid_t) -> Result<()> {
    let signal = signal_api().ok_or(Error::CleanupFailed)?;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let before = snapshot()?;
        let mut dirty = false;
        let mut live_owned = false;
        let Some(leader) = before.iter().find(|identity| identity.pid == session) else {
            return Err(Error::CleanupFailed);
        };
        if leader.state != libc::SZOMB as i32 {
            dirty = true;
        }
        for candidate in before
            .iter()
            .filter(|identity| identity.pid > 0 && identity.pid != session)
        {
            if !is_session_member(candidate, session)? {
                continue;
            }
            let pid = candidate.pid;
            live_owned = true;
            // Bind immutable identity before checking current birth time and SID.
            let mut identity = match token(pid) {
                Ok(token) => token,
                Err(_) => {
                    let current = current_identity(pid);
                    if current.as_ref().is_ok_and(|current| {
                        current.state == libc::SZOMB as i32 || !same_identity(candidate, current)
                    }) {
                        dirty = true;
                        continue;
                    }
                    if unsafe { libc::getsid(pid) } != session {
                        dirty = true;
                        continue;
                    }
                    return Err(Error::CleanupFailed);
                }
            };
            let current = match current_identity(pid) {
                Ok(current) => current,
                Err(_) => {
                    dirty = true;
                    continue;
                }
            };
            if !same_identity(candidate, &current) || unsafe { libc::getsid(pid) } != session {
                dirty = true;
                continue;
            }
            // libproc returns an errno NUMBER directly, unlike kill(2). Only
            // this immutable audit token authorizes a descendant signal.
            let result = unsafe { signal(&mut identity, libc::SIGKILL) };
            if result != 0 && result != libc::ESRCH {
                return Err(Error::CleanupFailed);
            }
        }
        let after = snapshot()?;
        let mut live_after = false;
        for candidate in &after {
            if is_session_member(candidate, session)? {
                live_after = true;
                break;
            }
        }
        // Experimental convergence check only: KERN_PROC_ALL proc_iterate skips
        // SIDL and vanished PIDs and is not an atomic containment proof. The
        // platform qualification must retain this fork-churn limitation.
        // Unrelated host process churn does not hold same-session cleanup open.
        if !dirty && !live_owned && !live_after {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(2));
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn experimental_api_resolves_and_task_name_token_matches_owned_process() {
        assert!(available());
        let current = token(std::process::id() as i32).unwrap();
        assert_eq!(current.values[5], std::process::id());
        let all = snapshot().unwrap();
        let own = all
            .iter()
            .find(|identity| identity.pid == std::process::id() as i32)
            .unwrap();
        assert!(same_identity(own, &current_identity(own.pid).unwrap()));
    }
    #[test]
    fn experimental_task_name_token_binds_an_owned_child() {
        struct Owned(Child);
        impl Drop for Owned {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }
        let child = Owned(Command::new("/bin/sleep").arg("5").spawn().unwrap());
        let identity = token(child.0.id() as i32).unwrap();
        assert_eq!(identity.values[5], child.0.id());
    }

    #[test]
    fn exiting_and_zombie_snapshot_entries_are_not_live_session_members() {
        let exiting = Identity {
            pid: i32::MAX,
            state: libc::SRUN as i32,
            uid: unsafe { libc::geteuid() } as u32,
            exiting: 1,
            ..Identity::default()
        };
        let zombie = Identity {
            state: libc::SZOMB as i32,
            exiting: 0,
            ..exiting
        };
        assert!(!is_session_member(&exiting, 42).unwrap());
        assert!(!is_session_member(&zombie, 42).unwrap());
    }
}
