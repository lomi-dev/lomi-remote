use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Process identity pinned to a PID version and executable path.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub pid: u32,
    pub executable: PathBuf,
    pub created: u64,
    pub boot: String,
}

impl Identity {
    pub fn read(pid: u32) -> Result<Self, String> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err("Invalid managed process ID".into());
        }
        native(pid).map_err(|error| format!("Cannot verify native process identity: {error}"))
    }

    pub fn still_matches(&self) -> Result<bool, String> {
        Ok(Self::read(self.pid)? == *self)
    }

    pub fn matches_or_exited(&self) -> Result<bool, String> {
        match Self::read(self.pid) {
            Ok(current) => Ok(current == *self),
            Err(_) if self.pid > 0 && self.pid <= i32::MAX as u32 && absent(self.pid) => Ok(false),
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "macos")]
fn absent(pid: u32) -> bool {
    unsafe {
        libc::kill(pid as i32, 0) == -1
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
    }
}

#[cfg(not(target_os = "macos"))]
fn absent(_: u32) -> bool {
    false
}

#[cfg(target_os = "macos")]
fn native(pid: u32) -> Result<Identity, String> {
    use std::{
        ffi::{CStr, c_char, c_int, c_void},
        os::unix::ffi::OsStrExt,
    };
    // rusage_info_v0 from the macOS SDK: UUID followed by ten uint64_t counters.
    #[repr(C)]
    #[derive(Default)]
    struct Usage {
        uuid: [u8; 16],
        counters: [u64; 10],
    }
    unsafe extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, size: u32) -> c_int;
        fn proc_pid_rusage(pid: c_int, flavor: c_int, buffer: *mut c_void) -> c_int;
        fn sysctlbyname(
            name: *const c_char,
            output: *mut c_void,
            size: *mut usize,
            input: *mut c_void,
            input_size: usize,
        ) -> c_int;
    }
    let read = || -> Result<Usage, String> {
        let mut usage = Usage::default();
        if unsafe { proc_pid_rusage(pid as c_int, 0, (&mut usage as *mut Usage).cast()) } != 0 {
            return Err(std::io::Error::last_os_error().to_string());
        }
        if usage.counters[9] != 0 {
            return Err("Process has exited and must be reaped".into());
        }
        Ok(usage)
    };
    let before_audit = AuditToken::fresh(pid)?;
    let before = read()?;
    let mut path = [0u8; 4096];
    if unsafe { proc_pidpath(pid as c_int, path.as_mut_ptr().cast(), path.len() as u32) } <= 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    let path = CStr::from_bytes_until_nul(&path).map_err(|e| e.to_string())?;
    let executable = PathBuf::from(std::ffi::OsStr::from_bytes(path.to_bytes()));
    let mut boot = [0u8; 128];
    let mut length = boot.len();
    if unsafe {
        sysctlbyname(
            c"kern.bootsessionuuid".as_ptr(),
            boot.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
        || length > boot.len()
    {
        return Err("Cannot read the host boot identity".into());
    }
    let boot = CStr::from_bytes_until_nul(&boot[..length])
        .map_err(|e| e.to_string())?
        .to_str()
        .map_err(|e| e.to_string())?
        .to_owned();
    let after = read()?;
    let after_audit = AuditToken::fresh(pid)?;
    if !before_audit.matches(&after_audit)
        || before.counters[8] != after.counters[8]
        || before.uuid != after.uuid
    {
        return Err("Process changed during identity lookup".into());
    }
    Ok(Identity {
        pid,
        executable,
        created: before.counters[8],
        boot,
    })
}

#[cfg(not(target_os = "macos"))]
fn native(_: u32) -> Result<Identity, String> {
    Err("Host process identity is unavailable on this platform".into())
}

#[cfg(target_os = "macos")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(C)]
pub(super) struct AuditToken {
    values: [u32; 8],
}
#[cfg(target_os = "macos")]
impl AuditToken {
    pub(super) fn fresh(pid: u32) -> Result<Self, String> {
        if pid == 0 || pid > i32::MAX as u32 {
            return Err("Invalid audited process ID.".into());
        }
        unsafe extern "C" {
            static mach_task_self_: u32;
            fn task_name_for_pid(target: u32, pid: i32, port: *mut u32) -> i32;
            fn mach_port_deallocate(task: u32, port: u32) -> i32;
        }
        struct Port(u32);
        impl Drop for Port {
            fn drop(&mut self) {
                unsafe {
                    mach_port_deallocate(mach_task_self_, self.0);
                }
            }
        }
        let mut port = 0;
        let status = unsafe { task_name_for_pid(mach_task_self_, pid as i32, &mut port) };
        if status != 0 || port == 0 {
            return Err("Cannot obtain a fresh descendant audit identity.".into());
        }
        let port = Port(port);
        let mut token = Self { values: [0; 8] };
        // SDK mach/task_info.h: TASK_AUDIT_TOKEN returns eight natural_t words.
        const TASK_AUDIT_TOKEN: u32 = 15;
        let mut count = 8;
        let status = unsafe {
            libc::task_info(
                port.0,
                TASK_AUDIT_TOKEN,
                token.values.as_mut_ptr().cast(),
                &mut count,
            )
        };
        if status != 0 || count != 8 || token.pid() != pid || !token.owned() {
            return Err("Cannot establish the audited descendant owner.".into());
        }
        Ok(token)
    }
    pub(super) fn pid(&self) -> u32 {
        unsafe { audit_token_to_pid(*self) as u32 }
    }
    pub(super) fn pid_version(&self) -> u32 {
        unsafe { audit_token_to_pidversion(*self) as u32 }
    }
    fn owned(&self) -> bool {
        unsafe {
            audit_token_to_euid(*self) == libc::geteuid()
                && audit_token_to_ruid(*self) == libc::getuid()
        }
    }
    pub(super) fn matches(&self, other: &Self) -> bool {
        self.pid() == other.pid()
            && self.pid_version() == other.pid_version()
            && self.owned()
            && other.owned()
            && self == other
    }
    /// XNU verifies PID version while retaining the target process reference;
    /// no raw PID signal is used after the ownership inspection.
    pub(super) fn signal(&self, signal: i32) -> Result<(), String> {
        if self.pid() == 0 || self.pid() > i32::MAX as u32 || !self.owned() {
            return Err("Refusing to signal an unauthenticated process identity.".into());
        }
        self.signal_using(signal, c"proc_signal_with_audittoken")
    }
    fn signal_using(&self, signal: i32, name: &std::ffi::CStr) -> Result<(), String> {
        struct Library(*mut std::ffi::c_void);
        impl Drop for Library {
            fn drop(&mut self) {
                unsafe {
                    libc::dlclose(self.0);
                }
            }
        }
        let library = Library(unsafe {
            libc::dlopen(
                c"/usr/lib/libSystem.B.dylib".as_ptr(),
                libc::RTLD_NOW | libc::RTLD_LOCAL,
            )
        });
        if library.0.is_null() {
            return Err(
                "Exact audited signalling is unavailable; ownership remains protected.".into(),
            );
        }
        let symbol = unsafe { libc::dlsym(library.0, name.as_ptr()) };
        if symbol.is_null() {
            return Err(
                "Exact audited signalling is unavailable; ownership remains protected.".into(),
            );
        }
        let send: unsafe extern "C" fn(*mut AuditToken, i32) -> i32 =
            unsafe { std::mem::transmute(symbol) };
        let mut token = *self;
        let error = unsafe { send(&mut token, signal) };
        if error != 0 {
            return Err(format!(
                "Cannot signal the exact audited descendant: OS error {error}."
            ));
        }
        Ok(())
    }
}
#[cfg(target_os = "macos")]
#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> i32;
    fn audit_token_to_pidversion(token: AuditToken) -> i32;
    fn audit_token_to_euid(token: AuditToken) -> u32;
    fn audit_token_to_ruid(token: AuditToken) -> u32;
}

/// Preserve the path and file identity pin used by the desktop custody code.
#[cfg(target_os = "macos")]
pub(crate) fn executable_identity(
    path: &std::path::Path,
) -> Result<(PathBuf, u64, u64, u64, i64, i64), String> {
    use std::{fs, os::unix::fs::MetadataExt};
    let path = path
        .canonicalize()
        .map_err(|_| "Cannot resolve the native client executable.")?;
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| "Cannot inspect the client executable.")?;
    if !metadata.is_file()
        || metadata.mode() & 0o022 != 0
        || ![0, unsafe { libc::geteuid() }].contains(&metadata.uid())
    {
        return Err("The native client executable is not privately owned or trusted.".into());
    }
    Ok((
        path,
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
    ))
}
