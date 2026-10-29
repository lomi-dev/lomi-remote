//! Detached owner launch with no inherited handles, including redirected caller pipes.
use std::{io, mem, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{Foundation::*, System::Threading::*};
struct Handle(HANDLE);
// Exclusive kernel handle ownership moves to the readiness/reaper thread.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}
pub(super) struct Child {
    process: Handle,
}
impl Child {
    pub(super) fn try_wait(&mut self) -> io::Result<Option<()>> {
        match unsafe { WaitForSingleObject(self.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                self.exit_code()?;
                Ok(Some(()))
            }
            _ => Err(io::Error::last_os_error()),
        }
    }
    fn exit_code(&self) -> io::Result<u32> {
        let mut code = 0;
        if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(code)
        }
    }
    pub(super) fn kill(&mut self) -> io::Result<()> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        if unsafe { TerminateProcess(self.process.0, 1) } == 0 {
            let error = io::Error::last_os_error();
            if self.try_wait()?.is_none() {
                return Err(error);
            }
        }
        Ok(())
    }
    /// Bound readiness-failure cleanup; a ready daemon has an independent IPC lifetime.
    pub(super) fn wait(&mut self) -> io::Result<()> {
        match unsafe { WaitForSingleObject(self.process.0, 3000) } {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => return Err(io::ErrorKind::TimedOut.into()),
            _ => return Err(io::Error::last_os_error()),
        }
        self.exit_code()?;
        Ok(())
    }
}
fn quote(value: &std::ffi::OsStr) -> io::Result<Vec<u16>> {
    let mut result = vec![34];
    let mut slashes = 0;
    for unit in value.encode_wide() {
        if unit == 0 {
            return Err(io::Error::from(io::ErrorKind::InvalidInput));
        }
        if unit == 92 {
            slashes += 1;
            continue;
        }
        result.extend(std::iter::repeat_n(
            92,
            if unit == 34 { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        result.push(unit);
    }
    result.extend(std::iter::repeat_n(92, slashes * 2));
    result.push(34);
    Ok(result)
}
pub(super) fn spawn(executable: &Path, profile: &Path) -> io::Result<Child> {
    spawn_bound(executable, profile, None)
}

pub(super) fn spawn_existing(executable: &Path, profile: &Path) -> io::Result<Child> {
    spawn_inner(executable, profile, None, true)
}

pub(super) fn spawn_bound(
    executable: &Path,
    profile: &Path,
    expected_host_id: Option<lomi_remote_protocol::HostId>,
) -> io::Result<Child> {
    spawn_inner(executable, profile, expected_host_id, false)
}

fn spawn_inner(
    executable: &Path,
    profile: &Path,
    expected_host_id: Option<lomi_remote_protocol::HostId>,
    existing_profile: bool,
) -> io::Result<Child> {
    if !executable.is_absolute() || !profile.is_absolute() {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut application: Vec<u16> = executable.as_os_str().encode_wide().collect();
    if application.contains(&0) {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    application.push(0);
    let mut command = quote(executable.as_os_str())?;
    let mut arguments = vec![
        std::ffi::OsString::from("--profile-dir"),
        profile.as_os_str().to_owned(),
        std::ffi::OsString::from("daemon"),
        std::ffi::OsString::from("run"),
    ];
    if existing_profile && expected_host_id.is_none() {
        arguments.push(std::ffi::OsString::from("--existing-profile"));
    }
    if let Some(expected_host_id) = expected_host_id {
        arguments.push(std::ffi::OsString::from("--expected-host-id"));
        arguments.push(std::ffi::OsString::from(String::from(expected_host_id)));
    }
    for arg in &arguments {
        command.push(32);
        command.extend(quote(arg)?);
    }
    command.push(0);
    if command.len() > 32767 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut startup: STARTUPINFOW = unsafe { mem::zeroed() };
    startup.cb = mem::size_of::<STARTUPINFOW>() as u32;
    // All hStd* remain null. Neither inherited handles nor a console are needed.
    startup.dwFlags = STARTF_USESTDHANDLES;
    let mut info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
    if unsafe {
        CreateProcessW(
            application.as_ptr(),
            command.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            0,
            // An independent daemon must also leave a caller's kill-on-close
            // Job (for example Windows OpenSSH). If that Job forbids breakaway,
            // fail creation rather than report a daemon that dies on disconnect.
            DETACHED_PROCESS
                | CREATE_NEW_PROCESS_GROUP
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_BREAKAWAY_FROM_JOB,
            ptr::null(),
            ptr::null(),
            &startup,
            &mut info,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // Acquire both successful handles before any further operation can fail.
    let child = Child {
        process: Handle(info.hProcess),
    };
    let thread = Handle(info.hThread);
    drop(thread);
    Ok(child)
}
/// Normalize the owned headless host before it creates any terminal children.
/// Clearing the inherited ignore attribute does not attach/allocate a console.
pub(super) fn prepare_console_control() -> io::Result<()> {
    if unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(None, 0) } == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn quote_spaces_quotes_and_trailing_slashes() {
        let value = std::ffi::OsStr::new("a b\"c\\");
        let expected: Vec<u16> = "\"a b\\\"c\\\\\"".encode_utf16().collect();
        assert_eq!(quote(value).unwrap(), expected);
    }
    #[test]
    fn reject_embedded_nul() {
        assert!(quote(std::ffi::OsStr::new("a\0b")).is_err());
    }
}
