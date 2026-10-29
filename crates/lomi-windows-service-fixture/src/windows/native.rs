//! Small RAII guards around the pinned windows-sys ABI. No foreign handles are adopted.
use std::{ffi::c_void, io, mem, os::windows::ffi::OsStrExt, path::Path, ptr};
use windows_sys::Win32::{
    Foundation::*,
    Security::{Authorization::*, *},
    Storage::FileSystem::{DELETE, WRITE_DAC, WRITE_OWNER},
    System::SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
    System::{Console::*, JobObjects::*, RemoteDesktop::ProcessIdToSessionId, Threading::*},
};
pub type Result<T> = io::Result<T>;
pub fn denied(message: &'static str) -> io::Error {
    io::Error::other(message)
}
pub fn wide(value: impl AsRef<std::ffi::OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
pub fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
pub struct Handle(pub HANDLE);
impl Handle {
    pub fn new(handle: HANDLE) -> Result<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle))
        }
    }
}
// Kernel handles may be moved to their exclusive worker thread.
unsafe impl Send for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
pub struct Local(pub *mut c_void);
impl Drop for Local {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}
pub struct Security {
    _descriptor: Local,
    pub attributes: SECURITY_ATTRIBUTES,
}
impl Security {
    pub fn new(sddl: &str) -> Result<Self> {
        let mut descriptor = ptr::null_mut();
        unsafe {
            check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            ))?;
        }
        Ok(Self {
            _descriptor: Local(descriptor),
            attributes: SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        })
    }
    pub fn canonical(&self) -> Result<String> {
        descriptor_text(self.attributes.lpSecurityDescriptor)
    }
}
pub fn descriptor_text(descriptor: PSECURITY_DESCRIPTOR) -> Result<String> {
    let mut output = ptr::null_mut();
    unsafe {
        check(ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            1,
            DACL_SECURITY_INFORMATION,
            &mut output,
            ptr::null_mut(),
        ))?;
    }
    let _guard = Local(output.cast());
    let mut length = 0;
    unsafe {
        while *output.add(length) != 0 {
            length += 1;
            if length > 8192 {
                return Err(denied("ACL too large"));
            }
        }
    }
    Ok(String::from_utf16_lossy(unsafe {
        std::slice::from_raw_parts(output, length)
    }))
}
pub fn check_directory_acl(path: &Path, expected: &Security) -> Result<()> {
    let mut descriptor = ptr::null_mut();
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(io::Error::from_raw_os_error(error as i32));
    }
    let _guard = Local(descriptor);
    if descriptor_text(descriptor)? != expected.canonical()? {
        return Err(denied("unexpected directory ACL"));
    }
    Ok(())
}
pub fn local_service() -> Result<bool> {
    let mut token = ptr::null_mut();
    unsafe {
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
    }
    let token = Handle::new(token)?;
    let mut length = 0;
    unsafe {
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length);
    }
    if length == 0 || length > 4096 {
        return Err(denied("invalid token size"));
    }
    let mut buffer = vec![0usize; (length as usize).div_ceil(mem::size_of::<usize>())];
    unsafe {
        check(GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        ))?;
    }
    let user = unsafe { &*buffer.as_ptr().cast::<TOKEN_USER>() };
    let mut sid = ptr::null_mut();
    unsafe {
        check(ConvertStringSidToSidW(wide("S-1-5-19").as_ptr(), &mut sid))?;
    }
    let _sid = Local(sid);
    Ok(unsafe { EqualSid(user.User.Sid, sid) } != 0)
}
pub fn session_id() -> Result<u32> {
    let mut id = u32::MAX;
    unsafe {
        check(ProcessIdToSessionId(GetCurrentProcessId(), &mut id))?;
    }
    Ok(id)
}
pub struct Job(pub Handle);
impl Job {
    pub fn new() -> Result<Self> {
        let handle = Handle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            check(SetInformationJobObject(
                handle.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of_val(&limits) as u32,
            ))?;
        }
        Ok(Self(handle))
    }
    pub fn active(&self) -> Result<u32> {
        let mut information: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { mem::zeroed() };
        unsafe {
            check(QueryInformationJobObject(
                self.0.0,
                JobObjectBasicAccountingInformation,
                (&mut information as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                mem::size_of_val(&information) as u32,
                ptr::null_mut(),
            ))?;
        }
        Ok(information.ActiveProcesses)
    }
    pub fn terminate(&self) -> Result<()> {
        unsafe { check(TerminateJobObject(self.0.0, 1)) }
    }
}
// Acquired immediately after CreateProcessW, before assignment or ResumeThread.
// A suspended child must be terminated explicitly even if job assignment fails.
pub struct Process {
    pub process: Handle,
    pub thread: Handle,
    pub pid: u32,
}
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            if WaitForSingleObject(self.process.0, 0) == WAIT_TIMEOUT {
                TerminateProcess(self.process.0, 1);
                WaitForSingleObject(self.process.0, 2000);
            }
        }
    }
}
pub struct Attributes {
    pub storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    pub fn new(console: HPCON) -> Result<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err(denied("invalid attribute allocation"));
        }
        let mut result = Self {
            storage: vec![0; size.div_ceil(mem::size_of::<usize>())],
            initialized: false,
        };
        unsafe {
            check(InitializeProcThreadAttributeList(
                result.pointer(),
                1,
                0,
                &mut size,
            ))?;
        }
        result.initialized = true;
        unsafe {
            check(UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const c_void,
                mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
        }
        Ok(result)
    }
    pub fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        // Also covers post-resume setup failures before Session exists. The
        // explicit shutdown path reports errors; Drop remains a bounded fallback.
        if self.active().ok() != Some(0) {
            let _ = self.terminate();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while self.active().ok().is_some_and(|count| count != 0)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        // Handle::drop closes the final job handle, enforcing KILL_ON_JOB_CLOSE
        // even when the explicit termination/query API fails.
    }
}

pub fn check_owner(path: &Path, expected: &[&str]) -> Result<()> {
    let mut descriptor = ptr::null_mut();
    let mut owner = ptr::null_mut();
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    let _descriptor = Local(descriptor);
    for text in expected {
        let mut sid = ptr::null_mut();
        unsafe {
            check(ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid))?;
        }
        let _sid = Local(sid);
        if unsafe { EqualSid(owner, sid) } != 0 {
            return Ok(());
        }
    }
    Err(denied("untrusted directory owner"))
}
pub fn no_untrusted_parent_delete(path: &Path) -> Result<()> {
    let mut descriptor = ptr::null_mut();
    let mut acl = ptr::null_mut();
    let error = unsafe {
        GetNamedSecurityInfoW(
            wide(path).as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    };
    if error != 0 {
        return Err(std::io::Error::from_raw_os_error(error as i32));
    }
    let _descriptor = Local(descriptor);
    if acl.is_null() {
        return Err(denied("missing parent DACL"));
    }
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        unsafe {
            check(GetAce(acl, index as u32, &mut ace))?;
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        // This OS directory needs ordinary filesystem ACEs only. Unknown allow
        // representations fail closed rather than guessing their SID/mask layout.
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(denied("unsupported parent ACE"));
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        if allowed.Mask & (0x40 | WRITE_DAC | WRITE_OWNER | DELETE | GENERIC_ALL | GENERIC_WRITE)
            == 0
        {
            continue;
        }
        let mut trusted = false;
        for identity in ["S-1-5-18", "S-1-5-32-544"] {
            let mut sid = ptr::null_mut();
            unsafe {
                check(ConvertStringSidToSidW(wide(identity).as_ptr(), &mut sid))?;
            }
            let _sid = Local(sid);
            if unsafe { EqualSid((&allowed.SidStart as *const u32).cast_mut().cast(), sid) } != 0 {
                trusted = true;
            }
        }
        if !trusted {
            return Err(denied("untrusted directory replacement rights"));
        }
    }
    Ok(())
}
