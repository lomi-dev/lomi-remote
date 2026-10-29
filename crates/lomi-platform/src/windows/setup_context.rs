use super::{CurrentAccount, Error, SelectedAccount, WindowsAccount};
use std::{
    ffi::{OsStr, OsString},
    mem,
    os::windows::ffi::{OsStrExt, OsStringExt},
    path::{Component, Path, PathBuf},
    process::ExitStatus,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{
        CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
        WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    },
    Security::{
        GetTokenInformation, LookupAccountNameW, LookupAccountSidW, SidTypeUser, TOKEN_ELEVATION,
        TOKEN_GROUPS, TOKEN_QUERY, TOKEN_USER, TokenElevation, TokenGroups, TokenUser,
    },
    System::{
        Registry::{
            HKEY_LOCAL_MACHINE, REG_EXPAND_SZ, REG_SZ, RRF_NOEXPAND, RRF_RT_REG_EXPAND_SZ,
            RRF_RT_REG_SZ, RRF_SUBKEY_WOW6464KEY, RegGetValueW,
        },
        SystemInformation::GetWindowsDirectoryW,
        Threading::{
            CREATE_NEW_CONSOLE, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
            CreateProcessWithLogonW, GetCurrentProcess, GetExitCodeProcess, INFINITE,
            LOGON_WITH_PROFILE, OpenProcessToken, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
            TerminateProcess, WaitForSingleObject,
        },
    },
    UI::Shell::GetUserProfileDirectoryW,
};
use zeroize::Zeroizing;

const MAX_ACCOUNT_NAME_UNITS: usize = 1024;
const MAX_SID_BYTES: u32 = 4096;
const MAX_DOMAIN_UNITS: u32 = 1024;
const MAX_PROFILE_VALUE_BYTES: u32 = 64 * 1024;
const MAX_COMMAND_UNITS: usize = 1024;
const MAX_ARGUMENTS: usize = 128;
const MAX_ARGUMENT_UNITS: usize = 16 * 1024;
const MAX_TOKEN_INFORMATION: u32 = 1024 * 1024;
const MAX_TOKEN_GROUPS: u32 = 4096;
const CLEANUP_WAIT_MS: u32 = 5_000;
const SYSTEM_SID: &str = "S-1-5-18";
const LOCAL_SERVICE_SID: &str = "S-1-5-19";
const NETWORK_SERVICE_SID: &str = "S-1-5-20";
const BUILTIN_ADMINISTRATORS_SID: &str = "S-1-5-32-544";

/// A credential received from the caller's native hidden prompt.
///
/// The original vector is immediately placed under zeroizing ownership. The
/// private buffer has a single allocation for its final NUL-terminated form.
/// It is intentionally neither clonable nor serializable and formats only as
/// a redacted marker.
pub struct WindowsLogonCredential(Zeroizing<Vec<u16>>);

impl std::fmt::Debug for WindowsLogonCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WindowsLogonCredential([REDACTED])")
    }
}

impl WindowsLogonCredential {
    /// Take ownership of the prompt's UTF-16 buffer and zero it on every exit.
    pub fn from_utf16(password: Vec<u16>) -> Result<Self, Error> {
        let secret = Zeroizing::new(password);
        if secret.is_empty() || secret.len() > 4096 || secret.contains(&0) || !valid_utf16(&secret)
        {
            return Err(Error::InvalidAccount);
        }

        let capacity = secret.len().checked_add(1).ok_or(Error::InvalidAccount)?;
        let mut terminated = Zeroizing::new(Vec::new());
        terminated
            .try_reserve_exact(capacity)
            .map_err(|_| Error::NativeIdentityUnavailable)?;
        terminated.extend_from_slice(&secret);
        terminated.push(0);
        Ok(Self(terminated))
    }

    fn as_ptr(&self) -> Result<*const u16, Error> {
        if self.0.len() < 2
            || self.0.len() > 4097
            || self.0.last() != Some(&0)
            || self.0[..self.0.len() - 1].contains(&0)
            || !valid_utf16(&self.0[..self.0.len() - 1])
        {
            return Err(Error::InvalidAccount);
        }
        Ok(self.0.as_ptr())
    }
}

fn valid_utf16(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let value = units[index];
        if (0xD800..=0xDBFF).contains(&value) {
            index += 1;
            if index >= units.len() || !(0xDC00..=0xDFFF).contains(&units[index]) {
                return false;
            }
        } else if (0xDC00..=0xDFFF).contains(&value) {
            return false;
        }
        index += 1;
    }
    true
}

fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}

fn current_windows_directory() -> Result<PathBuf, Error> {
    let mut wide = vec![0u16; 32_768];
    let length = unsafe { GetWindowsDirectoryW(wide.as_mut_ptr(), wide.len() as u32) };
    if length == 0 || length as usize >= wide.len() {
        return Err(Error::NativeIdentityUnavailable);
    }
    wide.truncate(length as usize);
    let path = PathBuf::from(OsString::from_wide(&wide));
    if !path.is_absolute() {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(path)
}

fn profile_directory_from_token(token: HANDLE) -> Result<PathBuf, Error> {
    let mut required = 0u32;
    unsafe { GetUserProfileDirectoryW(token, ptr::null_mut(), &mut required) };
    if required == 0 || required as usize > 32_768 {
        return Err(Error::NativeIdentityUnavailable);
    }
    let mut wide = vec![0u16; required as usize];
    if unsafe { GetUserProfileDirectoryW(token, wide.as_mut_ptr(), &mut required) } == 0
        || required == 0
        || required as usize > wide.len()
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    wide.truncate(required as usize);
    while wide.last() == Some(&0) {
        wide.pop();
    }
    let path = PathBuf::from(OsString::from_wide(&wide));
    validate_profile_directory(&path)
}

fn validate_profile_directory(path: &Path) -> Result<PathBuf, Error> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|_| Error::AccountProfileRequired)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(Error::AccountProfileRequired);
    }
    let canonical = std::fs::canonicalize(path).map_err(|_| Error::AccountProfileRequired)?;
    if !canonical.is_absolute() {
        return Err(Error::AccountProfileRequired);
    }
    Ok(canonical)
}

fn current_profile_directory() -> Result<PathBuf, Error> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    let path = profile_directory_from_token(token);
    unsafe {
        CloseHandle(token);
    }
    path
}

fn current_token_is_elevated() -> Result<bool, Error> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    let result = (|| {
        let mut elevation: TOKEN_ELEVATION = unsafe { mem::zeroed() };
        let mut returned = 0u32;
        if unsafe {
            GetTokenInformation(
                token,
                TokenElevation,
                (&mut elevation as *mut TOKEN_ELEVATION).cast(),
                mem::size_of::<TOKEN_ELEVATION>() as u32,
                &mut returned,
            )
        } == 0
            || returned as usize != mem::size_of::<TOKEN_ELEVATION>()
        {
            return Err(Error::NativeIdentityUnavailable);
        }
        Ok(elevation.TokenIsElevated != 0)
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

fn expand_profile_environment(raw: &str) -> Result<String, Error> {
    let windows = current_windows_directory()?
        .to_str()
        .ok_or(Error::NativeIdentityUnavailable)?
        .to_owned();
    let drive = windows
        .get(..2)
        .filter(|prefix| prefix.ends_with(':'))
        .ok_or(Error::NativeIdentityUnavailable)?
        .to_owned();
    let mut output = String::with_capacity(raw.len().min(4096));
    let mut rest = raw;
    while let Some(start) = rest.find('%') {
        output.push_str(&rest[..start]);
        let after = &rest[start + 1..];
        let end = after.find('%').ok_or(Error::NativeIdentityUnavailable)?;
        let variable = &after[..end];
        if variable.eq_ignore_ascii_case("systemroot") {
            output.push_str(&windows);
        } else if variable.eq_ignore_ascii_case("systemdrive") {
            output.push_str(&drive);
        } else {
            // ProfileImagePath is machine configuration. Do not expand from
            // an arbitrary caller environment or guess account-specific data.
            return Err(Error::NativeIdentityUnavailable);
        }
        rest = &after[end + 1..];
    }
    output.push_str(rest);
    if output.is_empty() || output.len() > 32_768 || output.chars().any(char::is_control) {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(output)
}

fn registered_profile_directory(sid: &str) -> Result<PathBuf, Error> {
    let key = wide(format!(
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{sid}"
    ));
    let value = wide("ProfileImagePath");
    let mut units = vec![0u16; (MAX_PROFILE_VALUE_BYTES as usize) / mem::size_of::<u16>()];
    let mut value_type = 0u32;
    let mut bytes = MAX_PROFILE_VALUE_BYTES;
    let status = unsafe {
        RegGetValueW(
            HKEY_LOCAL_MACHINE,
            key.as_ptr(),
            value.as_ptr(),
            RRF_RT_REG_SZ | RRF_RT_REG_EXPAND_SZ | RRF_NOEXPAND | RRF_SUBKEY_WOW6464KEY,
            &mut value_type,
            units.as_mut_ptr().cast(),
            &mut bytes,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Err(Error::AccountProfileRequired);
    }
    if status != ERROR_SUCCESS
        || !matches!(value_type, REG_SZ | REG_EXPAND_SZ)
        || bytes == 0
        || bytes > MAX_PROFILE_VALUE_BYTES
        || bytes as usize % mem::size_of::<u16>() != 0
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    units.truncate(bytes as usize / mem::size_of::<u16>());
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(Error::NativeIdentityUnavailable)?;
    if units[end + 1..].iter().any(|unit| *unit != 0) {
        return Err(Error::NativeIdentityUnavailable);
    }
    let raw = String::from_utf16(&units[..end]).map_err(|_| Error::NativeIdentityUnavailable)?;
    if raw.is_empty() || raw.chars().any(char::is_control) {
        return Err(Error::NativeIdentityUnavailable);
    }
    let expanded = if value_type == REG_EXPAND_SZ {
        expand_profile_environment(&raw)?
    } else {
        raw
    };
    validate_profile_directory(Path::new(&expanded))
}

fn account_sid_is_privileged(sid: &str) -> bool {
    sid == SYSTEM_SID
        || sid == LOCAL_SERVICE_SID
        || sid == NETWORK_SERVICE_SID
        || sid.ends_with("-500")
        || sid.starts_with("S-1-5-80-")
}

fn lookup_account_name(name: &str) -> Result<(String, String), Error> {
    if name.is_empty()
        || name.len() > MAX_ACCOUNT_NAME_UNITS
        || name.chars().any(char::is_control)
        || name.encode_utf16().any(|unit| unit == 0)
    {
        return Err(Error::InvalidAccount);
    }
    let input = wide(name);
    let (mut sid_bytes, mut domain_units, mut kind) = (0u32, 0u32, 0i32);
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            input.as_ptr(),
            ptr::null_mut(),
            &mut sid_bytes,
            ptr::null_mut(),
            &mut domain_units,
            &mut kind,
        );
    }
    if sid_bytes == 0
        || sid_bytes > MAX_SID_BYTES
        || domain_units == 0
        || domain_units > MAX_DOMAIN_UNITS
    {
        return Err(Error::AccountNotFound);
    }
    let mut sid_storage = vec![0usize; (sid_bytes as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_units as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            input.as_ptr(),
            sid_storage.as_mut_ptr().cast(),
            &mut sid_bytes,
            domain.as_mut_ptr(),
            &mut domain_units,
            &mut kind,
        )
    } == 0
        || kind != SidTypeUser
        || domain_units == 0
        || domain_units as usize > domain.len()
    {
        return Err(Error::AccountNotFound);
    }
    domain.truncate(domain_units as usize);
    while domain.last() == Some(&0) {
        domain.pop();
    }
    let sid = sid_text(sid_storage.as_mut_ptr().cast())?;
    if account_sid_is_privileged(&sid) {
        return Err(Error::AdministratorRequired);
    }
    let canonical = lookup_account_sid(sid_storage.as_mut_ptr().cast())?;
    Ok((sid, canonical))
}

fn lookup_account_sid(sid: windows_sys::Win32::Security::PSID) -> Result<String, Error> {
    let (mut name_units, mut domain_units, mut kind) = (0u32, 0u32, 0i32);
    unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            ptr::null_mut(),
            &mut name_units,
            ptr::null_mut(),
            &mut domain_units,
            &mut kind,
        );
    }
    if name_units == 0
        || name_units > MAX_ACCOUNT_NAME_UNITS as u32
        || domain_units == 0
        || domain_units > MAX_DOMAIN_UNITS
    {
        return Err(Error::AccountNotFound);
    }
    let mut name = vec![0u16; name_units as usize];
    let mut domain = vec![0u16; domain_units as usize];
    if unsafe {
        LookupAccountSidW(
            ptr::null(),
            sid,
            name.as_mut_ptr(),
            &mut name_units,
            domain.as_mut_ptr(),
            &mut domain_units,
            &mut kind,
        )
    } == 0
        || kind != SidTypeUser
        || name_units == 0
        || name_units as usize > name.len()
        || domain_units == 0
        || domain_units as usize > domain.len()
    {
        return Err(Error::AccountNotFound);
    }
    name.truncate(name_units as usize);
    domain.truncate(domain_units as usize);
    while name.last() == Some(&0) {
        name.pop();
    }
    while domain.last() == Some(&0) {
        domain.pop();
    }
    let username = String::from_utf16(&name).map_err(|_| Error::AccountNotFound)?;
    let domain = String::from_utf16(&domain).map_err(|_| Error::AccountNotFound)?;
    if username.is_empty()
        || domain.is_empty()
        || username.chars().any(char::is_control)
        || domain.chars().any(char::is_control)
        || username.contains(['\\', '/'])
    {
        return Err(Error::AccountNotFound);
    }
    Ok(format!("{domain}\\{username}"))
}

fn sid_text(sid: windows_sys::Win32::Security::PSID) -> Result<String, Error> {
    let mut text = ptr::null_mut();
    if unsafe {
        windows_sys::Win32::Security::Authorization::ConvertSidToStringSidW(sid, &mut text)
    } == 0
        || text.is_null()
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    let result = unsafe {
        let mut length = 0usize;
        while *text.add(length) != 0 {
            length += 1;
            if length > 256 {
                LocalFree(text.cast());
                return Err(Error::NativeIdentityUnavailable);
            }
        }
        String::from_utf16(std::slice::from_raw_parts(text, length))
            .map_err(|_| Error::NativeIdentityUnavailable)
    };
    unsafe {
        LocalFree(text.cast());
    }
    result
}

pub(super) fn current_account() -> Result<CurrentAccount, Error> {
    let (sid, name) = crate::windows::service_admin::current_account()
        .map_err(|_| Error::NativeIdentityUnavailable)?;
    if sid == SYSTEM_SID || current_token_is_elevated()? {
        return Ok(CurrentAccount {
            is_root: true,
            selected: None,
        });
    }
    let home = current_profile_directory()?;
    Ok(CurrentAccount {
        is_root: false,
        selected: Some(SelectedAccount::Windows(WindowsAccount { sid, name, home })),
    })
}

pub(super) fn select_windows_account(name: &str) -> Result<SelectedAccount, Error> {
    let (sid, canonical_name) = lookup_account_name(name)?;
    let home = registered_profile_directory(&sid)?;
    Ok(SelectedAccount::Windows(WindowsAccount {
        sid,
        name: canonical_name,
        home,
    }))
}

pub(super) fn validate_selection(account: &SelectedAccount) -> Result<(), Error> {
    let SelectedAccount::Windows(account) = account else {
        return Err(Error::Unsupported);
    };
    let current = current_account()?;
    if current.selected.as_ref() == Some(&SelectedAccount::Windows(account.clone())) {
        Ok(())
    } else {
        Err(Error::DifferentAccountRequiresNativeLogon)
    }
}

fn validate_selected_target(account: &WindowsAccount) -> Result<(), Error> {
    let (sid, canonical_name) = lookup_account_name(&account.name)?;
    if sid != account.sid || canonical_name != account.name {
        return Err(Error::InvalidAccount);
    }
    let profile = registered_profile_directory(&sid)?;
    if profile != account.home {
        return Err(Error::AccountProfileRequired);
    }
    Ok(())
}

fn validate_executable(executable: &Path) -> Result<(), Error> {
    if !executable.is_absolute()
        || executable
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || std::fs::canonicalize(executable).ok().as_deref() != Some(executable)
        || std::fs::symlink_metadata(executable).map_or(true, |metadata| {
            !metadata.is_file() || metadata.file_type().is_symlink()
        })
    {
        return Err(Error::InvalidExecutable);
    }
    Ok(())
}

fn command_line(executable: &Path, arguments: &[OsString]) -> Result<Vec<u16>, Error> {
    let total_arguments = arguments.iter().try_fold(0usize, |total, argument| {
        total.checked_add(argument.encode_wide().count())
    });
    if arguments.len() > MAX_ARGUMENTS
        || total_arguments.map_or(true, |total| total > MAX_ARGUMENT_UNITS)
        || arguments
            .iter()
            .any(|argument| argument.encode_wide().any(|unit| unit == 0))
    {
        return Err(Error::InvalidExecutable);
    }
    let mut result = Vec::new();
    append_quoted(
        &mut result,
        &executable.as_os_str().encode_wide().collect::<Vec<_>>(),
    );
    for argument in arguments {
        result.push(b' ' as u16);
        append_quoted(&mut result, &argument.encode_wide().collect::<Vec<_>>());
    }
    if result.len() + 1 > MAX_COMMAND_UNITS {
        return Err(Error::InvalidExecutable);
    }
    result.push(0);
    Ok(result)
}

fn append_quoted(command: &mut Vec<u16>, argument: &[u16]) {
    command.push(b'"' as u16);
    let mut backslashes = 0usize;
    for unit in argument {
        if *unit == b'\\' as u16 {
            backslashes += 1;
            continue;
        }
        if *unit == b'"' as u16 {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2 + 1));
        } else {
            command.extend(std::iter::repeat_n(b'\\' as u16, backslashes));
        }
        command.push(*unit);
        backslashes = 0;
    }
    command.extend(std::iter::repeat_n(b'\\' as u16, backslashes * 2));
    command.push(b'"' as u16);
}

fn token_information(token: HANDLE, information_class: i32) -> Result<Vec<usize>, Error> {
    let mut bytes = 0u32;
    unsafe {
        GetTokenInformation(token, information_class, ptr::null_mut(), 0, &mut bytes);
    }
    if bytes == 0 || bytes > MAX_TOKEN_INFORMATION {
        return Err(Error::NativeIdentityUnavailable);
    }
    let words = (bytes as usize).div_ceil(mem::size_of::<usize>());
    let mut buffer = vec![0usize; words];
    if unsafe {
        GetTokenInformation(
            token,
            information_class,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        )
    } == 0
        || bytes as usize > buffer.len() * mem::size_of::<usize>()
    {
        return Err(Error::NativeIdentityUnavailable);
    }
    Ok(buffer)
}

fn validate_target_token(
    process: HANDLE,
    expected_sid: &str,
    expected_home: &Path,
) -> Result<(), Error> {
    let mut token: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::NativeIdentityUnavailable);
    }
    let result = (|| {
        let user = token_information(token, TokenUser)?;
        let user_sid = unsafe { (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid };
        let sid = sid_text(user_sid)?;
        if sid == SYSTEM_SID || sid == LOCAL_SERVICE_SID || sid == NETWORK_SERVICE_SID {
            return Err(Error::AdministratorRequired);
        }
        if sid != expected_sid || account_sid_is_privileged(&sid) {
            return Err(Error::InvalidAccount);
        }
        let profile = profile_directory_from_token(token)?;
        if profile != expected_home {
            return Err(Error::AccountProfileRequired);
        }
        let groups = token_information(token, TokenGroups)?;
        let groups = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
        if groups.GroupCount > MAX_TOKEN_GROUPS {
            return Err(Error::NativeIdentityUnavailable);
        }
        let entries = unsafe {
            std::slice::from_raw_parts(groups.Groups.as_ptr(), groups.GroupCount as usize)
        };
        for group in entries {
            let group_sid = sid_text(group.Sid)?;
            if group_sid == BUILTIN_ADMINISTRATORS_SID
                || group_sid == "S-1-5-32-548"
                || group_sid == "S-1-5-32-549"
                || group_sid == "S-1-5-32-550"
                || group_sid == "S-1-5-32-551"
                || group_sid.ends_with("-512")
            {
                return Err(Error::AdministratorRequired);
            }
        }
        Ok(())
    })();
    unsafe {
        CloseHandle(token);
    }
    result
}

struct ChildHandles {
    process: HANDLE,
    thread: HANDLE,
}

impl ChildHandles {
    fn from_information(information: PROCESS_INFORMATION) -> Result<Self, Error> {
        if information.hProcess.is_null()
            || information.hThread.is_null()
            || information.hProcess == INVALID_HANDLE_VALUE
            || information.hThread == INVALID_HANDLE_VALUE
        {
            if !information.hThread.is_null() && information.hThread != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(information.hThread) };
            }
            if !information.hProcess.is_null() && information.hProcess != INVALID_HANDLE_VALUE {
                unsafe { CloseHandle(information.hProcess) };
            }
            return Err(Error::SpawnFailed);
        }
        Ok(Self {
            process: information.hProcess,
            thread: information.hThread,
        })
    }

    fn close_thread(&mut self) {
        if !self.thread.is_null() && self.thread != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.thread) };
            self.thread = ptr::null_mut();
        }
    }

    fn terminate_before_resume(&mut self) -> Result<(), Error> {
        let terminated = unsafe { TerminateProcess(self.process, 0xE000_0001) } != 0;
        let waited = unsafe { WaitForSingleObject(self.process, CLEANUP_WAIT_MS) };
        if !terminated && waited != WAIT_OBJECT_0 {
            return Err(Error::OperationUncertain);
        }
        if waited != WAIT_OBJECT_0 {
            return Err(Error::OperationUncertain);
        }
        Ok(())
    }
}

impl Drop for ChildHandles {
    fn drop(&mut self) {
        self.close_thread();
        if !self.process.is_null() && self.process != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(self.process) };
            self.process = ptr::null_mut();
        }
    }
}

fn logon_parts(canonical: &str) -> Result<(Vec<u16>, Vec<u16>), Error> {
    let (domain, username) = canonical.rsplit_once('\\').ok_or(Error::InvalidAccount)?;
    if domain.is_empty()
        || username.is_empty()
        || domain.chars().any(char::is_control)
        || username.chars().any(char::is_control)
    {
        return Err(Error::InvalidAccount);
    }
    Ok((wide(username), wide(domain)))
}

pub(super) fn reexec_windows_as_selected(
    account: &SelectedAccount,
    credential: &WindowsLogonCredential,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    let SelectedAccount::Windows(account) = account else {
        return Err(Error::Unsupported);
    };
    validate_selected_target(account)?;
    validate_executable(executable)?;
    let mut command_line = command_line(executable, arguments)?;
    let (username, domain) = logon_parts(&account.name)?;
    let password = credential.as_ptr()?;
    let windows_dir = current_windows_directory()?;
    let current_directory = wide(windows_dir);
    let application = wide(executable.as_os_str());
    let mut startup: STARTUPINFOW = unsafe { mem::zeroed() };
    startup.cb = mem::size_of::<STARTUPINFOW>() as u32;
    let mut information: PROCESS_INFORMATION = unsafe { mem::zeroed() };

    // CreateProcessWithLogonW is not supported from LocalSystem. Detect it
    // before invoking the native API and never fall back to thread impersonation.
    if crate::windows::service_admin::current_account()
        .map_err(|_| Error::NativeIdentityUnavailable)?
        .0
        == SYSTEM_SID
    {
        return Err(Error::DifferentAccountRequiresNativeLogon);
    }
    let created = unsafe {
        CreateProcessWithLogonW(
            username.as_ptr(),
            domain.as_ptr(),
            password,
            LOGON_WITH_PROFILE,
            application.as_ptr(),
            command_line.as_mut_ptr(),
            CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_CONSOLE,
            ptr::null(),
            current_directory.as_ptr(),
            &startup,
            &mut information,
        )
    };
    if created == 0 {
        if !information.hThread.is_null() && information.hThread != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(information.hThread) };
        }
        if !information.hProcess.is_null() && information.hProcess != INVALID_HANDLE_VALUE {
            unsafe { CloseHandle(information.hProcess) };
        }
        return Err(Error::SpawnFailed);
    }
    let mut child = ChildHandles::from_information(information)?;
    if let Err(error) = validate_target_token(child.process, &account.sid, &account.home) {
        child.terminate_before_resume()?;
        return Err(error);
    }
    if unsafe { ResumeThread(child.thread) } == u32::MAX {
        child.terminate_before_resume()?;
        return Err(Error::SpawnFailed);
    }
    child.close_thread();

    let waited = unsafe { WaitForSingleObject(child.process, INFINITE) };
    if waited != WAIT_OBJECT_0 || waited == WAIT_FAILED || waited == WAIT_TIMEOUT {
        return Err(Error::OperationUncertain);
    }
    let mut exit_code = 0u32;
    if unsafe { GetExitCodeProcess(child.process, &mut exit_code) } == 0 {
        return Err(Error::OperationUncertain);
    }
    use std::os::windows::process::ExitStatusExt;
    Ok(ExitStatus::from_raw(exit_code))
}

pub(super) fn reexec_as_selected(
    account: &SelectedAccount,
    executable: &Path,
    arguments: &[OsString],
) -> Result<ExitStatus, Error> {
    validate_selection(account)?;
    validate_executable(executable)?;
    let SelectedAccount::Windows(account) = account else {
        return Err(Error::Unsupported);
    };
    let windows_dir = current_windows_directory()?;
    let path = std::env::join_paths([
        windows_dir.join("System32"),
        windows_dir.clone(),
        windows_dir.join("System32/Wbem"),
    ])
    .map_err(|_| Error::NativeIdentityUnavailable)?;
    let appdata = account.home.join("AppData/Roaming");
    let local_appdata = account.home.join("AppData/Local");
    let mut command = std::process::Command::new(executable);
    command
        .args(arguments)
        .current_dir(&windows_dir)
        .env_clear()
        .env("SystemRoot", &windows_dir)
        .env("WINDIR", &windows_dir)
        .env("USERPROFILE", &account.home)
        .env("HOME", &account.home)
        .env("USER", &account.name)
        .env("LOGNAME", &account.name)
        .env("APPDATA", appdata)
        .env("LOCALAPPDATA", local_appdata)
        .env("PATH", path)
        .env("LC_ALL", "C")
        .env("TERM", "xterm-256color")
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    command.status().map_err(|_| Error::SpawnFailed)
}
