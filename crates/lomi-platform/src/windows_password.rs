//! Hidden, native-console password prompts for Windows account/service setup.
//!
//! Password input is read directly with `ReadConsoleW`; redirected stdin and
//! output are rejected. The fixed-size source buffer is zeroized on every
//! return path, and the constructors immediately take ownership of a bounded
//! copied UTF-16 vector under zeroizing storage.

use std::sync::Mutex;
use windows_sys::Win32::{
    Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE},
    Storage::FileSystem::{
        CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
    },
    System::Console::{
        AllocConsole, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
        FlushConsoleInputBuffer, FreeConsole, GetConsoleMode, GetStdHandle, ReadConsoleW,
        STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE, SetConsoleMode, SetStdHandle,
        WriteConsoleW,
    },
};
use zeroize::Zeroizing;

const MAX_PASSWORD_UNITS: usize = 4096;
const MAX_LABEL_BYTES: usize = 512;
const MAX_LABEL_CHARS: usize = 96;

static PROMPT_LOCK: Mutex<()> = Mutex::new(());

/// Temporary native-console attachment for a maintenance worker that was
/// launched without inherited standard handles. It never owns or stores a
/// credential; dropping it restores the previous process handles.
pub struct PromptConsoleGuard {
    input: HANDLE,
    output: HANDLE,
    old_input: HANDLE,
    old_output: HANDLE,
    old_error: HANDLE,
    allocated_console: bool,
}

impl Drop for PromptConsoleGuard {
    fn drop(&mut self) {
        unsafe {
            SetStdHandle(STD_INPUT_HANDLE, self.old_input);
            SetStdHandle(STD_OUTPUT_HANDLE, self.old_output);
            SetStdHandle(STD_ERROR_HANDLE, self.old_error);
            CloseHandle(self.input);
            CloseHandle(self.output);
            if self.allocated_console {
                FreeConsole();
            }
        }
    }
}

/// Ensure hidden credential prompts can use a genuine Windows console.
/// Existing console handles are left untouched. When this process has no
/// console (for example, a no-window updater worker), allocate one and bind
/// its input/output devices only for the guard's lifetime.
pub fn attach_prompt_console() -> Result<Option<PromptConsoleGuard>, PromptError> {
    let old_input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let old_output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    let old_error = unsafe { GetStdHandle(STD_ERROR_HANDLE) };
    if is_console_handle(old_input) && is_console_handle(old_output) {
        return Ok(None);
    }

    let allocated_console = unsafe { AllocConsole() } != 0;
    let input = match open_console_device(&[67, 79, 78, 73, 78, 36, 0]) {
        Ok(input) => input,
        Err(error) => {
            if allocated_console {
                unsafe { FreeConsole() };
            }
            return Err(error);
        }
    };
    let output = match open_console_device(&[67, 79, 78, 79, 85, 84, 36, 0]) {
        Ok(output) => output,
        Err(error) => {
            unsafe {
                CloseHandle(input);
                if allocated_console {
                    FreeConsole();
                }
            }
            return Err(error);
        }
    };
    let guard = PromptConsoleGuard {
        input,
        output,
        old_input,
        old_output,
        old_error,
        allocated_console,
    };
    if unsafe {
        SetStdHandle(STD_INPUT_HANDLE, input) == 0
            || SetStdHandle(STD_OUTPUT_HANDLE, output) == 0
            || SetStdHandle(STD_ERROR_HANDLE, output) == 0
    } {
        drop(guard);
        return Err(PromptError::ConsoleUnavailable);
    }
    if !is_console_handle(unsafe { GetStdHandle(STD_INPUT_HANDLE) })
        || !is_console_handle(unsafe { GetStdHandle(STD_OUTPUT_HANDLE) })
    {
        drop(guard);
        return Err(PromptError::ConsoleRequired);
    }
    Ok(Some(guard))
}

fn open_console_device(name: &[u16]) -> Result<HANDLE, PromptError> {
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if invalid_handle(handle) {
        Err(PromptError::ConsoleUnavailable)
    } else {
        Ok(handle)
    }
}

fn is_console_handle(handle: HANDLE) -> bool {
    if invalid_handle(handle) {
        return false;
    }
    let mut mode = 0u32;
    unsafe { GetConsoleMode(handle, &mut mode) != 0 }
}

/// Redacted error states returned by the native hidden prompt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptError {
    ConsoleRequired,
    ConsoleUnavailable,
    ConsoleIo,
    ConsoleModeRestore,
    PromptBusy,
    InvalidAccountLabel,
    Cancelled,
    PasswordTooLong,
    InvalidPassword,
    CredentialRejected,
}

impl std::fmt::Display for PromptError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ConsoleRequired => "PASSWORD_PROMPT_CONSOLE_REQUIRED",
            Self::ConsoleUnavailable => "PASSWORD_PROMPT_CONSOLE_UNAVAILABLE",
            Self::ConsoleIo => "PASSWORD_PROMPT_IO_FAILED",
            Self::ConsoleModeRestore => "PASSWORD_PROMPT_CONSOLE_RESTORE_FAILED",
            Self::PromptBusy => "PASSWORD_PROMPT_BUSY",
            Self::InvalidAccountLabel => "PASSWORD_PROMPT_ACCOUNT_LABEL_INVALID",
            Self::Cancelled => "PASSWORD_PROMPT_CANCELLED",
            Self::PasswordTooLong => "PASSWORD_PROMPT_TOO_LONG",
            Self::InvalidPassword => "PASSWORD_PROMPT_PASSWORD_INVALID",
            Self::CredentialRejected => "PASSWORD_PROMPT_CREDENTIAL_INVALID",
        })
    }
}

impl std::error::Error for PromptError {}

/// Prompt for a selected Windows account password for native logon.
pub fn prompt_logon_credential(
    account_label: &str,
) -> Result<crate::setup_context::WindowsLogonCredential, PromptError> {
    let source = prompt_password(account_label, "Windows account")?;
    let password = source.copy_to_vec()?;
    crate::setup_context::WindowsLogonCredential::from_utf16(password)
        .map_err(|_| PromptError::CredentialRejected)
}

/// Prompt for the selected Windows service account password.
pub fn prompt_service_password(
    account_label: &str,
) -> Result<crate::windows::service_admin::ServicePassword, PromptError> {
    let source = prompt_password(account_label, "Windows service account")?;
    let password = source.copy_to_vec()?;
    crate::windows::service_admin::ServicePassword::from_utf16(password)
        .map_err(|_| PromptError::CredentialRejected)
}

struct SecretBuffer {
    units: Zeroizing<[u16; MAX_PASSWORD_UNITS]>,
    len: usize,
}

impl SecretBuffer {
    fn copy_to_vec(&self) -> Result<Vec<u16>, PromptError> {
        if self.len == 0 || self.len > MAX_PASSWORD_UNITS {
            return Err(PromptError::InvalidPassword);
        }
        let mut password = Vec::new();
        password
            .try_reserve_exact(self.len)
            .map_err(|_| PromptError::ConsoleUnavailable)?;
        password.extend_from_slice(&self.units[..self.len]);
        Ok(password)
    }
}

struct ConsoleModeGuard {
    input: HANDLE,
    original: u32,
    restored: bool,
}

impl ConsoleModeGuard {
    fn hide_input(input: HANDLE) -> Result<Self, PromptError> {
        let mut original = 0u32;
        if unsafe { GetConsoleMode(input, &mut original) } == 0 {
            return Err(PromptError::ConsoleRequired);
        }
        let hidden = original & !(ENABLE_ECHO_INPUT | ENABLE_LINE_INPUT | ENABLE_PROCESSED_INPUT);
        if unsafe { SetConsoleMode(input, hidden) } == 0 {
            // Attempt an explicit restoration even on the rejected mode change.
            if unsafe { SetConsoleMode(input, original) } == 0 {
                return Err(PromptError::ConsoleModeRestore);
            }
            return Err(PromptError::ConsoleIo);
        }
        Ok(Self {
            input,
            original,
            restored: false,
        })
    }

    fn restore(&mut self) -> Result<(), PromptError> {
        if self.restored {
            return Ok(());
        }
        if unsafe { SetConsoleMode(self.input, self.original) } == 0 {
            return Err(PromptError::ConsoleModeRestore);
        }
        self.restored = true;
        Ok(())
    }
}

impl Drop for ConsoleModeGuard {
    fn drop(&mut self) {
        if !self.restored {
            let _ = unsafe { SetConsoleMode(self.input, self.original) };
        }
    }
}

fn prompt_password(account_label: &str, purpose: &str) -> Result<SecretBuffer, PromptError> {
    let _prompt = PROMPT_LOCK.lock().map_err(|_| PromptError::PromptBusy)?;
    let label = sanitize_label(account_label)?;
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) };
    if invalid_handle(input) || invalid_handle(output) {
        return Err(PromptError::ConsoleRequired);
    }
    let mut input_mode = 0u32;
    let mut output_mode = 0u32;
    if unsafe { GetConsoleMode(input, &mut input_mode) } == 0
        || unsafe { GetConsoleMode(output, &mut output_mode) } == 0
    {
        return Err(PromptError::ConsoleRequired);
    }
    let _ = (input_mode, output_mode);

    let mut mode = ConsoleModeGuard::hide_input(input)?;
    let prompt = format!("{purpose} password for {label} (hidden): ");
    let prompt_result = write_console_text(output, &prompt).and_then(|()| read_secret(input));

    // ReadConsoleW is in single-character mode. Clear any trailing CR/LF or
    // pasted keystrokes so they cannot become input to a subsequent prompt.
    let flushed = unsafe { FlushConsoleInputBuffer(input) } != 0;
    let restored = mode.restore();
    let newline = write_console_text(output, "\r\n");

    restored?;
    if !flushed || newline.is_err() {
        return Err(PromptError::ConsoleIo);
    }
    prompt_result
}

fn read_secret(input: HANDLE) -> Result<SecretBuffer, PromptError> {
    let mut units = Zeroizing::new([0u16; MAX_PASSWORD_UNITS]);
    let mut len = 0usize;
    loop {
        let mut unit = Zeroizing::new(0u16);
        let mut read = 0u32;
        if unsafe {
            ReadConsoleW(
                input,
                (&mut *unit as *mut u16).cast(),
                1,
                &mut read,
                std::ptr::null(),
            )
        } == 0
        {
            return Err(PromptError::ConsoleIo);
        }
        if read != 1 {
            return Err(PromptError::ConsoleIo);
        }
        match *unit {
            0x0003 => {
                *unit = 0;
                return Err(PromptError::Cancelled);
            }
            0x0000 => {
                *unit = 0;
                return Err(PromptError::InvalidPassword);
            }
            0x0008 => {
                if len > 0 {
                    let removed_low_surrogate = (0xDC00..=0xDFFF).contains(&units[len - 1]);
                    len -= 1;
                    units[len] = 0;
                    if removed_low_surrogate
                        && len > 0
                        && (0xD800..=0xDBFF).contains(&units[len - 1])
                    {
                        len -= 1;
                        units[len] = 0;
                    }
                }
            }
            0x000D | 0x000A => break,
            _ => {
                if len == MAX_PASSWORD_UNITS {
                    *unit = 0;
                    return Err(PromptError::PasswordTooLong);
                }
                units[len] = *unit;
                len += 1;
            }
        }
        *unit = 0;
    }

    if len == 0 || !valid_utf16(&units[..len]) {
        return Err(PromptError::InvalidPassword);
    }
    Ok(SecretBuffer { units, len })
}

fn valid_utf16(units: &[u16]) -> bool {
    let mut index = 0;
    while index < units.len() {
        let unit = &units[index];
        if (0xD800..=0xDBFF).contains(unit) {
            if units
                .get(index + 1)
                .is_none_or(|next| !(0xDC00..=0xDFFF).contains(next))
            {
                return false;
            }
            index += 2;
        } else if (0xDC00..=0xDFFF).contains(unit) {
            return false;
        } else {
            index += 1;
        }
    }
    true
}

fn sanitize_label(label: &str) -> Result<String, PromptError> {
    if label.is_empty() || label.len() > MAX_LABEL_BYTES {
        return Err(PromptError::InvalidAccountLabel);
    }
    let mut safe = String::with_capacity(MAX_LABEL_CHARS);
    for character in label.chars().take(MAX_LABEL_CHARS) {
        if character.is_ascii_alphanumeric()
            || matches!(character, ' ' | '_' | '-' | '.' | '@' | '\\' | ':')
        {
            safe.push(character);
        } else {
            safe.push('?');
        }
    }
    if safe.is_empty() {
        return Err(PromptError::InvalidAccountLabel);
    }
    Ok(safe)
}

fn invalid_handle(handle: HANDLE) -> bool {
    handle.is_null() || handle == INVALID_HANDLE_VALUE
}

fn write_console_text(output: HANDLE, text: &str) -> Result<(), PromptError> {
    let mut units = [0u16; 512];
    let mut len = 0usize;
    for unit in text.encode_utf16() {
        if len == units.len() {
            return Err(PromptError::ConsoleIo);
        }
        units[len] = unit;
        len += 1;
    }
    let mut written = 0u32;
    if unsafe {
        WriteConsoleW(
            output,
            units.as_ptr(),
            len as u32,
            &mut written,
            std::ptr::null(),
        )
    } == 0
        || written as usize != len
    {
        return Err(PromptError::ConsoleIo);
    }
    Ok(())
}
