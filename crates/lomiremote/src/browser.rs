//! Validates and opens a login URL without passing it through a shell.

#[cfg(any(target_os = "macos", target_os = "linux", windows))]
use std::sync::mpsc;
use std::sync::mpsc::Receiver;

const INVALID_URL: &str = "The login URL is not a valid HTTPS URL.";
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
const OPEN_FAILED: &str = "Unable to open the login URL.";
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
const OPENER_START_FAILED: &str = "Unable to start the browser opener.";
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
const UNSUPPORTED: &str = "Browser opening is unsupported on this platform.";

fn parsed_login_url(value: &str) -> Result<url::Url, &'static str> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(INVALID_URL);
    }

    let parsed = url::Url::parse(value).map_err(|_| INVALID_URL)?;
    if parsed.scheme() != "https" || parsed.host().is_none() || parsed.as_str() != value {
        return Err(INVALID_URL);
    }

    let authority = parsed
        .as_str()
        .strip_prefix("https://")
        .and_then(|remainder| remainder.split(['/', '?', '#']).next())
        .ok_or(INVALID_URL)?;
    if !parsed.username().is_empty() || parsed.password().is_some() || authority.contains('@') {
        return Err(INVALID_URL);
    }

    Ok(parsed)
}

fn canonical_login_url(value: &str) -> Result<String, &'static str> {
    parsed_login_url(value).map(|parsed| parsed.to_string())
}

/// Validate an absolute HTTPS URL suitable for a browser-based login.
///
/// The parsed URL must have a host, contain no user information, and include
/// no raw whitespace or control characters. Paths, queries, fragments, and
/// configured ports are preserved.
pub fn validate_url(value: &str) -> Result<(), &'static str> {
    parsed_login_url(value).map(|_| ())
}

/// Start opening a validated URL and return a receiver for the eventual result.
///
/// The receiver resolves when the platform opener reports success or failure;
/// this function only validates the URL and starts a worker thread.
pub fn open(value: &str) -> Result<Receiver<Result<(), &'static str>>, &'static str> {
    let canonical_url = canonical_login_url(value)?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let launch = move || launch_command(&canonical_url);

    #[cfg(windows)]
    let launch = move || launch_shell_execute(&canonical_url);

    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        let _ = canonical_url;
        return Err(UNSUPPORTED);
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows))]
    {
        let (sender, receiver) = mpsc::channel();
        std::thread::Builder::new()
            .name("login-browser-opener".to_owned())
            .spawn(move || {
                let _ = sender.send(launch());
            })
            .map_err(|_| OPENER_START_FAILED)?;
        Ok(receiver)
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[derive(Debug, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: [String; 1],
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn command_spec(url: &str) -> CommandSpec {
    #[cfg(target_os = "macos")]
    let program = "/usr/bin/open";
    #[cfg(target_os = "linux")]
    let program = "xdg-open";

    CommandSpec {
        program,
        args: [url.to_owned()],
    }
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn launch_command(url: &str) -> Result<(), &'static str> {
    use std::process::{Command, Stdio};

    let spec = command_spec(url);
    let mut child = Command::new(spec.program)
        .args(spec.args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| OPEN_FAILED)?;
    let status = child.wait().map_err(|_| OPEN_FAILED)?;
    if status.success() {
        Ok(())
    } else {
        Err(OPEN_FAILED)
    }
}

#[cfg(windows)]
fn url_wide_arg(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(windows)]
fn launch_shell_execute(url: &str) -> Result<(), &'static str> {
    use std::ptr;
    use windows_sys::Win32::{
        System::Com::{COINIT_APARTMENTTHREADED, CoInitializeEx, CoUninitialize},
        UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
    };

    struct ComApartment;
    impl Drop for ComApartment {
        fn drop(&mut self) {
            unsafe { CoUninitialize() };
        }
    }

    // Shell browser integration can require an STA. The caller starts this on
    // a fresh worker thread so COM lifetime never crosses the TUI thread.
    let initialized = unsafe { CoInitializeEx(ptr::null(), COINIT_APARTMENTTHREADED as u32) };
    if initialized < 0 {
        return Err(OPEN_FAILED);
    }
    let _apartment = ComApartment;

    let operation = url_wide_arg("open");
    let target = url_wide_arg(url);
    let instance = unsafe {
        ShellExecuteW(
            ptr::null_mut(),
            operation.as_ptr(),
            target.as_ptr(),
            ptr::null(),
            ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (instance as usize) > 32 {
        Ok(())
    } else {
        Err(OPEN_FAILED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_login_paths_queries_and_configured_ports() {
        assert!(validate_url("https://login.example.test/device?user_code=ABCD-1234").is_ok());
        assert!(validate_url("https://login.example.test:8443/device?next=%2Fapprove").is_ok());
        assert!(validate_url("https://login.example.test/oauth/verify/continue?step=2").is_ok());
        assert!(validate_url("https://login.example.test/").is_ok());
    }

    #[test]
    fn accepts_only_canonical_url_spelling() {
        assert_eq!(
            canonical_login_url("https://login.example.test/device?user_code=ABCD-1234").unwrap(),
            "https://login.example.test/device?user_code=ABCD-1234",
        );
        assert!(validate_url("HTTPS://LOGIN.EXAMPLE.TEST/device?user_code=ABCD-1234").is_err());
    }

    #[test]
    fn rejects_non_https_or_incomplete_urls() {
        for value in [
            "",
            "/device",
            "http://login.example.test/device",
            "ftp://login.example.test/device",
            "https:///device",
            "https://login.example.test:bad/device",
        ] {
            assert!(validate_url(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn rejects_whitespace_controls_and_user_information() {
        for value in [
            " https://login.example.test/device",
            "https://login.example.test/device?code=two words",
            "https://login.example.test/device\n",
            "https://login.example.test/device\0",
            "https://user@login.example.test/device",
            "https://user:secret@login.example.test/device",
            "https://@login.example.test/device",
        ] {
            assert!(validate_url(value).is_err(), "accepted {value:?}");
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn opener_command_passes_the_canonical_url_as_one_argument() {
        let url = "https://login.example.test:8443/device?user_code=ABCD-1234";
        let spec = command_spec(url);
        #[cfg(target_os = "macos")]
        assert_eq!(spec.program, "/usr/bin/open");
        #[cfg(target_os = "linux")]
        assert_eq!(spec.program, "xdg-open");
        assert_eq!(spec.args, [url.to_owned()]);
        assert_eq!(spec.args.len(), 1);
    }

    #[cfg(windows)]
    #[test]
    fn windows_url_argument_is_null_terminated_utf16() {
        let encoded = url_wide_arg("https://example.test/device?code=é");
        assert_eq!(encoded.last(), Some(&0));
        assert_eq!(
            String::from_utf16(&encoded[..encoded.len() - 1]).unwrap(),
            "https://example.test/device?code=é",
        );
    }
}
