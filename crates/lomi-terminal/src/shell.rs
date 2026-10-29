//! Canonical ordinary-shell integration used by the headless Host.
//!
//! Hook assets are bundled with `lomi-terminal` and copied, without following
//! links or replacing an existing target, into a versioned directory below the
//! locked Host profile. Only a typed local profile descriptor enables this
//! builder; legacy/custom executable and argument vectors remain untouched.

use crate::{Error, Result, SpawnProfile};
use lomi_remote_protocol::ipc::{LocalShellIntegration, LocalShellKind};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
    time::Instant,
};
#[cfg(windows)]
use std::{
    process::{Child, ChildStdout, Command, ExitStatus, Stdio},
    thread,
    time::Duration,
};

const MAX_ASSET_BYTES: u64 = 32 * 1024;
const CMD_PROMPT: &str = "$E]133;D$E\\$E]7;file://localhost/$P$E\\$E]133;A$E\\$P$G$E]133;B$E\\";
#[cfg(windows)]
const WSL_PATH_DEADLINE: Duration = Duration::from_secs(2);
#[cfg(windows)]
const WSL_PATH_BYTES: usize = 4096;

const ASSETS: &[(&str, &str)] = &[
    ("bash.sh", include_str!("shell_assets/bash.sh")),
    ("fish.fish", include_str!("shell_assets/fish.fish")),
    (
        "powershell.ps1",
        include_str!("shell_assets/powershell.ps1"),
    ),
    ("zsh/.zshenv", include_str!("shell_assets/zshenv")),
    ("zsh/.zprofile", include_str!("shell_assets/zprofile")),
    ("zsh/.zshrc", include_str!("shell_assets/zshrc")),
];

/// Prepare and validate the exact bundled assets for this Host profile.
/// Existing assets are reused only when their bytes and private-file shape
/// match the current version. A mismatch fails closed instead of replacing a
/// path that may have been substituted.
pub fn prepare(profile_root: &Path) -> Result<PathBuf> {
    if !profile_root.is_absolute() || !real_directory(profile_root)? {
        return Err(Error::InvalidArgument);
    }
    let bundle = bundle_path(profile_root);
    ensure_directory(profile_root, &profile_root.join("terminal-shell"))?;
    ensure_directory(profile_root, &bundle)?;
    ensure_directory(profile_root, &bundle.join("zsh"))?;
    for (relative, contents) in ASSETS {
        write_or_verify_asset(profile_root, &bundle.join(relative), contents.as_bytes())?;
    }
    Ok(bundle)
}

pub(crate) fn bundle_path(profile_root: &Path) -> PathBuf {
    profile_root.join("terminal-shell").join(bundle_version())
}

fn bundle_version() -> String {
    let mut digest = Sha256::new();
    digest.update(b"lomi-terminal-shell-assets-v1\0");
    for (name, contents) in ASSETS {
        digest.update((name.len() as u64).to_le_bytes());
        digest.update(name.as_bytes());
        digest.update((contents.len() as u64).to_le_bytes());
        digest.update(contents.as_bytes());
    }
    let hash = digest.finalize();
    let mut version = String::with_capacity(3 + hash.len() * 2);
    version.push_str("v1-");
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(version, "{byte:02x}");
    }
    version
}

/// Materialize a trusted Host profile using the canonical ordinary-shell
/// startup hooks. Profiles without typed integration metadata are returned
/// exactly as supplied.
pub(crate) fn build_spawn_profile(
    profile: &SpawnProfile,
    bundle: &Path,
    deadline: Instant,
    gate: &mut dyn FnMut() -> bool,
) -> Result<SpawnProfile> {
    check_build_gate(deadline, gate)?;
    let Some(integration) = &profile.shell_integration else {
        return Ok(profile.clone());
    };
    validate_profile(profile, integration)?;
    if !real_directory(bundle)? {
        return Err(Error::InvalidArgument);
    }
    let mut built = profile.clone();
    built.shell_integration = None;
    match integration {
        LocalShellIntegration::NativeV1 {
            shell,
            home,
            original_zdotdir,
        } => build_native(
            &mut built,
            *shell,
            Path::new(home.as_str()),
            original_zdotdir.as_ref(),
            bundle,
        )?,
        LocalShellIntegration::WslV1 {
            distro,
            shell,
            shell_executable,
            home,
        } => build_wsl(
            &mut built,
            distro.as_str(),
            *shell,
            shell_executable.as_str(),
            home.as_str(),
            bundle,
            deadline,
            gate,
        )?,
    }
    check_build_gate(deadline, gate)?;
    Ok(built)
}

fn check_build_gate(deadline: Instant, gate: &mut dyn FnMut() -> bool) -> Result<()> {
    if Instant::now() >= deadline || !gate() || Instant::now() >= deadline {
        return Err(Error::FenceRejected);
    }
    Ok(())
}

/// The Host accepts only an absolute platform launcher, with a path derived
/// from the current Windows installation rather than PATH or an app alias.
pub fn wsl_launcher() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_else(|| r"C:\Windows".into()))
            .join("System32")
            .join("wsl.exe")
    }
    #[cfg(not(windows))]
    {
        PathBuf::from("wsl.exe")
    }
}

/// Recognize only an unargumented executable whose basename names a supported
/// built-in shell. Unknown programs and profiles with caller-supplied argv stay
/// on the generic launch path.
pub fn native_integration(
    executable: &Path,
    args: &[String],
    home: &Path,
    original_zdotdir: Option<&Path>,
) -> Option<LocalShellIntegration> {
    if !args.is_empty() || !executable.is_absolute() || !home.is_absolute() {
        return None;
    }
    let shell = kind_from_executable(executable)?;
    let home =
        lomi_remote_protocol::ipc::LocalRootPath::try_from(home.to_str()?.to_owned()).ok()?;
    let original_zdotdir = if shell == LocalShellKind::Zsh {
        match original_zdotdir {
            Some(path) if path.is_absolute() => Some(
                lomi_remote_protocol::ipc::LocalRootPath::try_from(path.to_str()?.to_owned())
                    .ok()?,
            ),
            Some(_) => return None,
            None => None,
        }
    } else {
        None
    };
    let integration = LocalShellIntegration::NativeV1 {
        shell,
        home,
        original_zdotdir,
    };
    let executable =
        lomi_remote_protocol::ipc::LocalRootPath::try_from(executable.to_str()?.to_owned()).ok()?;
    let empty_args = lomi_remote_protocol::rpc::BoundedList::<
        lomi_remote_protocol::ipc::LocalProcessArgument,
        32,
    >(Vec::new());
    integration.validate_launch(&executable, &empty_args).ok()?;
    Some(integration)
}

pub fn kind_from_executable(executable: &Path) -> Option<LocalShellKind> {
    let name = executable
        .file_stem()?
        .to_string_lossy()
        .to_ascii_lowercase();
    match name.as_str() {
        "bash" => Some(LocalShellKind::Bash),
        "zsh" => Some(LocalShellKind::Zsh),
        "fish" => Some(LocalShellKind::Fish),
        "sh" => Some(LocalShellKind::Sh),
        "pwsh" | "powershell" => Some(LocalShellKind::PowerShell),
        "cmd" => Some(LocalShellKind::Cmd),
        _ => None,
    }
}

fn validate_profile(profile: &SpawnProfile, integration: &LocalShellIntegration) -> Result<()> {
    if !profile.args.is_empty() || !profile.executable.is_absolute() {
        return Err(Error::InvalidArgument);
    }
    match integration {
        LocalShellIntegration::NativeV1 {
            shell,
            home,
            original_zdotdir,
        } => {
            if !Path::new(home.as_str()).is_absolute() || !kind_matches(*shell, &profile.executable)
            {
                return Err(Error::InvalidArgument);
            }
            if original_zdotdir.as_ref().is_some_and(|directory| {
                *shell != LocalShellKind::Zsh || !Path::new(directory.as_str()).is_absolute()
            }) {
                return Err(Error::InvalidArgument);
            }
        }
        LocalShellIntegration::WslV1 {
            distro,
            shell,
            shell_executable,
            home,
        } => {
            if !cfg!(windows)
                || !valid_wsl_distro(distro.as_str())
                || !matches!(
                    shell,
                    LocalShellKind::Bash
                        | LocalShellKind::Zsh
                        | LocalShellKind::Fish
                        | LocalShellKind::Sh
                        | LocalShellKind::PowerShell
                        | LocalShellKind::Cmd
                        | LocalShellKind::Other
                )
                || !shell_executable.as_str().starts_with('/')
                || (*shell != LocalShellKind::Other
                    && !kind_matches_text(*shell, shell_executable.as_str()))
                || !home.as_str().starts_with('/')
                || !is_wsl_launcher(&profile.executable)
            {
                return Err(Error::InvalidArgument);
            }
        }
    }
    Ok(())
}

fn build_native(
    profile: &mut SpawnProfile,
    shell: LocalShellKind,
    home: &Path,
    original_zdotdir: Option<&lomi_remote_protocol::ipc::LocalRootPath>,
    bundle: &Path,
) -> Result<()> {
    let bundle = utf8_path(bundle)?;
    let home = utf8_path(home)?;
    set_environment(&mut profile.environment, "HOME", home);
    set_environment(&mut profile.environment, "TERM", "xterm-256color");
    set_environment(&mut profile.environment, "COLORTERM", "truecolor");
    set_environment(&mut profile.environment, "TERM_PROGRAM", "Lomi");
    match shell {
        LocalShellKind::Bash => {
            profile.args = vec!["--rcfile".into(), join(bundle, "bash.sh"), "-i".into()];
        }
        LocalShellKind::Zsh => {
            let original = original_zdotdir
                .map(|path| path.as_str().to_owned())
                .unwrap_or_else(|| home.to_owned());
            set_environment(&mut profile.environment, "LOMI_ZDOTDIR", &original);
            set_environment(&mut profile.environment, "ZDOTDIR", &join(bundle, "zsh"));
            if cfg!(target_os = "macos") {
                profile.args.push("-l".into());
            }
            profile.args.push("-i".into());
        }
        LocalShellKind::Fish => {
            let script = format!("source {}", fish_quote(&join(bundle, "fish.fish"))?);
            profile.args = vec!["-i".into(), "-C".into(), script];
        }
        LocalShellKind::Sh => profile.args = vec!["-i".into()],
        LocalShellKind::PowerShell => {
            profile.args = vec![
                "-NoLogo".into(),
                "-NoExit".into(),
                "-Command".into(),
                include_str!("shell_assets/powershell.ps1").into(),
            ];
        }
        LocalShellKind::Cmd => {
            profile.args = vec!["/Q".into(), "/D".into(), "/V:OFF".into()];
            set_environment(&mut profile.environment, "PROMPT", CMD_PROMPT);
        }
        LocalShellKind::Other => return Err(Error::InvalidArgument),
    }
    Ok(())
}

fn build_wsl(
    profile: &mut SpawnProfile,
    distro: &str,
    shell: LocalShellKind,
    shell_executable: &str,
    home: &str,
    bundle: &Path,
    deadline: Instant,
    gate: &mut dyn FnMut() -> bool,
) -> Result<()> {
    check_build_gate(deadline, gate)?;
    let cwd = wsl_path(&profile.executable, distro, &profile.cwd, deadline, gate)?;
    check_build_gate(deadline, gate)?;
    let bundle = wsl_path(&profile.executable, distro, bundle, deadline, gate)?;
    check_build_gate(deadline, gate)?;
    let mut args = vec![
        "-d".into(),
        distro.into(),
        "--cd".into(),
        cwd,
        "--exec".into(),
        "env".into(),
        "TERM=xterm-256color".into(),
        "COLORTERM=truecolor".into(),
        "TERM_PROGRAM=Lomi".into(),
        format!("HOME={home}"),
    ];
    if shell == LocalShellKind::Zsh {
        args.push(format!("ZDOTDIR={bundle}/zsh"));
        args.push(format!("LOMI_ZDOTDIR={home}"));
    }
    if shell == LocalShellKind::Cmd {
        args.push(format!("PROMPT={CMD_PROMPT}"));
    }
    args.push(shell_executable.into());
    match shell {
        LocalShellKind::Bash => {
            args.extend(["--rcfile".into(), format!("{bundle}/bash.sh"), "-i".into()])
        }
        LocalShellKind::Zsh | LocalShellKind::Sh => args.push("-i".into()),
        LocalShellKind::Fish => args.extend([
            "-i".into(),
            "-C".into(),
            format!("source {}", fish_quote(&format!("{bundle}/fish.fish"))?),
        ]),
        LocalShellKind::PowerShell => args.extend([
            "-NoLogo".into(),
            "-NoExit".into(),
            "-Command".into(),
            include_str!("shell_assets/powershell.ps1").into(),
        ]),
        LocalShellKind::Cmd => {
            args.extend(["/Q".into(), "/D".into(), "/V:OFF".into()]);
        }
        LocalShellKind::Other => args.push("-i".into()),
    }
    profile.args = args;
    Ok(())
}

#[cfg(not(windows))]
fn wsl_path(
    _launcher: &Path,
    _distro: &str,
    _path: &Path,
    deadline: Instant,
    gate: &mut dyn FnMut() -> bool,
) -> Result<String> {
    check_build_gate(deadline, gate)?;
    Err(Error::InvalidArgument)
}

#[cfg(windows)]
fn wsl_path(
    launcher: &Path,
    distro: &str,
    path: &Path,
    deadline: Instant,
    gate: &mut dyn FnMut() -> bool,
) -> Result<String> {
    check_build_gate(deadline, gate)?;
    let input = path.to_string_lossy();
    if input.starts_with('/') {
        return Ok(input.into_owned());
    }
    let input = wsl_path_argument(&input)?;
    let mut command = Command::new(launcher);
    command
        .args(["-d", distro, "--exec", "wslpath", "-a", "-u", &input])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    use std::os::windows::process::CommandExt;
    command.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    check_build_gate(deadline, gate)?;
    let mut child = command.spawn().map_err(|_| Error::InvalidArgument)?;
    let Some(mut stdout) = child.stdout.take() else {
        stop_wslpath_child(&mut child);
        return Err(Error::InvalidArgument);
    };
    let (status, output) = collect_wslpath_output(&mut child, &mut stdout, deadline, gate)?;
    check_build_gate(deadline, gate)?;
    if !status.success() || output.len() > WSL_PATH_BYTES * 2 + 2 {
        return Err(Error::InvalidArgument);
    }
    if (output.starts_with(&[0xff, 0xfe]) || output.contains(&0)) && output.len() % 2 != 0 {
        return Err(Error::InvalidArgument);
    }
    let text = decode_wsl_text(&output);
    let path = text.trim_end_matches(['\r', '\n']);
    if !path.starts_with('/') || path.len() > WSL_PATH_BYTES || path.contains(['\0', '\r', '\n']) {
        return Err(Error::InvalidArgument);
    }
    Ok(path.to_owned())
}

#[cfg(windows)]
fn collect_wslpath_output(
    child: &mut Child,
    stdout: &mut ChildStdout,
    deadline: Instant,
    gate: &mut dyn FnMut() -> bool,
) -> Result<(ExitStatus, Vec<u8>)> {
    let helper_deadline = (Instant::now() + WSL_PATH_DEADLINE).min(deadline);
    let mut output = Vec::new();
    let mut buffer = [0_u8; 1024];
    loop {
        if check_build_gate(helper_deadline, gate).is_err() {
            stop_wslpath_child(child);
            return Err(Error::FenceRejected);
        }
        let count = match read_available_pipe(stdout, &mut buffer) {
            Ok(count) => count,
            Err(_) => {
                stop_wslpath_child(child);
                return Err(Error::InvalidArgument);
            }
        };
        if count > 0 {
            output.extend_from_slice(&buffer[..count]);
            if output.len() > WSL_PATH_BYTES * 2 + 2 {
                stop_wslpath_child(child);
                return Err(Error::InvalidArgument);
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                // Drain bytes already written after observing process exit. Do
                // not wait for EOF: a descendant could retain this pipe handle.
                loop {
                    if check_build_gate(helper_deadline, gate).is_err() {
                        return Err(Error::FenceRejected);
                    }
                    let count = read_available_pipe(stdout, &mut buffer)
                        .map_err(|_| Error::InvalidArgument)?;
                    if count == 0 {
                        return Ok((status, output));
                    }
                    output.extend_from_slice(&buffer[..count]);
                    if output.len() > WSL_PATH_BYTES * 2 + 2 {
                        return Err(Error::InvalidArgument);
                    }
                }
            }
            Ok(None) if Instant::now() < helper_deadline => {
                let remaining = helper_deadline.saturating_duration_since(Instant::now());
                thread::sleep(remaining.min(Duration::from_millis(10)));
            }
            Ok(None) | Err(_) => {
                stop_wslpath_child(child);
                return Err(Error::InvalidArgument);
            }
        }
    }
}

#[cfg(windows)]
fn read_available_pipe(stdout: &mut ChildStdout, buffer: &mut [u8]) -> std::io::Result<usize> {
    use std::{os::windows::io::AsRawHandle, ptr};

    const ERROR_BROKEN_PIPE: i32 = 109;
    let mut available = 0_u32;
    let success = unsafe {
        peek_named_pipe(
            stdout.as_raw_handle(),
            ptr::null_mut(),
            0,
            ptr::null_mut(),
            &mut available,
            ptr::null_mut(),
        )
    };
    if success == 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(ERROR_BROKEN_PIPE) {
            return Ok(0);
        }
        return Err(error);
    }
    if available == 0 {
        return Ok(0);
    }
    let count = available.min(buffer.len() as u32) as usize;
    stdout.read(&mut buffer[..count])
}

#[cfg(windows)]
fn stop_wslpath_child(child: &mut Child) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }
    if child.kill().is_err() {
        return;
    }
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(10));
            }
            Ok(None) => return,
        }
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "PeekNamedPipe"]
    fn peek_named_pipe(
        pipe: std::os::windows::io::RawHandle,
        buffer: *mut std::ffi::c_void,
        buffer_size: u32,
        bytes_read: *mut u32,
        total_bytes_available: *mut u32,
        bytes_left_this_message: *mut u32,
    ) -> i32;
}

#[cfg(windows)]
fn wsl_path_argument(path: &str) -> Result<String> {
    if path.len() > WSL_PATH_BYTES || path.contains(['\0', '\r', '\n']) {
        return Err(Error::InvalidArgument);
    }
    let path = path.strip_prefix(r"\\?\").unwrap_or(path);
    let path = path
        .strip_prefix(r"UNC\")
        .map_or_else(|| path.to_owned(), |tail| format!(r"\\{tail}"));
    let windows_absolute = path.as_bytes().get(1) == Some(&b':') || path.starts_with(r"\\");
    if !windows_absolute {
        return Err(Error::InvalidArgument);
    }
    Ok(path)
}

#[cfg(windows)]
fn decode_wsl_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.contains(&0) {
        let units = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect::<Vec<_>>();
        String::from_utf16_lossy(&units)
            .trim_start_matches('\u{feff}')
            .to_owned()
    } else {
        String::from_utf8_lossy(bytes)
            .trim_start_matches('\u{feff}')
            .to_owned()
    }
}

fn kind_matches(kind: LocalShellKind, executable: &Path) -> bool {
    executable
        .file_stem()
        .is_some_and(|name| kind_matches_text(kind, &name.to_string_lossy()))
}

fn kind_matches_text(kind: LocalShellKind, executable: &str) -> bool {
    let name = Path::new(executable)
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_ascii_lowercase();
    match kind {
        LocalShellKind::Bash => name == "bash",
        LocalShellKind::Zsh => name == "zsh",
        LocalShellKind::Fish => name == "fish",
        LocalShellKind::Sh => name == "sh",
        LocalShellKind::PowerShell => name == "pwsh" || name == "powershell",
        LocalShellKind::Cmd => name == "cmd",
        LocalShellKind::Other => false,
    }
}

fn is_wsl_launcher(path: &Path) -> bool {
    path.file_stem()
        .is_some_and(|name| name.to_string_lossy().eq_ignore_ascii_case("wsl"))
}

fn valid_wsl_distro(distro: &str) -> bool {
    !distro.is_empty()
        && distro.len() <= 255
        && !distro.starts_with('-')
        && distro
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b' '))
}

fn set_environment(environment: &mut Vec<(String, String)>, key: &str, value: &str) {
    if let Some((_, current)) = environment.iter_mut().find(|(name, _)| name == key) {
        *current = value.to_owned();
    } else {
        environment.push((key.to_owned(), value.to_owned()));
    }
}

fn join(root: &str, relative: &str) -> String {
    format!("{}/{relative}", root.trim_end_matches(['/', '\\']))
}

fn utf8_path(path: &Path) -> Result<&str> {
    path.to_str().ok_or(Error::InvalidArgument)
}

fn fish_quote(value: &str) -> Result<String> {
    if value.contains(['\0', '\n', '\r', '\u{1b}']) {
        return Err(Error::InvalidArgument);
    }
    Ok(format!(
        "'{}'",
        value.replace('\\', "\\\\").replace('\'', "\\'")
    ))
}

fn ensure_directory(profile_root: &Path, path: &Path) -> Result<()> {
    #[cfg(windows)]
    {
        return windows_security::ensure_directory(profile_root, path)
            .map_err(|_| Error::InvalidArgument);
    }
    #[cfg(not(windows))]
    {
        let _ = profile_root;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink()
                    || is_reparse_point(&metadata)
                    || !metadata.is_dir()
                {
                    return Err(Error::InvalidArgument);
                }
                validate_private_directory(&metadata)?;
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    let mut builder = fs::DirBuilder::new();
                    builder.mode(0o700);
                    builder.create(path).map_err(|_| Error::InvalidArgument)?;
                }
                #[cfg(not(unix))]
                fs::create_dir(path).map_err(|_| Error::InvalidArgument)?;
                let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidArgument)?;
                if metadata.file_type().is_symlink()
                    || is_reparse_point(&metadata)
                    || !metadata.is_dir()
                {
                    return Err(Error::InvalidArgument);
                }
                validate_private_directory(&metadata)
            }
            Err(_) => Err(Error::InvalidArgument),
        }
    }
}

fn real_directory(path: &Path) -> Result<bool> {
    #[cfg(windows)]
    {
        return windows_security::validate_directory_tree(path, path, true)
            .map(|()| true)
            .map_err(|_| Error::InvalidArgument);
    }
    #[cfg(not(windows))]
    {
        let metadata = fs::symlink_metadata(path).map_err(|_| Error::InvalidArgument)?;
        if metadata.file_type().is_symlink() || is_reparse_point(&metadata) || !metadata.is_dir() {
            return Ok(false);
        }
        validate_private_directory(&metadata)?;
        Ok(true)
    }
}

fn write_or_verify_asset(profile_root: &Path, path: &Path, bytes: &[u8]) -> Result<()> {
    match verify_or_recover_asset(profile_root, path, bytes) {
        Ok(existing) => {
            return if existing == bytes {
                Ok(())
            } else {
                Err(Error::InvalidArgument)
            };
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::InvalidArgument),
    }
    let parent = path.parent().ok_or(Error::InvalidArgument)?;
    let temporary = parent.join(format!(".shell-asset-{}.tmp", uuid::Uuid::new_v4()));
    let mut file =
        create_private_asset(profile_root, &temporary).map_err(|_| Error::InvalidArgument)?;
    file.file
        .write_all(bytes)
        .map_err(|_| Error::InvalidArgument)?;
    file.file.sync_all().map_err(|_| Error::InvalidArgument)?;
    drop(file);
    match fs::hard_link(&temporary, path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = fs::remove_file(&temporary);
            return match verify_or_recover_asset(profile_root, path, bytes) {
                Ok(existing) if existing == bytes => Ok(()),
                _ => Err(Error::InvalidArgument),
            };
        }
        Err(_) => {
            let _ = fs::remove_file(&temporary);
            return Err(Error::InvalidArgument);
        }
    }
    fs::remove_file(&temporary).map_err(|_| Error::InvalidArgument)?;
    match verify_or_recover_asset(profile_root, path, bytes) {
        Ok(existing) if existing == bytes => Ok(()),
        _ => Err(Error::InvalidArgument),
    }
}

fn verify_or_recover_asset(
    profile_root: &Path,
    path: &Path,
    expected: &[u8],
) -> std::io::Result<Vec<u8>> {
    match read_private_asset(profile_root, path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Err(error),
        Err(_) => {
            if recover_duplicate_asset(profile_root, path, expected)? {
                read_private_asset(profile_root, path)
            } else {
                Err(std::io::Error::other("invalid shell asset file"))
            }
        }
    }
}

fn read_private_asset(profile_root: &Path, path: &Path) -> std::io::Result<Vec<u8>> {
    Ok(read_private_asset_with_links(profile_root, path, 1)?.bytes)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AssetIdentity(u64, u64);

struct AssetRead {
    bytes: Vec<u8>,
    identity: AssetIdentity,
    links: u64,
}

fn read_private_asset_with_links(
    profile_root: &Path,
    path: &Path,
    max_links: u64,
) -> std::io::Result<AssetRead> {
    let private_file = open_private_asset(profile_root, path, false, false, max_links)?;
    let metadata = private_file.file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(std::io::Error::other("invalid shell asset file"));
    }
    let (identity, links) = private_file_properties(&private_file, &metadata, max_links)?;
    let mut bytes = Vec::new();
    private_file
        .file
        .take(MAX_ASSET_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_ASSET_BYTES {
        return Err(std::io::Error::other("oversized shell asset"));
    }
    Ok(AssetRead {
        bytes,
        identity,
        links,
    })
}

const MAX_TEMP_RECOVERY_SCAN: usize = 256;

fn recover_duplicate_asset(
    profile_root: &Path,
    path: &Path,
    expected: &[u8],
) -> std::io::Result<bool> {
    let final_asset = match read_private_asset_with_links(profile_root, path, 2) {
        Ok(asset) if asset.links == 2 && asset.bytes == expected => asset,
        _ => return Ok(false),
    };
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("invalid shell asset path"))?;
    let mut entries = fs::read_dir(parent)?;
    for _ in 0..MAX_TEMP_RECOVERY_SCAN {
        let Some(entry) = entries.next() else {
            return Ok(false);
        };
        let entry = entry?;
        let name = entry.file_name();
        let Some(id) = name
            .to_str()
            .and_then(|name| name.strip_prefix(".shell-asset-"))
            .and_then(|name| name.strip_suffix(".tmp"))
        else {
            continue;
        };
        if uuid::Uuid::parse_str(id).is_err() {
            continue;
        }
        let candidate = match read_private_asset_with_links(profile_root, &entry.path(), 2) {
            Ok(asset)
                if asset.links == 2
                    && asset.identity == final_asset.identity
                    && asset.bytes == expected =>
            {
                asset
            }
            _ => continue,
        };
        if candidate.links != 2 {
            continue;
        }
        fs::remove_file(entry.path())?;
        return Ok(matches!(
            read_private_asset_with_links(profile_root, path, 1),
            Ok(asset) if asset.links == 1 && asset.bytes == expected
        ));
    }
    if entries.next().is_some() {
        return Ok(false);
    }
    Ok(false)
}

struct PrivateFile {
    file: File,
    #[cfg(windows)]
    _ancestors: Vec<windows_security::DirectoryHandle>,
    #[cfg(windows)]
    identity: AssetIdentity,
    #[cfg(windows)]
    links: u64,
}

fn open_private_asset(
    profile_root: &Path,
    path: &Path,
    write: bool,
    create: bool,
    max_links: u64,
) -> std::io::Result<PrivateFile> {
    #[cfg(windows)]
    {
        let (file, ancestors, identity, links) =
            windows_security::open_file(profile_root, path, write, create, max_links)?;
        Ok(PrivateFile {
            file,
            _ancestors: ancestors,
            identity,
            links,
        })
    }
    #[cfg(unix)]
    {
        let _ = (profile_root, max_links);
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options
            .read(!write || !create)
            .write(write)
            .create_new(create)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
        if create {
            options.mode(0o600);
        }
        options.open(path).map(|file| PrivateFile { file })
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (profile_root, path, write, create, max_links);
        Err(std::io::Error::other("unsupported shell asset platform"))
    }
}

fn create_private_asset(profile_root: &Path, path: &Path) -> std::io::Result<PrivateFile> {
    let file = open_private_asset(profile_root, path, true, true, 1)?;
    let metadata = file.file.metadata()?;
    if !metadata.is_file() || is_reparse_point(&metadata) {
        return Err(std::io::Error::other("invalid private shell asset"));
    }
    let (_, links) = private_file_properties(&file, &metadata, 1)?;
    if links != 1 {
        return Err(std::io::Error::other("invalid private shell asset"));
    }
    Ok(file)
}

#[cfg(windows)]
fn private_file_properties(
    file: &PrivateFile,
    _metadata: &fs::Metadata,
    max_links: u64,
) -> std::io::Result<(AssetIdentity, u64)> {
    if file.links == 0 || file.links > max_links {
        return Err(std::io::Error::other("invalid private shell asset"));
    }
    Ok((file.identity, file.links))
}

#[cfg(unix)]
fn private_file_properties(
    _file: &PrivateFile,
    metadata: &fs::Metadata,
    max_links: u64,
) -> std::io::Result<(AssetIdentity, u64)> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o600 {
        return Err(std::io::Error::other("invalid private shell asset"));
    }
    let links = metadata.nlink();
    if links == 0 || links > max_links {
        return Err(std::io::Error::other("invalid private shell asset"));
    }
    Ok((AssetIdentity(metadata.dev(), metadata.ino()), links))
}

#[cfg(not(any(unix, windows)))]
fn private_file_properties(
    _file: &PrivateFile,
    _metadata: &fs::Metadata,
    _max_links: u64,
) -> std::io::Result<(AssetIdentity, u64)> {
    Err(std::io::Error::other("unsupported shell asset platform"))
}

#[cfg(windows)]
mod windows_security {
    use super::*;
    use std::{
        ffi::{OsStr, c_void},
        mem,
        os::windows::{ffi::OsStrExt, io::FromRawHandle},
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::*,
        Security::{Authorization::*, *},
        Storage::FileSystem::*,
        System::{SystemServices::*, Threading::*},
    };

    pub(super) struct DirectoryHandle {
        _handle: HANDLE,
    }

    impl Drop for DirectoryHandle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self._handle);
            }
        }
    }

    struct Local(*mut c_void);

    impl Drop for Local {
        fn drop(&mut self) {
            unsafe {
                LocalFree(self.0);
            }
        }
    }

    struct Handle(HANDLE);

    impl Handle {
        fn new(handle: HANDLE) -> std::io::Result<Self> {
            if handle.is_null() || handle == INVALID_HANDLE_VALUE {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(Self(handle))
            }
        }

        fn into_file(self) -> File {
            let raw = self.0;
            std::mem::forget(self);
            unsafe { File::from_raw_handle(raw) }
        }
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
        value.as_ref().encode_wide().chain(Some(0)).collect()
    }

    fn check(ok: i32) -> std::io::Result<()> {
        if ok == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    fn sid_text(sid: PSID) -> std::io::Result<String> {
        let mut text = ptr::null_mut();
        unsafe {
            check(ConvertSidToStringSidW(sid, &mut text))?;
        }
        let _guard = Local(text.cast());
        let mut length = 0;
        unsafe {
            while *text.add(length) != 0 {
                length += 1;
                if length > 256 {
                    return Err(std::io::Error::other("invalid owner SID"));
                }
            }
            String::from_utf16(std::slice::from_raw_parts(text, length))
                .map_err(|_| std::io::Error::other("invalid owner SID"))
        }
    }

    fn current_sid() -> std::io::Result<String> {
        let mut token = ptr::null_mut();
        unsafe {
            check(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY,
                &mut token,
            ))?;
        }
        let token = Handle::new(token)?;
        let mut size = 0;
        unsafe {
            GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut size);
        }
        if size == 0 || size > 4096 {
            return Err(std::io::Error::other("invalid owner SID"));
        }
        let mut buffer = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
        unsafe {
            check(GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                size,
                &mut size,
            ))?;
            sid_text((*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid)
        }
    }

    fn security_descriptor(
        sid: &str,
        directory: bool,
    ) -> std::io::Result<(Local, SECURITY_ATTRIBUTES)> {
        let flags = if directory { "OICI" } else { "" };
        let sddl = format!("O:{sid}D:P(A;{flags};FA;;;{sid})");
        let mut descriptor = ptr::null_mut();
        unsafe {
            check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
                wide(sddl).as_ptr(),
                1,
                &mut descriptor,
                ptr::null_mut(),
            ))?;
        }
        Ok((
            Local(descriptor.cast()),
            SECURITY_ATTRIBUTES {
                nLength: mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            },
        ))
    }

    fn trusted_sid(sid: &str, owner: &str) -> bool {
        sid == owner
            || matches!(
                sid,
                "S-1-5-18"
                    | "S-1-5-32-544"
                    | "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
            )
    }

    fn validate_security(
        handle: HANDLE,
        owner: &str,
        private: bool,
        directory: bool,
    ) -> std::io::Result<()> {
        let (mut descriptor, mut owner_sid, mut acl) =
            (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
        let status = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner_sid,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(status as i32));
        }
        let _guard = Local(descriptor.cast());
        let found_owner = sid_text(owner_sid)?;
        if (private && found_owner != owner)
            || (!private && !trusted_sid(&found_owner, owner))
            || acl.is_null()
        {
            return Err(std::io::Error::other("invalid shell asset owner or DACL"));
        }
        let mut control = 0;
        let mut revision = 0;
        unsafe {
            check(GetSecurityDescriptorControl(
                descriptor,
                &mut control,
                &mut revision,
            ))?;
        }
        if private && directory && control & SE_DACL_PROTECTED == 0 {
            return Err(std::io::Error::other("unprotected shell asset directory"));
        }
        let mut owner_grant = false;
        for index in 0..unsafe { (*acl).AceCount } {
            let mut ace = ptr::null_mut();
            unsafe {
                check(GetAce(acl, index as u32, &mut ace))?;
            }
            let header = unsafe { &*ace.cast::<ACE_HEADER>() };
            if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0 && !(private && directory) {
                continue;
            }
            if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
                continue;
            }
            if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
                return Err(std::io::Error::other("unsupported shell asset ACL"));
            }
            let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
            let who = sid_text((&allowed.SidStart as *const u32).cast_mut().cast())?;
            if private {
                let flags = if directory {
                    OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
                } else {
                    0
                };
                if who != owner
                    || allowed.Mask != FILE_ALL_ACCESS
                    || header.AceFlags as u32 & !INHERITED_ACE != flags
                {
                    return Err(std::io::Error::other("invalid shell asset ACL"));
                }
                owner_grant = true;
            } else if allowed.Mask
                & (FILE_DELETE_CHILD
                    | WRITE_DAC
                    | WRITE_OWNER
                    | DELETE
                    | GENERIC_ALL
                    | GENERIC_WRITE)
                != 0
                && !trusted_sid(&who, owner)
            {
                return Err(std::io::Error::other("writable shell asset ancestor"));
            }
        }
        if private && !owner_grant {
            return Err(std::io::Error::other("missing shell asset owner ACL"));
        }
        Ok(())
    }

    fn validate_path(path: &Path) -> std::io::Result<Vec<std::path::Component<'_>>> {
        use std::path::{Component, Prefix};
        if !path.is_absolute() {
            return Err(std::io::Error::other("shell asset path is not absolute"));
        }
        let components = path.components().collect::<Vec<_>>();
        match components.first() {
            Some(Component::Prefix(prefix)) if matches!(prefix.kind(), Prefix::Disk(_)) => {}
            _ => return Err(std::io::Error::other("unsupported shell asset path")),
        }
        for component in &components {
            match component {
                Component::Prefix(_) | Component::RootDir => {}
                Component::Normal(name) => {
                    let name = name.to_string_lossy();
                    if name.contains(':') || name.ends_with(['.', ' ']) {
                        return Err(std::io::Error::other("aliased shell asset path"));
                    }
                }
                Component::CurDir | Component::ParentDir => {
                    return Err(std::io::Error::other("non-canonical shell asset path"));
                }
            }
        }
        Ok(components)
    }

    fn open_directory(path: &Path) -> std::io::Result<Handle> {
        let handle = Handle::new(unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                READ_CONTROL | FILE_READ_ATTRIBUTES,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS,
                ptr::null_mut(),
            )
        })?;
        let mut info = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        unsafe {
            check(GetFileInformationByHandle(handle.0, &mut info))?;
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)
            != FILE_ATTRIBUTE_DIRECTORY
        {
            return Err(std::io::Error::other("invalid shell asset directory"));
        }
        Ok(handle)
    }

    fn validate_directory_chain(
        profile_root: &Path,
        path: &Path,
        _private_final: bool,
    ) -> std::io::Result<Vec<DirectoryHandle>> {
        if !path.starts_with(profile_root) {
            return Err(std::io::Error::other("shell asset escaped its profile"));
        }
        let path_components = validate_path(path)?;
        let root_count = validate_path(profile_root)?.len();
        if path_components.len() < root_count {
            return Err(std::io::Error::other("shell asset escaped its profile"));
        }
        let owner = current_sid()?;
        let mut current = PathBuf::new();
        let mut handles = Vec::new();
        for (index, component) in path_components.iter().enumerate() {
            current.push(component.as_os_str());
            if matches!(component, std::path::Component::Prefix(_)) {
                continue;
            }
            let handle = open_directory(&current)?;
            let private = index + 1 >= root_count;
            validate_security(handle.0, &owner, private, true)?;
            handles.push(DirectoryHandle { _handle: handle.0 });
            std::mem::forget(handle);
        }
        Ok(handles)
    }

    pub(super) fn validate_directory_tree(
        profile_root: &Path,
        path: &Path,
        private_final: bool,
    ) -> std::io::Result<()> {
        let _ = private_final;
        let _handles = validate_directory_chain(profile_root, path, private_final)?;
        Ok(())
    }

    pub(super) fn ensure_directory(profile_root: &Path, path: &Path) -> std::io::Result<()> {
        match validate_directory_tree(profile_root, path, true) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error),
            Err(_) => {}
        }
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("invalid shell asset directory"))?;
        let _parents = validate_directory_chain(profile_root, parent, true)?;
        let owner = current_sid()?;
        let (_descriptor, attributes) = security_descriptor(&owner, true)?;
        if unsafe { CreateDirectoryW(wide(path).as_ptr(), &attributes) } == 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(ERROR_ALREADY_EXISTS as i32) {
                return Err(error);
            }
        }
        validate_directory_tree(profile_root, path, true)
    }

    pub(super) fn open_file(
        profile_root: &Path,
        path: &Path,
        write: bool,
        create: bool,
        max_links: u64,
    ) -> std::io::Result<(File, Vec<DirectoryHandle>, AssetIdentity, u64)> {
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("invalid shell asset path"))?;
        let ancestors = validate_directory_chain(profile_root, parent, true)?;
        validate_path(path)?;
        let owner = current_sid()?;
        let (_descriptor, attributes) = security_descriptor(&owner, false)?;
        let access =
            READ_CONTROL | FILE_READ_ATTRIBUTES | if write { GENERIC_WRITE } else { GENERIC_READ };
        let handle = Handle::new(unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                access,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                &attributes,
                if create { CREATE_NEW } else { OPEN_EXISTING },
                FILE_FLAG_OPEN_REPARSE_POINT,
                ptr::null_mut(),
            )
        })?;
        let mut info = unsafe { mem::zeroed::<BY_HANDLE_FILE_INFORMATION>() };
        unsafe {
            check(GetFileInformationByHandle(handle.0, &mut info))?;
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY) != 0
            || info.nNumberOfLinks == 0
            || u64::from(info.nNumberOfLinks) > max_links
        {
            return Err(std::io::Error::other("invalid shell asset file"));
        }
        validate_security(handle.0, &owner, true, false)?;
        let identity = AssetIdentity(
            u64::from(info.dwVolumeSerialNumber),
            (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
        );
        Ok((
            handle.into_file(),
            ancestors,
            identity,
            u64::from(info.nNumberOfLinks),
        ))
    }
}

#[cfg(unix)]
fn validate_private_directory(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o777 != 0o700 {
        return Err(Error::InvalidArgument);
    }
    Ok(())
}

#[cfg(all(not(unix), not(windows)))]
fn validate_private_directory(_metadata: &fs::Metadata) -> Result<()> {
    Err(Error::InvalidArgument)
}

#[cfg(windows)]
fn is_reparse_point(metadata: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & 0x400 != 0 // FILE_ATTRIBUTE_REPARSE_POINT
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &fs::Metadata) -> bool {
    false
}
