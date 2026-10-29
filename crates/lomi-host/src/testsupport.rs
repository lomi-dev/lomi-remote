//! Test-only helpers that hide the platform difference of creating private
//! directories. On unix a private directory is mode 0700; on Windows the
//! profile's DACL is established by `OwnerLock::acquire` (`PrivateProfile`), so
//! the directory is created normally and the host validates it itself.
use std::path::Path;

/// `tempfile::Builder::private_tempdir()`: a temporary directory the host accepts as
/// its profile. On unix that is mode 0700. On Windows the host only accepts a
/// profile whose directory it created itself with a protected DACL, below an
/// ancestor chain it trusts; `%TEMP%` is not trusted (it grants AppPackage
/// DELETE), so the directory is created under the user profile and re-created
/// by `OwnerLock::acquire`.
pub(crate) trait BuilderExt {
    fn private_tempdir(&mut self) -> std::io::Result<tempfile::TempDir>;
}
impl BuilderExt for tempfile::Builder<'_, '_> {
    fn private_tempdir(&mut self) -> std::io::Result<tempfile::TempDir> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            self.permissions(std::fs::Permissions::from_mode(0o700))
                .tempdir()
        }
        #[cfg(windows)]
        {
            let base = std::env::var_os("USERPROFILE").expect("USERPROFILE");
            let dir = self.tempdir_in(base)?;
            std::fs::remove_dir(dir.path())?;
            create_private_dir(dir.path())?;
            Ok(dir)
        }
    }
}

/// Creates one directory that only the current account may use.
pub(crate) fn create_private_dir(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        std::fs::DirBuilder::new().mode(0o700).create(path)
    }
    #[cfg(windows)]
    {
        // The platform creates the directory with its protected DACL and
        // validates every ancestor; dropping the lock keeps the directory.
        drop(lomi_platform::windows::OwnerLock::acquire(path).map_err(std::io::Error::other)?);
        Ok(())
    }
}

/// Makes an existing directory private (mode 0700 on unix, a no-op on Windows).
pub(crate) fn make_private(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

/// Child-process ownership is a unix concept (reaping, subreaper); Windows
/// owns children through job objects created by the terminal layer.
pub(crate) fn initialize_child_ownership() {
    #[cfg(unix)]
    lomi_platform::process::initialize_child_ownership().unwrap();
}

/// The interactive shell the real-PTY fixtures run.
pub(crate) fn shell_executable() -> std::path::PathBuf {
    #[cfg(unix)]
    {
        "/bin/sh".into()
    }
    #[cfg(windows)]
    {
        std::env::var_os("COMSPEC")
            .map(std::path::PathBuf::from)
            .filter(|p| p.is_absolute() && p.is_file())
            .unwrap_or_else(|| {
                std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap_or_default())
                    .join("System32")
                    .join("cmd.exe")
            })
    }
}

/// Environment for the fixtures' PTY shell rooted at `home`.
pub(crate) fn shell_environment(home: &Path) -> Vec<(String, String)> {
    let home = home.to_str().unwrap().to_owned();
    #[cfg(unix)]
    {
        vec![
            ("HOME".into(), home),
            ("PATH".into(), "/usr/bin:/bin".into()),
            ("TERM".into(), "xterm-256color".into()),
        ]
    }
    #[cfg(windows)]
    {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        vec![
            ("USERPROFILE".into(), home),
            ("PATH".into(), var("PATH")),
            ("SystemRoot".into(), var("SystemRoot")),
            ("COMSPEC".into(), var("COMSPEC")),
            ("TERM".into(), "xterm-256color".into()),
        ]
    }
}

/// Keystrokes that append one `x` to `remote-terminal-marker` (no newline) and
/// then print `banner` on its own line. Typing it twice would show two `x`.
pub(crate) fn marker_command(banner: &str) -> Vec<u8> {
    #[cfg(unix)]
    {
        format!("printf x >> remote-terminal-marker; printf '{banner}\\n'\n").into_bytes()
    }
    #[cfg(windows)]
    {
        format!("<nul set /p \"=x\" >> remote-terminal-marker & echo {banner}\r").into_bytes()
    }
}

/// Writes a shell wrapper at `path`. A working wrapper runs the platform shell;
/// the failing form passes "is an existing executable file" validation but makes
/// the real PTY spawn fail inside the operating system.
pub(crate) fn write_shell_wrapper(path: &Path, working: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(path, "#!/bin/sh\nexec /bin/sh \"$@\"\n").unwrap();
        // The owner (who runs it) has no execute bit: execve fails with EACCES.
        let mode = if working { 0o755 } else { 0o611 };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
    #[cfg(windows)]
    {
        if working {
            std::fs::copy(shell_executable(), path).unwrap();
        } else {
            // A running image cannot be overwritten or deleted, but it can be
            // renamed; the fixture's earlier PTYs still run from this path.
            if path.exists() {
                let moved = path.with_extension(format!("running-{}", std::process::id()));
                std::fs::rename(path, moved).unwrap();
            }
            // Not a PE image: CreateProcess fails with ERROR_BAD_EXE_FORMAT.
            std::fs::write(path, b"this is not a program").unwrap();
        }
    }
}

/// Creates a directory symlink. Returns false when the platform refuses for lack of
/// privilege (a standard Windows account without Developer Mode).
pub(crate) fn symlink_dir(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        match std::os::windows::fs::symlink_dir(target, link) {
            Ok(()) => true,
            Err(e) if e.raw_os_error() == Some(1314) => false,
            Err(e) => panic!("symlink_dir failed: {e}"),
        }
    }
}

/// The secret provider the fixtures declare. Their storage is in memory, so this
/// only has to be a provider the platform accepts: a protected file on unix and
/// DPAPI on Windows (where a protected file configuration is invalid).
pub(crate) fn provider() -> lomi_remote_protocol::ipc::LocalAuthProvider {
    #[cfg(unix)]
    {
        lomi_remote_protocol::ipc::LocalAuthProvider::ProtectedFile
    }
    #[cfg(windows)]
    {
        lomi_remote_protocol::ipc::LocalAuthProvider::WindowsDpapi
    }
}
pub(crate) fn file_acknowledgement() -> Option<lomi_remote_protocol::ipc::LocalFileAcknowledgement>
{
    #[cfg(unix)]
    {
        Some(lomi_remote_protocol::ipc::LocalFileAcknowledgement::OsPermissionsOnly)
    }
    #[cfg(windows)]
    {
        None
    }
}
pub(crate) fn provider_kind() -> lomi_platform::secrets::ProviderKind {
    #[cfg(unix)]
    {
        lomi_platform::secrets::ProviderKind::ProtectedFile
    }
    #[cfg(windows)]
    {
        lomi_platform::secrets::ProviderKind::WindowsDpapi
    }
}
