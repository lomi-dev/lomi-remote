use super::{Error, Observation};
use std::{
    fs::{self, File},
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

// /usr/bin/git is a developer-tool launcher on macOS, not a standalone Git.
// No PATH discovery or retry with another executable is permitted.
const GIT: &str = "/Library/Developer/CommandLineTools/usr/bin/git";
const SANDBOX: &str = "/usr/bin/sandbox-exec";
const PROFILE: &str = r#"(version 1)
(allow default)
(deny network*)
(deny process-fork)
(deny process-exec)
(allow process-exec (literal (param "GIT")))
(deny file-write*)
(allow file-write* (literal "/dev/null"))
(deny file-read-data)
(allow file-read-data (subpath (param "ROOT"))
  (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share")
  (literal (param "GIT")) (literal "/dev/null") (literal "/"))
"#;
const OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
const ERROR_LIMIT: usize = 16 * 1024;
const TIMEOUT: Duration = Duration::from_secs(5);

type Identity = (u64, u64, u64, i64, i64, i64, i64);
fn identity(m: &fs::Metadata) -> Identity {
    (
        m.dev(),
        m.ino(),
        m.len(),
        m.mtime(),
        m.mtime_nsec(),
        m.ctime(),
        m.ctime_nsec(),
    )
}
fn runtime_identity(path: &str) -> Result<Identity, Error> {
    for ancestor in Path::new(path).ancestors() {
        let m = fs::symlink_metadata(ancestor).map_err(|_| Error::UntrustedRuntime)?;
        if m.is_symlink() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error::UntrustedRuntime);
        }
    }
    let m = fs::metadata(path).map_err(|_| Error::UntrustedRuntime)?;
    if !m.is_file() || m.mode() & 0o111 == 0 {
        return Err(Error::UntrustedRuntime);
    }
    Ok(identity(&m))
}

pub(super) fn read(root: &Path, observation: Observation) -> Result<Vec<u8>, Error> {
    let arguments: &[&str] = match observation {
        Observation::Status => &[
            "status",
            "--porcelain=v2",
            "-z",
            "--untracked-files=all",
            "--ignore-submodules=all",
        ],
        Observation::Diff => &[
            "diff",
            "--no-ext-diff",
            "--no-textconv",
            "--no-color",
            "--no-renames",
            "--ignore-submodules=all",
            "--",
        ],
    };
    execute(root, arguments)
}

fn execute(root: &Path, arguments: &[&str]) -> Result<Vec<u8>, Error> {
    let root = root.canonicalize().map_err(|_| Error::Io)?;
    let root_text = root.to_str().ok_or(Error::UnsupportedRepository)?;
    let directory = File::open(&root).map_err(|_| Error::Io)?;
    let original = directory.metadata().map_err(|_| Error::Io)?;
    if !original.is_dir() {
        return Err(Error::UnsupportedRepository);
    }
    // Linked worktrees and symlinked metadata need a separate metadata grant.
    if !fs::symlink_metadata(root.join(".git"))
        .map_err(|_| Error::UnsupportedRepository)?
        .is_dir()
    {
        return Err(Error::UnsupportedRepository);
    }
    let git_identity = runtime_identity(GIT)?;
    let sandbox_identity = runtime_identity(SANDBOX)?;
    let mut command = Command::new(SANDBOX);
    command
        .args(["-p", PROFILE])
        .arg(format!("-DROOT={root_text}"))
        .arg(format!("-DGIT={GIT}"))
        .arg(GIT)
        .args([
            "--no-pager",
            "--no-optional-locks",
            "--literal-pathspecs",
            "--git-dir=.git",
            "--work-tree=.",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "core.attributesFile=/dev/null",
            "-c",
            "gc.auto=0",
        ])
        .args(arguments)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", &root)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let cwd = directory.try_clone().map_err(|_| Error::Io)?;
    // SAFETY: fchdir is async-signal-safe; the descriptor stays owned by closure.
    unsafe {
        command.pre_exec(move || {
            if libc::fchdir(cwd.as_raw_fd()) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = OwnedChild(command.spawn().map_err(|_| Error::UntrustedRuntime)?);
    let stdout = child.0.stdout.take().ok_or(Error::Io)?;
    let stderr = child.0.stderr.take().ok_or(Error::Io)?;
    let overflow = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + TIMEOUT;
    let result = thread::scope(|scope| {
        let out = scope.spawn(|| drain(stdout, OUTPUT_LIMIT, &overflow));
        let err = scope.spawn(|| drain(stderr, ERROR_LIMIT, &overflow));
        let status = loop {
            if overflow.load(Ordering::SeqCst) {
                break Err(Error::LimitExceeded);
            }
            if Instant::now() >= deadline {
                break Err(Error::DeadlineExceeded);
            }
            match child.0.try_wait() {
                Ok(Some(status)) => break Ok(status),
                Ok(None) => thread::sleep(Duration::from_millis(5)),
                Err(_) => break Err(Error::Io),
            }
        };
        if status.is_err() {
            let _ = child.0.kill();
        }
        let _ = child.0.wait();
        let out = out.join().map_err(|_| Error::Io)??;
        let err = err.join().map_err(|_| Error::Io)??;
        let status = status?;
        if overflow.load(Ordering::SeqCst) {
            return Err(Error::LimitExceeded);
        }
        // Optional filters can fail with stderr yet Git still exits zero and
        // returns an unfiltered diff. Never silently accept that fallback.
        if !status.success() || !err.is_empty() {
            return Err(Error::Rejected);
        }
        Ok(out)
    });
    let current = fs::metadata(&root).map_err(|_| Error::Changed)?;
    if (original.dev(), original.ino()) != (current.dev(), current.ino())
        || git_identity != runtime_identity(GIT)?
        || sandbox_identity != runtime_identity(SANDBOX)?
    {
        return Err(Error::Changed);
    }
    result
}

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn drain(mut reader: impl Read, limit: usize, overflow: &AtomicBool) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::new();
    let mut buffer = [0; 8192];
    loop {
        let size = reader.read(&mut buffer).map_err(|_| Error::Io)?;
        if size == 0 {
            return Ok(bytes);
        }
        if size > limit.saturating_sub(bytes.len()) {
            overflow.store(true, Ordering::SeqCst);
            return Ok(bytes);
        }
        bytes.extend_from_slice(&buffer[..size]);
    }
}

#[cfg(test)]
mod tests;
