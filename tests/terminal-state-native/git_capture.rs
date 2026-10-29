//! Fixed-command synthetic CLI capture; never inherits user Git configuration.
use std::{
    fs,
    io::{self, Read},
    os::{
        fd::AsRawFd,
        unix::{fs::MetadataExt, process::CommandExt},
    },
    path::Path,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

fn exited(child: &Child) -> io::Result<bool> {
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    let result = unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { info.si_pid() } != 0)
}
struct Owned {
    child: Child,
    armed: bool,
}
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Keep the direct child unreaped as the process-group identity anchor.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGTERM);
        }
        thread::sleep(Duration::from_millis(50));
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if exited(&self.child).unwrap_or(false) {
                let _ = self.child.wait();
                return;
            }
            thread::sleep(Duration::from_millis(5));
        }
    }
}
fn capture(command: &mut Command) -> io::Result<Output> {
    capture_with_timeout(command, Duration::from_secs(5))
}
fn capture_with_timeout(command: &mut Command, timeout: Duration) -> io::Result<Output> {
    let mut child = Owned {
        child: command
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
        armed: true,
    };
    let mut out = child
        .child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("missing fixture stdout"))?;
    let mut err = child
        .child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("missing fixture stderr"))?;
    for fd in [out.as_raw_fd(), err.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let deadline = Instant::now() + timeout;
    loop {
        for (reader, bytes, cap) in [
            (&mut out as &mut dyn Read, &mut stdout, 1024 * 1024),
            (&mut err as &mut dyn Read, &mut stderr, 4096),
        ] {
            let mut chunk = [0; 4096];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        if bytes.len() + n > cap {
                            return Err(io::Error::other("fixture output limit"));
                        }
                        bytes.extend_from_slice(&chunk[..n]);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e),
                }
            }
        }
        if exited(&child.child)? {
            // Read one final time after observing exit, without releasing the
            // identity anchor until every owned group member has been signaled.
            for (reader, bytes, cap) in [
                (&mut out as &mut dyn Read, &mut stdout, 1024 * 1024),
                (&mut err as &mut dyn Read, &mut stderr, 4096),
            ] {
                let mut chunk = [0; 4096];
                loop {
                    match reader.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => {
                            if bytes.len() + n > cap {
                                return Err(io::Error::other("fixture output limit"));
                            }
                            bytes.extend_from_slice(&chunk[..n]);
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e),
                    }
                }
            }
            unsafe {
                libc::kill(-(child.child.id() as i32), libc::SIGTERM);
            }
            thread::sleep(Duration::from_millis(50));
            unsafe {
                libc::kill(-(child.child.id() as i32), libc::SIGKILL);
            }
            // Every owned group member has been signaled while the unreaped
            // child still anchors its identity. Never signal it after reaping.
            child.armed = false;
            let status = child.child.wait()?;
            return Ok(Output {
                status,
                stdout,
                stderr,
            });
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "fixture Git deadline",
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn trusted_git() -> io::Result<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    let git = Path::new("/Library/Developer/CommandLineTools/usr/bin/git");
    #[cfg(not(target_os = "macos"))]
    let git = Path::new("/usr/bin/git");
    let executable = fs::canonicalize(git)?;
    for path in executable.ancestors() {
        let metadata = fs::metadata(path)?;
        if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(io::Error::other("untrusted fixture Git runtime"));
        }
    }
    Ok(executable)
}

pub fn diff(directory: &Path) -> io::Result<Vec<u8>> {
    let mut command = Command::new(trusted_git()?);
    command
        .env_clear()
        .current_dir(directory)
        .env("HOME", directory)
        .env("TMPDIR", directory)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_CONFIG_COUNT", "0")
        .args([
            "--no-pager",
            "diff",
            "--no-index",
            "--no-ext-diff",
            "--no-textconv",
            "--color=always",
            "--",
            "before",
            "after",
        ]);
    let output = capture(&mut command)?;
    if output.status.code() != Some(1) || !output.stderr.is_empty() {
        return Err(io::Error::other("synthetic Git capture rejected"));
    }
    Ok(output.stdout)
}

#[test]
fn inherited_external_diff_and_global_config_cannot_run_a_helper() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    fs::write(temp.path().join("before"), "synthetic before\n").unwrap();
    fs::write(temp.path().join("after"), "synthetic after\n").unwrap();
    let marker = temp.path().join("helper-ran");
    let helper = temp.path().join("helper");
    fs::write(
        &helper,
        format!(
            "#!/bin/sh\nprintf synthetic > '{}'\nexit 1\n",
            marker.to_string_lossy().replace('\'', "'\\''")
        ),
    )
    .unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    let helper_command = format!("'{}'", helper.to_string_lossy().replace('\'', "'\\''"));
    fs::write(
        temp.path().join(".gitconfig"),
        format!(
            "[diff]\n external = \"{}\"\n",
            helper_command.replace('\\', "\\\\").replace('"', "\\\"")
        ),
    )
    .unwrap();
    // Positive control proves this exact benign configured helper runs when
    // enabled. Its marker must then stay absent through the isolated capture.
    let mut positive = Command::new(trusted_git().unwrap());
    positive
        .env_clear()
        .current_dir(temp.path())
        .env("HOME", temp.path())
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_EXTERNAL_DIFF", &helper_command)
        .env("GIT_CONFIG_GLOBAL", temp.path().join(".gitconfig"))
        .args(["--no-pager", "diff", "--no-index", "--", "before", "after"]);
    assert!(!capture(&mut positive).unwrap().status.success());
    assert!(
        marker.exists(),
        "synthetic helper positive control did not execute"
    );
    fs::remove_file(&marker).unwrap();
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .env_clear()
        .env("HOME", temp.path())
        .env("GIT_EXTERNAL_DIFF", &helper_command)
        .env("GIT_CONFIG_GLOBAL", temp.path().join(".gitconfig"))
        .env("LOMI_SYNTHETIC_GIT_DIR", temp.path())
        .args([
            "--exact",
            "git_capture::isolated_capture_child",
            "--ignored",
            "--nocapture",
        ]);
    // Give the test child time to run and clean its own shorter-lived Git
    // group before the parent's independent deadline can stop the test child.
    let result = capture_with_timeout(&mut command, Duration::from_secs(15)).unwrap();
    assert!(result.status.success(), "isolated capture child failed");
    assert!(
        String::from_utf8_lossy(&result.stdout)
            .lines()
            .any(|line| line == "LOMI_SYNTHETIC_CAPTURE_COMPLETE")
    );
    assert!(!marker.exists(), "a synthetic configured helper executed");
}

#[test]
#[ignore = "private child entry; exercised by the parent isolation regression"]
fn isolated_capture_child() {
    let directory =
        std::env::var_os("LOMI_SYNTHETIC_GIT_DIR").expect("synthetic child fixture only");
    assert!(
        diff(Path::new(&directory))
            .unwrap()
            .windows(4)
            .any(|s| s == b"diff")
    );
    println!("LOMI_SYNTHETIC_CAPTURE_COMPLETE");
}
