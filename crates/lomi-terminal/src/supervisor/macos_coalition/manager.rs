use super::*;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};

fn retained(child: &Child) -> io::Result<()> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction != libc::SIG_DFL
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(io::Error::other("child ownership unavailable"));
    }
    let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
    if unsafe {
        libc::waitid(
            libc::P_PID,
            child.id(),
            &mut info,
            libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
struct Guard(Option<Child>);
impl Drop for Guard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0
            && retained(child).is_ok()
        {
            unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
            let _ = child.wait();
        }
    }
}
fn command(arguments: &[&str]) -> Result<(i32, String)> {
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &mut action) } != 0
        || action.sa_sigaction != libc::SIG_DFL
        || action.sa_flags & libc::SA_NOCLDWAIT != 0
    {
        return Err(Error::CleanupFailed);
    }
    let child = Command::new("/bin/launchctl")
        .args(arguments)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| Error::CleanupFailed)?;
    let mut guard = Guard(Some(child));
    let mut stdout = guard
        .0
        .as_mut()
        .unwrap()
        .stdout
        .take()
        .ok_or(Error::CleanupFailed)?;
    let mut stderr = guard
        .0
        .as_mut()
        .unwrap()
        .stderr
        .take()
        .ok_or(Error::CleanupFailed)?;
    for fd in [stdout.as_raw_fd(), stderr.as_raw_fd()] {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::CleanupFailed);
        }
    }
    let mut output = Vec::new();
    let mut errors = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(3);
    let mut exited = None;
    loop {
        for (reader, bytes) in [
            (&mut stdout as &mut dyn Read, &mut output),
            (&mut stderr as &mut dyn Read, &mut errors),
        ] {
            let mut buffer = [0; 4096];
            loop {
                match reader.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        bytes.extend_from_slice(&buffer[..n]);
                        if bytes.len() > 32768 {
                            return Err(Error::CleanupFailed);
                        }
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(_) => return Err(Error::CleanupFailed),
                }
            }
        }
        if let Some(code) = exited {
            // Neither stream is logged: launchctl may include inherited secrets.
            return Ok((
                code,
                String::from_utf8(output).map_err(|_| Error::CleanupFailed)?,
            ));
        }
        if let Some(status) = guard
            .0
            .as_mut()
            .unwrap()
            .try_wait()
            .map_err(|_| Error::CleanupFailed)?
        {
            guard.0.take();
            exited = Some(status.code().unwrap_or(-1));
        }
        if Instant::now() >= deadline {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(2));
    }
}
fn xml(value: &str) -> Result<String> {
    if value.len() > 4096 || value.chars().any(|c| c < ' ' || c == '\u{7f}') {
        return Err(Error::InvalidArgument);
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}
pub(super) fn definition(directory: &Directory, record: &Record) -> Result<Vec<u8>> {
    let executable = xml(record.executable.to_str().ok_or(Error::InvalidArgument)?)?;
    let path = xml(directory.path.to_str().ok_or(Error::InvalidArgument)?)?;
    let label = record.label();
    Ok(format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Label</key><string>{label}</string><key>ProgramArguments</key><array><string>{executable}</string><string>--internal-pty-coalition</string><string>{path}</string></array><key>RunAtLoad</key><true/><key>LaunchOnlyOnce</key><true/><key>KeepAlive</key><false/><key>LimitLoadToSessionType</key><string>Background</string><key>ProcessType</key><string>Background</string><key>ExitTimeOut</key><integer>3</integer><key>Umask</key><integer>63</integer><key>StandardOutPath</key><string>/dev/null</string><key>StandardErrorPath</key><string>/dev/null</string></dict></plist>").into_bytes())
}
pub(super) fn observe(directory: &Directory, record: &Record) -> Result<Option<Option<i32>>> {
    let target = record.target();
    let (status, output) = command(&["print", &target])?;
    if status == 113 {
        return Ok(None);
    }
    if status != 0 {
        return Err(Error::CleanupFailed);
    }
    let lines: Vec<_> = output.lines().collect();
    if lines.first().copied() != Some(format!("{target} = {{").as_str()) {
        return Err(Error::CleanupFailed);
    }
    for (key, wanted) in [
        ("path", directory.path.join("job.plist")),
        ("program", record.executable.clone()),
    ] {
        let prefix = format!("\t{key} = ");
        let values: Vec<_> = lines
            .iter()
            .filter_map(|line| line.strip_prefix(&prefix))
            .collect();
        if values != [wanted.to_str().ok_or(Error::CleanupFailed)?] {
            return Err(Error::CleanupFailed);
        }
    }
    let starts: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| (*line == "\targuments = {").then_some(i))
        .collect();
    if starts.len() != 1 {
        return Err(Error::CleanupFailed);
    }
    let wanted = [
        format!("\t\t{}", record.executable.display()),
        "\t\t--internal-pty-coalition".into(),
        format!("\t\t{}", directory.path.display()),
        "\t}".into(),
    ];
    if lines.get(starts[0] + 1..starts[0] + 5)
        != Some(
            wanted
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
        )
    {
        return Err(Error::CleanupFailed);
    }
    let pids: Vec<_> = lines
        .iter()
        .filter_map(|line| line.strip_prefix("\tpid = "))
        .collect();
    if pids.is_empty() {
        return Ok(Some(None));
    }
    if pids.len() != 1 || pids[0].is_empty() || !pids[0].bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Error::CleanupFailed);
    }
    let pid = pids[0]
        .parse::<i32>()
        .ok()
        .filter(|pid| *pid > 0)
        .ok_or(Error::CleanupFailed)?;
    Ok(Some(Some(pid)))
}
pub(super) fn absent(directory: &Directory, record: &Record) -> Result<bool> {
    Ok(observe(directory, record)?.is_none())
}
pub(super) fn fresh(directory: &Directory, record: &Record) -> Result<()> {
    if !absent(directory, record)? {
        return Err(Error::CleanupFailed);
    }
    let (status, output) = command(&["print-disabled", &record.domain()])?;
    let prefix = format!("\"{}\" => ", record.label());
    if status != 0 || output.lines().any(|line| line.trim().starts_with(&prefix)) {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}
pub(super) fn bootstrap(directory: &Directory, record: &Record) -> Result<()> {
    let path = directory.path.join("job.plist");
    if command(&[
        "bootstrap",
        &record.domain(),
        path.to_str().ok_or(Error::InvalidArgument)?,
    ])?
    .0 != 0
    {
        return Err(Error::SpawnOutcomeUnknown);
    }
    Ok(())
}
pub(super) fn remove(directory: &Directory, record: &Record) -> Result<()> {
    if !absent(directory, record)? {
        let loaded = observe(directory, record)?.ok_or(Error::CleanupFailed)?;
        if loaded.is_some() && loaded != record.manager_pid()? {
            return Err(Error::CleanupFailed);
        }
        let target = record.target();
        if command(&["bootout", &target])?.0 != 0 && !absent(directory, record)? {
            return Err(Error::CleanupFailed);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while !absent(directory, record)? {
        if Instant::now() >= deadline {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(10));
    }
    directory.remove("job.plist", &definition(directory, record)?)
}

/// Remove this exact generation after admission was durably left unused.
/// Unlike `remove`, the controller identity may not have reached the journal
/// before the host stopped. The immutable UUID label plus the exact loaded
/// plist path/program/arguments bind the bootout to this generation.
pub(super) fn remove_unconsumed(directory: &Directory, record: &Record) -> Result<()> {
    if record.admission_consumed || !matches!(record.stage, Stage::BootstrapIntent | Stage::Closing)
    {
        return Err(Error::CleanupFailed);
    }
    let definition = definition(directory, record)?;
    let already_absent = absent(directory, record)?;
    match directory.read("job.plist")? {
        Some(bytes) if bytes == definition => {}
        None if already_absent => return Ok(()),
        _ => return Err(Error::CleanupFailed),
    }
    if !already_absent {
        let target = record.target();
        if command(&["bootout", &target])?.0 != 0 && !absent(directory, record)? {
            return Err(Error::CleanupFailed);
        }
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while !absent(directory, record)? {
        if Instant::now() >= deadline {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(10));
    }
    directory.remove("job.plist", &definition)
}
