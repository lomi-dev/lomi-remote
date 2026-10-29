use lomi_terminal_state::{Delta, PROFILE, Snapshot, TerminalState};
use portable_pty::{Child, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde_json::{Value, json};
use std::{
    error::Error,
    io::{Read, Write},
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Command, Stdio},
    time::{Duration, Instant},
};
type Result<T> = std::result::Result<T, Box<dyn Error>>;
const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_EVENTS: usize = 128;
const MAX_ARTIFACT: usize = 32 * 1024 * 1024;
struct ChildGuard {
    child: Box<dyn Child + Send + Sync>,
    group: libc::pid_t,
    armed: bool,
}
impl ChildGuard {
    fn new(mut child: Box<dyn Child + Send + Sync>) -> Result<Self> {
        let pid = child
            .process_id()
            .and_then(|p| i32::try_from(p).ok())
            .filter(|p| *p > 0);
        let Some(pid) = pid else {
            let _ = child.kill();
            let _ = child.wait();
            return Err("missing child PID".into());
        };
        // native portable-pty creates a new session before exec. Never adopt another group.
        if unsafe { libc::getpgid(pid) } != pid {
            let _ = child.kill();
            let _ = child.wait();
            return Err("child has no dedicated process group".into());
        }
        Ok(Self {
            child,
            group: pid,
            armed: true,
        })
    }
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.armed {
            unsafe {
                libc::kill(-self.group, libc::SIGKILL);
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
struct Probe {
    host: TerminalState,
    master: Box<dyn MasterPty + Send>,
    reader: Box<dyn Read + Send>,
    writer: Box<dyn Write + Send>,
    child: ChildGuard,
    initial: Snapshot,
    previous: Snapshot,
    deltas: Vec<Delta>,
    bytes: usize,
    reply_bytes: usize,
    replies: usize,
    input_bytes: usize,
    deadline: Instant,
    milestones: Vec<Value>,
}
impl Probe {
    fn record(&mut self) -> Result<()> {
        if self.deltas.len() >= MAX_EVENTS {
            return Err("state event bound exceeded".into());
        }
        let d = self
            .host
            .next_delta(&self.previous)
            .map_err(|_| "state delta rejected")?;
        self.previous = d.state.clone();
        self.deltas.push(d);
        Ok(())
    }
    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        if bytes.len() > 512 {
            return Err("input chunk bound exceeded".into());
        }
        let mut written = 0;
        while written < bytes.len() {
            if Instant::now() >= self.deadline {
                return Err("PTY write deadline".into());
            }
            match self.writer.write(&bytes[written..]) {
                Ok(0) => return Err("PTY writer closed".into()),
                Ok(n) => written += n,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(2))
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
    fn input(&mut self, bytes: &[u8]) -> Result<()> {
        self.input_bytes += bytes.len();
        if self.input_bytes > 4096 {
            return Err("input total bound exceeded".into());
        }
        self.write(bytes)
    }
    fn pump(&mut self) -> Result<bool> {
        if Instant::now() >= self.deadline {
            return Err("total PTY deadline".into());
        }
        let timed = self
            .host
            .expire_sync(Instant::now())
            .map_err(|_| "host timer failed")?;
        if timed {
            self.record()?;
            for reply in self.host.take_replies() {
                self.replies += 1;
                self.reply_bytes += reply.len();
                if self.replies > 128 || self.reply_bytes > 8192 {
                    return Err("host reply total bound exceeded".into());
                }
                self.write(reply.as_bytes())?;
            }
        }
        let mut bytes = [0; 8192];
        let size = match self.reader.read(&mut bytes) {
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(timed),
            Err(e) if e.raw_os_error() == Some(libc::EIO) => return Ok(timed),
            Err(e) => return Err(e.into()),
        };
        if size == 0 {
            return Ok(timed);
        }
        self.bytes += size;
        if self.bytes > MAX_OUTPUT {
            return Err("output byte bound exceeded".into());
        }
        self.host
            .feed(&bytes[..size])
            .map_err(|_| "host rejected PTY output")?;
        self.record()?;
        for reply in self.host.take_replies() {
            self.replies += 1;
            self.reply_bytes += reply.len();
            if self.replies > 128 || self.reply_bytes > 8192 {
                return Err("host reply total bound exceeded".into());
            }
            self.write(reply.as_bytes())?;
        }
        if self.host.stats().dropped_replies != 0 {
            return Err("host reply queue overflow".into());
        }
        Ok(true)
    }
    fn until(&mut self, name: &str, condition: impl Fn(&Snapshot) -> bool) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(8);
        let mut quiet_since = Instant::now();
        loop {
            if self.pump()? {
                quiet_since = Instant::now();
            }
            let s = self.host.snapshot().map_err(|_| "snapshot rejected")?;
            if condition(&s) && quiet_since.elapsed() >= Duration::from_millis(40) {
                self.attach(name)?;
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("milestone timeout: {name}").into());
            }
            if self.child.child.try_wait()?.is_some() {
                return Err(format!("Vim exited before milestone: {name}").into());
            }
            std::thread::sleep(Duration::from_millis(3));
        }
    }
    fn attach(&mut self, name: &str) -> Result<()> {
        let before = self
            .host
            .snapshot()
            .map_err(|_| "attach snapshot rejected")?;
        let replies = self.replies;
        let input = self.input_bytes;
        if self.child.child.try_wait()?.is_some() {
            return Err("Vim exited during attach".into());
        }
        if before
            != self
                .host
                .snapshot()
                .map_err(|_| "repeat snapshot rejected")?
            || !self.host.take_replies().is_empty()
            || replies != self.replies
            || input != self.input_bytes
        {
            return Err("attachment changed live state or replies".into());
        }
        self.milestones.push(json!({"name":name,"sequence":before.sequence,"outputOffset":before.output_offset,"rows":before.rows,"cols":before.cols,"active":before.active,"attachPreservedProcessStateInputAndReplies":true}));
        Ok(())
    }
}
fn visible(s: &Snapshot) -> String {
    let b = if s.active == "alternate" {
        &s.alternate
    } else {
        &s.normal
    };
    b.lines
        .iter()
        .skip(b.base_y)
        .map(|r| r.cells.iter().map(|c| c.text.as_str()).collect::<String>())
        .collect::<Vec<_>>()
        .join("\n")
}
fn size(rows: u16, cols: u16) -> PtySize {
    PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
}
// Version discovery also has a dedicated group, no startup files, bounded
// output and a deadline; no unguarded subprocess precedes the interactive run.
fn bounded_version(cwd: &std::path::Path, locale: &str) -> Result<String> {
    let mut child = Command::new("/usr/bin/vim")
        .arg("--version")
        .env_clear()
        .env("HOME", cwd)
        .env("PATH", "/usr/bin:/bin")
        .env("LC_ALL", locale)
        .current_dir(cwd)
        .process_group(0)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let mut stdout = child
        .stdout
        .take()
        .expect("version stdout configured as pipe");
    let mut guard = ChildGuard::new(Box::new(child))?;
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut bytes = Vec::new();
    let mut status = None;
    let mut eof = false;
    while !eof || status.is_none() {
        if Instant::now() >= deadline {
            return Err("Vim version deadline".into());
        }
        let mut buffer = [0; 4096];
        match stdout.read(&mut buffer) {
            Ok(0) => eof = true,
            Ok(n) => {
                bytes.extend_from_slice(&buffer[..n]);
                if bytes.len() > 16384 {
                    return Err("Vim version byte bound".into());
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(e) => return Err(e.into()),
        }
        if status.is_none() {
            status = guard.child.try_wait()?;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    if !status.is_some_and(|s| s.success()) {
        return Err("Vim version probe failed".into());
    }
    if unsafe { libc::kill(-guard.group, 0) } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err("Vim version group remains".into());
    }
    guard.armed = false;
    Ok(String::from_utf8(bytes)?
        .lines()
        .next()
        .ok_or("empty Vim version")?
        .to_owned())
}
pub fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let artifact = match args.as_slice() {
        [] => None,
        [flag, path] if flag == "--fixtures" => Some(std::path::PathBuf::from(path)),
        _ => return Err("usage: lomi-terminal-pty-fixture [--fixtures PATH]".into()),
    };
    let temp = tempfile::tempdir()?;
    let cwd = temp.path().canonicalize()?;
    let text = format!(
        "LOMI_PTY_FIXTURE\nUnicode: 界 e\u{301} 🙂\n{}",
        (3..=24)
            .map(|n| format!("navigation target {n:02}\n"))
            .collect::<String>()
    );
    std::fs::write(cwd.join("syntheticfixture.txt"), &text)?;
    let locale = if cfg!(target_os = "macos") {
        "en_US.UTF-8"
    } else {
        "C.UTF-8"
    };
    let version = bounded_version(&cwd, locale)?;
    let pair = native_pty_system().openpty(size(12, 60))?;
    let mut command = CommandBuilder::new("/usr/bin/vim");
    command.args([
        "-N",
        "-u",
        "NONE",
        "-U",
        "NONE",
        "-i",
        "NONE",
        "-n",
        "--noplugin",
        "-R",
        "syntheticfixture.txt",
    ]);
    command.env_clear();
    command.cwd(&cwd);
    command.env("HOME", &cwd);
    command.env("PATH", "/usr/bin:/bin");
    command.env("LC_ALL", locale);
    command.env("TERM", "xterm-256color");
    let child = ChildGuard::new(pair.slave.spawn_command(command)?)?;
    drop(pair.slave);
    let fd = pair.master.as_raw_fd().ok_or("PTY has no fd")?;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let reader = pair.master.try_clone_reader()?;
    let writer = pair.master.take_writer()?;
    let host = TerminalState::new(12, 60, 8).map_err(|_| "invalid initial terminal")?;
    let initial = host.snapshot().map_err(|_| "initial snapshot")?;
    let mut p = Probe {
        host,
        master: pair.master,
        reader,
        writer,
        child,
        initial: initial.clone(),
        previous: initial,
        deltas: Vec::new(),
        bytes: 0,
        reply_bytes: 0,
        replies: 0,
        input_bytes: 0,
        deadline: Instant::now() + Duration::from_secs(30),
        milestones: Vec::new(),
    };
    p.until("startup_unicode", |s| {
        s.active == "alternate"
            && visible(s).contains("LOMI_PTY_FIXTURE")
            && visible(s).contains("Unicode: 界 e\u{301} 🙂")
    })?;
    p.input(b"jjl")?;
    p.until("normal_navigation", |s| {
        s.alternate.cursor.y == 2 && s.alternate.cursor.x == 1
    })?;
    p.input(b"G")?;
    p.until("normal_scroll", |s| {
        visible(s).contains("navigation target 24")
    })?;
    p.input(b"gg:")?;
    p.until("command_mode", |s| {
        visible(s)
            .lines()
            .last()
            .is_some_and(|l| l.starts_with(':'))
    })?;
    p.input(b"echo 'LOMI_COMMAND_OK'\r")?;
    p.until("command_result", |s| visible(s).contains("LOMI_COMMAND_OK"))?;
    p.input(b":highlight Normal ctermfg=2 ctermbg=0\r:redraw!\r")?;
    p.until("ansi_color", |s| {
        matches!(
            s.alternate.lines[0].cells[0].fg,
            lomi_terminal_state::Color::Indexed { index: 2 }
        )
    })?;
    p.master.resize(size(14, 72))?;
    p.host.resize(14, 72).map_err(|_| "host resize failed")?;
    p.record()?;
    p.input(b":echo printf('LOMI_SIZE_%d_%d', &lines, &columns)\r")?;
    p.until("resize_vim_and_host", |s| {
        s.rows == 14 && s.cols == 72 && visible(s).contains("LOMI_SIZE_14_72")
    })?;
    p.input(b":q!\r")?;
    let status = loop {
        p.pump()?;
        if let Some(status) = p.child.child.try_wait()? {
            break status;
        }
        std::thread::sleep(Duration::from_millis(3));
    };
    // Drain remaining output through the sole Rust parser after the final child write.
    while p.pump()? {}
    if !status.success() {
        return Err("Vim clean exit failed".into());
    }
    if unsafe { libc::kill(-p.child.group, 0) } != -1
        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    {
        return Err("owned child group remains after Vim exit".into());
    }
    p.child.armed = false;
    let final_state = p.host.snapshot().map_err(|_| "final snapshot failed")?;
    if final_state.active != "normal" {
        return Err("Vim did not restore normal buffer".into());
    }
    if std::fs::read_to_string(cwd.join("syntheticfixture.txt"))? != text {
        return Err("synthetic read-only fixture changed".into());
    }
    let event_count = p.deltas.len();
    let fixtures = json!({"profile":PROFILE,"qualified":false,"cases":[{"id":"real_interactive_vim","snapshot":p.initial,"deltas":p.deltas,"final":final_state}]});
    let bytes = serde_json::to_vec(&fixtures)?;
    if bytes.len() > MAX_ARTIFACT {
        return Err("artifact byte bound exceeded".into());
    }
    if let Some(path) = artifact {
        std::fs::write(path, &bytes)?;
    }
    println!(
        "{}",
        json!({"profile":PROFILE,"qualified":false,"platform":std::env::consts::OS,"vimVersion":version,"argv":["/usr/bin/vim","-N","-u","NONE","-U","NONE","-i","NONE","-n","--noplugin","-R","syntheticfixture.txt"],"locale":locale,"outputBytes":p.bytes,"inputBytes":p.input_bytes,"hostReplyCount":p.replies,"hostReplyBytes":p.reply_bytes,"stateEvents":event_count,"artifactBytes":bytes.len(),"milestones":p.milestones,"cleanExit":true,"childGroupGone":true,"rawPtyClientWrites":0,"userFileModified":false,"syntheticFixtureUnchanged":true,"remaining":["multi-hour soak","arbitrary CLI compatibility","Windows native PTY"]})
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn owned_sleep() -> (portable_pty::PtyPair, ChildGuard) {
        let pair = native_pty_system().openpty(size(12, 60)).unwrap();
        let mut command = CommandBuilder::new("/bin/sleep");
        command.arg("30");
        command.env_clear();
        let guard = ChildGuard::new(pair.slave.spawn_command(command).unwrap()).unwrap();
        (pair, guard)
    }
    fn gone(group: libc::pid_t) {
        assert_eq!(unsafe { libc::kill(-group, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    #[test]
    fn child_group_guard_cleans_up_on_error() {
        let (_pair, guard) = owned_sleep();
        let group = guard.group;
        let failed: Result<()> = {
            let _guard = guard;
            Err("forced fixture error".into())
        };
        assert!(failed.is_err());
        gone(group);
    }
    #[test]
    fn child_group_guard_cleans_up_on_panic() {
        let (_pair, guard) = owned_sleep();
        let group = guard.group;
        let failed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
            let _guard = guard;
            panic!("forced fixture panic")
        }));
        assert!(failed.is_err());
        gone(group);
    }
}
