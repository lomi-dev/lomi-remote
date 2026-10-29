use super::{
    native::*,
    state::{Config, persist},
};
use lomi_terminal_state::TerminalState;
use serde::Serialize;
use std::{
    mem, ptr,
    sync::{Arc, Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_sys::Win32::{
    Storage::FileSystem::*,
    System::{Console::*, JobObjects::*, Pipes::*, Threading::*},
};

#[derive(Default, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Observation {
    pub output_bytes: u64,
    pub output_chunks: u64,
    pub ready: bool,
    pub resized: bool,
    pub after_detach: bool,
    pub ctrl_c: bool,
    pub synthetic_worker_pid: Option<u32>,
    pub input_writes: u32,
    pub model_rows: usize,
    pub model_cols: usize,
    pub model_nonempty_cells: usize,
    pub failed: bool,
    pub conpty_close_fault_retained: bool,
    pub conpty_close_retry_complete: bool,
}
struct Drain {
    observation: Observation,
    model: TerminalState,
    tail: Vec<u8>,
}
// The reader owns and drains the output pipe throughout ClosePseudoConsole.
struct Console {
    handle: HPCON,
    drained: Option<mpsc::Receiver<()>>,
    closing: Option<mpsc::Receiver<()>>,
    close_complete: bool,
    shared: Arc<Mutex<Drain>>,
}
impl Console {
    fn close(&mut self) -> Result<()> {
        if self.handle != 0 {
            let handle = self.handle;
            let (tx, rx) = mpsc::channel();
            #[cfg(feature = "fixture-test-hooks")]
            if FAIL_CLOSE_SPAWN.swap(false, std::sync::atomic::Ordering::SeqCst) {
                return Err(denied("injected closer thread failure"));
            }
            // A failed spawn retains HPCON ownership. Transfer ownership only
            // after a worker exists; pending close is never treated as closed.
            thread::Builder::new()
                .name("synthetic-conpty-close".into())
                .spawn(move || {
                    unsafe {
                        ClosePseudoConsole(handle);
                    }
                    let _ = tx.send(());
                })?;
            self.handle = 0;
            self.closing = Some(rx);
        }
        if !self.close_complete {
            self.closing
                .as_ref()
                .ok_or_else(|| denied("missing closer"))?
                .recv_timeout(Duration::from_secs(3))
                .map_err(|_| denied("ConPTY close deadline"))?;
            self.closing.take();
            self.close_complete = true;
        }
        if let Some(drained) = &self.drained {
            drained
                .recv_timeout(Duration::from_secs(1))
                .map_err(|_| denied("output drain deadline"))?;
            self.drained.take();
        }
        Ok(())
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
fn output_reader(output: Handle, shared: Arc<Mutex<Drain>>, done: mpsc::Sender<()>) {
    let mut bytes = [0; 2048];
    loop {
        let mut count = 0;
        let ok = unsafe {
            ReadFile(
                output.0,
                bytes.as_mut_ptr(),
                bytes.len() as u32,
                &mut count,
                ptr::null_mut(),
            )
        };
        if ok == 0 || count == 0 {
            break;
        }
        let Ok(mut drain) = shared.lock() else {
            break;
        };
        let bytes = &bytes[..count as usize];
        drain.observation.output_bytes += count as u64;
        drain.observation.output_chunks += 1;
        if drain.observation.output_bytes > 1024 * 1024 || drain.model.feed(bytes).is_err() {
            drain.observation.failed = true;
            // Failure terminates the job; keep draining until ConPTY is closed.
            continue;
        }
        drain.tail.extend_from_slice(bytes);
        if drain.tail.len() > 4096 {
            let excess = drain.tail.len() - 4096;
            drain.tail.drain(..excess);
        }
        let text = String::from_utf8_lossy(&drain.tail);
        let ready = text.contains("FIXTURE_READY");
        let resized = text.contains("FIXTURE_SIZE_37_101");
        let detached = text.contains("FIXTURE_AFTER_DETACH");
        let ctrl_c = text.contains("FIXTURE_CTRL_C");
        let worker = text.split("FIXTURE_WORKER:").nth(1).and_then(|s| {
            let digits: String = s.chars().take_while(|c| c.is_ascii_digit()).collect();
            // Parse only once a delimiter is present; never adopt the PID.
            (s.len() > digits.len())
                .then(|| digits.parse::<u32>().ok())
                .flatten()
        });
        drain.observation.ready |= ready;
        drain.observation.resized |= resized;
        drain.observation.after_detach |= detached;
        drain.observation.ctrl_c |= ctrl_c;
        if worker.is_some() {
            drain.observation.synthetic_worker_pid = worker;
        }
        if let Ok(snapshot) = drain.model.snapshot() {
            drain.observation.model_rows = snapshot.rows;
            drain.observation.model_cols = snapshot.cols;
            drain.observation.model_nonempty_cells = snapshot
                .normal
                .lines
                .iter()
                .chain(snapshot.alternate.lines.iter())
                .flat_map(|row| &row.cells)
                .filter(|cell| !cell.text.trim().is_empty())
                .count();
        } else {
            drain.observation.failed = true;
        }
        if !drain.model.take_replies().is_empty() {
            // This fixed native child never requests terminal replies. Reject a
            // changed fixture instead of silently discarding a reply obligation.
            drain.observation.failed = true;
        }
    }
    let _ = done.send(());
}
fn pipe() -> Result<(Handle, Handle)> {
    let mut read = ptr::null_mut();
    let mut write = ptr::null_mut();
    unsafe {
        check(CreatePipe(&mut read, &mut write, ptr::null(), 4096))?;
    }
    Ok((Handle(read), Handle(write)))
}
pub struct Session {
    pub epoch: String,
    process: Option<Process>,
    job: Job,
    input: Handle,
    console: Console,
    stopped: bool,
}
impl Session {
    pub fn start(config: &Config) -> Result<Self> {
        let model = TerminalState::new(24, 80, 8).map_err(|_| denied("model creation"))?;
        let shared = Arc::new(Mutex::new(Drain {
            observation: Observation::default(),
            model,
            tail: Vec::new(),
        }));
        let job = Job::new()?;
        let (input_read, input) = pipe()?;
        let (output_read, output_write) = pipe()?;
        let (tx, rx) = mpsc::channel();
        let reader_shared = shared.clone();
        // Create the fallible reader thread before acquiring a pseudoconsole;
        // dropping output_write breaks its read if creation subsequently fails.
        thread::Builder::new()
            .name("synthetic-output".into())
            .spawn(move || output_reader(output_read, reader_shared, tx))?;
        let mut handle = 0;
        let hr = unsafe {
            CreatePseudoConsole(
                COORD { X: 80, Y: 24 },
                input_read.0,
                output_write.0,
                0,
                &mut handle,
            )
        };
        if hr < 0 {
            return Err(denied("ConPTY creation"));
        }
        let console = Console {
            handle,
            drained: Some(rx),
            closing: None,
            close_complete: false,
            shared,
        };
        let mut attributes = Attributes::new(console.handle)?;
        let executable = std::env::current_exe()?;
        let mut command = wide(format!("\"{}\" synthetic-child", executable.display()));
        let mut startup: STARTUPINFOEXW = unsafe { mem::zeroed() };
        startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
        startup.lpAttributeList = attributes.pointer();
        let mut info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        // Empty environment: the fixed child uses only native APIs/current_exe.
        let environment = [0u16, 0u16];
        unsafe {
            check(CreateProcessW(
                wide(&executable).as_ptr(),
                command.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                wide(&config.directory).as_ptr(),
                &startup.StartupInfo,
                &mut info,
            ))?;
        }
        let process = Process {
            process: Handle(info.hProcess),
            thread: Handle(info.hThread),
            pid: info.dwProcessId,
        };
        // Direct child is guarded even if job assignment or resume fails.
        unsafe {
            check(AssignProcessToJobObject(job.0.0, process.process.0))?;
        }
        drop(input_read);
        drop(output_write);
        if unsafe { ResumeThread(process.thread.0) } == u32::MAX {
            return Err(std::io::Error::last_os_error());
        }
        let epoch = Uuid::new_v4().to_string();
        let result = Self {
            epoch,
            process: Some(process),
            job,
            input,
            console,
            stopped: false,
        };
        persist(config, &result.epoch)?;
        Ok(result)
    }
    pub fn observation(&self) -> Result<Observation> {
        Ok(self
            .console
            .shared
            .lock()
            .map_err(|_| denied("model lock"))?
            .observation
            .clone())
    }
    pub fn pid(&self) -> Option<u32> {
        self.process.as_ref().map(|p| p.pid)
    }
    pub fn active(&self) -> Result<u32> {
        self.job.active()
    }
    pub fn send(&mut self, command: &str) -> Result<()> {
        let bytes: &[u8] = match command {
            "resize" => {
                if unsafe { ResizePseudoConsole(self.console.handle, COORD { X: 101, Y: 37 }) } < 0
                {
                    return Err(denied("resize ConPTY"));
                }
                self.console
                    .shared
                    .lock()
                    .map_err(|_| denied("model lock"))?
                    .model
                    .resize(37, 101)
                    .map_err(|_| denied("model resize"))?;
                b"size\r\n"
            }
            "after-detach" => b"after_detach\r\n",
            "ctrl-c" => &[3],
            "exit" => b"exit\r\n",
            _ => return Err(denied("unknown fixture input")),
        };
        let mut shared = self
            .console
            .shared
            .lock()
            .map_err(|_| denied("model lock"))?;
        if shared.observation.input_writes >= 32 {
            return Err(denied("input command bound"));
        }
        shared.observation.input_writes += 1;
        drop(shared);
        // At most 32 fixed commands (<512 bytes total), below the 4096-byte
        // pipe allocation even if a failed child never reads any input.
        let mut written = 0;
        unsafe {
            check(WriteFile(
                self.input.0,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                ptr::null_mut(),
            ))?;
        }
        if written as usize != bytes.len() {
            return Err(denied("incomplete fixed input"));
        }
        Ok(())
    }
    pub fn shutdown(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.job.terminate()?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.job.active()? != 0 {
            if Instant::now() >= deadline {
                return Err(denied("job cleanup deadline"));
            }
            thread::sleep(Duration::from_millis(10));
        }
        self.process.take();
        self.console.close()?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

#[cfg(feature = "fixture-test-hooks")]
static FAIL_CLOSE_SPAWN: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "fixture-test-hooks")]
pub fn close_guard_probe(session: &mut Session) -> Result<()> {
    // Execute in the actual SCM owner/account after its fixed child is ready.
    // The unrelated operator/SSH console environment is not this proof's host.
    if !session.observation()?.ready || session.active()? != 2 {
        return Err(denied("fault probe requires ready owned child and worker"));
    }
    FAIL_CLOSE_SPAWN.store(true, std::sync::atomic::Ordering::SeqCst);
    if session.console.close().is_ok() || session.console.handle == 0 {
        return Err(denied("close guard failed to retain acquired ConPTY"));
    }
    session
        .console
        .shared
        .lock()
        .map_err(|_| denied("model lock"))?
        .observation
        .conpty_close_fault_retained = true;
    session.shutdown()?;
    if !session.console.close_complete
        || session.console.drained.is_some()
        || session.active()? != 0
    {
        return Err(denied("acquired ConPTY not released after retry"));
    }
    session
        .console
        .shared
        .lock()
        .map_err(|_| denied("model lock"))?
        .observation
        .conpty_close_retry_complete = true;
    Ok(())
}
