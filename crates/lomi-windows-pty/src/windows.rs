use std::{
    ffi::{OsStr, OsString, c_void},
    io, mem,
    os::windows::ffi::OsStrExt,
    path::{Path, PathBuf},
    ptr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::{
    Foundation::*,
    Storage::FileSystem::*,
    System::{Console::*, IO::*, JobObjects::*, Pipes::*, Threading::*},
};
type NativeResult<T> = io::Result<T>;
fn native_error(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn check(ok: i32) -> NativeResult<()> {
    if ok == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
fn wide(value: impl AsRef<OsStr>) -> Vec<u16> {
    value.as_ref().encode_wide().chain(Some(0)).collect()
}
const MAX_CONSOLES: usize = 32;
static OWNED_CONSOLES: AtomicUsize = AtomicUsize::new(0);
struct Permit;
impl Permit {
    fn acquire() -> Result<Arc<Self>> {
        OWNED_CONSOLES
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_CONSOLES).then_some(n + 1)
            })
            .map_err(|_| Error::ResourceExhausted)?;
        Ok(Arc::new(Self))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        OWNED_CONSOLES.fetch_sub(1, Ordering::AcqRel);
    }
}
// Backing pipe handles carry the admission charge. Retained asynchronous work,
// forgotten kernel operations and quarantined HPCONs cannot free that charge.
struct Handle(pub HANDLE, Option<Arc<Permit>>);
impl Handle {
    pub fn new(handle: HANDLE) -> NativeResult<Self> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(handle, None))
        }
    }
}
// Kernel handles may be moved to their exclusive worker thread.
unsafe impl Send for Handle {}
// Kernel handles support concurrent I/O; ownership is shared only through Arc.
unsafe impl Sync for Handle {}
impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.0);
        }
    }
}
struct Job(pub Handle);
impl Job {
    pub fn new() -> NativeResult<Self> {
        let handle = Handle::new(unsafe { CreateJobObjectW(ptr::null(), ptr::null()) })?;
        let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { mem::zeroed() };
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        unsafe {
            check(SetInformationJobObject(
                handle.0,
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                mem::size_of_val(&limits) as u32,
            ))?;
        }
        Ok(Self(handle))
    }
    pub fn active(&self) -> NativeResult<u32> {
        let mut information: JOBOBJECT_BASIC_ACCOUNTING_INFORMATION = unsafe { mem::zeroed() };
        unsafe {
            check(QueryInformationJobObject(
                self.0.0,
                JobObjectBasicAccountingInformation,
                (&mut information as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                mem::size_of_val(&information) as u32,
                ptr::null_mut(),
            ))?;
        }
        Ok(information.ActiveProcesses)
    }
    pub fn terminate(&self) -> NativeResult<()> {
        unsafe { check(TerminateJobObject(self.0.0, 1)) }
    }
}
// Acquired immediately after CreateProcessW, before assignment or ResumeThread.
// A suspended child must be terminated explicitly even if job assignment fails.
struct Process {
    pub process: Handle,
    pub thread: Handle,
    pub pid: u32,
}
impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            if WaitForSingleObject(self.process.0, 0) == WAIT_TIMEOUT {
                TerminateProcess(self.process.0, 1);
                WaitForSingleObject(self.process.0, 2000);
            }
        }
    }
}
struct Attributes {
    pub storage: Vec<usize>,
    initialized: bool,
}
impl Attributes {
    pub fn new(console: HPCON) -> NativeResult<Self> {
        let mut size = 0;
        unsafe {
            InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
        }
        if size == 0 || size > 65536 {
            return Err(native_error("invalid attribute allocation"));
        }
        let mut result = Self {
            storage: vec![0; size.div_ceil(mem::size_of::<usize>())],
            initialized: false,
        };
        unsafe {
            check(InitializeProcThreadAttributeList(
                result.pointer(),
                1,
                0,
                &mut size,
            ))?;
        }
        result.initialized = true;
        unsafe {
            check(UpdateProcThreadAttribute(
                result.pointer(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                console as *const c_void,
                mem::size_of::<HPCON>(),
                ptr::null_mut(),
                ptr::null(),
            ))?;
        }
        Ok(result)
    }
    pub fn pointer(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.storage.as_mut_ptr().cast()
    }
}
impl Drop for Attributes {
    fn drop(&mut self) {
        if self.initialized {
            unsafe {
                DeleteProcThreadAttributeList(self.pointer());
            }
        }
    }
}
impl Drop for Job {
    fn drop(&mut self) {
        // Also covers post-resume setup failures before Session exists. The
        // explicit shutdown path reports errors; Drop remains a bounded fallback.
        if self.active().ok() != Some(0) {
            let _ = self.terminate();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while self.active().ok().is_some_and(|count| count != 0)
                && std::time::Instant::now() < deadline
            {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
        // Handle::drop closes the final job handle, enforcing KILL_ON_JOB_CLOSE
        // even when the explicit termination/query API fails.
    }
}

/// Closed operational metadata; never includes terminal data, paths or environment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    InvalidProfile,
    ResourceExhausted,
    SpawnFailed,
    SpawnOutcomeUnknown,
    Io,
    Deadline,
    Cleanup,
    Closed,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
/// The caller must resolve and authorize all executable, directory and environment choices.
#[derive(Clone, Debug)]
pub struct TrustedSpawnProfile {
    pub executable: PathBuf,
    pub args: Vec<OsString>,
    pub cwd: PathBuf,
    pub environment: Vec<(OsString, OsString)>,
    pub rows: u16,
    pub cols: u16,
}
/// Diagnostic identity only: process ownership always comes from the retained handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExitIdentity {
    pub process_id: u32,
    pub creation_time: u64,
    pub exit_code: Option<u32>,
}
fn dimensions(rows: u16, cols: u16) -> Result<COORD> {
    if rows == 0 || cols == 0 || rows > i16::MAX as u16 || cols > i16::MAX as u16 {
        return Err(Error::InvalidProfile);
    }
    Ok(COORD {
        X: cols as i16,
        Y: rows as i16,
    })
}
fn quote(value: &OsStr) -> Vec<u16> {
    let mut out = vec![b'"' as u16];
    let mut slashes = 0;
    for c in value.encode_wide() {
        if c == b'\\' as u16 {
            slashes += 1;
            continue;
        }
        if c == b'"' as u16 {
            out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
        } else {
            out.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        }
        slashes = 0;
        out.push(c);
    }
    out.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    out.push(b'"' as u16);
    out
}
/// Project roots are canonicalized and therefore verbatim (`\\?\C:\work`). `cmd.exe`
/// does not accept a verbatim working directory and silently starts in the Windows
/// directory instead, so a plain drive path is handed to the shell. Paths that
/// are too long for the legacy form, UNC paths and anything else stay verbatim.
fn shell_cwd(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\") {
        let bytes = rest.as_bytes();
        if bytes.len() >= 3
            && bytes.len() < 240
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && bytes[2] == b'\\'
            && !rest.contains('/')
        {
            return PathBuf::from(rest);
        }
    }
    path.to_path_buf()
}
fn has_nul(value: &OsStr) -> bool {
    value.encode_wide().any(|c| c == 0)
}
fn encode(profile: &TrustedSpawnProfile) -> Result<(Vec<u16>, Vec<u16>)> {
    dimensions(profile.rows, profile.cols)?;
    if !profile.executable.is_absolute()
        || !profile.cwd.is_absolute()
        || has_nul(profile.executable.as_os_str())
        || has_nul(profile.cwd.as_os_str())
        || profile.args.iter().any(|s| has_nul(s))
    {
        return Err(Error::InvalidProfile);
    }
    let mut command = quote(profile.executable.as_os_str());
    for arg in &profile.args {
        command.push(32);
        command.extend(quote(arg));
    }
    command.push(0);
    if command.len() > 32767 {
        return Err(Error::InvalidProfile);
    }
    let mut vars = profile.environment.clone();
    vars.sort_by_key(|(k, _)| k.to_string_lossy().to_uppercase());
    let mut environment = Vec::new();
    let mut previous = None;
    for (key, value) in vars {
        let normalized = key.to_string_lossy().to_uppercase();
        if key.is_empty()
            || has_nul(&key)
            || has_nul(&value)
            || key.encode_wide().any(|c| c == 61)
            || previous.as_ref() == Some(&normalized)
        {
            return Err(Error::InvalidProfile);
        }
        previous = Some(normalized);
        environment.extend(key.encode_wide());
        environment.push(61);
        environment.extend(value.encode_wide());
        environment.push(0);
    }
    environment.push(0);
    if environment.len() == 1 {
        environment.push(0)
    }
    if environment.len() > 32767 {
        return Err(Error::InvalidProfile);
    }
    Ok((command, environment))
}
static PIPE_NUMBER: AtomicU64 = AtomicU64::new(0);
// Only the host end is overlapped. ConPTY receives a synchronous client endpoint.
fn pipe(host_reads: bool, permit: Arc<Permit>) -> NativeResult<(Arc<Handle>, Handle)> {
    let name = wide(format!(
        "\\\\.\\pipe\\lomi-product-pty-{}-{}",
        unsafe { GetCurrentProcessId() },
        PIPE_NUMBER.fetch_add(1, Ordering::Relaxed)
    ));
    let access = if host_reads {
        PIPE_ACCESS_INBOUND
    } else {
        PIPE_ACCESS_OUTBOUND
    };
    let mut server = Handle::new(unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            access | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            65536,
            65536,
            0,
            ptr::null(),
        )
    })?;
    let mut client = Handle::new(unsafe {
        CreateFileW(
            name.as_ptr(),
            if host_reads {
                GENERIC_WRITE
            } else {
                GENERIC_READ
            },
            0,
            ptr::null(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        )
    })?;
    server.1 = Some(permit.clone());
    client.1 = Some(permit);
    // The client is already connected. Still supply valid overlapped storage:
    // even this documented ERROR_PIPE_CONNECTED path requires it on overlapped handles.
    let server = Arc::new(server);
    let mut connection =
        Operation::new(server.clone(), Vec::new()).map_err(|_| native_error("pipe event"))?;
    if unsafe { ConnectNamedPipe(server.0, &mut connection.overlapped) } == 0 {
        let error = unsafe { GetLastError() };
        if error != ERROR_PIPE_CONNECTED {
            if error == ERROR_IO_PENDING {
                unsafe { CancelIoEx(server.0, &connection.overlapped) };
                if unsafe { WaitForSingleObject(connection.event.0, 100) } != WAIT_OBJECT_0 {
                    std::mem::forget(connection)
                }
            }
            return Err(native_error("pipe connection"));
        }
    }
    Ok((server, client))
}
struct Operation {
    overlapped: OVERLAPPED,
    data: Vec<u8>,
    event: Handle,
    pipe: Arc<Handle>,
}
// All storage touched by the kernel is heap owned until completion or deliberately retained.
impl Operation {
    fn new(pipe: Arc<Handle>, data: Vec<u8>) -> Result<Box<Self>> {
        let event = Handle::new(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
            .map_err(|_| Error::Io)?;
        let mut result = Box::new(Self {
            overlapped: unsafe { mem::zeroed() },
            data,
            event,
            pipe,
        });
        result.overlapped.hEvent = result.event.0;
        Ok(result)
    }
    fn finish(&mut self, wait: u32) -> Result<usize> {
        match unsafe { WaitForSingleObject(self.event.0, wait) } {
            WAIT_OBJECT_0 => {
                let mut count = 0;
                if unsafe { GetOverlappedResult(self.pipe.0, &self.overlapped, &mut count, 0) } == 0
                {
                    if unsafe { GetLastError() } == ERROR_BROKEN_PIPE {
                        Err(Error::Closed)
                    } else {
                        Err(Error::Io)
                    }
                } else {
                    Ok(count as usize)
                }
            }
            WAIT_TIMEOUT => Err(Error::Deadline),
            _ => Err(Error::Io),
        }
    }
}
struct Console {
    handle: HPCON,
    input: Arc<Handle>,
    output: Arc<Handle>,
    closing: Option<std::sync::mpsc::Receiver<()>>,
    resizing: Option<std::sync::mpsc::Receiver<bool>>,
}
impl Console {
    fn resize_finished(&mut self) -> bool {
        if let Some(rx) = &self.resizing {
            if matches!(rx.try_recv(), Err(std::sync::mpsc::TryRecvError::Empty)) {
                return false;
            }
            self.resizing = None;
        }
        true
    }
    fn resize(&mut self, size: COORD) -> Result<()> {
        if !self.resize_finished() {
            return Err(Error::Deadline);
        }
        let h = self.handle;
        let input = self.input.clone();
        let output = self.output.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker_cancelled = cancelled.clone();
        let deadline = Instant::now() + Duration::from_millis(100);
        thread::Builder::new()
            .name("lomi-conpty-resize".into())
            .spawn(move || {
                // A queued operation must never begin after the caller's
                // absolute deadline or after timeout/revocation cancellation.
                let ok = if worker_cancelled.load(Ordering::Acquire) || Instant::now() >= deadline {
                    false
                } else {
                    (unsafe { ResizePseudoConsole(h, size) }) >= 0
                };
                // Signal only after the final HPCON access, while backing pipes live.
                drop((input, output));
                let _ = tx.send(ok);
            })
            .map_err(|_| Error::Io)?;
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(true) => Ok(()),
            Ok(false) => Err(Error::Io),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                cancelled.store(true, Ordering::Release);
                self.resizing = Some(rx);
                Err(Error::Deadline)
            }
            Err(_) => Err(Error::Io),
        }
    }
    fn start_close(&mut self) -> Result<()> {
        if !self.resize_finished() {
            return Err(Error::Deadline);
        }
        if self.handle != 0 {
            let h = self.handle;
            let input = self.input.clone();
            let output = self.output.clone();
            let (tx, rx) = std::sync::mpsc::channel();
            thread::Builder::new()
                .name("lomi-conpty-close".into())
                .spawn(move || {
                    unsafe { ClosePseudoConsole(h) };
                    drop((input, output));
                    let _ = tx.send(());
                })
                .map_err(|_| Error::Cleanup)?;
            self.handle = 0;
            self.closing = Some(rx);
        }
        Ok(())
    }
    fn poll_closed(&mut self) -> Result<bool> {
        if self.handle != 0 {
            return Ok(false);
        }
        if let Some(rx) = &self.closing {
            match rx.try_recv() {
                Ok(()) => self.closing = None,
                Err(std::sync::mpsc::TryRecvError::Empty) => return Ok(false),
                Err(_) => return Err(Error::Cleanup),
            }
        }
        Ok(true)
    }
    fn close(&mut self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut drain = Endpoint::new(self.output.clone());
        loop {
            match self.start_close() {
                Ok(()) => (),
                Err(Error::Deadline) => (),
                Err(error) => return Err(error),
            }
            if self.poll_closed()? {
                break;
            }
            if Instant::now() >= deadline {
                return Err(Error::Cleanup);
            }
            // Explicit shutdown may discard contents; natural exit uses its
            // retained Reader and poll_closed instead so final output is fed.
            if drain.transfer(None).is_err() {
                thread::sleep(Duration::from_millis(1));
            }
        }
        Ok(())
    }
}
impl Drop for Console {
    fn drop(&mut self) {
        if self.close().is_err() && self.handle != 0 {
            // Thread creation failed: retain the HPCON's backing pipe handles too.
            std::mem::forget(self.input.clone());
            std::mem::forget(self.output.clone());
        }
    }
}
struct Endpoint {
    pipe: Arc<Handle>,
    pending: Option<Box<Operation>>,
    closed: bool,
}
// OVERLAPPED and data are exclusively owned; moving Box never moves kernel storage.
unsafe impl Send for Endpoint {}
impl Endpoint {
    fn new(pipe: Arc<Handle>) -> Self {
        Self {
            pipe,
            pending: None,
            closed: false,
        }
    }
    fn stop(&mut self) -> Result<()> {
        self.closed = true;
        if let Some(op) = self.pending.take() {
            unsafe { CancelIoEx(op.pipe.0, &op.overlapped) };
            if unsafe { WaitForSingleObject(op.event.0, 100) } != WAIT_OBJECT_0 {
                self.pending = Some(op);
                return Err(Error::Cleanup);
            }
            let mut count = 0;
            // Consume either success or ERROR_OPERATION_ABORTED after signalling.
            unsafe { GetOverlappedResult(op.pipe.0, &op.overlapped, &mut count, 0) };
        }
        Ok(())
    }
    fn transfer(&mut self, input: Option<&[u8]>) -> Result<Vec<u8>> {
        if self.closed {
            return Err(Error::Closed);
        }
        if let Some(mut op) = self.pending.take() {
            if unsafe { WaitForSingleObject(op.event.0, 0) } != WAIT_OBJECT_0 {
                self.pending = Some(op);
                return Err(Error::Deadline);
            }
            let previous = op.finish(0);
            if input.is_none() && previous == Err(Error::Closed) {
                return Ok(Vec::new());
            }
            if input.is_none()
                && let Ok(count) = previous
            {
                op.data.truncate(count);
                return Ok(std::mem::take(&mut op.data));
            }
        }
        let mut op = Operation::new(
            self.pipe.clone(),
            input.map_or_else(|| vec![0; 65536], |b| b.to_vec()),
        )?;
        let ok = unsafe {
            if input.is_some() {
                WriteFile(
                    op.pipe.0,
                    op.data.as_ptr(),
                    op.data.len() as u32,
                    ptr::null_mut(),
                    &mut op.overlapped,
                )
            } else {
                ReadFile(
                    op.pipe.0,
                    op.data.as_mut_ptr(),
                    op.data.len() as u32,
                    ptr::null_mut(),
                    &mut op.overlapped,
                )
            }
        };
        if ok == 0 {
            let error = unsafe { GetLastError() };
            if input.is_none() && error == ERROR_BROKEN_PIPE {
                return Ok(Vec::new());
            }
            if error != ERROR_IO_PENDING {
                return Err(Error::Io);
            }
        }
        match op.finish(100) {
            Ok(count) => {
                op.data.truncate(count);
                Ok(std::mem::take(&mut op.data))
            }
            Err(Error::Closed) if input.is_none() => Ok(Vec::new()),
            Err(error) => {
                unsafe { CancelIoEx(op.pipe.0, &op.overlapped) };
                // Keep exactly one cancelled operation until kernel completion.
                self.pending = Some(op);
                Err(error)
            }
        }
    }
}
impl Drop for Endpoint {
    fn drop(&mut self) {
        if self.stop().is_err()
            && let Some(op) = self.pending.take()
        {
            // The pipe's admission permit stays charged with kernel storage.
            std::mem::forget(op);
        }
    }
}
/// Independent output owner. A timeout returns WouldBlock after at most 100ms.
pub struct Reader {
    endpoint: Arc<Mutex<Endpoint>>,
    buffered: Vec<u8>,
    offset: usize,
}
impl io::Read for Reader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.offset == self.buffered.len() {
            self.buffered = self
                .endpoint
                .lock()
                .map_err(|_| io::Error::from(io::ErrorKind::BrokenPipe))?
                .transfer(None)
                .map_err(|e| {
                    io::Error::from(if e == Error::Deadline {
                        io::ErrorKind::WouldBlock
                    } else {
                        io::ErrorKind::BrokenPipe
                    })
                })?;
            self.offset = 0;
        }
        let count = output.len().min(self.buffered.len() - self.offset);
        output[..count].copy_from_slice(&self.buffered[self.offset..self.offset + count]);
        self.offset += count;
        Ok(count)
    }
}
/// Exclusive owner of one ConPTY and its non-breakaway kill-on-close Job.
pub struct Pty {
    process: Process,
    job: Job,
    console: Console,
    identity: ExitIdentity,
    stopped: bool,
    input: Endpoint,
    reader: Option<Reader>,
    read_control: Arc<Mutex<Endpoint>>,
    failed_resize: bool,
}
impl Pty {
    /// The callback is the final authorization check immediately before ResumeThread.
    pub fn spawn(
        profile: TrustedSpawnProfile,
        before_spawn: impl FnOnce() -> bool,
    ) -> Result<Self> {
        let (mut command, environment) = encode(&profile)?;
        let permit = Permit::acquire()?;
        let result = (|| -> NativeResult<_> {
            let job = Job::new()?;
            let (input, input_read) = pipe(false, permit.clone())?;
            let (output, output_write) = pipe(true, permit.clone())?;
            let mut handle = 0;
            if unsafe {
                CreatePseudoConsole(
                    dimensions(profile.rows, profile.cols).map_err(|_| native_error("size"))?,
                    input_read.0,
                    output_write.0,
                    0,
                    &mut handle,
                )
            } < 0
            {
                return Err(native_error("console"));
            }
            let console = Console {
                handle,
                input,
                output,
                closing: None,
                resizing: None,
            };
            let mut attributes = Attributes::new(handle)?;
            let mut startup: STARTUPINFOEXW = unsafe { mem::zeroed() };
            startup.StartupInfo.cb = mem::size_of::<STARTUPINFOEXW>() as u32;
            // Null standard handles force the attached console defaults even if
            // this host itself has redirected stdin/stdout (e.g. an SSH service).
            startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
            startup.lpAttributeList = attributes.pointer();
            let mut info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
            unsafe {
                check(CreateProcessW(
                    wide(&profile.executable).as_ptr(),
                    command.as_mut_ptr(),
                    ptr::null(),
                    ptr::null(),
                    0,
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                    environment.as_ptr().cast(),
                    wide(shell_cwd(&profile.cwd)).as_ptr(),
                    &startup.StartupInfo,
                    &mut info,
                ))?;
            }
            let process = Process {
                process: Handle(info.hProcess, None),
                thread: Handle(info.hThread, None),
                pid: info.dwProcessId,
            };
            unsafe {
                check(AssignProcessToJobObject(job.0.0, process.process.0))?;
            }
            let mut creation = unsafe { mem::zeroed() };
            let mut exit = unsafe { mem::zeroed() };
            let mut kernel = unsafe { mem::zeroed() };
            let mut user = unsafe { mem::zeroed() };
            unsafe {
                check(GetProcessTimes(
                    process.process.0,
                    &mut creation,
                    &mut exit,
                    &mut kernel,
                    &mut user,
                ))?;
            }
            drop((input_read, output_write));
            Ok((process, job, console, creation))
        })()
        .map_err(|_| Error::SpawnFailed)?;
        let (process, job, mut console, creation) = result;
        if !before_spawn() {
            let cleanup = (|| -> Result<()> {
                job.terminate().map_err(|_| Error::Cleanup)?;
                let deadline = Instant::now() + Duration::from_secs(2);
                while job.active().map_err(|_| Error::Cleanup)? != 0
                    || unsafe { WaitForSingleObject(process.process.0, 0) } != WAIT_OBJECT_0
                {
                    if Instant::now() >= deadline {
                        return Err(Error::Cleanup);
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                console.close()
            })();

            return Err(if cleanup.is_ok() {
                Error::SpawnFailed
            } else {
                Error::SpawnOutcomeUnknown
            });
        }
        if unsafe { ResumeThread(process.thread.0) } == u32::MAX {
            return Err(Error::SpawnOutcomeUnknown);
        }
        let identity = ExitIdentity {
            process_id: process.pid,
            creation_time: ((creation.dwHighDateTime as u64) << 32) | creation.dwLowDateTime as u64,
            exit_code: None,
        };
        let input = Endpoint::new(console.input.clone());
        let read_control = Arc::new(Mutex::new(Endpoint::new(console.output.clone())));
        let reader = Some(Reader {
            endpoint: read_control.clone(),
            buffered: Vec::new(),
            offset: 0,
        });
        Ok(Self {
            process,
            job,
            console,
            identity,
            stopped: false,
            input,
            reader,
            read_control,
            failed_resize: false,
        })
    }
    pub fn identity(&self) -> ExitIdentity {
        self.identity
    }
    pub fn exit(&self) -> Result<Option<ExitIdentity>> {
        match unsafe { WaitForSingleObject(self.process.process.0, 0) } {
            WAIT_TIMEOUT => Ok(None),
            WAIT_OBJECT_0 => {
                let mut code = 0;
                unsafe { check(GetExitCodeProcess(self.process.process.0, &mut code)) }
                    .map_err(|_| Error::Io)?;
                Ok(Some(ExitIdentity {
                    exit_code: Some(code),
                    ..self.identity
                }))
            }
            _ => Err(Error::Io),
        }
    }
    pub fn take_reader(&mut self) -> Option<Reader> {
        self.reader.take()
    }
    pub fn read(&mut self) -> Result<Vec<u8>> {
        if self.stopped {
            return Err(Error::Closed);
        }
        self.reader
            .as_mut()
            .ok_or(Error::Closed)?
            .endpoint
            .lock()
            .map_err(|_| Error::Io)?
            .transfer(None)
    }
    pub fn write(&mut self, bytes: &[u8]) -> Result<usize> {
        if self.stopped || self.failed_resize {
            return Err(Error::Closed);
        }
        if bytes.len() > 16384 {
            return Err(Error::InvalidProfile);
        }
        if bytes.is_empty() {
            return Ok(0);
        }
        self.input.transfer(Some(bytes)).map(|b| b.len())
    }
    pub fn resize(&mut self, rows: u16, cols: u16) -> Result<()> {
        if self.stopped || self.failed_resize || self.console.handle == 0 {
            return Err(Error::Closed);
        }
        let result = self.console.resize(dimensions(rows, cols)?);
        if result.is_err() {
            self.failed_resize = true;
        }
        result
    }
    pub fn active_processes(&self) -> Result<u32> {
        self.job.active().map_err(|_| Error::Io)
    }
    fn stop_processes(&self) -> Result<()> {
        self.job.terminate().map_err(|_| Error::Cleanup)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while self.job.active().map_err(|_| Error::Cleanup)? != 0
            || unsafe { WaitForSingleObject(self.process.process.0, 0) } != WAIT_OBJECT_0
        {
            if Instant::now() >= deadline {
                return Err(Error::Cleanup);
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }
    fn stop_input(&mut self) -> Result<()> {
        self.input.stop()
    }
    /// Begin natural-exit cleanup while the independent reader keeps feeding output.
    /// The caller must impose a time/byte budget and read to EOF before polling completion.
    pub fn begin_shutdown(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.stop_processes()?;
        self.stop_input()?;
        self.console.start_close()
    }
    /// Confirm ConPTY close after the independent reader has observed output EOF.
    pub fn poll_shutdown(&mut self) -> Result<bool> {
        if self.stopped {
            return Ok(true);
        }
        if !self.console.poll_closed()? {
            return Ok(false);
        }
        self.read_control
            .lock()
            .map_err(|_| Error::Cleanup)?
            .stop()?;
        self.stopped = true;
        Ok(true)
    }
    pub fn shutdown(&mut self) -> Result<()> {
        if self.stopped {
            return Ok(());
        }
        self.stop_processes()?;
        self.stop_input()?;
        self.read_control
            .lock()
            .map_err(|_| Error::Cleanup)?
            .stop()?;
        self.console.close()?;
        self.stopped = true;
        Ok(())
    }
}
impl Drop for Pty {
    fn drop(&mut self) {
        let _ = self.shutdown();
    }
}

/// Clear inherited Ctrl+C ignore once at owned host startup, before spawning children.
/// Does not allocate/attach a console or change other processes' control policy.
pub fn prepare_host_control() -> Result<()> {
    if unsafe { SetConsoleCtrlHandler(None, 0) } == 0 {
        Err(Error::Io)
    } else {
        Ok(())
    }
}
