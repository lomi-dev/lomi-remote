//! Default-off per-PTY launchd generation. Private SPI is capability checked;
//! no SID fallback, replay, or PID-absence cleanup certificate exists here.
use super::*;
use serde_json::{Value, json};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::{
    fs::{MetadataExt, PermissionsExt},
    net::{UnixListener, UnixStream},
    process::CommandExt,
};
use std::process::{Child, Command, Stdio};
mod filesystem;
mod gc;
mod manager;
mod socket;
use filesystem::Directory;
const DEADLINE: Duration = Duration::from_secs(6);
const HANDSHAKE_POLL_MS: i32 = 10;

#[repr(C)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}
unsafe extern "C" {
    fn mach_continuous_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

/// An absolute deadline in the Darwin continuous clock domain shared by the
/// host, protocol child, and custodian. Conversion rounds down so IPC and
/// scheduling time cannot extend the operation's original expiry.
#[derive(Clone, Copy)]
struct MachDeadline(u64);
impl MachDeadline {
    fn from_instant(deadline: Instant) -> Result<Self> {
        let continuous_now = unsafe { mach_continuous_time() };
        let remaining = deadline.saturating_duration_since(Instant::now());
        let mut timebase = MachTimebaseInfo { numer: 0, denom: 0 };
        if unsafe { mach_timebase_info(&mut timebase) } != 0
            || timebase.numer == 0
            || timebase.denom == 0
        {
            return Err(Error::SpawnFailed);
        }
        let ticks = remaining
            .as_nanos()
            .checked_mul(u128::from(timebase.denom))
            .ok_or(Error::SpawnFailed)?
            / u128::from(timebase.numer);
        let ticks = u64::try_from(ticks).map_err(|_| Error::SpawnFailed)?;
        continuous_now
            .checked_add(ticks)
            .map(Self)
            .ok_or(Error::SpawnFailed)
    }
    fn from_bytes(bytes: [u8; 8]) -> Self {
        Self(u64::from_be_bytes(bytes))
    }
    fn bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
    fn expired(self) -> bool {
        (unsafe { mach_continuous_time() }) >= self.0
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
struct Identity {
    pid: i32,
    audit: [u32; 8],
    resource: u64,
    jetsam: u64,
}
unsafe extern "C" {
    fn lomi_coalition_identity(pid: i32, identity: *mut Identity) -> i32;
    fn lomi_coalition_parent(child: *const Identity, parent: *const Identity) -> i32;
    fn lomi_coalition_available() -> i32;
    fn lomi_coalition_count(original: *const Identity, active: *mut u64) -> i32;
    fn lomi_coalition_drain(original: *const Identity, signal: i32) -> i32;
    fn lomi_coalition_safe_acl(fd: i32) -> i32;
}
impl Identity {
    fn query(pid: i32) -> Result<Self> {
        let mut identity = Self::default();
        if unsafe { lomi_coalition_identity(pid, &mut identity) } != 0 {
            return Err(Error::CleanupFailed);
        }
        Ok(identity)
    }
    fn json(self) -> Value {
        json!({"pid":self.pid,"audit":self.audit,"resource":self.resource,"jetsam":self.jetsam})
    }
    fn decode(value: &Value) -> Result<Self> {
        let pid = value["pid"]
            .as_i64()
            .and_then(|pid| i32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or(Error::CleanupFailed)?;
        let audit = value["audit"]
            .as_array()
            .filter(|words| words.len() == 8)
            .ok_or(Error::CleanupFailed)?;
        let mut words = [0; 8];
        for (word, value) in words.iter_mut().zip(audit) {
            *word = value
                .as_u64()
                .and_then(|word| u32::try_from(word).ok())
                .ok_or(Error::CleanupFailed)?;
        }
        let resource = value["resource"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(Error::CleanupFailed)?;
        let jetsam = value["jetsam"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or(Error::CleanupFailed)?;
        Ok(Self {
            pid,
            audit: words,
            resource,
            jetsam,
        })
    }
    fn count(self) -> Result<u64> {
        let mut active = 0;
        if unsafe { lomi_coalition_count(&self, &mut active) } != 0 || active == 0 {
            return Err(Error::CleanupFailed);
        }
        Ok(active)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Prepared,
    BootstrapIntent,
    AdmissionConsumed,
    Closing,
    Cleaned,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Prepared => "Prepared",
            Self::BootstrapIntent => "BootstrapIntent",
            Self::AdmissionConsumed => "AdmissionConsumed",
            Self::Closing => "Closing",
            Self::Cleaned => "Cleaned",
        }
    }
    fn decode(value: &Value) -> Result<Self> {
        match value.as_str() {
            Some("Prepared") => Ok(Self::Prepared),
            Some("BootstrapIntent") => Ok(Self::BootstrapIntent),
            Some("AdmissionConsumed") => Ok(Self::AdmissionConsumed),
            Some("Closing") => Ok(Self::Closing),
            Some("Cleaned") => Ok(Self::Cleaned),
            _ => Err(Error::CleanupFailed),
        }
    }
}
#[derive(Clone)]
struct Record {
    schema: u64,
    run: String,
    nonce: String,
    stage: Stage,
    executable: PathBuf,
    executable_pin: [u64; 5],
    host: Identity,
    /// Schema 1: launchd process. Schema 2: disposable protocol child.
    controller: Option<Identity>,
    /// Schema 2 launchd process and direct PTY child/wait owner.
    custodian: Option<Identity>,
    /// Schema 1 controller or schema 2 custodian lifetime lock pin.
    lifetime: Option<[u64; 2]>,
    /// Schema 2 protocol-child lifetime lock pin.
    controller_lifetime: Option<[u64; 2]>,
    controller_reaped: bool,
    disposed: bool,
    leader_reaped: bool,
    drained: bool,
    admission_consumed: bool,
    profile_pin: [u64; 2],
    generation_pin: [u64; 2],
    runtime_pin: Option<[u64; 2]>,
    socket_pin: Option<[u64; 2]>,
    runtime_removal_started: bool,
    runtime_removed: bool,
    host_step: String,
    worker_step: String,
}
impl Record {
    fn label(&self) -> String {
        format!("dev.lomi.pty.{}", self.run.replace('-', ""))
    }
    fn domain(&self) -> String {
        format!("user/{}", unsafe { libc::geteuid() })
    }
    fn target(&self) -> String {
        format!("{}/{}", self.domain(), self.label())
    }
    fn manager_pid(&self) -> Result<Option<i32>> {
        let identity = if self.schema == 1 {
            self.controller
        } else {
            self.custodian
        };
        Ok(identity.map(|identity| identity.pid))
    }
    fn bytes(&self) -> Result<Vec<u8>> {
        let value = if self.schema == 1 {
            json!({"schema":1,"uid":unsafe{libc::geteuid()},"run":self.run,"nonce":self.nonce,"stage":self.stage.name(),"executable":self.executable.to_str().ok_or(Error::InvalidArgument)?,"executablePin":self.executable_pin,"host":self.host.json(),"controller":self.controller.map(Identity::json),"lifetime":self.lifetime,"disposed":self.disposed,"leaderReaped":self.leader_reaped,"drained":self.drained,"admissionConsumed":self.admission_consumed,"profilePin":self.profile_pin,"generationPin":self.generation_pin,"runtimePin":self.runtime_pin,"socketPin":self.socket_pin,"runtimeRemovalStarted":self.runtime_removal_started,"runtimeRemoved":self.runtime_removed,"hostStep":self.host_step,"workerStep":self.worker_step})
        } else {
            json!({"schema":2,"uid":unsafe{libc::geteuid()},"run":self.run,"nonce":self.nonce,"stage":self.stage.name(),"executable":self.executable.to_str().ok_or(Error::InvalidArgument)?,"executablePin":self.executable_pin,"host":self.host.json(),"controller":self.controller.map(Identity::json),"custodian":self.custodian.map(Identity::json),"lifetime":self.lifetime,"controllerLifetime":self.controller_lifetime,"controllerReaped":self.controller_reaped,"disposed":self.disposed,"leaderReaped":self.leader_reaped,"drained":self.drained,"admissionConsumed":self.admission_consumed,"profilePin":self.profile_pin,"generationPin":self.generation_pin,"runtimePin":self.runtime_pin,"socketPin":self.socket_pin,"runtimeRemovalStarted":self.runtime_removal_started,"runtimeRemoved":self.runtime_removed,"hostStep":self.host_step,"workerStep":self.worker_step})
        };
        serde_json::to_vec(&value).map_err(|_| Error::CleanupFailed)
    }
    fn decode(directory: &Directory, bytes: &[u8]) -> Result<Self> {
        Self::decode_with_pin(directory, bytes, None)
    }
    fn decode_retired(profile: &Directory, run: &str, bytes: &[u8], pin: [u64; 2]) -> Result<Self> {
        let directory = Directory {
            path: profile.path.join(run),
            file: profile.file.try_clone().map_err(|_| Error::CleanupFailed)?,
        };
        Self::decode_with_pin(&directory, bytes, Some(pin))
    }
    fn decode_with_pin(
        directory: &Directory,
        bytes: &[u8],
        retired_pin: Option<[u64; 2]>,
    ) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes).map_err(|_| Error::CleanupFailed)?;
        let schema = value["schema"].as_u64().ok_or(Error::CleanupFailed)?;
        if !matches!(schema, 1 | 2)
            || value["uid"].as_u64() != Some(unsafe { libc::geteuid() } as u64)
        {
            return Err(Error::CleanupFailed);
        }
        let run = value["run"]
            .as_str()
            .ok_or(Error::CleanupFailed)?
            .to_owned();
        let nonce = value["nonce"]
            .as_str()
            .ok_or(Error::CleanupFailed)?
            .to_owned();
        if uuid::Uuid::parse_str(&run)
            .map(|id| id.to_string())
            .ok()
            .as_deref()
            != Some(run.as_str())
            || directory.path.file_name().and_then(|name| name.to_str()) != Some(run.as_str())
            || uuid::Uuid::parse_str(&nonce).is_err()
        {
            return Err(Error::CleanupFailed);
        }
        let executable = PathBuf::from(value["executable"].as_str().ok_or(Error::CleanupFailed)?);
        if !executable.is_absolute() {
            return Err(Error::CleanupFailed);
        }
        let pin: Vec<u64> = serde_json::from_value(value["executablePin"].clone())
            .map_err(|_| Error::CleanupFailed)?;
        let executable_pin = pin.try_into().map_err(|_| Error::CleanupFailed)?;
        let controller = if value["controller"].is_null() {
            None
        } else {
            Some(Identity::decode(&value["controller"])?)
        };
        let custodian = if schema == 1 || value["custodian"].is_null() {
            None
        } else {
            Some(Identity::decode(&value["custodian"])?)
        };
        let lifetime = if value["lifetime"].is_null() {
            None
        } else {
            Some(
                serde_json::from_value(value["lifetime"].clone())
                    .map_err(|_| Error::CleanupFailed)?,
            )
        };
        let controller_lifetime = if schema == 1 || value["controllerLifetime"].is_null() {
            None
        } else {
            Some(
                serde_json::from_value(value["controllerLifetime"].clone())
                    .map_err(|_| Error::CleanupFailed)?,
            )
        };
        let profile_pin = serde_json::from_value(value["profilePin"].clone())
            .map_err(|_| Error::CleanupFailed)?;
        let generation_pin = serde_json::from_value(value["generationPin"].clone())
            .map_err(|_| Error::CleanupFailed)?;
        let profile = Directory::open(
            directory
                .path
                .parent()
                .and_then(Path::parent)
                .ok_or(Error::CleanupFailed)?,
            false,
        )?;
        if retired_pin
            .map(Ok)
            .unwrap_or_else(|| socket::pin(directory))?
            != generation_pin
            || socket::pin(&profile)? != profile_pin
        {
            return Err(Error::CleanupFailed);
        }
        let stage = Stage::decode(&value["stage"])?;
        let controller_reaped = if schema == 1 {
            false
        } else {
            value["controllerReaped"]
                .as_bool()
                .ok_or(Error::CleanupFailed)?
        };
        if schema == 2 {
            let has_controller = controller.is_some();
            let has_custodian = custodian.is_some();
            let pinned_unconsumed_without_identity = !has_controller
                && !has_custodian
                && lifetime.is_some()
                && value["hostStep"] == "UnconsumedRemovalIntent";
            if (has_custodian != lifetime.is_some() && !pinned_unconsumed_without_identity)
                || (has_custodian && controller_lifetime.is_none())
                || (has_controller && (!has_custodian || controller_lifetime.is_none()))
                || (controller_reaped
                    && (!has_controller
                        || !matches!(stage, Stage::Closing | Stage::Cleaned)
                        || value["disposed"] != true
                        || value["leaderReaped"] != true
                        || value["drained"] != true))
            {
                return Err(Error::CleanupFailed);
            }
        }
        Ok(Self {
            schema,
            run,
            nonce,
            stage,
            executable,
            executable_pin,
            host: Identity::decode(&value["host"])?,
            controller,
            custodian,
            lifetime,
            controller_lifetime,
            controller_reaped,
            disposed: value["disposed"].as_bool().ok_or(Error::CleanupFailed)?,
            leader_reaped: value["leaderReaped"]
                .as_bool()
                .ok_or(Error::CleanupFailed)?,
            drained: value["drained"].as_bool().ok_or(Error::CleanupFailed)?,
            profile_pin,
            generation_pin,
            runtime_pin: serde_json::from_value(value["runtimePin"].clone())
                .map_err(|_| Error::CleanupFailed)?,
            socket_pin: serde_json::from_value(value["socketPin"].clone())
                .map_err(|_| Error::CleanupFailed)?,
            runtime_removal_started: value["runtimeRemovalStarted"]
                .as_bool()
                .ok_or(Error::CleanupFailed)?,
            runtime_removed: value["runtimeRemoved"]
                .as_bool()
                .ok_or(Error::CleanupFailed)?,
            admission_consumed: value["admissionConsumed"]
                .as_bool()
                .ok_or(Error::CleanupFailed)?,
            host_step: value["hostStep"]
                .as_str()
                .ok_or(Error::CleanupFailed)?
                .into(),
            worker_step: value["workerStep"]
                .as_str()
                .ok_or(Error::CleanupFailed)?
                .into(),
        })
    }
    fn read(directory: &Directory) -> Result<Self> {
        Self::decode(
            directory,
            &directory
                .read("journal.json")?
                .ok_or(Error::CleanupFailed)?,
        )
    }
}
fn update(
    directory: &Directory,
    nonce: &str,
    change: impl FnOnce(&mut Record) -> Result<()>,
) -> Result<Record> {
    let _lock = directory.lock("journal.lock", DEADLINE)?;
    let before = directory
        .read("journal.json")?
        .ok_or(Error::CleanupFailed)?;
    let mut record = Record::decode(directory, &before)?;
    if record.nonce != nonce {
        return Err(Error::CleanupFailed);
    }
    change(&mut record)?;
    directory.write("journal.json", &record.bytes()?, Some(&before))?;
    Ok(record)
}
fn fingerprint(path: &Path) -> Result<[u64; 5]> {
    use std::os::unix::fs::OpenOptionsExt;
    let _ancestry = Directory::ancestry(path.parent().ok_or(Error::InvalidArgument)?)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| Error::SpawnFailed)?;
    if unsafe { lomi_coalition_safe_acl(file.as_raw_fd()) } != 0 {
        return Err(Error::InvalidArgument);
    }
    let metadata = file.metadata().map_err(|_| Error::SpawnFailed)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != unsafe { libc::geteuid() })
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(Error::InvalidArgument);
    }
    Ok([
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        metadata.mtime() as u64,
        metadata.mtime_nsec() as u64,
    ])
}
fn peer(socket: &UnixStream) -> Result<i32> {
    let mut uid = 0;
    let mut gid = 0;
    if unsafe { libc::getpeereid(socket.as_raw_fd(), &mut uid, &mut gid) } != 0
        || uid != unsafe { libc::geteuid() }
    {
        return Err(Error::CleanupFailed);
    }
    let mut pid = 0i32;
    let mut size = std::mem::size_of::<i32>() as libc::socklen_t;
    // SDK sys/un.h SOL_LOCAL=0, LOCAL_PEERPID=2; kernel-authenticated peer PID.
    if unsafe {
        libc::getsockopt(
            socket.as_raw_fd(),
            0,
            2,
            (&mut pid as *mut i32).cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of::<i32>()
        || pid <= 0
    {
        return Err(Error::CleanupFailed);
    }
    Ok(pid)
}
fn configure(socket: &UnixStream) -> Result<()> {
    socket
        .set_nonblocking(false)
        .and_then(|_| socket.set_read_timeout(Some(DEADLINE)))
        .and_then(|_| socket.set_write_timeout(Some(DEADLINE)))
        .map_err(|_| Error::SpawnFailed)?;
    #[cfg(target_os = "macos")]
    {
        let enabled: libc::c_int = 1;
        if unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&enabled as *const libc::c_int).cast(),
                std::mem::size_of_val(&enabled) as libc::socklen_t,
            )
        } != 0
        {
            return Err(Error::SpawnFailed);
        }
    }
    Ok(())
}
fn frame(socket: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    if bytes.len() > PROFILE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    socket
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| socket.write_all(bytes))
        .map_err(|_| Error::SpawnFailed)
}
fn read_frame(socket: &mut UnixStream) -> Result<Vec<u8>> {
    let mut length = [0; 4];
    socket
        .read_exact(&mut length)
        .map_err(|_| Error::SpawnFailed)?;
    let length = u32::from_be_bytes(length) as usize;
    if length > PROFILE_LIMIT {
        return Err(Error::InvalidArgument);
    }
    let mut bytes = vec![0; length];
    socket
        .read_exact(&mut bytes)
        .map_err(|_| Error::SpawnFailed)?;
    Ok(bytes)
}
fn spawn_command(name: &str, nonce: &str, deadline: MachDeadline) -> Result<Vec<u8>> {
    serde_json::to_vec(&json!({
        "command": name,
        "nonce": nonce,
        "deadlineContinuous": deadline.0,
    }))
    .map_err(|_| Error::SpawnFailed)
}
fn is_spawn_command(bytes: &[u8], name: &str, nonce: &str, deadline: MachDeadline) -> bool {
    let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(bytes) else {
        return false;
    };
    fields.len() == 3
        && fields.get("command").and_then(Value::as_str) == Some(name)
        && fields.get("nonce").and_then(Value::as_str) == Some(nonce)
        && fields.get("deadlineContinuous").and_then(Value::as_u64) == Some(deadline.0)
}
fn send_spawn_command(
    socket: &mut UnixStream,
    name: &str,
    nonce: &str,
    deadline: MachDeadline,
) -> Result<()> {
    frame(socket, &spawn_command(name, nonce, deadline)?)
}
fn poll_one(fd: RawFd, events: i16, timeout_ms: i32) -> io::Result<i16> {
    let mut descriptor = libc::pollfd {
        fd,
        events,
        revents: 0,
    };
    let result = unsafe { libc::poll(&mut descriptor, 1, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(error);
    }
    Ok(descriptor.revents)
}
fn poll_pair(first: RawFd, second: RawFd, timeout_ms: i32) -> io::Result<[i16; 2]> {
    let mut descriptors = [
        libc::pollfd {
            fd: first,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: second,
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout_ms) };
    if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok([0, 0]);
        }
        return Err(error);
    }
    Ok([descriptors[0].revents, descriptors[1].revents])
}
fn ipc_cancel_pending(socket: &UnixStream) -> bool {
    let mut descriptor = libc::pollfd {
        fd: socket.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return true;
        }
        return descriptor.revents
            & (libc::POLLIN | libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)
            != 0;
    }
}
fn await_preflight(
    mut socket: &UnixStream,
    deadline: Instant,
    mach_deadline: MachDeadline,
    before_spawn: &mut impl FnMut() -> bool,
) -> bool {
    loop {
        if Instant::now() >= deadline || mach_deadline.expired() || !before_spawn() {
            return false;
        }
        let revents = match poll_one(socket.as_raw_fd(), libc::POLLIN, HANDSHAKE_POLL_MS) {
            Ok(revents) => revents,
            Err(_) => return false,
        };
        if revents & libc::POLLIN != 0 {
            let mut ready = [0];
            return socket.read_exact(&mut ready).is_ok() && ready == *b"F";
        }
        if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return false;
        }
    }
}
fn await_master(
    socket: &mut UnixStream,
    deadline: Instant,
    mach_deadline: MachDeadline,
    nonce: &str,
    before_spawn: &mut impl FnMut() -> bool,
) -> Result<File> {
    loop {
        if Instant::now() >= deadline || mach_deadline.expired() || !before_spawn() {
            let _ = send_spawn_command(socket, "cancel", nonce, mach_deadline);
            let _ = socket.shutdown(std::net::Shutdown::Write);
            return Err(Error::SpawnOutcomeUnknown);
        }
        let revents = match poll_one(socket.as_raw_fd(), libc::POLLIN, HANDSHAKE_POLL_MS) {
            Ok(revents) => revents,
            Err(_) => {
                let _ = send_spawn_command(socket, "cancel", nonce, mach_deadline);
                let _ = socket.shutdown(std::net::Shutdown::Write);
                return Err(Error::SpawnOutcomeUnknown);
            }
        };
        if revents & libc::POLLIN != 0 {
            let master = super::receive_fd(socket).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    Error::SpawnFailed
                } else {
                    Error::SpawnOutcomeUnknown
                }
            })?;
            if Instant::now() >= deadline || mach_deadline.expired() || !before_spawn() {
                drop(master);
                let _ = send_spawn_command(socket, "cancel", nonce, mach_deadline);
                let _ = socket.shutdown(std::net::Shutdown::Write);
                return Err(Error::SpawnOutcomeUnknown);
            }
            return Ok(master);
        }
        if revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::SpawnOutcomeUnknown);
        }
    }
}
fn lifetime(directory: &Directory, expected: [u64; 2]) -> Result<File> {
    let file = directory
        .file("controller.lock", false)?
        .ok_or(Error::CleanupFailed)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(file)
}
fn controller_lifetime(directory: &Directory, expected: [u64; 2]) -> Result<File> {
    let file = directory
        .file("protocol.lock", false)?
        .ok_or(Error::CleanupFailed)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(file)
}
fn verify_lifetime_pin(directory: &Directory, name: &str, expected: [u64; 2]) -> Result<()> {
    let file = directory.file(name, false)?.ok_or(Error::CleanupFailed)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}
fn verify_held_lifetime(directory: &Directory, name: &str, expected: [u64; 2]) -> Result<()> {
    let file = directory.file(name, false)?.ok_or(Error::CleanupFailed)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if [metadata.dev(), metadata.ino()] != expected
        || metadata.len() != 0
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0
        || io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock
    {
        return Err(Error::CleanupFailed);
    }
    Ok(())
}
fn unpersisted_lifetime_pin(directory: &Directory) -> Result<[u64; 2]> {
    let file = directory
        .file("controller.lock", false)?
        .ok_or(Error::CleanupFailed)?;
    let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
    if metadata.len() != 0 {
        return Err(Error::CleanupFailed);
    }
    let pin = [metadata.dev(), metadata.ino()];
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
        // A free lock is ambiguous here: the job may not have reached its
        // first instruction yet. Only persist a pin after observing the
        // controller hold this generation's lifetime lock.
        return Err(Error::CleanupFailed);
    }
    if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock {
        return Err(Error::CleanupFailed);
    }
    Ok(pin)
}
fn await_lifetime_release(directory: &Directory, expected: [u64; 2]) -> Result<File> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let file = directory
            .file("controller.lock", false)?
            .ok_or(Error::CleanupFailed)?;
        let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
        if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
            return Err(Error::CleanupFailed);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            let current = directory
                .file("controller.lock", false)?
                .ok_or(Error::CleanupFailed)?;
            let metadata = current.metadata().map_err(|_| Error::CleanupFailed)?;
            if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
                return Err(Error::CleanupFailed);
            }
            return Ok(file);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock
            || Instant::now() >= deadline
        {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn await_controller_lifetime_release(directory: &Directory, expected: [u64; 2]) -> Result<File> {
    let deadline = Instant::now() + DEADLINE;
    loop {
        let file = directory
            .file("protocol.lock", false)?
            .ok_or(Error::CleanupFailed)?;
        let metadata = file.metadata().map_err(|_| Error::CleanupFailed)?;
        if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
            return Err(Error::CleanupFailed);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            let current = directory
                .file("protocol.lock", false)?
                .ok_or(Error::CleanupFailed)?;
            let metadata = current.metadata().map_err(|_| Error::CleanupFailed)?;
            if [metadata.dev(), metadata.ino()] != expected || metadata.len() != 0 {
                return Err(Error::CleanupFailed);
            }
            return Ok(file);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::WouldBlock
            || Instant::now() >= deadline
        {
            return Err(Error::CleanupFailed);
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn finalize_unconsumed(directory: &Directory, record: &Record) -> Result<()> {
    if record.admission_consumed || !matches!(record.stage, Stage::BootstrapIntent | Stage::Closing)
    {
        return Err(Error::CleanupFailed);
    }
    if record.schema == 2
        && (record.custodian.is_some() != record.lifetime.is_some()
            || (record.controller.is_some() && record.custodian.is_none()))
    {
        return Err(Error::CleanupFailed);
    }
    let pin = match record.lifetime {
        Some(pin)
            if record.controller.is_some()
                || record.custodian.is_some()
                || record.host_step == "UnconsumedRemovalIntent" =>
        {
            pin
        }
        Some(_) => return Err(Error::CleanupFailed),
        None if record.controller.is_none() => unpersisted_lifetime_pin(directory)?,
        None => return Err(Error::CleanupFailed),
    };
    let record = update(directory, &record.nonce, |current| {
        if current.admission_consumed
            || !matches!(current.stage, Stage::BootstrapIntent | Stage::Closing)
            || current.lifetime.is_some_and(|current| current != pin)
            || (current.controller.is_some() && current.lifetime != Some(pin))
            || (current.custodian.is_some() && current.lifetime != Some(pin))
        {
            return Err(Error::CleanupFailed);
        }
        current.lifetime = Some(pin);
        // This durable intent also records why `lifetime` may be present before
        // controller identity was committed: the no-grant path was pinned
        // while its original lock was held.
        current.host_step = "UnconsumedRemovalIntent".into();
        Ok(())
    })?;
    if record.manager_pid()?.is_some() {
        if record.lifetime != Some(pin) {
            return Err(Error::CleanupFailed);
        }
        manager::remove(directory, &record)?;
    } else {
        manager::remove_unconsumed(directory, &record)?;
    }
    let _controller_lifetime = await_lifetime_release(directory, pin)?;
    let _protocol_lifetime = record
        .controller_lifetime
        .map(|pin| await_controller_lifetime_release(directory, pin))
        .transpose()?;
    let current = Record::read(directory)?;
    if current.nonce != record.nonce
        || current.admission_consumed
        || !matches!(current.stage, Stage::BootstrapIntent | Stage::Closing)
        || current.lifetime != Some(pin)
    {
        return Err(Error::CleanupFailed);
    }
    socket::cleanup(directory, &current)?;
    update(directory, &record.nonce, |current| {
        if current.admission_consumed
            || !matches!(current.stage, Stage::BootstrapIntent | Stage::Closing)
            || current.lifetime != Some(pin)
        {
            return Err(Error::CleanupFailed);
        }
        current.stage = Stage::Cleaned;
        Ok(())
    })?;
    Ok(())
}
fn finalize(directory: &Directory, nonce: &str) -> Result<()> {
    let record = Record::read(directory)?;
    if record.nonce != nonce {
        return Err(Error::CleanupFailed);
    }
    if record.stage == Stage::Cleaned {
        return Ok(());
    }
    if record.stage == Stage::Prepared {
        // Durable Prepared excludes any manager bootstrap or G. An unexpected
        // label here is foreign/ambiguous, never authority to boot it out.
        if !manager::absent(directory, &record)? {
            return Err(Error::CleanupFailed);
        }
        directory.remove("job.plist", &manager::definition(directory, &record)?)?;
        socket::cleanup(directory, &record)?;
        update(directory, nonce, |record| {
            if record.stage != Stage::Prepared {
                return Err(Error::CleanupFailed);
            }
            record.stage = Stage::Cleaned;
            Ok(())
        })?;
        return Ok(());
    }
    if !record.admission_consumed && matches!(record.stage, Stage::BootstrapIntent | Stage::Closing)
    {
        return finalize_unconsumed(directory, &record);
    }
    if record.stage != Stage::Closing
        || !record.disposed
        || !record.leader_reaped
        || !record.drained
        || record.controller.is_none()
    {
        return Err(Error::CleanupFailed);
    }
    if record.schema == 2 {
        if record.custodian.is_none()
            || record.controller_lifetime.is_none()
            || !record.controller_reaped
        {
            return Err(Error::CleanupFailed);
        }
        let _protocol = await_controller_lifetime_release(
            directory,
            record.controller_lifetime.ok_or(Error::CleanupFailed)?,
        )?;
    }
    let _custodian =
        await_lifetime_release(directory, record.lifetime.ok_or(Error::CleanupFailed)?)?;
    // No bootout until the custodian's durable PTY/leader/cohort proof, the
    // helper's direct-child reap, and both recorded process-lifetime locks have
    // been established.
    manager::remove(directory, &record)?;
    socket::cleanup(directory, &record)?;
    update(directory, nonce, |record| {
        if record.stage != Stage::Closing || !record.drained {
            return Err(Error::CleanupFailed);
        }
        record.stage = Stage::Cleaned;
        Ok(())
    })?;
    Ok(())
}
struct Generation {
    directory: Directory,
    record: Record,
    socket: Option<UnixStream>,
    acknowledged: bool,
    cleaned: bool,
    _owner: File,
}
impl Generation {
    fn finish(&mut self) -> Result<()> {
        finalize(&self.directory, &self.record.nonce)?;
        self.cleaned = true;
        Ok(())
    }
}
pub(crate) struct Worker {
    generation: Mutex<Option<Generation>>,
    reaper: std::sync::mpsc::SyncSender<Generation>,
}
impl Worker {
    pub(super) fn finished(&self) -> Result<bool> {
        let mut guard = self.generation.lock().map_err(|_| Error::CleanupFailed)?;
        let generation = guard.as_mut().ok_or(Error::CleanupFailed)?;
        if generation.cleaned {
            return Ok(true);
        }
        let socket = generation.socket.as_ref().ok_or(Error::CleanupFailed)?;
        if !super::peek_cleanup(socket)? {
            return Ok(false);
        }
        generation.acknowledged = true;
        generation.finish()?;
        Ok(true)
    }
    pub(super) fn stop(&mut self) -> Result<()> {
        let mut guard = self.generation.lock().map_err(|_| Error::CleanupFailed)?;
        let generation = guard.as_mut().ok_or(Error::CleanupFailed)?;
        if generation.cleaned {
            return Ok(());
        }
        let socket = generation.socket.as_mut().ok_or(Error::CleanupFailed)?;
        let _ = socket.shutdown(std::net::Shutdown::Write);
        if !generation.acknowledged {
            let mut ack = [0];
            socket
                .read_exact(&mut ack)
                .map_err(|_| Error::CleanupFailed)?;
            if ack != *b"A" {
                return Err(Error::CleanupFailed);
            }
            generation.acknowledged = true;
        }
        generation.finish()
    }
}
impl Drop for Worker {
    fn drop(&mut self) {
        if let Some(mut generation) = self
            .generation
            .get_mut()
            .unwrap_or_else(|p| p.into_inner())
            .take()
        {
            if let Some(socket) = generation.socket.take() {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
            if let Err(error) = self.reaper.send(generation) {
                Box::leak(Box::new(error.0));
            }
        }
    }
}
fn reaper() -> Result<std::sync::mpsc::SyncSender<Generation>> {
    super::WORKERS
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
            (count < MAX_SESSIONS).then_some(count + 1)
        })
        .map_err(|_| Error::ResourceExhausted)?;
    let slot = super::Slot;
    let (sender, receiver) = std::sync::mpsc::sync_channel::<Generation>(1);
    thread::Builder::new()
        .name("pty-coalition-reap".into())
        .spawn(move || {
            // Unexpected panic retains the permit. Only a proven cleanup releases it.
            let slot = std::mem::ManuallyDrop::new(slot);
            if let Ok(mut generation) = receiver.recv() {
                while !generation.cleaned && generation.finish().is_err() {
                    thread::sleep(Duration::from_millis(100));
                }
            }
            drop(std::mem::ManuallyDrop::into_inner(slot));
        })
        .map_err(|_| Error::SpawnFailed)?;
    Ok(sender)
}
fn recover_profile(profile: &Directory) -> Result<usize> {
    recover_profile_with(profile, &mut manager::absent)
}
fn recover_profile_with(
    profile: &Directory,
    absent: &mut impl FnMut(&Directory, &Record) -> Result<bool>,
) -> Result<usize> {
    gc::collect(profile, absent)?;
    let mut unresolved = 0;
    // This fresh pass is stable: GC has finished deleting directories, and
    // lifecycle reapers only change journal contents while holding owner.lock.
    profile.visit_names(|name| {
        if uuid::Uuid::parse_str(name)
            .map(|id| id.to_string())
            .ok()
            .as_deref()
            != Some(name)
        {
            return Err(Error::CleanupFailed);
        }
        let directory = Directory::open(&profile.path.join(name), false)?;
        let record = Record::read(&directory)?;
        if record.stage == Stage::Cleaned {
            if !gc::eligible(&record) {
                unresolved += 1;
            }
            return Ok(());
        }
        match directory.lock("owner.lock", Duration::ZERO) {
            Ok(_owner) => {
                if finalize(&directory, &record.nonce).is_err() {
                    unresolved += 1;
                }
            }
            Err(_) => unresolved += 1,
        }
        Ok(())
    })?;
    Ok(unresolved)
}
pub(crate) fn spawn(
    executable: &Path,
    profile_dir: &Path,
    profile: &SpawnProfile,
    mut before_spawn: impl FnMut() -> bool,
    operation_deadline: Instant,
) -> Result<(unix::Pty, Box<dyn Read + Send>)> {
    if unsafe { lomi_coalition_available() } != 0 {
        return Err(Error::UnsupportedPlatform);
    }
    let local_deadline = (Instant::now() + DEADLINE).min(operation_deadline);
    let mach_deadline = MachDeadline::from_instant(operation_deadline)?;
    if mach_deadline.expired() {
        return Err(Error::SpawnFailed);
    }
    let bytes = super::profile_bytes(profile)?;
    let executable = std::fs::canonicalize(executable).map_err(|_| Error::SpawnFailed)?;
    let executable_pin = fingerprint(&executable)?;
    let private = Directory::open(profile_dir, true)?;
    let generations = private.child("pty-generations")?;
    let _operations = private.lock("pty-operations.lock", DEADLINE)?;
    if recover_profile(&generations)? >= MAX_SESSIONS {
        return Err(Error::ResourceExhausted);
    }
    let run = uuid::Uuid::new_v4().to_string();
    let nonce = uuid::Uuid::new_v4().to_string();
    let reaper = reaper()?;
    let directory = generations.child(&run)?;
    let owner = directory.lock("owner.lock", Duration::ZERO)?;
    directory.write("protocol.lock", b"", None)?;
    let protocol_file = directory
        .file("protocol.lock", false)?
        .ok_or(Error::CleanupFailed)?;
    let protocol_metadata = protocol_file.metadata().map_err(|_| Error::CleanupFailed)?;
    let controller_lifetime = [protocol_metadata.dev(), protocol_metadata.ino()];
    let record = Record {
        schema: 2,
        run,
        nonce,
        stage: Stage::Prepared,
        executable,
        executable_pin,
        host: Identity::query(unsafe { libc::getpid() })?,
        controller: None,
        custodian: None,
        lifetime: None,
        controller_lifetime: Some(controller_lifetime),
        controller_reaped: false,
        disposed: false,
        leader_reaped: false,
        drained: false,
        admission_consumed: false,
        profile_pin: socket::pin(&private)?,
        generation_pin: socket::pin(&directory)?,
        runtime_pin: None,
        socket_pin: None,
        runtime_removal_started: false,
        runtime_removed: false,
        host_step: "Prepared".into(),
        worker_step: "Unconnected".into(),
    };
    directory.write("journal.json", &record.bytes()?, None)?;
    let worker = Worker {
        generation: Mutex::new(Some(Generation {
            directory,
            record,
            socket: None,
            acknowledged: false,
            cleaned: false,
            _owner: owner,
        })),
        reaper,
    };
    let master = {
        let mut guard = worker.generation.lock().map_err(|_| Error::CleanupFailed)?;
        let generation = guard.as_mut().unwrap();
        let directory = &generation.directory;
        let definition = manager::definition(directory, &generation.record)?;
        directory.write("job.plist", &definition, None)?;
        let runtime = socket::create(&generation.record)?;
        generation.record = update(directory, &generation.record.nonce, |record| {
            record.runtime_pin = Some(socket::pin(&runtime)?);
            Ok(())
        })?;
        let socket_path = runtime.path.join("s");
        let listener = UnixListener::bind(&socket_path).map_err(|_| Error::SpawnFailed)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::SpawnFailed)?;
        runtime.sync()?;
        generation.record = update(directory, &generation.record.nonce, |record| {
            record.socket_pin = Some(socket::socket_pin(&runtime)?);
            Ok(())
        })?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::SpawnFailed)?;
        manager::fresh(directory, &generation.record)?;
        generation.record = update(directory, &generation.record.nonce, |record| {
            if record.stage != Stage::Prepared {
                return Err(Error::CleanupFailed);
            }
            record.stage = Stage::BootstrapIntent;
            Ok(())
        })?;
        manager::bootstrap(directory, &generation.record)?;
        let mut socket = loop {
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock
                        && Instant::now() < local_deadline
                        && !mach_deadline.expired() =>
                {
                    thread::sleep(Duration::from_millis(5))
                }
                Err(_) => return Err(Error::SpawnFailed),
            }
        };
        configure(&socket)?;
        update(directory, &generation.record.nonce, |record| {
            record.host_step = "Connected".into();
            Ok(())
        })?;
        let pid = peer(&socket)?;
        let independent = Identity::query(pid)?;
        let hello: Value =
            serde_json::from_slice(&read_frame(&mut socket)?).map_err(|_| Error::SpawnFailed)?;
        let custodian = Identity::decode(&hello["custodian"])?;
        let lifetime: [u64; 2] = serde_json::from_value(hello["custodianLifetime"].clone())
            .map_err(|_| Error::SpawnFailed)?;
        let controller_lifetime: [u64; 2] =
            serde_json::from_value(hello["controllerLifetime"].clone())
                .map_err(|_| Error::SpawnFailed)?;
        if hello["nonce"].as_str() != Some(generation.record.nonce.as_str())
            || Identity::decode(&hello["identity"])? != independent
            || custodian.pid == generation.record.host.pid
            || unsafe { lomi_coalition_parent(&independent, &custodian) } != 0
            || independent.resource == generation.record.host.resource
            || independent.jetsam == generation.record.host.jetsam
            || custodian.resource != independent.resource
            || custodian.jetsam != independent.jetsam
            || custodian.count()? != 2
        {
            return Err(Error::SpawnFailed);
        }
        update(directory, &generation.record.nonce, |record| {
            record.host_step = "IdentityChecked".into();
            Ok(())
        })?;
        loop {
            match manager::observe(directory, &generation.record)? {
                Some(Some(loaded)) if loaded == custodian.pid => break,
                Some(Some(_)) => return Err(Error::SpawnFailed),
                _ => {}
            }
            if Instant::now() >= local_deadline || mach_deadline.expired() {
                return Err(Error::SpawnFailed);
            }
            thread::sleep(Duration::from_millis(5));
        }
        update(directory, &generation.record.nonce, |record| {
            record.host_step = "ManagerChecked".into();
            Ok(())
        })?;
        verify_held_lifetime(directory, "controller.lock", lifetime)
            .map_err(|_| Error::SpawnFailed)?;
        verify_held_lifetime(directory, "protocol.lock", controller_lifetime)
            .map_err(|_| Error::SpawnFailed)?;
        update(directory, &generation.record.nonce, |record| {
            record.host_step = "LifetimeChecked".into();
            Ok(())
        })?;
        generation.record = update(directory, &generation.record.nonce, |record| {
            if record.schema != 2
                || record.stage != Stage::BootstrapIntent
                || record
                    .controller
                    .is_some_and(|identity| identity != independent)
                || record.custodian != Some(custodian)
                || record.lifetime != Some(lifetime)
                || record.controller_lifetime != Some(controller_lifetime)
            {
                return Err(Error::CleanupFailed);
            }
            record.controller = Some(independent);
            record.custodian = Some(custodian);
            record.lifetime = Some(lifetime);
            record.controller_lifetime = Some(controller_lifetime);
            record.host_step = "IdentityPinned".into();
            Ok(())
        })?;
        generation.socket = Some(socket.try_clone().map_err(|_| Error::SpawnFailed)?);
        socket::validate(&runtime, &generation.record)?;
        if fingerprint(&generation.record.executable)? != generation.record.executable_pin {
            return Err(Error::SpawnFailed);
        }
        update(directory, &generation.record.nonce, |record| {
            record.host_step = "ExecutableChecked".into();
            Ok(())
        })?;
        generation.record = update(directory, &generation.record.nonce, |record| {
            if record.stage != Stage::BootstrapIntent
                || record.controller != Some(independent)
                || record.custodian != Some(custodian)
                || record.lifetime != Some(lifetime)
                || record.controller_lifetime != Some(controller_lifetime)
            {
                return Err(Error::CleanupFailed);
            }
            if unsafe { lomi_coalition_parent(&independent, &custodian) } != 0
                || custodian.count()? != 2
            {
                return Err(Error::SpawnFailed);
            }
            verify_held_lifetime(directory, "controller.lock", lifetime)?;
            verify_held_lifetime(directory, "protocol.lock", controller_lifetime)?;
            record.stage = Stage::AdmissionConsumed;
            record.admission_consumed = true;
            record.host_step = "AdmissionConsumed".into();
            Ok(())
        })?;
        if Instant::now() >= local_deadline || mach_deadline.expired() {
            return Err(Error::SpawnFailed);
        }
        frame(&mut socket, &bytes)?;
        socket
            .write_all(&mach_deadline.bytes())
            .map_err(|_| Error::SpawnFailed)?;
        if !await_preflight(&socket, local_deadline, mach_deadline, &mut before_spawn) {
            let _ = send_spawn_command(
                &mut socket,
                "cancel",
                &generation.record.nonce,
                mach_deadline,
            );
            let _ = socket.shutdown(std::net::Shutdown::Write);
            return Err(Error::SpawnFailed);
        }
        generation.record = update(directory, &generation.record.nonce, |record| {
            if record.stage != Stage::AdmissionConsumed || !record.admission_consumed {
                return Err(Error::CleanupFailed);
            }
            record.host_step = "ReadyReceived".into();
            Ok(())
        })?;
        if Instant::now() >= local_deadline || mach_deadline.expired() || !before_spawn() {
            let _ = send_spawn_command(
                &mut socket,
                "cancel",
                &generation.record.nonce,
                mach_deadline,
            );
            let _ = socket.shutdown(std::net::Shutdown::Write);
            return Err(Error::SpawnFailed);
        }
        if send_spawn_command(&mut socket, "exec", &generation.record.nonce, mach_deadline).is_err()
        {
            let _ = socket.shutdown(std::net::Shutdown::Write);
            return Err(Error::SpawnOutcomeUnknown);
        }
        await_master(
            &mut socket,
            local_deadline,
            mach_deadline,
            &generation.record.nonce,
            &mut before_spawn,
        )?
    };
    unix::Pty::from_worker(master, super::Worker::Coalition(Box::new(worker)))
}
fn closing(
    directory: &Directory,
    nonce: &str,
    controller: Identity,
    custodian: Identity,
    lifetime: [u64; 2],
    controller_lifetime: [u64; 2],
    controller_reaped: bool,
    proof: bool,
) -> Result<Record> {
    update(directory, nonce, |record| {
        if record.schema != 2
            || !matches!(
                record.stage,
                Stage::BootstrapIntent | Stage::AdmissionConsumed | Stage::Closing
            )
            || record
                .controller
                .is_some_and(|original| original != controller)
            || record
                .custodian
                .is_some_and(|original| original != custodian)
            || record.lifetime.is_some_and(|original| original != lifetime)
            || record
                .controller_lifetime
                .is_some_and(|original| original != controller_lifetime)
        {
            return Err(Error::CleanupFailed);
        }
        record.controller = Some(controller);
        record.custodian = Some(custodian);
        record.lifetime = Some(lifetime);
        record.controller_lifetime = Some(controller_lifetime);
        record.controller_reaped = controller_reaped;
        record.stage = Stage::Closing;
        if proof {
            if !controller_reaped {
                return Err(Error::CleanupFailed);
            }
            record.disposed = true;
            record.leader_reaped = true;
            record.drained = true;
        }
        Ok(())
    })
}
struct ProtocolChild {
    child: Child,
    reaped: bool,
}
impl ProtocolChild {
    fn reap(&mut self, ipc: &mut UnixStream) -> bool {
        if self.reaped {
            return true;
        }
        let _ = frame(ipc, b"C");
        let deadline = Instant::now() + Duration::from_millis(300);
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => {
                    self.reaped = self.child.wait().is_ok();
                    return self.reaped;
                }
                Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(5)),
                Ok(None) => {
                    let _ = self.child.kill();
                    self.reaped = self.child.wait().is_ok();
                    return self.reaped;
                }
                // A failed wait observation is not authority to signal a PID
                // that could have been reused. Retain custody without proof.
                Err(_) => return false,
            }
        }
    }
}
impl Drop for ProtocolChild {
    fn drop(&mut self) {
        if !self.reaped {
            match self.child.try_wait() {
                Ok(Some(_)) => self.reaped = self.child.wait().is_ok(),
                Ok(None) => {
                    let _ = self.child.kill();
                    self.reaped = self.child.wait().is_ok();
                }
                Err(_) => {}
            }
        }
    }
}
fn start_protocol_child(
    record: &Record,
    directory: &Directory,
    custodian: Identity,
    lifetime: [u64; 2],
) -> Result<(UnixStream, UnixStream, ProtocolChild, Identity, [u64; 2])> {
    let (mut ipc, inherited) = UnixStream::pair().map_err(|_| Error::SpawnFailed)?;
    configure(&ipc)?;
    let inherited_fd = inherited.as_raw_fd();
    let mut command = Command::new(&record.executable);
    command
        .env_clear()
        .arg("--internal-pty-coalition-protocol")
        .arg("3")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    unsafe {
        command.pre_exec(move || {
            if libc::dup2(inherited_fd, 3) < 0 || libc::fcntl(3, libc::F_SETFD, 0) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let child = command.spawn().map_err(|_| Error::SpawnFailed)?;
    drop(inherited);
    let child = ProtocolChild {
        child,
        reaped: false,
    };
    let path = directory.path.to_str().ok_or(Error::SpawnFailed)?;
    let bootstrap = json!({"path":path,"nonce":record.nonce});
    frame(&mut ipc, bootstrap.to_string().as_bytes())?;
    let host_file = super::receive_fd(&ipc).map_err(|_| Error::SpawnFailed)?;
    let host_socket = unsafe { UnixStream::from_raw_fd(host_file.into_raw_fd()) };
    configure(&host_socket)?;
    if peer(&host_socket)? != record.host.pid || Identity::query(record.host.pid)? != record.host {
        return Err(Error::SpawnFailed);
    }
    let hello: Value =
        serde_json::from_slice(&read_frame(&mut ipc)?).map_err(|_| Error::SpawnFailed)?;
    let controller = Identity::decode(&hello["identity"])?;
    let controller_pid = i32::try_from(child.child.id()).map_err(|_| Error::SpawnFailed)?;
    let reported_custodian = Identity::decode(&hello["custodian"])?;
    let controller_lifetime: [u64; 2] = serde_json::from_value(hello["controllerLifetime"].clone())
        .map_err(|_| Error::SpawnFailed)?;
    let reported_lifetime: [u64; 2] = serde_json::from_value(hello["custodianLifetime"].clone())
        .map_err(|_| Error::SpawnFailed)?;
    if hello["nonce"].as_str() != Some(record.nonce.as_str())
        || controller.pid != controller_pid
        || Identity::query(controller.pid)? != controller
        || reported_custodian != custodian
        || reported_lifetime != lifetime
        || record.controller_lifetime != Some(controller_lifetime)
        || unsafe { lomi_coalition_parent(&controller, &custodian) } != 0
        || custodian.count()? != 2
    {
        return Err(Error::SpawnFailed);
    }
    verify_lifetime_pin(directory, "controller.lock", lifetime)?;
    verify_held_lifetime(directory, "protocol.lock", controller_lifetime)?;
    Ok((ipc, host_socket, child, controller, controller_lifetime))
}
fn child_alive(controller: Identity, custodian: Identity) -> bool {
    Identity::query(controller.pid).ok() == Some(controller)
        && Identity::query(custodian.pid).ok() == Some(custodian)
        && unsafe { lomi_coalition_parent(&controller, &custodian) } == 0
}
fn clean_consumed(
    directory: &Directory,
    record: &Record,
    custodian: Identity,
    lifetime: [u64; 2],
    controller: Identity,
    controller_lifetime: [u64; 2],
    ipc: &mut UnixStream,
    host_socket: &mut UnixStream,
    mut controller_child: ProtocolChild,
    mut pty: Option<unix::Pty>,
    unknown: bool,
) -> i32 {
    // The journal barrier precedes fd disposal and every signal. If it cannot
    // be made durable, the custodian keeps both process handles and capacity.
    while closing(
        directory,
        &record.nonce,
        controller,
        custodian,
        lifetime,
        controller_lifetime,
        false,
        false,
    )
    .is_err()
    {
        thread::sleep(Duration::from_millis(20));
    }
    if let Some(pty) = &mut pty {
        pty.dispose_coalition_pty();
    }
    let controller_reaped = loop {
        if controller_child.reap(ipc) {
            break true;
        }
        thread::sleep(Duration::from_millis(20));
    };
    let start = Instant::now();
    loop {
        let signal = if start.elapsed() < Duration::from_millis(300) {
            libc::SIGTERM
        } else {
            libc::SIGKILL
        };
        let pass = unsafe { lomi_coalition_drain(&custodian, signal) };
        let leader_reaped = match &mut pty {
            Some(pty) => pty.reap_coalition_leader().unwrap_or(false),
            None => !unknown,
        };
        if pass >= 0
            && controller_reaped
            && leader_reaped
            && custodian.count() == Ok(1)
            && closing(
                directory,
                &record.nonce,
                controller,
                custodian,
                lifetime,
                controller_lifetime,
                true,
                true,
            )
            .is_ok()
        {
            let _ = host_socket.write_all(b"A");
            return 0;
        }
        // Nonforking quarantine: only direct-child wait and coalition SPI run.
        thread::sleep(Duration::from_millis(20));
    }
}
fn run_custodian(path: &Path) -> Result<i32> {
    portable_pty::unix::close_random_fds();
    let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
    action.sa_sigaction = libc::SIG_DFL;
    if unsafe { libc::sigemptyset(&mut action.sa_mask) } != 0
        || unsafe { libc::sigaction(libc::SIGCHLD, &action, std::ptr::null_mut()) } != 0
    {
        return Err(Error::SpawnFailed);
    }
    let directory = Directory::open(path, false)?;
    let record = Record::read(&directory)?;
    if record.schema != 2
        || record.stage != Stage::BootstrapIntent
        || record.admission_consumed
        || std::env::current_exe().ok().as_ref() != Some(&record.executable)
        || fingerprint(&record.executable).ok() != Some(record.executable_pin)
    {
        return Err(Error::SpawnFailed);
    }
    directory.write("controller.lock", b"", None)?;
    let lock = directory.lock("controller.lock", Duration::ZERO)?;
    let metadata = lock.metadata().map_err(|_| Error::SpawnFailed)?;
    let lifetime = [metadata.dev(), metadata.ino()];
    std::mem::forget(lock);
    if unsafe { lomi_coalition_available() } != 0 {
        return Err(Error::UnsupportedPlatform);
    }
    let custodian = Identity::query(unsafe { libc::getpid() })?;
    if custodian.count()? != 1 {
        return Err(Error::SpawnFailed);
    }
    let record = update(&directory, &record.nonce, |current| {
        if current.schema != 2
            || current.stage != Stage::BootstrapIntent
            || current.admission_consumed
            || current.controller.is_some()
            || current.custodian.is_some()
            || current.lifetime.is_some()
            || current.controller_lifetime.is_none()
        {
            return Err(Error::CleanupFailed);
        }
        verify_lifetime_pin(
            &directory,
            "protocol.lock",
            current.controller_lifetime.ok_or(Error::CleanupFailed)?,
        )?;
        current.custodian = Some(custodian);
        current.lifetime = Some(lifetime);
        current.host_step = "CustodianPinned".into();
        Ok(())
    })?;
    let (mut ipc, mut host_socket, mut controller_child, controller, controller_lifetime) =
        start_protocol_child(&record, &directory, custodian, lifetime)?;
    let record = update(&directory, &record.nonce, |current| {
        let stage_is_current = matches!(
            (current.stage, current.admission_consumed),
            (Stage::BootstrapIntent, false) | (Stage::AdmissionConsumed, true)
        );
        let controller_is_current = if current.stage == Stage::AdmissionConsumed {
            current.controller == Some(controller)
        } else {
            current
                .controller
                .is_none_or(|identity| identity == controller)
        };
        if current.schema != 2
            || !stage_is_current
            || current.host != record.host
            || current.custodian != Some(custodian)
            || current.lifetime != Some(lifetime)
            || current.controller_lifetime != Some(controller_lifetime)
            || !controller_is_current
        {
            return Err(Error::CleanupFailed);
        }
        current.controller = Some(controller);
        Ok(())
    })?;
    let profile_bytes = read_frame(&mut ipc)?;
    let profile = super::decode(&profile_bytes).ok_or(Error::SpawnFailed)?;
    let _ = super::profile_bytes(&profile)?;
    let mut deadline_bytes = [0; 8];
    ipc.read_exact(&mut deadline_bytes)
        .map_err(|_| Error::SpawnFailed)?;
    let mach_deadline = MachDeadline::from_bytes(deadline_bytes);
    let runtime = socket::open(&record)?;
    socket::validate(&runtime, &record)?;
    update(&directory, &record.nonce, |current| {
        if current.stage != Stage::AdmissionConsumed
            || !current.admission_consumed
            || current.controller != Some(controller)
            || current.custodian != Some(custodian)
            || current.lifetime != Some(lifetime)
            || current.controller_lifetime != Some(controller_lifetime)
        {
            return Err(Error::CleanupFailed);
        }
        current.worker_step = "ProfileDecoded".into();
        Ok(())
    })?;
    let mut accepted = false;
    let acquired = unix::Pty::acquire_coalition(&profile, || {
        let _ = update(&directory, &record.nonce, |current| {
            current.worker_step = "PtyOpened".into();
            Ok(())
        });
        let Ok(current) = Record::read(&directory) else {
            return false;
        };
        if current.stage != Stage::AdmissionConsumed
            || !current.admission_consumed
            || current.nonce != record.nonce
            || current.controller != Some(controller)
            || current.custodian != Some(custodian)
            || current.lifetime != Some(lifetime)
            || current.controller_lifetime != Some(controller_lifetime)
            || !child_alive(controller, custodian)
            || custodian.count() != Ok(2)
            || verify_lifetime_pin(&directory, "controller.lock", lifetime).is_err()
            || verify_held_lifetime(&directory, "protocol.lock", controller_lifetime).is_err()
            || socket::validate(&runtime, &current).is_err()
            || mach_deadline.expired()
            || ipc.write_all(b"F").is_err()
        {
            return false;
        }
        let Ok(command) = read_frame(&mut ipc) else {
            return false;
        };
        if !is_spawn_command(&command, "exec", &record.nonce, mach_deadline) {
            return false;
        }
        accepted = true;
        // Journal, lifetime, executable, and coalition checks all completed
        // before F. This is the custodian's last boundary before the backend
        // returns to its adjacent spawn_command call: reject expiry, a relayed
        // IPC cancellation, or unread host input/closure without another
        // blocking check. Both socket observations are non-consuming.
        // A revoke can still race the following syscall; that outcome remains
        // unknown unless cleanup proves the shell never started.
        if mach_deadline.expired() || ipc_cancel_pending(&ipc) || ipc_cancel_pending(&host_socket) {
            return false;
        }
        true
    });
    let acquisition_succeeded = acquired.is_ok();
    let mut unknown = matches!(acquired, Err(Error::SpawnOutcomeUnknown));
    let pty = acquired.ok();
    let current_result = Record::read(&directory);
    let consumed = accepted
        || current_result
            .as_ref()
            .map(|current| current.admission_consumed)
            .unwrap_or(true);
    let current = current_result.unwrap_or_else(|_| record.clone());
    if let Some(pty) = &pty {
        let _ = update(&directory, &record.nonce, |current| {
            current.worker_step = "Acquired".into();
            Ok(())
        });
        let fd = pty.worker_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        let configured =
            flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } == 0;
        let actual = if configured {
            unsafe { libc::fcntl(fd, libc::F_GETFL) }
        } else {
            -1
        };
        let nonblocking = actual >= 0 && actual & libc::O_NONBLOCK != 0;
        if nonblocking && super::send_fd(&ipc, fd).is_ok() {
            loop {
                match controller_child.child.try_wait() {
                    Ok(Some(_)) | Err(_) => break,
                    Ok(None) => {}
                }
                if pty.leader_exited() {
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
        } else {
            // The shell may already exist. Retain its direct owner and run
            // consumed cleanup; never expose a blocking FD or drop custody.
            unknown = true;
            let _ = host_socket.write_all(b"U");
        }
    } else if accepted || current.admission_consumed {
        let _ = host_socket.write_all(if unknown { b"U" } else { b"F" });
    }
    if !consumed {
        let _ = controller_child.reap(&mut ipc);
        return Ok(if acquisition_succeeded { 0 } else { 1 });
    }
    Ok(clean_consumed(
        &directory,
        &current,
        custodian,
        lifetime,
        controller,
        controller_lifetime,
        &mut ipc,
        &mut host_socket,
        controller_child,
        pty,
        unknown,
    ))
}
fn protocol_cancel(ipc: &mut UnixStream, nonce: &str, deadline: MachDeadline) {
    let _ = send_spawn_command(ipc, "cancel", nonce, deadline);
}
fn protocol_wait_preflight(
    ipc: &mut UnixStream,
    host: &mut UnixStream,
    nonce: &str,
    deadline: MachDeadline,
) -> Result<()> {
    loop {
        if deadline.expired() {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        let [host_events, ipc_events] =
            poll_pair(host.as_raw_fd(), ipc.as_raw_fd(), HANDSHAKE_POLL_MS)
                .map_err(|_| Error::SpawnFailed)?;
        if host_events & libc::POLLIN != 0 {
            // Keep the host input visible on the custodian's duplicate too.
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if host_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if ipc_events & libc::POLLIN != 0 {
            let mut ready = [0];
            ipc.read_exact(&mut ready).map_err(|_| Error::SpawnFailed)?;
            return if ready == *b"F" {
                Ok(())
            } else {
                Err(Error::SpawnFailed)
            };
        }
        if ipc_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::SpawnFailed);
        }
    }
}
fn protocol_wait_commit(
    ipc: &mut UnixStream,
    host: &mut UnixStream,
    nonce: &str,
    deadline: MachDeadline,
) -> Result<Vec<u8>> {
    loop {
        if deadline.expired() {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        let [host_events, ipc_events] =
            poll_pair(host.as_raw_fd(), ipc.as_raw_fd(), HANDSHAKE_POLL_MS)
                .map_err(|_| Error::SpawnFailed)?;
        if host_events & libc::POLLIN != 0 {
            let Ok(command) = read_frame(host) else {
                protocol_cancel(ipc, nonce, deadline);
                return Err(Error::SpawnFailed);
            };
            if is_spawn_command(&command, "cancel", nonce, deadline) {
                protocol_cancel(ipc, nonce, deadline);
                return Err(Error::SpawnFailed);
            }
            if is_spawn_command(&command, "exec", nonce, deadline) {
                return Ok(command);
            }
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if host_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if ipc_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::SpawnFailed);
        }
    }
}
fn protocol_wait_master(
    ipc: &mut UnixStream,
    host: &mut UnixStream,
    nonce: &str,
    deadline: MachDeadline,
) -> Result<File> {
    loop {
        if deadline.expired() {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        let [host_events, ipc_events] =
            poll_pair(host.as_raw_fd(), ipc.as_raw_fd(), HANDSHAKE_POLL_MS)
                .map_err(|_| Error::SpawnFailed)?;
        if host_events & libc::POLLIN != 0 {
            // After forwarding exec, do not consume host input. The custodian
            // retains a duplicate and rejects this readable event itself.
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if host_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            protocol_cancel(ipc, nonce, deadline);
            return Err(Error::SpawnFailed);
        }
        if ipc_events & libc::POLLIN != 0 {
            return super::receive_fd(ipc).map_err(|_| Error::SpawnFailed);
        }
        if ipc_events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(Error::SpawnFailed);
        }
    }
}
pub(crate) fn protocol_child(fd: RawFd) -> i32 {
    if fd < 3 || unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return 1;
    }
    let mut ipc = unsafe { UnixStream::from_raw_fd(fd) };
    if configure(&ipc).is_err() {
        return 1;
    }
    let bootstrap = match read_frame(&mut ipc)
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).map_err(|_| Error::SpawnFailed))
    {
        Ok(bootstrap) => bootstrap,
        Err(_) => return 1,
    };
    let path = match bootstrap["path"].as_str() {
        Some(path) => PathBuf::from(path),
        None => return 1,
    };
    let nonce = match bootstrap["nonce"].as_str() {
        Some(nonce) => nonce,
        None => return 1,
    };
    if !path.is_absolute() {
        return 1;
    }
    let directory = match Directory::open(&path, false) {
        Ok(directory) => directory,
        Err(_) => return 1,
    };
    let record = match Record::read(&directory) {
        Ok(record)
            if record.schema == 2
                && record.stage == Stage::BootstrapIntent
                && !record.admission_consumed
                && record.nonce == nonce
                && std::env::current_exe().ok().as_ref() == Some(&record.executable)
                && fingerprint(&record.executable).ok() == Some(record.executable_pin) =>
        {
            record
        }
        _ => return 1,
    };
    let custodian = match Identity::query(unsafe { libc::getppid() }) {
        Ok(identity) => identity,
        Err(_) => return 1,
    };
    let controller = match Identity::query(unsafe { libc::getpid() }) {
        Ok(identity) => identity,
        Err(_) => return 1,
    };
    if unsafe { lomi_coalition_parent(&controller, &custodian) } != 0 || custodian.count() != Ok(2)
    {
        return 1;
    }
    let lock = match directory.lock("protocol.lock", Duration::ZERO) {
        Ok(lock) => lock,
        Err(_) => return 1,
    };
    let metadata = match lock.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return 1,
    };
    let controller_lifetime = [metadata.dev(), metadata.ino()];
    let custodian_file = match directory.file("controller.lock", false) {
        Ok(Some(file)) => file,
        _ => return 1,
    };
    let custodian_metadata = match custodian_file.metadata() {
        Ok(metadata) => metadata,
        Err(_) => return 1,
    };
    let custodian_lifetime = [custodian_metadata.dev(), custodian_metadata.ino()];
    if record.custodian != Some(custodian)
        || record.lifetime != Some(custodian_lifetime)
        || record.controller_lifetime != Some(controller_lifetime)
        || verify_held_lifetime(&directory, "controller.lock", custodian_lifetime).is_err()
    {
        return 1;
    }
    let runtime = match socket::open(&record) {
        Ok(runtime) if socket::validate(&runtime, &record).is_ok() => runtime,
        _ => return 1,
    };
    let mut host = match UnixStream::connect(runtime.path.join("s")) {
        Ok(host) => host,
        Err(_) => return 1,
    };
    if configure(&host).is_err()
        || peer(&host).ok() != Some(record.host.pid)
        || Identity::query(record.host.pid).ok() != Some(record.host)
    {
        return 1;
    }
    if super::send_fd(&ipc, host.as_raw_fd()).is_err() {
        return 1;
    }
    let hello = json!({"nonce":record.nonce,"identity":controller.json(),"custodian":custodian.json(),"custodianLifetime":custodian_lifetime,"controllerLifetime":controller_lifetime});
    if frame(&mut host, hello.to_string().as_bytes()).is_err()
        || frame(&mut ipc, hello.to_string().as_bytes()).is_err()
    {
        return 1;
    }
    let bytes = match read_frame(&mut host) {
        Ok(bytes) => bytes,
        Err(_) => return 1,
    };
    if super::decode(&bytes).is_none()
        || super::profile_bytes(&super::decode(&bytes).unwrap()).is_err()
    {
        return 1;
    }
    if frame(&mut ipc, &bytes).is_err() {
        return 1;
    }
    let mut deadline_bytes = [0; 8];
    if host.read_exact(&mut deadline_bytes).is_err() || ipc.write_all(&deadline_bytes).is_err() {
        return 1;
    }
    let mach_deadline = MachDeadline::from_bytes(deadline_bytes);
    if protocol_wait_preflight(&mut ipc, &mut host, nonce, mach_deadline).is_err()
        || mach_deadline.expired()
        || host.write_all(b"F").is_err()
    {
        return 1;
    }
    let command = match protocol_wait_commit(&mut ipc, &mut host, nonce, mach_deadline) {
        Ok(command) => command,
        Err(_) => return 1,
    };
    if !is_spawn_command(&command, "exec", nonce, mach_deadline)
        || mach_deadline.expired()
        || frame(&mut ipc, &command).is_err()
    {
        return 1;
    }
    let master = match protocol_wait_master(&mut ipc, &mut host, nonce, mach_deadline) {
        Ok(master) => master,
        Err(_) => return 1,
    };
    if super::send_fd(&host, master.as_raw_fd()).is_err() {
        return 1;
    }
    drop(master);
    loop {
        let mut fds = [
            libc::pollfd {
                fd: host.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: ipc.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let result = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as _, 100) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return 1;
        }
        if result == 0 {
            continue;
        }
        if fds[1].revents != 0 {
            match read_frame(&mut ipc) {
                Ok(command) if command == b"C" => return 0,
                _ => return 1,
            }
        }
        if fds[0].revents != 0 {
            let mut byte = [0];
            match host.read(&mut byte) {
                Ok(_) => return 0,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return 0,
            }
        }
    }
}
pub(crate) fn run(path: &Path) -> i32 {
    run_custodian(path).unwrap_or_else(|_| 1)
}
/// Teardown-only startup recovery. Never resubmits a label or grants an old spawn.
pub(crate) fn recover(profile_dir: &Path) -> Result<()> {
    let private = Directory::open(profile_dir, false)?;
    let _operations = private.lock("pty-operations.lock", DEADLINE)?;
    match std::fs::symlink_metadata(private.path.join("pty-generations")) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(Error::CleanupFailed),
        Ok(_) => {}
    }
    let generations = Directory::open(&private.path.join("pty-generations"), false)?;
    if recover_profile(&generations)? == 0 {
        Ok(())
    } else {
        Err(Error::CleanupFailed)
    }
}
