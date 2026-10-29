//! Exact-current-user logon tasks; Scheduler engine PIDs never identify the host.
use super::service;
use super::{
    Handle, LocalClient, OwnerLock, PrivateProfile, current_sid, normalized, open_regular,
    security, wide,
};
use crate::windows_login_start_policy::{
    self as start_policy, Decision, Observation as LaunchObservation,
};
use lomi_remote_protocol::{
    RuntimeId,
    ipc::{LocalCall, LocalOperatorIntent, LocalResult},
    rpc::Confirmed,
};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    ffi::OsStr,
    fs::File,
    io::{Read, Write},
    mem,
    os::windows::io::FromRawHandle,
    path::{Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows::{
    Win32::{
        Foundation::{VARIANT_BOOL, VARIANT_FALSE, VARIANT_TRUE},
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            TaskScheduler::*,
            Variant::VARIANT,
        },
    },
    core::{BSTR, Interface},
};
use windows_sys::Win32::{
    Foundation::*,
    Security::*,
    Storage::FileSystem::*,
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::*,
    },
};
mod uuid_encoding {
    use super::*;
    pub fn serialize<S: serde::Serializer>(
        value: &Uuid,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Uuid, D::Error> {
        let value = String::deserialize(deserializer)?;
        let uuid = Uuid::parse_str(&value).map_err(serde::de::Error::custom)?;
        if uuid.to_string() != value {
            return Err(serde::de::Error::custom("invalid UUID"));
        }
        Ok(uuid)
    }
}
const LIMIT: u64 = 32 * 1024;
const WAIT: Duration = Duration::from_secs(45);
const RECORD: &str = "registration.json";
const MARKER: &str = "managed-run.json";
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    Manager,
    Deadline,
    NotReady,
    PrivilegedAccount,
    SessionRequired,
    HelperMissing,
    NotInstalled,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "LOGIN_INVALID_CONFIGURATION",
            Self::Conflict => "LOGIN_OWNERSHIP_CONFLICT",
            Self::Manager => "LOGIN_TASK_SETUP_UNAVAILABLE",
            Self::Deadline => "LOGIN_OPERATION_UNCERTAIN",
            Self::NotReady => "LOGIN_HOST_NOT_READY",
            Self::PrivilegedAccount => "LOGIN_ORDINARY_CURRENT_ACCOUNT_REQUIRED",
            Self::SessionRequired => "LOGIN_INTERACTIVE_SESSION_REQUIRED",
            Self::HelperMissing => "LOGIN_MANAGED_HELPER_REQUIRED",
            Self::NotInstalled => "LOGIN_NOT_INSTALLED",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn conflict<T>(_: T) -> Error {
    Error::Conflict
}
fn policy(error: service::Error) -> Error {
    if error == service::Error::PrivilegedAccount {
        Error::PrivilegedAccount
    } else {
        Error::Conflict
    }
}
fn com(error: windows::core::Error) -> Error {
    if matches!(error.code().0 as u32, 0x80041320 | 0x80070520) {
        Error::SessionRequired
    } else if error.code().0 as u32 == 0x8004131f {
        Error::NotReady
    } else {
        Error::Manager
    }
}
fn absent(error: &windows::core::Error) -> bool {
    matches!(error.code().0 as u32, 0x80070002 | 0x80070003)
}
fn text(value: &OsStr) -> Result<String> {
    let value = value.to_str().ok_or(Error::Invalid)?;
    if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    Ok(value.into())
}
fn sid(value: &str) -> Result<String> {
    if value.starts_with("S-1-") {
        Ok(value.into())
    } else {
        service::account_sid(value).map_err(policy)
    }
}
fn task_text(value: &OsStr) -> Result<String> {
    let value = text(value)?;
    if value.contains('%') || value.contains("$(") {
        return Err(Error::Invalid);
    }
    Ok(value)
}
fn registration_path(profile: &Path) -> Result<PathBuf> {
    let profile = normalized(profile).map_err(conflict)?;
    let name = text(profile.file_name().ok_or(Error::Invalid)?)?;
    Ok(profile.with_file_name(format!("{name}-service-windows-login")))
}
fn scm_path(profile: &Path) -> Result<PathBuf> {
    let name = text(profile.file_name().ok_or(Error::Invalid)?)?;
    Ok(profile.with_file_name(format!("{name}-service-windows")))
}
/// Common library-entrypoint lock, distinct from the actual host OwnerLock.
/// The protected control directory/lock inode remains after uninstall.
pub(super) fn selection_lock(profile: &Path) -> Result<OwnerLock> {
    let name = text(profile.file_name().ok_or(Error::Invalid)?)?;
    OwnerLock::acquire(&profile.with_file_name(format!("{name}-service-windows-control")))
        .map_err(conflict)
}
pub(super) fn login_present(profile: &Path) -> Result<bool> {
    let path = registration_path(profile)?;
    if !path.try_exists().map_err(conflict)? {
        return Ok(false);
    }
    let directory = PrivateProfile::open(&path, false).map_err(conflict)?;
    let record: Option<Registration> = load(&directory, RECORD)?;
    if let Some(record) = &record {
        record.check()?;
    }
    Ok(record.is_some())
}
/// Routing never silently changes the adapter of an existing registration.
pub fn selected(profile: &Path, operation: &str, mode: Option<&str>) -> Result<bool> {
    let login = login_present(profile)?;
    let scm = scm_path(&normalized(profile).map_err(conflict)?)?
        .join(RECORD)
        .try_exists()
        .map_err(conflict)?;
    if login && scm {
        return Err(Error::Conflict);
    }
    if operation == "install" {
        return match mode {
            Some("login") if !scm => Ok(true),
            Some("boot") if !login => Ok(false),
            Some("login" | "boot") => Err(Error::Conflict),
            _ => Err(Error::Invalid),
        };
    }
    Ok(login)
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Phase {
    Intent,
    Registered,
    SetupRequired,
    Deleting,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Registration {
    version: u8,
    #[serde(with = "uuid_encoding")]
    installation: Uuid,
    sid: String,
    profile: PathBuf,
    helper: PathBuf,
    registration: PathBuf,
    phase: Phase,
}
impl Registration {
    fn folder(&self) -> String {
        format!("\\LomiRemote-{}", self.installation)
    }
    fn task_path(&self) -> String {
        format!("{}\\Host", self.folder())
    }
    fn arguments(&self) -> Result<String> {
        let args = [
            "--managed-logon".into(),
            task_text(self.registration.as_os_str())?,
            self.installation.to_string(),
        ];
        let command = args
            .iter()
            .map(|s| service::quote(s).map_err(policy))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        if command.len() > 4096 || service::parse(&command).map_err(policy)? != args {
            return Err(Error::Invalid);
        }
        Ok(command)
    }
    fn check(&self) -> Result<()> {
        if self.version != 1
            || self.installation.is_nil()
            || self.sid != current_sid().map_err(conflict)?
            || registration_path(&self.profile)? != self.registration
        {
            return Err(Error::Conflict);
        }
        if normalized(&self.helper).map_err(conflict)? != self.helper
            || normalized(&self.profile).map_err(conflict)? != self.profile
        {
            return Err(Error::Conflict);
        }
        self.arguments()?;
        task_text(self.helper.as_os_str())?;
        Ok(())
    }
    fn pins(&self) -> Result<(service::Pinned, PrivateProfile)> {
        self.check()?;
        let binary = service::pin(&self.helper, &self.sid, true).map_err(policy)?;
        use std::os::windows::io::BorrowedHandle;
        let pinned = binary._file.as_ref().ok_or(Error::Conflict)?;
        let borrowed = unsafe { BorrowedHandle::borrow_raw(pinned.0) };
        let mut file = File::from(borrowed.try_clone_to_owned().map_err(conflict)?);
        use std::io::{Seek, SeekFrom};
        let mut dos = [0u8; 64];
        file.read_exact(&mut dos).map_err(conflict)?;
        let offset = u32::from_le_bytes(dos[60..64].try_into().unwrap()) as u64;
        if &dos[..2] != b"MZ" || !(64..=1024 * 1024).contains(&offset) {
            return Err(Error::HelperMissing);
        }
        file.seek(SeekFrom::Start(offset)).map_err(conflict)?;
        let mut header = [0u8; 94];
        file.read_exact(&mut header).map_err(conflict)?;
        if !gui_header(&header) {
            return Err(Error::HelperMissing);
        }
        Ok((
            binary,
            PrivateProfile::open(&self.profile, false).map_err(conflict)?,
        ))
    }
}
fn load<T: DeserializeOwned>(profile: &PrivateProfile, name: &str) -> Result<Option<T>> {
    profile.check_current().map_err(conflict)?;
    let file = match open_regular(&profile.path.join(name), false, false, &profile.sid) {
        Ok(f) => f,
        Err(super::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(Error::Conflict),
    };
    if file.metadata().map_err(conflict)?.len() > LIMIT {
        return Err(Error::Conflict);
    }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1)
        .read_to_end(&mut bytes)
        .map_err(conflict)?;
    Ok(Some(serde_json::from_slice(&bytes).map_err(conflict)?))
}
fn atomic<T: Serialize + DeserializeOwned + PartialEq>(
    profile: &PrivateProfile,
    name: &str,
    old: Option<&T>,
    value: &T,
) -> Result<()> {
    profile.check_current().map_err(conflict)?;
    if load::<T>(profile, name)?.as_ref() != old {
        return Err(Error::Conflict);
    }
    let temporary = profile.path.join(format!(".pending-{}", Uuid::new_v4()));
    let sd = security(&profile.sid, false).map_err(conflict)?;
    let raw = unsafe {
        CreateFileW(
            wide(&temporary).as_ptr(),
            GENERIC_WRITE | READ_CONTROL,
            0,
            &sd.attributes,
            CREATE_NEW,
            FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(Error::Deadline);
    }
    let mut file = unsafe { File::from_raw_handle(raw) };
    let bytes = serde_json::to_vec(value).map_err(conflict)?;
    if bytes.len() as u64 > LIMIT {
        return Err(Error::Invalid);
    }
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| Error::Deadline)?;
    drop(file);
    profile.check_current().map_err(conflict)?;
    if load::<T>(profile, name)?.as_ref() != old {
        return Err(Error::Conflict);
    }
    if unsafe {
        MoveFileExW(
            wide(&temporary).as_ptr(),
            wide(profile.path.join(name)).as_ptr(),
            MOVEFILE_WRITE_THROUGH
                | if old.is_some() {
                    MOVEFILE_REPLACE_EXISTING
                } else {
                    0
                },
        )
    } == 0
    {
        return Err(Error::Deadline);
    }
    Ok(())
}
fn remove<T: DeserializeOwned + PartialEq>(
    profile: &PrivateProfile,
    name: &str,
    value: &T,
) -> Result<()> {
    if load::<T>(profile, name)?.as_ref() != Some(value) {
        return Err(Error::Conflict);
    }
    if unsafe { DeleteFileW(wide(profile.path.join(name)).as_ptr()) } == 0 {
        return Err(Error::Deadline);
    }
    Ok(())
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Completion {
    Running,
    Clean,
    Failed,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Marker {
    #[serde(with = "uuid_encoding")]
    installation: Uuid,
    runtime: RuntimeId,
    #[serde(with = "uuid_encoding")]
    run: Uuid,
    sid: String,
    helper: PathBuf,
    pid: u32,
    created: u64,
    completion: Completion,
}
fn process_creation(process: HANDLE) -> Result<u64> {
    let (mut created, mut exited, mut kernel, mut user) = (
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
    );
    if unsafe { GetProcessTimes(process, &mut created, &mut exited, &mut kernel, &mut user) } == 0 {
        return Err(Error::Conflict);
    }
    Ok(((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64)
}
fn process_executable(process: HANDLE) -> Result<PathBuf> {
    let mut path = vec![0u16; 32768];
    let mut len = path.len() as u32;
    if unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut len) } == 0 {
        return Err(Error::Conflict);
    }
    use std::os::windows::ffi::OsStringExt;
    normalized(Path::new(&std::ffi::OsString::from_wide(
        &path[..len as usize],
    )))
    .map_err(conflict)
}
fn marker_matches(record: &Registration, marker: &Marker) -> Result<()> {
    if marker.installation != record.installation
        || marker.sid != record.sid
        || marker.helper != record.helper
        || marker.pid == 0
        || marker.created == 0
        || marker.run.is_nil()
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
/// The host calls ready/finish only while its real endpoint holds OwnerLock.
/// This object never takes the manager lock that a CLI readiness wait holds.
pub struct ManagedRun {
    record: Registration,
    directory: PrivateProfile,
    marker: Option<Marker>,
    _pins: (service::Pinned, PrivateProfile),
}
impl ManagedRun {
    pub fn prepare(registration: &Path, installation: Uuid) -> Result<Self> {
        service::ordinary_identity().map_err(policy)?;
        let directory = PrivateProfile::open(registration, false).map_err(conflict)?;
        let record: Registration = load(&directory, RECORD)?.ok_or(Error::NotInstalled)?;
        record.check()?;
        if record.installation != installation
            || record.registration != directory.path
            || record.phase != Phase::Registered
            || normalized(&std::env::current_exe().map_err(conflict)?).map_err(conflict)?
                != record.helper
        {
            return Err(Error::Conflict);
        }
        let pins = record.pins()?;
        let check = record.clone();
        thread::spawn(move || {
            let _apartment = Apartment::new()?;
            let scheduler = Scheduler::connect()?;
            let folder = scheduler.folder(&check, false)?.ok_or(Error::Conflict)?;
            scheduler.task(&check, &folder)?.ok_or(Error::Conflict)?;
            Ok::<(), Error>(())
        })
        .join()
        .map_err(|_| Error::Manager)??;
        Ok(Self {
            record,
            directory,
            marker: None,
            _pins: pins,
        })
    }
    pub fn profile(&self) -> &Path {
        &self.record.profile
    }
    pub fn ready(&mut self, runtime: RuntimeId) -> Result<()> {
        if load::<Registration>(&self.directory, RECORD)?.as_ref() != Some(&self.record) {
            return Err(Error::Conflict);
        }
        let old: Option<Marker> = load(&self.directory, MARKER)?;
        if let Some(old) = &old {
            marker_matches(&self.record, old)?;
            if live_process(old)?.is_some() {
                return Err(Error::Conflict);
            }
        }
        let marker = Marker {
            installation: self.record.installation,
            runtime,
            run: Uuid::new_v4(),
            sid: self.record.sid.clone(),
            helper: self.record.helper.clone(),
            pid: unsafe { GetCurrentProcessId() },
            created: process_creation(unsafe { GetCurrentProcess() })?,
            completion: Completion::Running,
        };
        atomic(&self.directory, MARKER, old.as_ref(), &marker)?;
        self.marker = Some(marker);
        Ok(())
    }
    pub fn finish(&mut self, clean: bool) -> Result<()> {
        if let Some(old) = self.marker.take() {
            let mut next = old.clone();
            next.completion = if clean {
                Completion::Clean
            } else {
                Completion::Failed
            };
            atomic(&self.directory, MARKER, Some(&old), &next)?;
        }
        Ok(())
    }
}
fn live_process(marker: &Marker) -> Result<Option<Handle>> {
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            marker.pid,
        )
    };
    if raw.is_null() {
        return if unsafe { GetLastError() } == ERROR_INVALID_PARAMETER {
            Ok(None)
        } else {
            Err(Error::Conflict)
        };
    }
    let process = Handle::new(raw).map_err(conflict)?;
    if process_creation(process.0)? != marker.created {
        return Ok(None);
    }
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_OBJECT_0 => return Ok(None),
        WAIT_TIMEOUT => {}
        _ => return Err(Error::Conflict),
    }
    let identity = (|| {
        if super::process_sid(process.0).map_err(conflict)? != marker.sid
            || process_executable(process.0)? != marker.helper
        {
            return Err(Error::Conflict);
        }
        Ok(())
    })();
    if let Err(error) = identity {
        // The retained object can terminate between the first wait and an
        // identity query. Only its positively signaled HANDLE proves absence;
        // a live process or an unknown wait still fails closed.
        return if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
            Ok(None)
        } else {
            Err(error)
        };
    }
    match unsafe { WaitForSingleObject(process.0, 0) } {
        WAIT_TIMEOUT => Ok(Some(process)),
        WAIT_OBJECT_0 => Ok(None),
        _ => Err(Error::Conflict),
    }
}
struct BoundHost {
    client: LocalClient,
    marker: Marker,
}
fn bind(record: &Registration, directory: &PrivateProfile, deadline: Instant) -> Result<BoundHost> {
    let marker: Marker = load(directory, MARKER)?.ok_or(Error::NotReady)?;
    marker_matches(record, &marker)?;
    if marker.completion != Completion::Running {
        return Err(Error::NotReady);
    }
    let mut client = LocalClient::connect_with_timeout(
        &record.profile,
        remaining(deadline)?.min(Duration::from_secs(1)),
    )
    .map_err(|_| Error::NotReady)?;
    let process = client.connection.stream._process.0;
    peer_matches(
        record,
        &marker,
        unsafe { GetProcessId(process) },
        process_creation(process)?,
        &process_executable(process)?,
        client.discovery().runtime_id,
    )?;
    let response = client
        .request_with_timeout(
            LocalCall::Status {},
            remaining(deadline)?.min(super::REQUEST_TIMEOUT),
        )
        .map_err(|_| Error::NotReady)?;
    if !matches!(response.result,Ok(LocalResult::Status(ref value)) if value.runtime_id==marker.runtime)
        || Instant::now() >= deadline
        || load::<Marker>(directory, MARKER)?.as_ref() != Some(&marker)
    {
        return Err(Error::NotReady);
    }
    Ok(BoundHost { client, marker })
}
fn peer_matches(
    record: &Registration,
    marker: &Marker,
    pid: u32,
    created: u64,
    executable: &Path,
    runtime: RuntimeId,
) -> Result<()> {
    marker_matches(record, marker)?;
    if marker.completion != Completion::Running
        || marker.pid != pid
        || marker.created != created
        || record.helper != executable
        || marker.runtime != runtime
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn remaining(deadline: Instant) -> Result<Duration> {
    let value = deadline.saturating_duration_since(Instant::now());
    if value.is_zero() {
        Err(Error::Deadline)
    } else {
        Ok(value)
    }
}
#[derive(Debug, Clone, Copy)]
enum LaunchStage {
    StopState,
    StopBind,
    PreIdle,
    Admission,
    InstanceIdentity,
    Bind,
    Marker,
    Refresh,
    State,
    Readiness,
}
fn launch_error(stage: LaunchStage, error: Error) -> Error {
    let _ = stage;
    error
}
fn launch_observation(old: Option<&Marker>, marker: Option<&Marker>) -> LaunchObservation {
    match marker {
        None => LaunchObservation::SchedulerOnly,
        Some(marker) if old.is_some_and(|old| old.run == marker.run) => {
            LaunchObservation::PreviousGeneration
        }
        Some(marker) if marker.completion == Completion::Running => {
            LaunchObservation::NewGenerationPending
        }
        Some(_) => LaunchObservation::NewGenerationFinished,
    }
}
// Compare all task semantics used by this adapter, not Scheduler XML formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Definition {
    values: Vec<(String, String)>,
}
macro_rules! get {
    ($object:expr,$method:ident,$kind:ty) => {{
        let mut value: $kind = Default::default();
        $object.$method(&mut value).map_err(com)?;
        value
    }};
}
impl Definition {
    fn read(definition: &ITaskDefinition) -> Result<Self> {
        let mut values = Vec::new();
        macro_rules! value {
            ($name:expr,$value:expr) => {
                values.push(($name.into(), $value.to_string()))
            };
        }
        unsafe {
            let p = definition.Principal().map_err(com)?;
            value!("principal", sid(&get!(p, UserId, BSTR).to_string())?);
            value!("principal-id", get!(p, Id, BSTR));
            value!("group", get!(p, GroupId, BSTR));
            value!("logon", get!(p, LogonType, TASK_LOGON_TYPE).0);
            value!("level", get!(p, RunLevel, TASK_RUNLEVEL_TYPE).0);
            let p2: IPrincipal2 = p.cast().map_err(com)?;
            value!(
                "process-token-sid-type",
                get!(p2, ProcessTokenSidType, TASK_PROCESSTOKENSID_TYPE).0
            );
            let privileges = get!(p2, RequiredPrivilegeCount, i32);
            if privileges != 0 {
                return Err(Error::Conflict);
            }
            value!("required-privileges", privileges);
            value!("data", get!(definition, Data, BSTR));
            let info = definition.RegistrationInfo().map_err(com)?;
            value!("source", get!(info, Source, BSTR));
            let actions = definition.Actions().map_err(com)?;
            if get!(actions, Count, i32) != 1 {
                return Err(Error::Conflict);
            }
            value!("context", get!(actions, Context, BSTR));
            let a = actions.get_Item(1).map_err(com)?;
            value!("action-type", get!(a, Type, TASK_ACTION_TYPE).0);
            value!("action-id", get!(a, Id, BSTR));
            let a: IExecAction = a.cast().map_err(com)?;
            value!("executable", get!(a, Path, BSTR));
            value!("arguments", get!(a, Arguments, BSTR));
            value!("cwd", get!(a, WorkingDirectory, BSTR));
            let triggers = definition.Triggers().map_err(com)?;
            if get!(triggers, Count, i32) != 1 {
                return Err(Error::Conflict);
            }
            let t = triggers.get_Item(1).map_err(com)?;
            value!("trigger-type", get!(t, Type, TASK_TRIGGER_TYPE2).0);
            value!("trigger-id", get!(t, Id, BSTR));
            value!("trigger-enabled", get!(t, Enabled, VARIANT_BOOL).0);
            value!("trigger-start", get!(t, StartBoundary, BSTR));
            value!("trigger-end", get!(t, EndBoundary, BSTR));
            value!("trigger-limit", get!(t, ExecutionTimeLimit, BSTR));
            let repetition = t.Repetition().map_err(com)?;
            value!("repeat-interval", get!(repetition, Interval, BSTR));
            value!("repeat-duration", get!(repetition, Duration, BSTR));
            value!(
                "repeat-stop",
                get!(repetition, StopAtDurationEnd, VARIANT_BOOL).0
            );
            let t: ILogonTrigger = t.cast().map_err(com)?;
            value!("trigger-user", sid(&get!(t, UserId, BSTR).to_string())?);
            value!("trigger-delay", get!(t, Delay, BSTR));
            let s = definition.Settings().map_err(com)?;
            macro_rules! setting {
                ($method:ident,$kind:ty) => {
                    value!(stringify!($method), get!(s, $method, $kind))
                };
            }
            macro_rules! flag {
                ($method:ident) => {
                    value!(stringify!($method), get!(s, $method, VARIANT_BOOL).0)
                };
            }
            flag!(AllowDemandStart);
            flag!(StopIfGoingOnBatteries);
            flag!(DisallowStartIfOnBatteries);
            flag!(AllowHardTerminate);
            flag!(StartWhenAvailable);
            flag!(RunOnlyIfNetworkAvailable);
            flag!(Enabled);
            flag!(Hidden);
            flag!(RunOnlyIfIdle);
            flag!(WakeToRun);
            setting!(RestartInterval, BSTR);
            setting!(RestartCount, i32);
            setting!(ExecutionTimeLimit, BSTR);
            setting!(DeleteExpiredTaskAfter, BSTR);
            setting!(Priority, i32);
            value!(
                "MultipleInstances",
                get!(s, MultipleInstances, TASK_INSTANCES_POLICY).0
            );
            value!(
                "Compatibility",
                get!(s, Compatibility, TASK_COMPATIBILITY).0
            );
            let s2: ITaskSettings2 = s.cast().map_err(com)?;
            value!(
                "remote-app-session",
                get!(s2, DisallowStartOnRemoteAppSession, VARIANT_BOOL).0
            );
            value!(
                "unified-engine",
                get!(s2, UseUnifiedSchedulingEngine, VARIANT_BOOL).0
            );
            let s3: ITaskSettings3 = s.cast().map_err(com)?;
            value!("volatile", get!(s3, Volatile, VARIANT_BOOL).0);
            match s3.MaintenanceSettings() {
                Ok(maintenance) => {
                    value!("maintenance", "present");
                    value!("maintenance-period", get!(maintenance, Period, BSTR));
                    value!("maintenance-deadline", get!(maintenance, Deadline, BSTR));
                    value!(
                        "maintenance-exclusive",
                        get!(maintenance, Exclusive, VARIANT_BOOL).0
                    );
                }
                // S_OK with a null optional COM interface becomes Error::empty()
                // in windows-rs. Actual failed HRESULTs remain failures.
                Err(error) if error.code().0 == 0 => {
                    value!("maintenance", "absent")
                }
                Err(error) => return Err(com(error)),
            }
            let idle = s.IdleSettings().map_err(com)?;
            value!("idle-duration", get!(idle, IdleDuration, BSTR));
            value!("idle-wait", get!(idle, WaitTimeout, BSTR));
            value!("idle-stop", get!(idle, StopOnIdleEnd, VARIANT_BOOL).0);
            value!("idle-restart", get!(idle, RestartOnIdle, VARIANT_BOOL).0);
        }
        Ok(Self { values })
    }
    fn matches(&self, expected: &Self, deleting: bool) -> Result<()> {
        if self.values.len() != expected.values.len() {
            return Err(Error::Conflict);
        }
        for ((name, value), (expected_name, expected_value)) in
            self.values.iter().zip(&expected.values)
        {
            if name != expected_name
                || (value != expected_value && !(deleting && name == "Enabled" && value == "0"))
            {
                return Err(Error::Conflict);
            }
        }
        Ok(())
    }
}
struct Apartment;
impl Apartment {
    fn new() -> Result<Self> {
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(com)?;
        Ok(Self)
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        unsafe { CoUninitialize() }
    }
}
struct Scheduler {
    service: ITaskService,
    root: ITaskFolder,
}
impl Scheduler {
    fn connect() -> Result<Self> {
        unsafe {
            let service: ITaskService =
                CoCreateInstance(&TaskScheduler, None, CLSCTX_INPROC_SERVER).map_err(com)?;
            let empty = VARIANT::default();
            service
                .Connect(&empty, &empty, &empty, &empty)
                .map_err(com)?;
            let root = service.GetFolder(&BSTR::from("\\")).map_err(com)?;
            Ok(Self { service, root })
        }
    }
    fn desired(&self, record: &Registration) -> Result<ITaskDefinition> {
        unsafe {
            let d = self.service.NewTask(0).map_err(com)?;
            let principal = d.Principal().map_err(com)?;
            principal.SetId(&BSTR::from("Owner")).map_err(com)?;
            principal.SetUserId(&BSTR::from(&record.sid)).map_err(com)?;
            principal
                .SetLogonType(TASK_LOGON_INTERACTIVE_TOKEN)
                .map_err(com)?;
            principal.SetRunLevel(TASK_RUNLEVEL_LUA).map_err(com)?;
            d.SetData(&BSTR::from(record.installation.to_string()))
                .map_err(com)?;
            d.RegistrationInfo()
                .map_err(com)?
                .SetSource(&BSTR::from("lomiremote-login-v1"))
                .map_err(com)?;
            let triggers = d.Triggers().map_err(com)?;
            let t = triggers.Create(TASK_TRIGGER_LOGON).map_err(com)?;
            t.SetId(&BSTR::from("OwnerLogon")).map_err(com)?;
            t.SetEnabled(VARIANT_TRUE).map_err(com)?;
            t.SetExecutionTimeLimit(&BSTR::from("PT0S")).map_err(com)?;
            let t: ILogonTrigger = t.cast().map_err(com)?;
            t.SetUserId(&BSTR::from(&record.sid)).map_err(com)?;
            let actions = d.Actions().map_err(com)?;
            actions.SetContext(&BSTR::from("Owner")).map_err(com)?;
            let a = actions.Create(TASK_ACTION_EXEC).map_err(com)?;
            a.SetId(&BSTR::from("ManagedHost")).map_err(com)?;
            let a: IExecAction = a.cast().map_err(com)?;
            a.SetPath(&BSTR::from(text(record.helper.as_os_str())?))
                .map_err(com)?;
            a.SetArguments(&BSTR::from(record.arguments()?))
                .map_err(com)?;
            a.SetWorkingDirectory(&BSTR::from(text(
                record.helper.parent().ok_or(Error::Invalid)?.as_os_str(),
            )?))
            .map_err(com)?;
            let s = d.Settings().map_err(com)?;
            s.SetCompatibility(TASK_COMPATIBILITY_V2).map_err(com)?;
            s.SetAllowDemandStart(VARIANT_TRUE).map_err(com)?;
            s.SetMultipleInstances(TASK_INSTANCES_IGNORE_NEW)
                .map_err(com)?;
            s.SetExecutionTimeLimit(&BSTR::from("PT0S")).map_err(com)?;
            s.SetRestartCount(0).map_err(com)?;
            s.SetAllowHardTerminate(VARIANT_FALSE).map_err(com)?;
            s.SetStartWhenAvailable(VARIANT_FALSE).map_err(com)?;
            s.SetDisallowStartIfOnBatteries(VARIANT_FALSE)
                .map_err(com)?;
            s.SetStopIfGoingOnBatteries(VARIANT_FALSE).map_err(com)?;
            s.SetRunOnlyIfIdle(VARIANT_FALSE).map_err(com)?;
            s.SetRunOnlyIfNetworkAvailable(VARIANT_FALSE).map_err(com)?;
            s.SetWakeToRun(VARIANT_FALSE).map_err(com)?;
            s.SetHidden(VARIANT_TRUE).map_err(com)?;
            s.SetEnabled(VARIANT_TRUE).map_err(com)?;
            let idle = s.IdleSettings().map_err(com)?;
            idle.SetStopOnIdleEnd(VARIANT_FALSE).map_err(com)?;
            idle.SetRestartOnIdle(VARIANT_FALSE).map_err(com)?;
            Ok(d)
        }
    }
    fn folder(&self, record: &Registration, create: bool) -> Result<Option<ITaskFolder>> {
        unsafe {
            let folder = match self.root.GetFolder(&BSTR::from(record.folder())) {
                Ok(folder) => folder,
                Err(error) if absent(&error) && create => self
                    .root
                    .CreateFolder(
                        &BSTR::from(record.folder()),
                        &VARIANT::from(BSTR::from(sddl(&record.sid))),
                    )
                    .map_err(com)?,
                Err(error) if absent(&error) => return Ok(None),
                Err(error) => return Err(com(error)),
            };
            task_acl(
                &folder
                    .GetSecurityDescriptor(
                        OWNER_SECURITY_INFORMATION as i32 | DACL_SECURITY_INFORMATION as i32,
                    )
                    .map_err(com)?
                    .to_string(),
                &record.sid,
            )?;
            if folder.Path().map_err(com)? != record.folder() {
                return Err(Error::Conflict);
            }
            let tasks = folder.GetTasks(TASK_ENUM_HIDDEN.0).map_err(com)?;
            let count = tasks.Count().map_err(com)?;
            let children = folder.GetFolders(0).map_err(com)?;
            let child_count = children.Count().map_err(com)?;
            if count > 1 || child_count != 0 {
                return Err(Error::Conflict);
            }
            if count == 1
                && tasks
                    .get_Item(&VARIANT::from(1i32))
                    .map_err(com)?
                    .Name()
                    .map_err(com)?
                    != "Host"
            {
                return Err(Error::Conflict);
            }
            Ok(Some(folder))
        }
    }
    fn task(&self, record: &Registration, folder: &ITaskFolder) -> Result<Option<IRegisteredTask>> {
        unsafe {
            let task = match folder.GetTask(&BSTR::from("Host")) {
                Ok(task) => task,
                Err(error) if absent(&error) => return Ok(None),
                Err(error) => return Err(com(error)),
            };
            self.verify(record, &task)?;
            Ok(Some(task))
        }
    }
    fn verify(&self, record: &Registration, task: &IRegisteredTask) -> Result<()> {
        unsafe {
            record.pins()?;
            self.folder(record, false)?.ok_or(Error::Conflict)?;
            if task.Path().map_err(com)? != record.task_path() {
                return Err(Error::Conflict);
            }
            task_acl(
                &task
                    .GetSecurityDescriptor(
                        (OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION) as i32,
                    )
                    .map_err(com)?
                    .to_string(),
                &record.sid,
            )?;
            Definition::read(&task.Definition().map_err(com)?)?.matches(
                &Definition::read(&self.desired(record)?)?,
                record.phase == Phase::Deleting,
            )
        }
    }
}
fn sddl(sid: &str) -> String {
    format!("O:{sid}D:P(A;;GA;;;{sid})(A;;GA;;;SY)")
}
fn task_acl(value: &str, sid: &str) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::*;
    let mut descriptor = ptr::null_mut();
    if unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide(value).as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            ptr::null_mut(),
        )
    } == 0
    {
        return Err(Error::Conflict);
    }
    let _descriptor = super::Local(descriptor);
    let mut owner = ptr::null_mut();
    let mut defaulted = 0;
    if unsafe { GetSecurityDescriptorOwner(descriptor, &mut owner, &mut defaulted) } == 0
        || owner.is_null()
        || super::sid_text(owner).map_err(conflict)? != sid
    {
        return Err(Error::Conflict);
    }
    let (mut present, mut acl) = (0, ptr::null_mut());
    if unsafe { GetSecurityDescriptorDacl(descriptor, &mut present, &mut acl, &mut defaulted) } == 0
        || present == 0
        || acl.is_null()
    {
        return Err(Error::Conflict);
    }
    let mut own = false;
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceType == ACCESS_DENIED_ACE_TYPE as u8 {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
            || header.AceFlags as u32 & INHERIT_ONLY_ACE != 0
        {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let who = super::sid_text((&allowed.SidStart as *const u32).cast_mut().cast())
            .map_err(conflict)?;
        if who == sid {
            own = true
        } else if who != "S-1-5-18" && who != "S-1-5-32-544" {
            return Err(Error::Conflict);
        }
    }
    if !own {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn no_owner(record: &Registration) -> Result<()> {
    let lock = OwnerLock::acquire(&record.profile).map_err(conflict)?;
    drop(lock);
    Ok(())
}
fn instances(task: &IRegisteredTask) -> Result<i32> {
    unsafe { task.GetInstances(0).map_err(com)?.Count().map_err(com) }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Observation {
    idle: bool,
    failed: bool,
}
fn classify(state: TASK_STATE, count: i32, last: i32) -> Result<Observation> {
    if count < 0
        || !matches!(
            state,
            TASK_STATE_READY | TASK_STATE_DISABLED | TASK_STATE_RUNNING | TASK_STATE_QUEUED
        )
    {
        return Err(Error::NotReady);
    }
    Ok(Observation {
        idle: count == 0 && matches!(state, TASK_STATE_READY | TASK_STATE_DISABLED),
        failed: !matches!(last, 0 | 0x41303),
    })
}
fn observation(task: Option<&IRegisteredTask>) -> Result<Observation> {
    match task {
        None => Ok(Observation {
            idle: true,
            failed: false,
        }),
        Some(task) => unsafe {
            classify(
                task.State().map_err(com)?,
                instances(task)?,
                task.LastTaskResult().map_err(com)?,
            )
        },
    }
}

fn public_observation_error(error: Error) -> crate::service_observation::ServiceError {
    use crate::service_observation::ServiceError as PublicError;
    match error {
        Error::Invalid | Error::HelperMissing => PublicError::InvalidBinding,
        Error::Conflict => PublicError::Conflict,
        Error::Manager => PublicError::ManagerUnavailable,
        Error::Deadline => PublicError::OperationUncertain,
        Error::NotReady => PublicError::NotReady,
        Error::PrivilegedAccount | Error::SessionRequired => PublicError::Unsupported,
        Error::NotInstalled => PublicError::NotReady,
    }
}

fn manual_host_ready(profile: &Path, helper: &Path, sid: &str) -> bool {
    let Ok(mut client) = LocalClient::connect_with_timeout(profile, Duration::from_millis(500))
    else {
        return false;
    };
    let process = client.connection.stream._process.0;
    if super::process_sid(process).ok().as_deref() != Some(sid)
        || process_executable(process).ok().as_deref() != Some(helper)
    {
        return false;
    }
    let discovery = client.discovery().clone();
    client
        .request(LocalCall::Status {})
        .is_ok_and(|response| {
            matches!(response.result, Ok(LocalResult::Status(status)) if status.runtime_id == discovery.runtime_id)
        })
}

pub(crate) fn registered_helper(
    profile: &Path,
) -> std::result::Result<Option<PathBuf>, crate::service_observation::ServiceError> {
    let profile = normalized(profile)
        .map_err(conflict)
        .map_err(public_observation_error)?;
    let registration = registration_path(&profile).map_err(public_observation_error)?;
    match std::fs::symlink_metadata(&registration) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(crate::service_observation::ServiceError::Conflict),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(crate::service_observation::ServiceError::Conflict),
    }
    let directory = PrivateProfile::open(&registration, false)
        .map_err(conflict)
        .map_err(public_observation_error)?;
    let Some(record) =
        load::<Registration>(&directory, RECORD).map_err(public_observation_error)?
    else {
        return Ok(None);
    };
    record.check().map_err(public_observation_error)?;
    if record.profile != profile || record.registration != directory.path {
        return Err(crate::service_observation::ServiceError::Conflict);
    }
    record.pins().map_err(public_observation_error)?;
    Ok(Some(record.helper))
}

fn inspect_login_task(
    registration_path: PathBuf,
    expected_profile: PathBuf,
    expected_helper: PathBuf,
    expected_sid: String,
) -> Result<crate::service_observation::ServiceObservation> {
    use crate::service_observation::{
        AutostartState, BindingState, IpcReadiness, RegistrationState, RuntimeState,
        ServiceObservation,
    };

    let directory = PrivateProfile::open(&registration_path, false).map_err(conflict)?;
    let Some(record) = load::<Registration>(&directory, RECORD)? else {
        let ready = manual_host_ready(&expected_profile, &expected_helper, &expected_sid);
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: RegistrationState::Missing,
            runtime: if ready {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            autostart: AutostartState::Unknown,
            ipc: if ready {
                IpcReadiness::Ready
            } else {
                IpcReadiness::NotReady
            },
        });
    };
    record.check()?;
    if record.registration != directory.path
        || record.profile != expected_profile
        || record.helper != expected_helper
        || record.sid != expected_sid
    {
        return Err(Error::Conflict);
    }
    if record.phase != Phase::Registered {
        return Err(Error::Manager);
    }
    let _pins = record.pins()?;
    let worker_record = record.clone();
    thread::Builder::new()
        .name("lomi-login-observe".into())
        .spawn(move || {
            let _apartment = Apartment::new()?;
            let directory = PrivateProfile::open(&registration_path, false).map_err(conflict)?;
            if load::<Registration>(&directory, RECORD)?.as_ref() != Some(&worker_record) {
                return Err(Error::Conflict);
            }
            let scheduler = Scheduler::connect()?;
            let folder = scheduler
                .folder(&worker_record, false)?
                .ok_or(Error::Conflict)?;
            let task = scheduler
                .task(&worker_record, &folder)?
                .ok_or(Error::Conflict)?;
            scheduler.verify(&worker_record, &task)?;
            let state = unsafe { task.State().map_err(com)? };
            let instances = instances(&task)?;
            let last_result = unsafe { task.LastTaskResult().map_err(com)? };
            let task_observation = classify(state, instances, last_result)?;
            let deadline = Instant::now() + Duration::from_secs(2);
            let ipc_ready = bind(&worker_record, &directory, deadline).is_ok();
            let runtime = match state {
                TASK_STATE_RUNNING => RuntimeState::Running,
                TASK_STATE_QUEUED => RuntimeState::Starting,
                TASK_STATE_READY | TASK_STATE_DISABLED if task_observation.failed => {
                    RuntimeState::Failed
                }
                TASK_STATE_READY | TASK_STATE_DISABLED => RuntimeState::Stopped,
                _ => RuntimeState::Unknown,
            };
            Ok::<_, Error>(ServiceObservation {
                binding: BindingState::Matches,
                registration: RegistrationState::Present,
                runtime,
                autostart: if state == TASK_STATE_DISABLED {
                    AutostartState::Disabled
                } else {
                    AutostartState::Enabled
                },
                ipc: if ipc_ready {
                    IpcReadiness::Ready
                } else if runtime == RuntimeState::Unknown {
                    IpcReadiness::Unknown
                } else {
                    IpcReadiness::NotReady
                },
            })
        })
        .map_err(|_| Error::Manager)?
        .join()
        .map_err(|_| Error::Manager)?
}

/// Read-only inspection of the selected account's login task or manual Host.
/// It performs no profile/registration lock acquisition and never creates a
/// registration directory or task.
pub(crate) fn inspect_read_only(
    binding: &crate::service_observation::ServiceBinding,
) -> std::result::Result<
    crate::service_observation::ServiceObservation,
    crate::service_observation::ServiceError,
> {
    use crate::service_observation::{
        AutostartState, BindingState, IpcReadiness, RegistrationState, RuntimeState,
        ServiceAccount, ServiceError as PublicError, ServiceMode, ServiceObservation,
    };

    let ServiceAccount::Windows { sid, name } = &binding.account else {
        return Err(PublicError::InvalidBinding);
    };
    service::ordinary_identity().map_err(|error| public_observation_error(policy(error)))?;
    if super::current_sid()
        .map_err(conflict)
        .map_err(public_observation_error)?
        != *sid
        || service::account_sid(name)
            .map_err(policy)
            .map_err(public_observation_error)?
            != *sid
    {
        return Err(PublicError::Conflict);
    }
    let profile = normalized(&binding.profile)
        .map_err(conflict)
        .map_err(public_observation_error)?;
    let helper = normalized(&binding.executable)
        .map_err(conflict)
        .map_err(public_observation_error)?;
    service::pin(&helper, sid, true)
        .map_err(policy)
        .map_err(public_observation_error)?;
    let registration = registration_path(&profile).map_err(public_observation_error)?;
    if scm_path(&profile)
        .map_err(public_observation_error)?
        .join(RECORD)
        .try_exists()
        .map_err(conflict)
        .map_err(public_observation_error)?
    {
        return Err(PublicError::Conflict);
    }
    let exists = match std::fs::symlink_metadata(&registration) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(_) => return Err(PublicError::Conflict),
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => true,
        Ok(_) => return Err(PublicError::Conflict),
    };
    if exists {
        let result = inspect_login_task(registration, profile.clone(), helper.clone(), sid.clone())
            .map_err(public_observation_error)?;
        if binding.mode == ServiceMode::Manual && result.registration != RegistrationState::Missing
        {
            return Err(PublicError::Conflict);
        }
        if binding.mode == ServiceMode::Login {
            return Ok(result);
        }
    } else if binding.mode == ServiceMode::Login {
        let ready = manual_host_ready(&profile, &helper, sid);
        return Ok(ServiceObservation {
            binding: BindingState::Matches,
            registration: RegistrationState::Missing,
            runtime: if ready {
                RuntimeState::Running
            } else {
                RuntimeState::Stopped
            },
            autostart: AutostartState::Unknown,
            ipc: if ready {
                IpcReadiness::Ready
            } else {
                IpcReadiness::NotReady
            },
        });
    }
    let ready = manual_host_ready(&profile, &helper, sid);
    Ok(ServiceObservation {
        binding: BindingState::Matches,
        registration: RegistrationState::Missing,
        runtime: if ready {
            RuntimeState::Running
        } else {
            RuntimeState::Stopped
        },
        autostart: AutostartState::Disabled,
        ipc: if ready {
            IpcReadiness::Ready
        } else {
            IpcReadiness::NotReady
        },
    })
}
fn stopped(record: &Registration, directory: &PrivateProfile) -> Result<bool> {
    let marker: Option<Marker> = load(directory, MARKER)?;
    if let Some(marker) = marker {
        marker_matches(record, &marker)?;
        if live_process(&marker)?.is_some() {
            return Err(Error::NotReady);
        }
        no_owner(record)?;
        return Ok(marker.completion != Completion::Clean);
    }
    no_owner(record)?;
    Ok(false)
}
fn stop_host(
    record: &Registration,
    directory: &PrivateProfile,
    deadline: Instant,
    allow_failed: bool,
    mut observe: impl FnMut() -> Result<Observation>,
) -> Result<bool> {
    let mut host = loop {
        remaining(deadline)?;
        let observation = observe().map_err(|error| launch_error(LaunchStage::StopState, error))?;
        let stopped_state = stopped(record, directory);
        if let Ok(failed) = stopped_state
            && observation.idle
        {
            let failed = failed || observation.failed;
            return if failed && !allow_failed {
                Err(Error::NotReady)
            } else {
                Ok(failed)
            };
        }
        match bind(record, directory, deadline) {
            Ok(host) => break host,
            Err(Error::Conflict) => return Err(Error::Conflict),
            Err(error) if observation.idle => {
                return Err(launch_error(LaunchStage::StopBind, error));
            }
            Err(_) => {
                remaining(deadline)?;
                thread::sleep(Duration::from_millis(20));
            }
        }
    };
    // Do not reconnect between identity admission, Status and DaemonStop.
    let response = host
        .client
        .request_with_timeout(
            LocalCall::DaemonStop(LocalOperatorIntent {
                operator_intent: Confirmed::Confirmed,
            }),
            remaining(deadline)?.min(super::REQUEST_TIMEOUT),
        )
        .map_err(|_| Error::Deadline)?;
    if !matches!(response.result, Ok(LocalResult::Stopping {})) {
        return Err(Error::NotReady);
    }
    let process = host.client.connection.stream._process.0;
    loop {
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            break;
        }
        remaining(deadline)?;
        thread::sleep(Duration::from_millis(50));
    }
    let mut code = 1;
    if unsafe { GetExitCodeProcess(process, &mut code) } == 0 || code != 0 {
        return Err(Error::NotReady);
    }
    let next: Marker = load(directory, MARKER)?.ok_or(Error::Conflict)?;
    let mut expected = host.marker;
    expected.completion = Completion::Clean;
    if next != expected {
        return Err(Error::NotReady);
    }
    no_owner(record)?;
    while !observe()?.idle {
        remaining(deadline)?;
        thread::sleep(Duration::from_millis(20));
    }
    remaining(deadline)?;
    Ok(false)
}
fn ensure_record(directory: &PrivateProfile, record: &Registration) -> Result<()> {
    if load::<Registration>(directory, RECORD)?.as_ref() != Some(record) {
        return Err(Error::Conflict);
    }
    record.pins()?;
    Ok(())
}
fn execute(
    profile: PathBuf,
    helper: PathBuf,
    operation: String,
    account: Option<String>,
) -> Result<String> {
    service::ordinary_identity().map_err(policy)?;
    if !matches!(
        operation.as_str(),
        "install" | "start" | "stop" | "restart" | "status" | "uninstall"
    ) {
        return Err(Error::Invalid);
    }
    let sid = current_sid().map_err(conflict)?;
    let registration = registration_path(&profile)?;
    if scm_path(&profile)?
        .join(RECORD)
        .try_exists()
        .map_err(conflict)?
    {
        return Err(Error::Conflict);
    }
    if operation != "install" && !registration.try_exists().map_err(conflict)? {
        return Err(Error::NotInstalled);
    }
    if operation == "install" {
        let account = account.ok_or(Error::Invalid)?;
        if service::account_sid(&account).map_err(policy)? != sid {
            return Err(Error::Conflict);
        }
        if !helper.try_exists().map_err(conflict)? {
            return Err(Error::HelperMissing);
        }
        service::pin(&helper, &sid, true).map_err(policy)?;
        PrivateProfile::open(&profile, true).map_err(conflict)?;
    }
    let lock = OwnerLock::acquire(&registration).map_err(conflict)?;
    let directory = lock.profile();
    let mut record: Registration = match load(directory, RECORD)? {
        Some(record) => record,
        None if operation == "install" => {
            let record = Registration {
                version: 1,
                installation: Uuid::new_v4(),
                sid,
                profile: profile.clone(),
                helper: helper.clone(),
                registration,
                phase: Phase::Intent,
            };
            record.check()?;
            atomic(directory, RECORD, None, &record)?;
            record
        }
        None => return Err(Error::NotInstalled),
    };
    record.check()?;
    if record.profile != profile || record.helper != helper {
        return Err(Error::Conflict);
    }
    let _pins = record.pins()?;
    let _apartment = Apartment::new()?;
    let scheduler = Scheduler::connect()?;
    let mut folder = scheduler.folder(&record, operation == "install")?;
    let mut task = if let Some(folder) = &folder {
        scheduler.task(&record, folder)?
    } else {
        None
    };
    if operation == "install" {
        if record.phase == Phase::Deleting {
            return Err(Error::Conflict);
        }
        if record.phase == Phase::SetupRequired {
            return Err(Error::Manager);
        }
        if task.is_none() {
            if record.phase != Phase::Intent {
                return Err(Error::Conflict);
            }
            ensure_record(directory, &record)?;
            let desired = scheduler.desired(&record)?;
            let (created, warning) =
                register(folder.as_ref().ok_or(Error::Conflict)?, &record, &desired)?;
            scheduler.verify(&record, &created)?;
            if warning {
                let old = record.clone();
                record.phase = Phase::SetupRequired;
                atomic(directory, RECORD, Some(&old), &record)?;
                return Err(Error::Manager);
            }
            task = Some(created);
        }
        let task = task.as_ref().ok_or(Error::Conflict)?;
        scheduler.verify(&record, task)?;
        ensure_record(directory, &record)?;
        if record.phase == Phase::Intent {
            let old = record.clone();
            record.phase = Phase::Registered;
            atomic(directory, RECORD, Some(&old), &record)?;
        }
        return Ok("Login autostart installed; host not started.".into());
    }
    if operation == "uninstall" {
        if record.phase != Phase::Deleting {
            let old = record.clone();
            record.phase = Phase::Deleting;
            atomic(directory, RECORD, Some(&old), &record)?;
        }
        ensure_record(directory, &record)?;
        if let Some(task) = &task {
            scheduler.verify(&record, task)?;
            unsafe { task.SetEnabled(VARIANT_FALSE) }.map_err(com)?;
            scheduler.verify(&record, task)?;
        }
        let failed = stop_host(&record, directory, Instant::now() + WAIT, true, || {
            observation(task.as_ref())
        })?;
        if let Some(task) = task.take() {
            scheduler.verify(&record, &task)?;
            ensure_record(directory, &record)?;
            if instances(&task)? != 0 {
                return Err(Error::Deadline);
            }
            unsafe {
                folder
                    .as_ref()
                    .ok_or(Error::Conflict)?
                    .DeleteTask(&BSTR::from("Host"), 0)
            }
            .map_err(com)?;
            drop(task);
        }
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(current) = &folder
                && scheduler.task(&record, current)?.is_some()
            {
                remaining(deadline)?;
                thread::sleep(Duration::from_millis(50));
                continue;
            }
            break;
        }
        if let Some(current) = folder.take() {
            let tasks = unsafe { current.GetTasks(TASK_ENUM_HIDDEN.0) }.map_err(com)?;
            let count = unsafe { tasks.Count() }.map_err(com)?;
            if count != 0 {
                return Err(Error::Conflict);
            }
            drop(current);
            ensure_record(directory, &record)?;
            unsafe { scheduler.root.DeleteFolder(&BSTR::from(record.folder()), 0) }.map_err(com)?;
        }
        if scheduler.folder(&record, false)?.is_some() {
            return Err(Error::Deadline);
        }
        if let Some(marker) = load::<Marker>(directory, MARKER)? {
            marker_matches(&record, &marker)?;
            remove(directory, MARKER, &marker)?;
        }
        remove(directory, RECORD, &record)?;
        return Ok(if failed {
            "Login autostart uninstalled after previous host failure; data preserved."
        } else {
            "Login autostart uninstalled; data preserved."
        }
        .into());
    }
    if matches!(record.phase, Phase::Intent | Phase::SetupRequired) {
        return Err(Error::Manager);
    }
    if record.phase != Phase::Registered {
        return Err(Error::Conflict);
    }
    let task = task.ok_or(Error::Conflict)?;
    let deadline = Instant::now() + WAIT;
    if operation == "status" {
        if bind(&record, directory, deadline).is_ok() {
            return Ok("Login host running.".into());
        }
        let failed = stopped(&record, directory)?;
        let observation = observation(Some(&task))?;
        if !observation.idle {
            return Err(Error::NotReady);
        }
        return if failed || observation.failed {
            Err(Error::NotReady)
        } else {
            Ok("Login host stopped.".into())
        };
    }
    let mut previous_failure = false;
    if matches!(operation.as_str(), "stop" | "restart") {
        scheduler.verify(&record, &task)?;
        ensure_record(directory, &record)?;
        previous_failure = stop_host(&record, directory, deadline, operation == "restart", || {
            observation(Some(&task))
        })?;
        if operation == "stop" {
            return Ok("Login host stopped.".into());
        }
    }
    if operation == "start" && bind(&record, directory, deadline).is_ok() {
        return Ok("Login host running.".into());
    }
    stopped(&record, directory).map_err(|error| launch_error(LaunchStage::PreIdle, error))?;
    if !observation(Some(&task))
        .map_err(|error| launch_error(LaunchStage::PreIdle, error))?
        .idle
    {
        return Err(launch_error(LaunchStage::PreIdle, Error::NotReady));
    }
    scheduler.verify(&record, &task)?;
    ensure_record(directory, &record)?;
    let old: Option<Marker> = load(directory, MARKER)?;
    // One successful Run is the only admission attempt. In particular, a
    // transient READY state below must not cause a second helper launch.
    let instance = unsafe { task.Run(&VARIANT::default()) }
        .map_err(|error| launch_error(LaunchStage::Admission, com(error)))?;
    if unsafe { instance.Path() }
        .map_err(|error| launch_error(LaunchStage::InstanceIdentity, com(error)))?
        != record.task_path()
    {
        return Err(launch_error(LaunchStage::InstanceIdentity, Error::Conflict));
    }
    loop {
        remaining(deadline).map_err(|error| launch_error(LaunchStage::Readiness, error))?;
        let readiness = match bind(&record, directory, deadline) {
            Ok(bound) if old.as_ref().is_none_or(|old| old.run != bound.marker.run) => {
                LaunchObservation::NewGenerationReady
            }
            Err(Error::Conflict) => return Err(launch_error(LaunchStage::Bind, Error::Conflict)),
            _ => {
                let marker: Option<Marker> = load(directory, MARKER)
                    .map_err(|error| launch_error(LaunchStage::Marker, error))?;
                if let Some(marker) = &marker {
                    marker_matches(&record, marker)
                        .map_err(|error| launch_error(LaunchStage::Marker, error))?;
                }
                launch_observation(old.as_ref(), marker.as_ref())
            }
        };
        match start_policy::decide(readiness, Instant::now() >= deadline) {
            Decision::Ready => {
                scheduler.verify(&record, &task)?;
                return Ok(if previous_failure {
                    "Login host running after previous host failure."
                } else {
                    "Login host running."
                }
                .into());
            }
            Decision::NotReady => {
                return Err(launch_error(LaunchStage::Readiness, Error::NotReady));
            }
            Decision::Deadline => {
                return Err(launch_error(LaunchStage::Readiness, Error::Deadline));
            }
            Decision::Wait => {}
        }
        unsafe { instance.Refresh() }
            .map_err(|error| launch_error(LaunchStage::Refresh, com(error)))?;
        // Refresh/State COM failures remain closed. State itself (including
        // READY/UNKNOWN) is not authoritative after successful admission; only
        // a fresh identity-bound IPC status or a fresh completed marker is.
        let _ = unsafe { instance.State() }
            .map_err(|error| launch_error(LaunchStage::State, com(error)))?;
        thread::sleep(Duration::from_millis(50));
    }
}
/// Local COM objects remain on this owned apartment thread; no credential input.
/// WAIT bounds polling/IPC, not synchronous COM/RPC latency. This call joins its
/// worker and never detaches a mutator. Interrupted/unconfirmed OS operations
/// retain durable intent for reconciliation; there is no hard wall-clock claim.
pub fn run(
    profile: &Path,
    helper: &Path,
    operation: &str,
    account: Option<&str>,
) -> Result<String> {
    service::ordinary_identity().map_err(policy)?;
    let profile = normalized(profile).map_err(conflict)?;
    let helper = normalized(helper).map_err(conflict)?;
    if operation == "install" {
        let account = account.ok_or(Error::Invalid)?;
        if service::account_sid(account).map_err(policy)? != current_sid().map_err(conflict)? {
            return Err(Error::Conflict);
        }
    }
    let selection = selection_lock(&profile)?;
    let operation = operation.to_owned();
    let account = account.map(str::to_owned);
    thread::Builder::new()
        .name("lomi-login-manager".into())
        .spawn(move || {
            let _selection = selection;
            execute(profile, helper, operation, account)
        })
        .map_err(|_| Error::Manager)?
        .join()
        .map_err(|_| Error::Manager)?
}
fn gui_header(header: &[u8; 94]) -> bool {
    &header[..4] == b"PE\0\0"
        && matches!(u16::from_le_bytes([header[24], header[25]]), 0x10b | 0x20b)
        && u16::from_le_bytes([header[92], header[93]]) == 2
}
// Preserve positive warning HRESULTs: the generated binding otherwise discards
// them. A created-but-warning task stays setup-required, never readiness success.
fn register(
    folder: &ITaskFolder,
    record: &Registration,
    definition: &ITaskDefinition,
) -> Result<(IRegisteredTask, bool)> {
    let name = BSTR::from("Host");
    let user = VARIANT::from(BSTR::from(&record.sid));
    let password = VARIANT::default();
    let acl = VARIANT::from(BSTR::from(sddl(&record.sid)));
    let mut output = ptr::null_mut();
    let hr = unsafe {
        (Interface::vtable(folder).RegisterTaskDefinition)(
            folder.as_raw(),
            mem::transmute_copy(&name),
            definition.as_raw(),
            TASK_CREATE.0,
            mem::transmute_copy(&user),
            mem::transmute_copy(&password),
            TASK_LOGON_INTERACTIVE_TOKEN,
            mem::transmute_copy(&acl),
            &mut output,
        )
    };
    if hr.is_err() {
        if !output.is_null() {
            drop(unsafe { IRegisteredTask::from_raw(output) })
        }
        return Err(com(windows::core::Error::from(hr)));
    }
    if output.is_null() {
        return Err(Error::Manager);
    }
    Ok((unsafe { IRegisteredTask::from_raw(output) }, hr.0 != 0))
}
