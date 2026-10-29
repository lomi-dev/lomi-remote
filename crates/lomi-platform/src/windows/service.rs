//! Exact-current-account SCM management; no credentials, account provisioning, or IPC impersonation.
use super::{
    Handle, LocalClient, OwnerLock, PrivateProfile, current_sid, normalized, open_path,
    open_regular, security, validate_security, wide,
};
use lomi_remote_protocol::ipc::{LocalCall, LocalResult};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::{Read, Write},
    mem,
    os::windows::io::FromRawHandle,
    path::{Component, Path, PathBuf},
    ptr, thread,
    time::{Duration, Instant},
};
use uuid::Uuid;
use windows_service::{
    service::{
        Service, ServiceAccess, ServiceConfig, ServiceErrorControl, ServiceExitCode, ServiceInfo,
        ServiceStartType, ServiceState, ServiceType,
    },
    service_manager::{ServiceManager, ServiceManagerAccess},
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
const RECORD: &str = "registration.json";
const LIMIT: u64 = 32 * 1024;
const WAIT: Duration = Duration::from_secs(45);
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Invalid,
    Conflict,
    Manager,
    Deadline,
    NotReady,
    Unimplemented,
    CredentialsRequired,
    PrivilegedAccount,
    NotInstalled,
    AdministratorManaged,
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "SERVICE_INVALID_CONFIGURATION",
            Self::Conflict => "SERVICE_OWNERSHIP_CONFLICT",
            Self::Manager => "SERVICE_MANAGER_UNAVAILABLE",
            Self::Deadline => "SERVICE_OPERATION_UNCERTAIN",
            Self::NotReady => "SERVICE_NOT_READY",
            Self::Unimplemented => "SERVICE_ADAPTER_UNIMPLEMENTED_FOR_MODE_OR_ACCOUNT",
            Self::CredentialsRequired => "SERVICE_OS_CREDENTIALS_OR_LOGON_RIGHT_REQUIRED",
            Self::PrivilegedAccount => "SERVICE_DEDICATED_NONADMIN_ACCOUNT_REQUIRED",
            Self::NotInstalled => "SERVICE_NOT_INSTALLED",
            Self::AdministratorManaged => "SERVICE_ADMINISTRATOR_MANAGED_ACCOUNT_ADAPTER_REQUIRED",
        })
    }
}
impl std::error::Error for Error {}
type Result<T> = std::result::Result<T, Error>;
fn invalid(_: super::Error) -> Error {
    Error::Conflict
}
pub(super) fn scm(error: windows_service::Error) -> Error {
    match error {
        windows_service::Error::Winapi(ref e) if e.raw_os_error() == Some(1072) => Error::Deadline,
        windows_service::Error::Winapi(ref e)
            if matches!(e.raw_os_error(), Some(1069 | 1079 | 1057)) =>
        {
            Error::CredentialsRequired
        }
        _ => Error::Manager,
    }
}
pub(super) fn missing(error: &windows_service::Error) -> bool {
    matches!(error,windows_service::Error::Winapi(e) if e.raw_os_error()==Some(1060))
}
pub(super) fn deleting(error: &windows_service::Error) -> bool {
    matches!(error,windows_service::Error::Winapi(e) if e.raw_os_error()==Some(1072))
}
pub(super) fn text(value: &OsStr) -> Result<String> {
    let s = value.to_str().ok_or(Error::Invalid)?;
    if s.is_empty() || s.len() > 4096 || s.chars().any(char::is_control) {
        return Err(Error::Invalid);
    }
    Ok(s.to_owned())
}
pub(super) fn account_sid(account: &str) -> Result<String> {
    let account = wide(account);
    let (mut size, mut domain_size, mut kind) = (0, 0, 0);
    unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            &mut domain_size,
            &mut kind,
        );
    }
    if size == 0 || size > 4096 || domain_size > 4096 {
        return Err(Error::Invalid);
    }
    let mut sid = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    let mut domain = vec![0u16; domain_size as usize];
    if unsafe {
        LookupAccountNameW(
            ptr::null(),
            account.as_ptr(),
            sid.as_mut_ptr().cast(),
            &mut size,
            domain.as_mut_ptr(),
            &mut domain_size,
            &mut kind,
        )
    } == 0
    {
        return Err(Error::Invalid);
    }
    super::sid_text(sid.as_mut_ptr().cast()).map_err(invalid)
}
fn unimpersonated() -> Result<()> {
    let mut token = ptr::null_mut();
    if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } != 0 {
        unsafe { CloseHandle(token) };
        return Err(Error::Conflict);
    }
    if unsafe { GetLastError() } != ERROR_NO_TOKEN {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(super) fn ordinary_identity() -> Result<()> {
    unimpersonated()?;
    let sid = current_sid().map_err(invalid)?;
    if !sid.starts_with("S-1-5-21-") {
        return Err(Error::PrivilegedAccount);
    }
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(Error::Invalid);
    }
    let token = Handle::new(token).map_err(|_| Error::Conflict)?;
    let mut elevation: TOKEN_ELEVATION = unsafe { mem::zeroed() };
    let mut returned = 0;
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(Error::Invalid);
    }
    if elevation.TokenIsElevated != 0 {
        return Err(Error::PrivilegedAccount);
    }
    let mut size = 0;
    unsafe { GetTokenInformation(token.0, TokenGroups, ptr::null_mut(), 0, &mut size) };
    if size == 0 || size > 65536 {
        return Err(Error::Invalid);
    }
    let mut groups = vec![0usize; (size as usize).div_ceil(mem::size_of::<usize>())];
    if unsafe {
        GetTokenInformation(
            token.0,
            TokenGroups,
            groups.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(Error::Invalid);
    }
    let header = unsafe { &*groups.as_ptr().cast::<TOKEN_GROUPS>() };
    if header.GroupCount > 4096 {
        return Err(Error::Invalid);
    }
    let entries =
        unsafe { std::slice::from_raw_parts(header.Groups.as_ptr(), header.GroupCount as usize) };
    for group in entries {
        if super::sid_text(group.Sid).map_err(invalid)? == "S-1-5-32-544" {
            return Err(Error::PrivilegedAccount);
        }
    }
    if super::service_admin::is_managed_for_current_sid(&sid).map_err(|_| Error::Conflict)? {
        return Err(Error::AdministratorManaged);
    }
    Ok(())
}
// Match windows-service 0.8.1's UTF-16 command construction exactly. The parser
// also roundtrips every argument; query_config.executable_path is the WHOLE command.
pub(super) fn quote(value: &str) -> Result<String> {
    if value.contains('\0') {
        return Err(Error::Invalid);
    }
    if !value.is_empty()
        && !value
            .chars()
            .any(|c| matches!(c, '"' | ' ' | '\n' | '\t' | '\u{b}'))
    {
        return Ok(value.to_owned());
    }
    let mut out = String::from("\"");
    let mut slashes = 0;
    for c in value.chars() {
        if c == '\\' {
            slashes += 1;
            continue;
        }
        out.extend(std::iter::repeat_n(
            '\\',
            if c == '"' { slashes * 2 + 1 } else { slashes },
        ));
        slashes = 0;
        out.push(c)
    }
    out.extend(std::iter::repeat_n('\\', slashes * 2));
    out.push('"');
    Ok(out)
}
pub(super) fn parse(command: &str) -> Result<Vec<String>> {
    let chars: Vec<char> = command.chars().collect();
    let mut i = 0;
    let mut args = Vec::new();
    while i < chars.len() {
        while i < chars.len() && matches!(chars[i], ' ' | '\t') {
            i += 1
        }
        if i == chars.len() {
            break;
        }
        let mut arg = String::new();
        let mut quoted = false;
        while i < chars.len() {
            if !quoted && matches!(chars[i], ' ' | '\t') {
                break;
            }
            let mut slashes = 0;
            while i < chars.len() && chars[i] == '\\' {
                slashes += 1;
                i += 1
            }
            if i < chars.len() && chars[i] == '"' {
                arg.extend(std::iter::repeat_n('\\', slashes / 2));
                if slashes % 2 == 1 {
                    arg.push('"')
                } else {
                    quoted = !quoted
                }
                i += 1
            } else {
                arg.extend(std::iter::repeat_n('\\', slashes));
                if !quoted && i < chars.len() && matches!(chars[i], ' ' | '\t') {
                    break;
                }
                if i < chars.len() {
                    arg.push(chars[i]);
                    i += 1
                }
            }
        }
        if quoted {
            return Err(Error::Invalid);
        }
        args.push(arg);
    }
    Ok(args)
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) enum Phase {
    Intent,
    CredentialsRequired,
    Registered,
    Deleting,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Registration {
    pub(super) version: u8,
    pub(super) operator_sid: String,
    pub(super) account_sid: String,
    pub(super) account: String,
    pub(super) profile: String,
    pub(super) executable: String,
    pub(super) name: String,
    pub(super) command: String,
    pub(super) mode: String,
    pub(super) phase: Phase,
    pub(super) fixture: bool,
}
impl Registration {
    fn arguments(&self) -> Vec<String> {
        vec![
            self.executable.clone(),
            "--internal-scm".into(),
            self.name.clone(),
            self.profile.clone(),
        ]
    }
    pub(super) fn command(&self) -> Result<String> {
        let args = self.arguments();
        let value = args
            .iter()
            .map(|a| quote(a))
            .collect::<Result<Vec<_>>>()?
            .join(" ");
        if value.len() > 4096 || parse(&value)? != args {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
    pub(super) fn info(&self) -> ServiceInfo {
        ServiceInfo {
            name: OsString::from(&self.name),
            display_name: OsString::from(&self.name),
            service_type: ServiceType::OWN_PROCESS,
            start_type: if self.mode == "boot" {
                ServiceStartType::AutoStart
            } else {
                ServiceStartType::OnDemand
            },
            error_control: ServiceErrorControl::Normal,
            executable_path: PathBuf::from(&self.executable),
            launch_arguments: self
                .arguments()
                .into_iter()
                .skip(1)
                .map(OsString::from)
                .collect(),
            dependencies: vec![],
            account_name: Some(OsString::from(&self.account)),
            account_password: None,
        }
    }
    pub(super) fn matches(&self, config: &ServiceConfig) -> Result<()> {
        self.matches_config(config, false)
    }
    // SCM changes a marked service to Disabled while retained handles keep it
    // queryable. This allowance is only for read-only deletion observation.
    pub(super) fn matches_config(&self, config: &ServiceConfig, pending: bool) -> Result<()> {
        if config.service_type != ServiceType::OWN_PROCESS
            || (config.start_type != self.info().start_type
                && !(pending && config.start_type == ServiceStartType::Disabled))
            || config.error_control != ServiceErrorControl::Normal
            || !config.dependencies.is_empty()
            || config.display_name != OsStr::new(&self.name)
            || config
                .load_order_group
                .as_ref()
                .is_some_and(|s| !s.is_empty())
        {
            return Err(Error::Conflict);
        }
        let raw = text(config.executable_path.as_os_str())?;
        if raw != self.command
            || parse(&raw)? != self.arguments()
            || account_sid(&text(
                config.account_name.as_deref().ok_or(Error::Conflict)?,
            )?)? != self.account_sid
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
// Path pinning alone does not prevent in-place executable writes. Reject
// mapped file-specific write rights, not only GENERIC_WRITE and DELETE.
fn executable_security(handle: HANDLE, sid: &str) -> Result<()> {
    use windows_sys::Win32::Security::Authorization::*;
    let (mut descriptor, mut acl) = (ptr::null_mut(), ptr::null_mut());
    if unsafe {
        GetSecurityInfo(
            handle,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut acl,
            ptr::null_mut(),
            &mut descriptor,
        )
    } != ERROR_SUCCESS
        || acl.is_null()
    {
        return Err(Error::Conflict);
    }
    let _descriptor = super::Local(descriptor);
    for index in 0..unsafe { (*acl).AceCount } {
        let mut ace = ptr::null_mut();
        if unsafe { GetAce(acl, index as u32, &mut ace) } == 0 {
            return Err(Error::Conflict);
        }
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        if header.AceFlags as u32 & INHERIT_ONLY_ACE != 0
            || header.AceType == ACCESS_DENIED_ACE_TYPE as u8
        {
            continue;
        }
        if header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8 {
            return Err(Error::Conflict);
        }
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let who = super::sid_text((&allowed.SidStart as *const u32).cast_mut().cast())
            .map_err(invalid)?;
        let writes = FILE_WRITE_DATA
            | FILE_APPEND_DATA
            | FILE_WRITE_EA
            | FILE_WRITE_ATTRIBUTES
            | WRITE_DAC
            | WRITE_OWNER
            | DELETE
            | GENERIC_WRITE
            | GENERIC_ALL;
        if !super::trusted_sid(&who, sid) && allowed.Mask & writes != 0 {
            return Err(Error::Conflict);
        }
    }
    Ok(())
}
pub(super) struct Pinned {
    _directories: Vec<Handle>,
    pub(super) _file: Option<Handle>,
}
pub(super) fn pin(path: &Path, sid: &str, file: bool) -> Result<Pinned> {
    let path = normalized(path).map_err(invalid)?;
    let mut built = PathBuf::new();
    let mut directories = Vec::new();
    let mut pinned = None;
    for part in path.components() {
        built.push(part.as_os_str());
        if matches!(part, Component::Prefix(_)) {
            continue;
        }
        let directory = !file || built != path;
        let h = open_path(&built, false, false, directory, sid).map_err(invalid)?;
        validate_security(h.0, sid, false, directory).map_err(invalid)?;
        if directory {
            directories.push(h)
        } else {
            executable_security(h.0, sid)?;
            pinned = Some(h)
        }
    }
    if normalized(&path.canonicalize().map_err(|_| Error::Conflict)?).map_err(invalid)? != path {
        return Err(Error::Conflict);
    }
    Ok(Pinned {
        _directories: directories,
        _file: pinned,
    })
}
struct Context {
    profile: PathBuf,
    executable: PathBuf,
    registration: PathBuf,
    operator_sid: String,
    account_sid: String,
    account: Option<String>,
    fixture: bool,
    name: Option<String>,
    wait: Duration,
    create_profile: bool,
    #[cfg(feature = "service-fixture")]
    fault: Option<&'static str>,
}
impl Context {
    fn pins(&self) -> Result<(Pinned, Option<PrivateProfile>)> {
        let binary = pin(&self.executable, &self.account_sid, true)?;
        if self.fixture {
            let parent = self.profile.parent().ok_or(Error::Invalid)?;
            let _ = pin(parent, &self.account_sid, false)?;
            Ok((binary, None))
        } else {
            Ok((
                binary,
                Some(PrivateProfile::open(&self.profile, self.create_profile).map_err(invalid)?),
            ))
        }
    }
    fn check(&self, record: &Registration) -> Result<()> {
        if record.version != 1
            || record.operator_sid != self.operator_sid
            || record.account_sid != self.account_sid
            || record.profile != text(self.profile.as_os_str())?
            || record.executable != text(self.executable.as_os_str())?
            || record.command != record.command()?
            || record.fixture != self.fixture
            || !matches!(record.mode.as_str(), "boot" | "manual")
            || (self.fixture
                && (record.mode != "manual" || Some(&record.name) != self.name.as_ref()))
            || (!self.fixture && record.mode != "boot")
            || !record.name.starts_with(if self.fixture {
                "LomiProductService-"
            } else {
                "LomiRemote-"
            })
            || Uuid::parse_str(record.name.split_once('-').ok_or(Error::Conflict)?.1).is_err()
            || account_sid(&text(OsStr::new(&record.account))?)? != record.account_sid
        {
            return Err(Error::Conflict);
        }
        if let Some(account) = &self.account
            && account_sid(account)? != record.account_sid
        {
            return Err(Error::Conflict);
        }
        Ok(())
    }
}
struct Store {
    lock: OwnerLock,
}
impl Store {
    fn open(path: &Path) -> Result<Self> {
        Ok(Self {
            lock: OwnerLock::acquire(path).map_err(invalid)?,
        })
    }
    fn check(&self) -> Result<()> {
        self.lock.profile.check_current().map_err(invalid)
    }
    fn load(&self) -> Result<Option<Registration>> {
        self.check()?;
        let path = self.lock.profile.path.join(RECORD);
        let file = match open_regular(&path, false, false, &self.lock.profile.sid) {
            Ok(file) => file,
            Err(super::Error::Io(e)) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(None);
            }
            Err(_) => return Err(Error::Conflict),
        };
        if file.metadata().map_err(|_| Error::Conflict)?.len() > LIMIT {
            return Err(Error::Conflict);
        }
        let mut bytes = Vec::new();
        file.take(LIMIT + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::Conflict)?;
        Ok(Some(
            serde_json::from_slice(&bytes).map_err(|_| Error::Conflict)?,
        ))
    }
    fn write(&self, old: Option<&Registration>, record: &Registration) -> Result<()> {
        self.check()?;
        if self.load()?.as_ref() != old {
            return Err(Error::Conflict);
        }
        let profile = &self.lock.profile;
        let temporary = profile.path.join(format!(".intent-{}", Uuid::new_v4()));
        let sd = security(&profile.sid, false).map_err(invalid)?;
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
            return Err(Error::Conflict);
        }
        let mut file = unsafe { File::from_raw_handle(raw) };
        let bytes = serde_json::to_vec(record).map_err(|_| Error::Invalid)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Deadline)?;
        drop(file);
        self.check()?;
        if unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(profile.path.join(RECORD)).as_ptr(),
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
    fn remove(&self, record: &Registration) -> Result<()> {
        self.check()?;
        if self.load()?.as_ref() != Some(record) {
            return Err(Error::Conflict);
        }
        if unsafe { DeleteFileW(wide(self.lock.profile.path.join(RECORD)).as_ptr()) } == 0 {
            return Err(Error::Deadline);
        }
        Ok(())
    }
}
pub(super) fn open(
    manager: &ServiceManager,
    record: &Registration,
    access: ServiceAccess,
) -> Result<Option<Service>> {
    match manager.open_service(
        &record.name,
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | access,
    ) {
        Ok(s) => {
            let config = s.query_config().map_err(scm)?;
            if record.phase == Phase::Deleting && config.start_type == ServiceStartType::Disabled {
                record.matches_config(&config, true)?;
                return Err(Error::Deadline);
            }
            record.matches(&config)?;
            Ok(Some(s))
        }
        Err(e) if missing(&e) => Ok(None),
        Err(e) if deleting(&e) => Err(Error::Deadline),
        Err(e) => Err(scm(e)),
    }
}
pub(super) fn recovery(service: &Service) -> Result<()> {
    let actions = service.get_failure_actions().map_err(scm)?;
    if service
        .get_failure_actions_on_non_crash_failures()
        .map_err(scm)?
        || actions.actions.is_some_and(|a| !a.is_empty())
        || actions.command.is_some_and(|s| !s.is_empty())
        || actions.reboot_msg.is_some_and(|s| !s.is_empty())
    {
        return Err(Error::Conflict);
    }
    Ok(())
}
fn validate(
    context: &Context,
    store: &Store,
    record: &Registration,
    service: &Service,
) -> Result<()> {
    store.check()?;
    context.check(record)?;
    let _pins = context.pins()?;
    record.matches(&service.query_config().map_err(scm)?)?;
    recovery(service)?;
    Ok(())
}
pub(super) fn wait(
    service: &Service,
    wanted: ServiceState,
    deadline: Instant,
) -> Result<windows_service::service::ServiceStatus> {
    loop {
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        let status = service.query_status().map_err(scm)?;
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        if status.current_state == wanted {
            return Ok(status);
        }
        if wanted == ServiceState::Running && status.current_state == ServiceState::Stopped {
            return Err(
                if matches!(status.exit_code, ServiceExitCode::Win32(1069)) {
                    Error::CredentialsRequired
                } else {
                    Error::NotReady
                },
            );
        }
        if Instant::now() >= deadline {
            return Err(Error::Deadline);
        }
        thread::sleep(Duration::from_millis(50));
    }
}
fn ready(context: &Context, service: &Service, deadline: Instant) -> Result<()> {
    let status = wait(service, ServiceState::Running, deadline)?;
    if context.fixture {
        return Ok(());
    }
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(Error::Deadline);
    }
    let mut client =
        LocalClient::connect_with_timeout(&context.profile, remaining.min(Duration::from_secs(1)))
            .map_err(|_| Error::NotReady)?;
    let peer = unsafe { GetProcessId(client.connection.stream._process.0) };
    if Some(peer) != status.process_id || peer == 0 {
        return Err(Error::Conflict);
    }
    if !matches!(client.request_with_timeout(LocalCall::Status{},deadline.saturating_duration_since(Instant::now()).min(super::REQUEST_TIMEOUT)),Ok(response)if matches!(response.result,Ok(LocalResult::Status(_))))
    {
        return Err(Error::NotReady);
    }
    let after = service.query_status().map_err(scm)?;
    if Instant::now() >= deadline
        || after.current_state != ServiceState::Running
        || after.process_id != Some(peer)
    {
        return Err(Error::NotReady);
    }
    Ok(())
}
fn stop(
    context: &Context,
    store: &Store,
    record: &Registration,
    service: &Service,
    deadline: Instant,
    allow_failed_stopped: bool,
) -> Result<bool> {
    validate(context, store, record, service)?;
    let status = service.query_status().map_err(scm)?;
    if status.current_state == ServiceState::Stopped {
        let failed = !matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077));
        return if !failed || allow_failed_stopped {
            Ok(failed)
        } else {
            Err(Error::NotReady)
        };
    }
    if status.current_state != ServiceState::Stopped
        && status.current_state != ServiceState::StopPending
    {
        service.stop().map_err(scm)?;
    }
    let stopped = wait(service, ServiceState::Stopped, deadline)?;
    if !matches!(stopped.exit_code, ServiceExitCode::Win32(0 | 1077)) {
        return Err(Error::NotReady);
    }
    Ok(false)
}
fn remember_create_failure(
    store: &Store,
    record: &mut Registration,
    error: Error,
) -> Result<Error> {
    if error == Error::CredentialsRequired && record.phase != Phase::CredentialsRequired {
        let old = record.clone();
        record.phase = Phase::CredentialsRequired;
        store.write(Some(&old), record)?;
    }
    Ok(error)
}
fn execute(context: Context, operation: &str) -> Result<String> {
    if !matches!(
        operation,
        "install" | "start" | "stop" | "restart" | "status" | "uninstall"
    ) {
        return Err(Error::Invalid);
    }
    if operation != "install" && !context.registration.exists() {
        return Err(Error::NotInstalled);
    }
    let _pins = context.pins()?;
    let store = Store::open(&context.registration)?;
    let mut existing = store.load()?;
    if let Some(r) = &existing {
        context.check(r)?
    }
    if operation == "install" && existing.is_none() {
        let mut record = Registration {
            version: 1,
            operator_sid: context.operator_sid.clone(),
            account_sid: context.account_sid.clone(),
            account: context.account.clone().ok_or(Error::Invalid)?,
            profile: text(context.profile.as_os_str())?,
            executable: text(context.executable.as_os_str())?,
            name: context
                .name
                .clone()
                .unwrap_or_else(|| format!("LomiRemote-{}", Uuid::new_v4())),
            command: String::new(),
            mode: if context.fixture { "manual" } else { "boot" }.into(),
            phase: Phase::Intent,
            fixture: context.fixture,
        };
        record.command = record.command()?;
        context.check(&record)?;
        store.write(None, &record)?;
        existing = Some(record);
        #[cfg(feature = "service-fixture")]
        if context.fault == Some("intent") {
            return Err(Error::Deadline);
        }
    }
    let mut record = existing.ok_or(Error::NotInstalled)?;
    let access = if operation == "install" {
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE
    } else {
        ServiceManagerAccess::CONNECT
    };
    let manager = ServiceManager::local_computer(None::<&str>, access).map_err(scm)?;
    let service_access = match operation {
        "start" => ServiceAccess::START,
        "stop" => ServiceAccess::STOP,
        "restart" => ServiceAccess::START | ServiceAccess::STOP,
        "uninstall" => ServiceAccess::STOP | ServiceAccess::DELETE,
        _ => ServiceAccess::empty(),
    };
    let mut service = match open(&manager, &record, service_access) {
        Err(Error::Deadline) if operation == "uninstall" && record.phase == Phase::Deleting => None,
        other => other?,
    };
    if let Some(service) = &service {
        validate(&context, &store, &record, service)?;
    }
    if service.is_none()
        && record.phase == Phase::CredentialsRequired
        && !matches!(operation, "install" | "uninstall")
    {
        return Err(Error::CredentialsRequired);
    }
    if operation == "install" {
        if record.phase == Phase::Deleting {
            return Err(Error::Conflict);
        }
        if service.is_none() {
            if !matches!(record.phase, Phase::Intent | Phase::CredentialsRequired) {
                return Err(Error::Conflict);
            }
            validate_create(&context, &store, &record)?;
            #[cfg(feature = "service-fixture")]
            if context.fault == Some("credentials") {
                return Err(remember_create_failure(
                    &store,
                    &mut record,
                    Error::CredentialsRequired,
                )?);
            }
            let created = match manager.create_service(
                &record.info(),
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            ) {
                Ok(created) => created,
                Err(error) => {
                    return Err(remember_create_failure(&store, &mut record, scm(error))?);
                }
            };
            record.matches(&created.query_config().map_err(scm)?)?;
            service = Some(created);
            #[cfg(feature = "service-fixture")]
            if context.fault == Some("create") {
                return Err(Error::Deadline);
            }
        }
        validate(
            &context,
            &store,
            &record,
            service.as_ref().ok_or(Error::Conflict)?,
        )?;
        let next = if context.fixture {
            Phase::Registered
        } else {
            Phase::CredentialsRequired
        };
        if record.phase == Phase::Intent
            || (context.fixture && record.phase == Phase::CredentialsRequired)
        {
            let old = record.clone();
            record.phase = next;
            store.write(Some(&old), &record)?;
        }
        if record.phase == Phase::CredentialsRequired {
            return Err(Error::CredentialsRequired);
        }
        return Ok("Service installed; not started.".into());
    }
    if operation == "uninstall" {
        let mut previous_failure = false;
        if record.phase != Phase::Deleting {
            let old = record.clone();
            record.phase = Phase::Deleting;
            store.write(Some(&old), &record)?;
        }
        if let Some(s) = service.take() {
            previous_failure = stop(
                &context,
                &store,
                &record,
                &s,
                Instant::now() + context.wait,
                true,
            )?;
            validate(&context, &store, &record, &s)?;
            match s.delete() {
                Ok(()) => {}
                Err(error) if deleting(&error) => {}
                Err(error) => return Err(scm(error)),
            }
            drop(s);
            #[cfg(feature = "service-fixture")]
            if context.fault == Some("delete") {
                return Err(Error::Deadline);
            }
        }
        let deadline = Instant::now() + context.wait;
        loop {
            match manager.open_service(&record.name, ServiceAccess::QUERY_CONFIG) {
                Err(e) if missing(&e) => break,
                Err(e) if deleting(&e) => {}
                Ok(s) => {
                    match s.query_config() {
                        Ok(config) => record.matches_config(&config, true)?,
                        Err(error) if deleting(&error) || missing(&error) => {}
                        Err(error) => return Err(scm(error)),
                    }
                    drop(s);
                }
                Err(e) => return Err(scm(e)),
            }
            if Instant::now() >= deadline {
                return Err(Error::Deadline);
            }
            thread::sleep(Duration::from_millis(50))
        }
        store.remove(&record)?;
        return Ok(if previous_failure {
            "Service uninstalled after previous service failure; host data preserved."
        } else {
            "Service uninstalled; host data preserved."
        }
        .into());
    }
    if record.phase == Phase::Deleting {
        return Err(Error::Conflict);
    }
    let service = service.ok_or(Error::Conflict)?;
    validate(&context, &store, &record, &service)?;
    if operation == "status" {
        let status = service.query_status().map_err(scm)?;
        if status.current_state == ServiceState::Running {
            ready(&context, &service, Instant::now() + context.wait)?;
            return Ok("Service running.".into());
        }
        if status.current_state == ServiceState::Stopped
            && !matches!(status.exit_code, ServiceExitCode::Win32(0 | 1077))
        {
            return Err(if status.exit_code == ServiceExitCode::Win32(1069) {
                Error::CredentialsRequired
            } else {
                Error::NotReady
            });
        }
        if record.phase == Phase::CredentialsRequired {
            return Err(Error::CredentialsRequired);
        }
        return Ok(format!("Service {:?}.", status.current_state));
    }
    let deadline = Instant::now() + context.wait;
    let mut previous_failure = false;
    if matches!(operation, "stop" | "restart") {
        previous_failure = stop(
            &context,
            &store,
            &record,
            &service,
            deadline,
            operation == "restart",
        )?;
        if operation == "stop" {
            return Ok("Service stopped.".into());
        }
    }
    validate(&context, &store, &record, &service)?;
    let status = service.query_status().map_err(scm)?;
    if status.current_state != ServiceState::Running {
        if status.current_state != ServiceState::Stopped {
            return Err(Error::NotReady);
        }
        service.start(&[] as &[OsString]).map_err(scm)?;
    }
    ready(&context, &service, deadline)?;
    if record.phase != Phase::Registered {
        let old = record.clone();
        record.phase = Phase::Registered;
        store.write(Some(&old), &record)?;
    }
    Ok(if previous_failure {
        "Service running after previous service failure."
    } else {
        "Service running."
    }
    .into())
}
fn validate_create(context: &Context, store: &Store, record: &Registration) -> Result<()> {
    store.check()?;
    context.check(record)?;
    let _pins = context.pins()?;
    Ok(())
}
/// Public policy: explicit ordinary current account only; credentials and logon
/// rights are provisioned by OS administration, never accepted by this adapter.
pub fn run(
    profile: &Path,
    executable: &Path,
    operation: &str,
    mode: Option<&str>,
    account: Option<&str>,
) -> Result<String> {
    if operation == "install" && mode != Some("boot") {
        return Err(Error::Unimplemented);
    }
    ordinary_identity()?;
    let sid = current_sid().map_err(invalid)?;
    if let Some(account) = account {
        let account = text(OsStr::new(account))?;
        if account_sid(&account)? != sid {
            return Err(Error::Unimplemented);
        }
    } else if operation == "install" {
        return Err(Error::Invalid);
    }
    let profile = normalized(profile).map_err(invalid)?;
    let executable = normalized(executable).map_err(invalid)?;
    let name = profile
        .file_name()
        .ok_or(Error::Invalid)?
        .to_str()
        .ok_or(Error::Invalid)?;
    let registration = profile.with_file_name(format!("{name}-service-windows"));
    let _selection = super::task::selection_lock(&profile).map_err(|_| Error::Conflict)?;
    if super::task::login_present(&profile).map_err(|_| Error::Conflict)? {
        return Err(Error::Conflict);
    }
    execute(
        Context {
            profile,
            executable,
            registration,
            operator_sid: sid.clone(),
            account_sid: sid,
            account: account.map(str::to_owned),
            fixture: false,
            name: None,
            wait: WAIT,
            create_profile: operation == "install",
            #[cfg(feature = "service-fixture")]
            fault: None,
        },
        operation,
    )
}
#[cfg(feature = "service-fixture")]
pub fn fixture_run(run_id: &str, operation: &str) -> Result<String> {
    unimpersonated()?;
    let (operation, fault) = match operation {
        "install-intent-fault" => ("install", Some("intent")),
        "install-create-fault" => ("install", Some("create")),
        "install-logon-fault" => ("install", Some("credentials")),
        "uninstall-delete-fault" => ("uninstall", Some("delete")),
        value => (value, None),
    };
    let id = Uuid::parse_str(run_id).map_err(|_| Error::Invalid)?;
    if id.to_string() != run_id {
        return Err(Error::Invalid);
    }
    let root = PathBuf::from(r"C:\ProgramData\LomiWindowsFixture").join(run_id);
    let _root = pin(&root, "S-1-5-19", false)?;
    let marker = std::fs::read(root.join("fixture.marker")).map_err(|_| Error::Conflict)?;
    if marker != format!("lomi-product-service-v1:{run_id}\n").as_bytes() {
        return Err(Error::Conflict);
    }
    let home = std::env::var_os("USERPROFILE").ok_or(Error::Invalid)?;
    execute(
        Context {
            profile: root.join("host-profile"),
            executable: root.join("lomiremote.exe"),
            registration: PathBuf::from(home).join(format!(".lomi-service-manager-{run_id}")),
            operator_sid: current_sid().map_err(invalid)?,
            account_sid: "S-1-5-19".into(),
            account: Some(r"NT AUTHORITY\LocalService".into()),
            fixture: true,
            name: Some(format!("LomiProductService-{run_id}")),
            wait: Duration::from_secs(5),
            create_profile: false,
            fault,
        },
        operation,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn command_roundtrip_matches_service_serializer_cases() {
        let cases = [
            "",
            "simple",
            r"C:\path\tail\",
            "with space",
            "quotes\"here",
            "😀\\trail\\",
            "one\\\"two",
        ];
        for value in cases {
            let command = format!(
                "{} {}",
                quote(value).unwrap(),
                quote("next argument").unwrap()
            );
            assert_eq!(
                parse(&command).unwrap(),
                vec![value.to_owned(), "next argument".into()]
            );
        }
        assert_eq!(
            quote(r"C:\Program Files\Lomi\lomiremote.exe").unwrap(),
            r#""C:\Program Files\Lomi\lomiremote.exe""#
        );
        assert!(quote("nul\0value").is_err());
        assert!(parse("\"unterminated").is_err());
    }
    fn disabled_config() -> (Registration, ServiceConfig) {
        let mut record = Registration {
            version: 1,
            operator_sid: "S-1-5-19".into(),
            account_sid: "S-1-5-19".into(),
            account: r"NT AUTHORITY\LocalService".into(),
            profile: r"C:\fixture\host-profile".into(),
            executable: r"C:\fixture\lomiremote.exe".into(),
            name: "LomiProductService-00000000-0000-4000-8000-000000000001".into(),
            command: String::new(),
            mode: "manual".into(),
            phase: Phase::Registered,
            fixture: true,
        };
        record.command = record.command().unwrap();
        let config = ServiceConfig {
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::Disabled,
            error_control: ServiceErrorControl::Normal,
            executable_path: PathBuf::from(&record.command),
            load_order_group: None,
            tag_id: 0,
            dependencies: vec![],
            account_name: Some(OsString::from(&record.account)),
            display_name: OsString::from(&record.name),
        };
        (record, config)
    }
    #[test]
    fn disabled_start_mode_conflicts_with_strict_mutation_validation() {
        let (mut record, config) = disabled_config();
        for phase in [
            Phase::Intent,
            Phase::CredentialsRequired,
            Phase::Registered,
            Phase::Deleting,
        ] {
            record.phase = phase;
            assert_eq!(record.matches(&config), Err(Error::Conflict));
        }
        assert_eq!(record.matches_config(&config, true), Ok(()));
    }
    #[test]
    fn pending_disabled_service_with_changed_raw_command_conflicts() {
        let (mut record, mut config) = disabled_config();
        record.phase = Phase::Deleting;
        config.executable_path = PathBuf::from(format!("{} extra-argument", record.command));
        assert_eq!(record.matches_config(&config, true), Err(Error::Conflict));
    }
    #[test]
    fn logon_failure_requires_os_setup_without_password_handling() {
        for code in [1069, 1079, 1057] {
            assert_eq!(
                scm(windows_service::Error::Winapi(
                    std::io::Error::from_raw_os_error(code)
                )),
                Error::CredentialsRequired
            );
        }
    }
    #[test]
    fn public_login_is_rejected_before_profile_creation() {
        let path = Path::new(r"C:\must-not-create-lomi-service-profile");
        assert_eq!(
            run(path, path, "install", Some("login"), Some("any")),
            Err(Error::Unimplemented)
        );
    }
}

/// Separate native observer and explicit fixture teardown for the fixed
/// synthetic host profile. Never initializes or supervises a host.
#[cfg(feature = "service-fixture")]
pub fn fixture_probe(run_id: &str, phase: &str) -> Result<()> {
    probe::dispatch(run_id, phase)
}
#[cfg(feature = "service-fixture")]
mod probe {
    use super::*;
    use std::sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
    };
    use windows_service::{
        define_windows_service,
        service::{ServiceControlAccept, ServiceStatus},
        service_control_handler::{self, ServiceControlHandlerResult},
        service_dispatcher,
    };
    static CONFIG: OnceLock<(String, String)> = OnceLock::new();
    static FAILED: AtomicBool = AtomicBool::new(false);
    define_windows_service!(ffi_main, main);
    pub(super) fn dispatch(id: &str, phase: &str) -> Result<()> {
        if Uuid::parse_str(id).map_err(|_| Error::Invalid)?.to_string() != id {
            return Err(Error::Invalid);
        }
        let dpapi = cfg!(feature = "dpapi-fixture") && phase == "dpapi";
        if !matches!(phase, "before" | "after" | "cleanup") && !dpapi {
            return Err(Error::Invalid);
        }
        CONFIG
            .set((id.into(), phase.into()))
            .map_err(|_| Error::Conflict)?;
        service_dispatcher::start(format!("LomiProductServiceProbe-{id}"), ffi_main)
            .map_err(scm)?;
        if FAILED.load(Ordering::Acquire) {
            Err(Error::NotReady)
        } else {
            Ok(())
        }
    }
    fn digest(bytes: &[u8]) -> Result<String> {
        use windows_sys::Win32::Security::Cryptography::*;
        let mut algorithm = ptr::null_mut();
        if unsafe {
            BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
        } < 0
        {
            return Err(Error::NotReady);
        }
        let mut output = [0u8; 32];
        let result = unsafe {
            BCryptHash(
                algorithm,
                ptr::null(),
                0,
                bytes.as_ptr(),
                bytes.len() as u32,
                output.as_mut_ptr(),
                output.len() as u32,
            )
        };
        unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
        if result < 0 {
            return Err(Error::NotReady);
        }
        Ok(output.iter().map(|b| format!("{b:02x}")).collect())
    }
    fn observe(id: &str, phase: &str) -> Result<()> {
        unimpersonated()?;
        if current_sid().map_err(invalid)? != "S-1-5-19" {
            return Err(Error::Conflict);
        }
        let root = PathBuf::from(r"C:\ProgramData\LomiWindowsFixture").join(id);
        let _parent = pin(&root, "S-1-5-19", false)?;
        if std::fs::read(root.join("fixture.marker")).map_err(|_| Error::Conflict)?
            != format!("lomi-product-service-v1:{id}\n").as_bytes()
        {
            return Err(Error::Conflict);
        }
        #[cfg(feature = "dpapi-fixture")]
        if phase == "dpapi" {
            return super::super::dpapi_fixture::local_service(id);
        }
        let profile = PrivateProfile::open(&root.join("host-profile"), false).map_err(invalid)?;
        if phase == "cleanup" {
            let owner = OwnerLock::acquire(&profile.path).map_err(invalid)?;
            let mut files = Vec::new();
            for entry in std::fs::read_dir(&profile.path).map_err(|_| Error::Conflict)? {
                let entry = entry.map_err(|_| Error::Conflict)?;
                if !matches!(
                    entry.file_name().to_str(),
                    Some("owner.lock" | "host.sqlite3" | "host.sqlite3-wal" | "host.sqlite3-shm")
                ) {
                    return Err(Error::Conflict);
                }
                drop(open_regular(&entry.path(), false, false, &profile.sid).map_err(invalid)?);
                files.push(entry.path());
            }
            let path = profile.path.clone();
            drop(owner);
            drop(profile);
            for file in files {
                std::fs::remove_file(file).map_err(|_| Error::Deadline)?;
            }
            std::fs::remove_dir(&path).map_err(|_| Error::Deadline)?;
            std::fs::write(
                root.join("profile-cleanup.json"),
                b"{\"cleanupComplete\":true,\"localService\":true,\"fixtureCleanup\":true}",
            )
            .map_err(|_| Error::Deadline)?;
            return Ok(());
        }
        let file = open_regular(
            &profile.path.join("host.sqlite3"),
            false,
            false,
            &profile.sid,
        )
        .map_err(invalid)?;
        let mut bytes = Vec::new();
        file.take(8 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error::NotReady)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(Error::Invalid);
        }
        let value = serde_json::json!({"exists":true,"sha256":digest(&bytes)?,"bytes":bytes.len(),"localService":true,"readOnlyObserver":true});
        std::fs::write(
            root.join(if phase == "after" {
                "db-after.json"
            } else {
                "db-before.json"
            }),
            serde_json::to_vec(&value).map_err(|_| Error::Invalid)?,
        )
        .map_err(|_| Error::NotReady)?;
        Ok(())
    }
    fn main(_args: Vec<OsString>) {
        let Some((id, phase)) = CONFIG.get() else {
            FAILED.store(true, Ordering::Release);
            return;
        };
        let name = format!("LomiProductServiceProbe-{id}");
        let Ok(handle) = service_control_handler::register(&name, |_| {
            ServiceControlHandlerResult::NotImplemented
        }) else {
            FAILED.store(true, Ordering::Release);
            return;
        };
        let status = |state, failed| ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: state,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(u32::from(failed)),
            checkpoint: 0,
            wait_hint: Duration::ZERO,
            process_id: None,
        };
        if handle
            .set_service_status(status(ServiceState::Running, false))
            .is_err()
        {
            FAILED.store(true, Ordering::Release);
            return;
        }
        let failed = observe(id, phase).is_err();
        FAILED.store(failed, Ordering::Release);
        let _ = handle.set_service_status(status(ServiceState::Stopped, failed));
    }
}

/// Read-only native closure audit: only explicit ERROR_SERVICE_DOES_NOT_EXIST
/// counts as absence, including for the separate probe and collision fixtures.
#[cfg(feature = "service-fixture")]
pub fn fixture_audit_absence(run_id: &str) -> Result<()> {
    if Uuid::parse_str(run_id)
        .map_err(|_| Error::Invalid)?
        .to_string()
        != run_id
    {
        return Err(Error::Invalid);
    }
    let manager =
        ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).map_err(scm)?;
    for prefix in [
        "LomiProductService-",
        "LomiProductServiceProbe-",
        "LomiProductServiceForeign-",
    ] {
        match manager.open_service(format!("{prefix}{run_id}"), ServiceAccess::QUERY_CONFIG) {
            Err(error) if missing(&error) => {}
            Err(error) if deleting(&error) => return Err(Error::Deadline),
            Err(error) => return Err(scm(error)),
            Ok(_) => return Err(Error::Conflict),
        }
    }
    Ok(())
}
