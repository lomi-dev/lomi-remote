//! Default-off synthetic cross-account provider proof; no production profile input.
use super::secrets::WindowsDpapi as ProductUserDpapi;
use super::{
    Handle, Local, OwnerLock, PrivateProfile, Security, current_sid, normalized, open_regular,
    process_sid, service, wide,
};
use crate::secrets::{
    Error as ProviderError, ProviderKind, SecretBundle, SecretStorage, Selection, StorageState,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    mem,
    os::windows::io::{BorrowedHandle, FromRawHandle},
    path::{Path, PathBuf},
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
    Security::{Authorization::*, Cryptography::*, *},
    Storage::FileSystem::*,
    System::{SystemServices::ACCESS_ALLOWED_ACE_TYPE, Threading::*},
};
type Result<T> = std::result::Result<T, service::Error>;
const LS: &str = "S-1-5-19";
const MAX_BLOB: usize = 64 * 1024 + 12;
const PAYLOAD: &[u8] = b"LOMI-PUBLIC-SYNTHETIC-DPAPI-OPERATOR-V1";
const LOCAL_PAYLOAD: &[u8] = b"LOMI-PUBLIC-SYNTHETIC-DPAPI-LOCALSERVICE-V1";
fn invalid<T>(_: T) -> service::Error {
    service::Error::Conflict
}
fn failed<T>(_: T) -> service::Error {
    service::Error::NotReady
}
fn check(value: bool) -> Result<()> {
    if value {
        Ok(())
    } else {
        Err(service::Error::Conflict)
    }
}
fn root(id: &str) -> Result<PathBuf> {
    check(Uuid::parse_str(id).map_err(invalid)?.to_string() == id)?;
    Ok(Path::new(r"C:\ProgramData\LomiWindowsFixture").join(id))
}
fn operator_profile(id: &str) -> Result<PathBuf> {
    let exe = normalized(&std::env::current_exe().map_err(invalid)?).map_err(invalid)?;
    let source = exe.ancestors().nth(4).ok_or(service::Error::Invalid)?;
    check(
        source.file_name().and_then(|s| s.to_str())
            == Some(format!("lomi-product-dpapi-{id}").as_str()),
    )?;
    Ok(source.join("operator-profile"))
}
fn digest(bytes: &[u8]) -> Result<String> {
    let mut algorithm = ptr::null_mut();
    if unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, BCRYPT_SHA256_ALGORITHM, ptr::null(), 0)
    } < 0
    {
        return Err(service::Error::NotReady);
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
            32,
        )
    };
    unsafe { BCryptCloseAlgorithmProvider(algorithm, 0) };
    if result < 0 {
        return Err(service::Error::NotReady);
    }
    Ok(output.iter().map(|b| format!("{b:02x}")).collect())
}
fn binary_digest(path: &Path) -> Result<String> {
    let pin = service::pin(path, LS, true)?;
    let handle = pin._file.as_ref().ok_or(service::Error::Conflict)?;
    let file = File::from(
        unsafe { BorrowedHandle::borrow_raw(handle.0) }
            .try_clone_to_owned()
            .map_err(invalid)?,
    );
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    check(bytes.len() <= 64 * 1024 * 1024)?;
    digest(&bytes)
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum Phase {
    Prepared,
    Created,
    Running,
    Complete,
    Deleting,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Intent {
    version: u8,
    id: String,
    operator_sid: String,
    binary_sha256: String,
    ciphertext_sha256: String,
    ciphertext_bytes: usize,
    phase: Phase,
}
impl Intent {
    fn name(&self) -> String {
        format!("LomiProductServiceProbe-{}", self.id)
    }
    fn binary(&self) -> Result<PathBuf> {
        Ok(root(&self.id)?.join("windows-service-proof.exe"))
    }
    fn command(&self) -> Result<String> {
        [
            self.binary()?
                .to_str()
                .ok_or(service::Error::Invalid)?
                .to_owned(),
            self.id.clone(),
            "probe-dpapi".into(),
        ]
        .iter()
        .map(|s| service::quote(s))
        .collect::<Result<Vec<_>>>()
        .map(|v| v.join(" "))
    }
    fn info(&self) -> Result<ServiceInfo> {
        Ok(ServiceInfo {
            name: self.name().into(),
            display_name: self.name().into(),
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::OnDemand,
            error_control: ServiceErrorControl::Normal,
            executable_path: self.binary()?,
            launch_arguments: vec![self.id.clone().into(), "probe-dpapi".into()],
            dependencies: vec![],
            account_name: Some(r"NT AUTHORITY\LocalService".into()),
            account_password: None,
        })
    }
    fn check(&self) -> Result<()> {
        check(
            self.version == 1
                && self.operator_sid.starts_with("S-1-5-21-")
                && self.operator_sid != LS
                && (13..=MAX_BLOB).contains(&self.ciphertext_bytes),
        )?;
        for hash in [&self.binary_sha256, &self.ciphertext_sha256] {
            check(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
            )?;
        }
        let path = root(&self.id)?;
        let _pin = service::pin(&path, LS, false)?;
        check(
            std::fs::read(path.join("fixture.marker")).map_err(invalid)?
                == format!("lomi-product-service-v1:{}\n", self.id).as_bytes(),
        )?;
        check(binary_digest(&self.binary()?)? == self.binary_sha256)
    }
    fn verify(&self, service: &Service, pending: bool) -> Result<()> {
        self.check()?;
        let config = service.query_config().map_err(failed)?;
        self.verify_config(&config, pending)?;
        let actions = service.get_failure_actions().map_err(failed)?;
        check(
            !service
                .get_failure_actions_on_non_crash_failures()
                .map_err(failed)?
                && actions.actions.is_none_or(|v| v.is_empty())
                && actions.command.is_none_or(|s| s.is_empty())
                && actions.reboot_msg.is_none_or(|s| s.is_empty()),
        )
    }
    fn verify_config(&self, config: &ServiceConfig, pending: bool) -> Result<()> {
        check(
            config.service_type == ServiceType::OWN_PROCESS
                && (config.start_type == ServiceStartType::OnDemand
                    || (pending
                        && self.phase == Phase::Deleting
                        && config.start_type == ServiceStartType::Disabled))
                && config.error_control == ServiceErrorControl::Normal
                && config.display_name == std::ffi::OsStr::new(&self.name())
                && config.dependencies.is_empty()
                && config
                    .load_order_group
                    .as_ref()
                    .is_none_or(|v| v.is_empty()),
        )?;
        check(config.executable_path.as_os_str() == std::ffi::OsStr::new(&self.command()?))?;
        check(
            service::account_sid(
                config
                    .account_name
                    .as_ref()
                    .and_then(|s| s.to_str())
                    .ok_or(service::Error::Conflict)?,
            )? == LS,
        )?;
        Ok(())
    }
}
fn shared_acl(handle: HANDLE, owner: &str, reader: &str) -> Result<()> {
    let (mut descriptor, mut acl, mut actual_owner) =
        (ptr::null_mut(), ptr::null_mut(), ptr::null_mut());
    check(
        unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut actual_owner,
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        } == ERROR_SUCCESS,
    )?;
    let _guard = Local(descriptor);
    check(!actual_owner.is_null() && !acl.is_null())?;
    check(super::sid_text(actual_owner).map_err(invalid)? == owner)?;
    let (mut control, mut revision) = (0, 0);
    check(
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } != 0
            && control & SE_DACL_PROTECTED != 0
            && unsafe { (*acl).AceCount } == 3,
    )?;
    let mut found = std::collections::BTreeMap::new();
    for index in 0..3 {
        let mut ace = ptr::null_mut();
        check(unsafe { GetAce(acl, index, &mut ace) } != 0)?;
        let header = unsafe { &*ace.cast::<ACE_HEADER>() };
        check(header.AceType == ACCESS_ALLOWED_ACE_TYPE as u8 && header.AceFlags == 0)?;
        let allowed = unsafe { &*ace.cast::<ACCESS_ALLOWED_ACE>() };
        let sid = super::sid_text((&allowed.SidStart as *const u32).cast_mut().cast())
            .map_err(invalid)?;
        check(found.insert(sid, allowed.Mask).is_none())?;
    }
    check(
        found.get(owner) == Some(&FILE_ALL_ACCESS)
            && found.get("S-1-5-18") == Some(&FILE_ALL_ACCESS)
            && found.get(reader) == Some(&FILE_GENERIC_READ),
    )
}
fn shared_file(path: &Path, owner: &str, reader: &str) -> Result<File> {
    let handle = super::open_path(path, false, false, false, owner).map_err(invalid)?;
    shared_acl(handle.0, owner, reader)?;
    let raw = handle.0;
    mem::forget(handle);
    Ok(unsafe { File::from_raw_handle(raw) })
}
fn read_shared(path: &Path, owner: &str, reader: &str, limit: usize) -> Result<Vec<u8>> {
    let file = shared_file(path, owner, reader)?;
    check(file.metadata().map_err(invalid)?.len() <= limit as u64)?;
    let mut bytes = Vec::new();
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    check(bytes.len() <= limit)?;
    Ok(bytes)
}
fn write_shared(path: &Path, owner: &str, reader: &str, bytes: &[u8], replace: bool) -> Result<()> {
    check(current_sid().map_err(invalid)? == owner)?;
    if replace {
        drop(shared_file(path, owner, reader)?)
    } else {
        check(!path.try_exists().map_err(invalid)?)?;
    }
    let temporary = path.with_file_name(format!(".dpapi-write-{}", Uuid::new_v4()));
    let sd = Security::new(&format!(
        "O:{owner}D:P(A;;FA;;;{owner})(A;;FA;;;SY)(A;;FR;;;{reader})"
    ))
    .map_err(invalid)?;
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
    check(raw != INVALID_HANDLE_VALUE)?;
    let mut file = unsafe { File::from_raw_handle(raw) };
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(failed)?;
    drop(file);
    check(
        unsafe {
            MoveFileExW(
                wide(&temporary).as_ptr(),
                wide(path).as_ptr(),
                MOVEFILE_WRITE_THROUGH
                    | if replace {
                        MOVEFILE_REPLACE_EXISTING
                    } else {
                        0
                    },
            )
        } != 0,
    )
}
fn intent(id: &str) -> Result<Intent> {
    let path = root(id)?.join("dpapi-intent.json");
    // Parse only bounded metadata, then require that claimed operator is the
    // actual file owner and exactly the allowed transport writer.
    let handle = super::open_path(&path, false, false, false, LS).map_err(invalid)?;
    let raw = handle.0;
    mem::forget(handle);
    let mut file = unsafe { File::from_raw_handle(raw) };
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(8193)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    check(bytes.len() <= 8192)?;
    let value: Intent = serde_json::from_slice(&bytes).map_err(invalid)?;
    check(value.id == id)?;
    use std::os::windows::io::AsRawHandle;
    shared_acl(file.as_raw_handle(), &value.operator_sid, LS)?;
    value.check()?;
    Ok(value)
}
fn save_intent(old: &Intent, next: &Intent) -> Result<()> {
    check(intent(&old.id)? == *old)?;
    write_shared(
        &root(&old.id)?.join("dpapi-intent.json"),
        &old.operator_sid,
        LS,
        &serde_json::to_vec(next).map_err(invalid)?,
        true,
    )
}
fn private_bytes(profile: &PrivateProfile) -> Result<Vec<u8>> {
    let file = open_regular(
        &profile.path.join("host-secrets.dpapi"),
        false,
        false,
        &profile.sid,
    )
    .map_err(invalid)?;
    check(file.metadata().map_err(invalid)?.len() <= MAX_BLOB as u64)?;
    let mut bytes = Vec::new();
    file.take(MAX_BLOB as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(invalid)?;
    check(bytes.len() <= MAX_BLOB)?;
    Ok(bytes)
}
fn overwrite_private(profile: &PrivateProfile, bytes: &[u8]) -> Result<()> {
    check((13..=MAX_BLOB).contains(&bytes.len()))?;
    let mut file = open_regular(
        &profile.path.join("host-secrets.dpapi"),
        true,
        false,
        &profile.sid,
    )
    .map_err(invalid)?;
    file.set_len(0).map_err(failed)?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(failed)
}
fn cleanup_profile(path: &Path) -> Result<()> {
    let owner = OwnerLock::acquire(path).map_err(invalid)?;
    let mut files = Vec::new();
    for entry in std::fs::read_dir(path).map_err(invalid)? {
        let entry = entry.map_err(invalid)?;
        check(matches!(
            entry.file_name().to_str(),
            Some("owner.lock" | "host-secrets.dpapi" | "host-secrets.lock")
        ))?;
        drop(open_regular(&entry.path(), false, false, &owner.profile.sid).map_err(invalid)?);
        files.push(entry.path());
    }
    drop(owner);
    for file in files {
        std::fs::remove_file(file).map_err(failed)?;
    }
    std::fs::remove_dir(path).map_err(failed)
}
fn wait_gate(root: &Path, name: &str, operator: &str) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(25);
    loop {
        let path = root.join(name);
        if path.try_exists().map_err(invalid)? {
            check(read_shared(&path, operator, LS, 64)? == b"synthetic-dpapi-gate-v1")?;
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    same_account_before: bool,
    same_account_after: bool,
    provider_kind_windows_dpapi: bool,
    provider_available_after: bool,
    transport_acl_verified: bool,
    ciphertext_readable: bool,
    ciphertext_unchanged: bool,
    ciphertext_sha256: String,
    ciphertext_bytes: usize,
    wrong_sid_rejected: bool,
    provider_error: String,
    local_service_sid: String,
}
/// Called by the existing one-shot SCM probe, under the actual LocalService token.
pub fn local_service(id: &str) -> Result<()> {
    check(current_sid().map_err(invalid)? == LS)?;
    let record = intent(id)?;
    let root = root(id)?;
    check(
        normalized(&std::env::current_exe().map_err(invalid)?).map_err(invalid)?
            == record.binary()?,
    )?;
    wait_gate(&root, "dpapi-go", &record.operator_sid)?;
    let ciphertext = read_shared(
        &root.join("operator-ciphertext.bin"),
        &record.operator_sid,
        LS,
        MAX_BLOB,
    )?;
    check(
        ciphertext.len() == record.ciphertext_bytes
            && digest(&ciphertext)? == record.ciphertext_sha256,
    )?;
    check(!root.join("dpapi-profile").try_exists().map_err(invalid)?)?;
    let owner = OwnerLock::acquire(&root.join("dpapi-profile")).map_err(invalid)?;
    {
        let mut provider =
            ProductUserDpapi::open(owner.profile(), Selection::WindowsDpapi).map_err(failed)?;
        provider
            .replace(&SecretBundle::new(LOCAL_PAYLOAD.to_vec()).map_err(failed)?)
            .map_err(failed)?;
    }
    let proof = {
        let provider =
            ProductUserDpapi::open(owner.profile(), Selection::WindowsDpapi).map_err(failed)?;
        let before = provider
            .load()
            .map_err(failed)?
            .ok_or(service::Error::NotReady)?
            .expose()
            == LOCAL_PAYLOAD;
        check(before)?;
        let own_ciphertext = private_bytes(owner.profile())?;
        overwrite_private(owner.profile(), &ciphertext)?;
        check(private_bytes(owner.profile())? == ciphertext)?;
        let error = provider.load().err().ok_or(service::Error::NotReady)?;
        let unchanged = private_bytes(owner.profile())? == ciphertext;
        overwrite_private(owner.profile(), &own_ciphertext)?;
        let after = provider
            .load()
            .map_err(failed)?
            .ok_or(service::Error::NotReady)?
            .expose()
            == LOCAL_PAYLOAD;
        check(after)?;
        let status = provider.status();
        check(
            error == ProviderError::Unavailable
                && unchanged
                && status.state == StorageState::Available
                && status.kind == Some(ProviderKind::WindowsDpapi),
        )?;
        Proof {
            same_account_before: before,
            same_account_after: after,
            provider_kind_windows_dpapi: true,
            provider_available_after: true,
            transport_acl_verified: true,
            ciphertext_readable: true,
            ciphertext_unchanged: unchanged,
            ciphertext_sha256: digest(&ciphertext)?,
            ciphertext_bytes: ciphertext.len(),
            wrong_sid_rejected: true,
            provider_error: error.to_string(),
            local_service_sid: current_sid().map_err(invalid)?,
        }
    };
    drop(owner);
    write_shared(
        &root.join("dpapi-proof.json"),
        LS,
        &record.operator_sid,
        &serde_json::to_vec(&proof).map_err(invalid)?,
        false,
    )?;
    wait_gate(&root, "dpapi-clean", &record.operator_sid)?;
    cleanup_profile(&root.join("dpapi-profile"))?;
    write_shared(
        &root.join("dpapi-cleanup.json"),
        LS,
        &record.operator_sid,
        b"{\"localServiceProfileAbsent\":true,\"cleanupComplete\":true}",
        false,
    )
}
fn open(
    manager: &ServiceManager,
    record: &Intent,
    access: ServiceAccess,
) -> Result<Option<Service>> {
    match manager.open_service(
        record.name(),
        ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS | access,
    ) {
        Ok(service) => {
            if record.phase == Phase::Deleting
                && service.query_config().map_err(failed)?.start_type == ServiceStartType::Disabled
            {
                record.verify(&service, true)?;
                // Already marked for deletion: never mutate this read-only exception.
                return Err(service::Error::Deadline);
            }
            record.verify(&service, false)?;
            Ok(Some(service))
        }
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1060) => {
            Ok(None)
        }
        Err(windows_service::Error::Winapi(error)) if error.raw_os_error() == Some(1072) => {
            Err(service::Error::Deadline)
        }
        Err(error) => Err(failed(error)),
    }
}
fn process_identity(process: HANDLE) -> Result<(u32, u64, u32)> {
    check(process_sid(process).map_err(invalid)? == LS)?;
    let (mut created, mut ended, mut kernel, mut user) = (
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
        unsafe { mem::zeroed() },
    );
    check(
        unsafe { GetProcessTimes(process, &mut created, &mut ended, &mut kernel, &mut user) } != 0,
    )?;
    let pid = unsafe { GetProcessId(process) };
    let mut token = ptr::null_mut();
    check(unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) } != 0)?;
    let token = Handle::new(token).map_err(invalid)?;
    let mut session = 0u32;
    let mut returned = 0;
    check(
        pid != 0
            && unsafe {
                GetTokenInformation(
                    token.0,
                    TokenSessionId,
                    (&mut session as *mut u32).cast(),
                    4,
                    &mut returned,
                )
            } != 0
            && returned == 4
            && session == 0,
    )?;
    Ok((
        pid,
        ((created.dwHighDateTime as u64) << 32) | created.dwLowDateTime as u64,
        session,
    ))
}
fn process_path(process: HANDLE) -> Result<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    check(unsafe { QueryFullProcessImageNameW(process, 0, path.as_mut_ptr(), &mut length) } != 0)?;
    normalized(Path::new(&std::ffi::OsString::from_wide(
        &path[..length as usize],
    )))
    .map_err(invalid)
}
fn wait_result(
    path: &Path,
    owner: &str,
    reader: &str,
    process: HANDLE,
    deadline: Instant,
) -> Result<Vec<u8>> {
    loop {
        if path.try_exists().map_err(invalid)? {
            return read_shared(path, owner, reader, 8192);
        }
        check(unsafe { WaitForSingleObject(process, 0) } == WAIT_TIMEOUT)?;
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn export(id: &str) -> Result<serde_json::Value> {
    let sid = current_sid().map_err(invalid)?;
    check(sid.starts_with("S-1-5-21-"))?;
    let root = root(id)?;
    let _pin = service::pin(&root, LS, false)?;
    check(
        std::fs::read(root.join("fixture.marker")).map_err(invalid)?
            == format!("lomi-product-service-v1:{id}\n").as_bytes(),
    )?;
    check(
        !root
            .join("dpapi-intent.json")
            .try_exists()
            .map_err(invalid)?,
    )?;
    let profile = operator_profile(id)?;
    check(!profile.try_exists().map_err(invalid)?)?;
    let owner = OwnerLock::acquire(&profile).map_err(invalid)?;
    {
        let mut provider =
            ProductUserDpapi::open(owner.profile(), Selection::WindowsDpapi).map_err(failed)?;
        provider
            .replace(&SecretBundle::new(PAYLOAD.to_vec()).map_err(failed)?)
            .map_err(failed)?;
    }
    let provider =
        ProductUserDpapi::open(owner.profile(), Selection::WindowsDpapi).map_err(failed)?;
    check(
        provider
            .load()
            .map_err(failed)?
            .ok_or(service::Error::NotReady)?
            .expose()
            == PAYLOAD,
    )?;
    let bytes = private_bytes(owner.profile())?;
    drop(provider);
    drop(owner);
    let record = Intent {
        version: 1,
        id: id.into(),
        operator_sid: sid.clone(),
        binary_sha256: binary_digest(&root.join("windows-service-proof.exe"))?,
        ciphertext_sha256: digest(&bytes)?,
        ciphertext_bytes: bytes.len(),
        phase: Phase::Prepared,
    };
    record.check()?;
    write_shared(
        &root.join("operator-ciphertext.bin"),
        &sid,
        LS,
        &bytes,
        false,
    )?;
    // Durable intent exists before the first SCM mutation.
    write_shared(
        &root.join("dpapi-intent.json"),
        &sid,
        LS,
        &serde_json::to_vec(&record).map_err(invalid)?,
        false,
    )?;
    Ok(
        serde_json::json!({"operatorSameAccountBefore":true,"operatorSid":sid,"ciphertextSha256":record.ciphertext_sha256,"ciphertextBytes":bytes.len(),"provider":"WindowsDpapi","serviceCreated":false}),
    )
}
fn create(record: &Intent) -> Result<serde_json::Value> {
    check(record.phase == Phase::Prepared)?;
    let manager = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .map_err(failed)?;
    let service = match open(&manager, record, ServiceAccess::empty())? {
        Some(owned) => owned,
        None => manager
            .create_service(
                &record.info()?,
                ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
            )
            .map_err(failed)?,
    };
    record.verify(&service, false)?;
    check(service.query_status().map_err(failed)?.current_state == ServiceState::Stopped)?;
    let mut next = record.clone();
    next.phase = Phase::Created;
    save_intent(record, &next)?;
    Ok(
        serde_json::json!({"created":true,"started":false,"manualLocalService":true,"service":record.name(),"intentBeforeCreate":true}),
    )
}
fn run_service(record: &Intent) -> Result<serde_json::Value> {
    check(record.phase == Phase::Created)?;
    let root = root(&record.id)?;
    let _binary = service::pin(&record.binary()?, LS, true)?;
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(failed)?;
    let service = open(&manager, record, ServiceAccess::START)?.ok_or(service::Error::Conflict)?;
    check(service.query_status().map_err(failed)?.current_state == ServiceState::Stopped)?;
    let mut running = record.clone();
    running.phase = Phase::Running;
    save_intent(record, &running)?;
    running.verify(&service, false)?;
    service
        .start(&[] as &[std::ffi::OsString])
        .map_err(failed)?;
    let deadline = Instant::now() + Duration::from_secs(40);
    let process = loop {
        let status = service.query_status().map_err(failed)?;
        if status.current_state == ServiceState::Running {
            let pid = status.process_id.ok_or(service::Error::Conflict)?;
            let process = Handle::new(unsafe {
                OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid)
            })
            .map_err(invalid)?;
            let (actual, _, _) = process_identity(process.0)?;
            check(actual == pid && process_path(process.0)? == record.binary()?)?;
            let again = service.query_status().map_err(failed)?;
            check(again.current_state == ServiceState::Running && again.process_id == Some(pid))?;
            break process;
        }
        check(status.current_state != ServiceState::Stopped)?;
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    };
    let (pid, created, session) = process_identity(process.0)?;
    write_shared(
        &root.join("dpapi-go"),
        &record.operator_sid,
        LS,
        b"synthetic-dpapi-gate-v1",
        false,
    )?;
    let bytes = wait_result(
        &root.join("dpapi-proof.json"),
        LS,
        &record.operator_sid,
        process.0,
        deadline,
    )?;
    let proof: Proof = serde_json::from_slice(&bytes).map_err(invalid)?;
    verify_proof(record, &proof)?;
    running.verify(&service, false)?;
    write_shared(
        &root.join("dpapi-clean"),
        &record.operator_sid,
        LS,
        b"synthetic-dpapi-gate-v1",
        false,
    )?;
    let cleanup = wait_result(
        &root.join("dpapi-cleanup.json"),
        LS,
        &record.operator_sid,
        process.0,
        deadline,
    )?;
    let cleanup: serde_json::Value = serde_json::from_slice(&cleanup).map_err(invalid)?;
    check(cleanup["localServiceProfileAbsent"] == true && cleanup["cleanupComplete"] == true)?;
    loop {
        let status = service.query_status().map_err(failed)?;
        if status.current_state == ServiceState::Stopped {
            check(status.exit_code == ServiceExitCode::Win32(0))?;
            break;
        }
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
    loop {
        if unsafe { WaitForSingleObject(process.0, 0) } == WAIT_OBJECT_0 {
            break;
        }
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut code = 1;
    check(unsafe { GetExitCodeProcess(process.0, &mut code) } != 0 && code == 0)?;
    check(!root.join("dpapi-profile").try_exists().map_err(invalid)?)?;
    let mut complete = running.clone();
    complete.phase = Phase::Complete;
    save_intent(&running, &complete)?;
    Ok(
        serde_json::json!({"passed":true,"proof":proof,"localServiceProfileAbsent":true,"processExitCode":code,"processHandleRetained":true,"ownerPid":pid,"ownerCreated":created,"ownerSession":session,"serviceStoppedExitCode":0}),
    )
}
fn delete(record: &Intent) -> Result<serde_json::Value> {
    let manager = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .map_err(failed)?;
    let mut deleting = record.clone();
    deleting.phase = Phase::Deleting;
    if record.phase != Phase::Deleting {
        save_intent(record, &deleting)?;
    }
    match open(&manager, &deleting, ServiceAccess::DELETE) {
        Ok(Some(service)) => {
            check(service.query_status().map_err(failed)?.current_state == ServiceState::Stopped)?;
            deleting.verify(&service, false)?;
            match service.delete() {
                Ok(()) => {}
                Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1072) => {}
                Err(e) => return Err(failed(e)),
            };
        }
        Ok(None) => {}
        Err(service::Error::Deadline) => {}
        Err(e) => return Err(e),
    }
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match manager.open_service(
            deleting.name(),
            ServiceAccess::QUERY_CONFIG | ServiceAccess::QUERY_STATUS,
        ) {
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => {
                return Ok(serde_json::json!({"serviceAbsent":true,"nativeAbsenceError":1060}));
            }
            Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1072) => {}
            Ok(service) => {
                deleting.verify(&service, true)?;
            }
            Err(e) => return Err(failed(e)),
        }
        if Instant::now() >= deadline {
            return Err(service::Error::Deadline);
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn finish(record: &Intent) -> Result<serde_json::Value> {
    check(matches!(record.phase, Phase::Complete | Phase::Deleting))?;
    let profile = operator_profile(&record.id)?;
    let owner = OwnerLock::acquire(&profile).map_err(invalid)?;
    {
        let provider =
            ProductUserDpapi::open(owner.profile(), Selection::WindowsDpapi).map_err(failed)?;
        check(
            provider
                .load()
                .map_err(failed)?
                .ok_or(service::Error::NotReady)?
                .expose()
                == PAYLOAD,
        )?;
        check(digest(&private_bytes(owner.profile())?)? == record.ciphertext_sha256)?;
    }
    drop(owner);
    cleanup_profile(&profile)?;
    Ok(
        serde_json::json!({"operatorSameAccountAfter":true,"originalCiphertextUnchanged":true,"operatorProfileAbsent":true}),
    )
}
/// Modes are available only in this fixture feature and accept only its UUID.
pub fn operator(id: &str, operation: &str) -> Result<serde_json::Value> {
    if operation == "export" {
        return export(id);
    }
    let record = intent(id)?;
    check(current_sid().map_err(invalid)? == record.operator_sid)?;
    match operation {
        "create" => create(&record),
        "run" => run_service(&record),
        "delete" => delete(&record),
        "finish" => finish(&record),
        _ => Err(service::Error::Invalid),
    }
}

fn verify_proof(record: &Intent, proof: &Proof) -> Result<()> {
    check(
        proof.same_account_before
            && proof.same_account_after
            && proof.provider_kind_windows_dpapi
            && proof.provider_available_after
            && proof.transport_acl_verified
            && proof.ciphertext_readable
            && proof.ciphertext_unchanged
            && proof.wrong_sid_rejected
            && proof.provider_error == ProviderError::Unavailable.to_string()
            && proof.local_service_sid == LS
            && proof.ciphertext_sha256 == record.ciphertext_sha256
            && proof.ciphertext_bytes == record.ciphertext_bytes,
    )?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    fn record() -> Intent {
        Intent {
            version: 1,
            id: Uuid::new_v4().to_string(),
            operator_sid: "S-1-5-21-1-2-3-1001".into(),
            binary_sha256: "b".repeat(64),
            ciphertext_sha256: "a".repeat(64),
            ciphertext_bytes: 256,
            phase: Phase::Prepared,
        }
    }
    fn proof(record: &Intent) -> Proof {
        Proof {
            same_account_before: true,
            same_account_after: true,
            provider_kind_windows_dpapi: true,
            provider_available_after: true,
            transport_acl_verified: true,
            ciphertext_readable: true,
            ciphertext_unchanged: true,
            ciphertext_sha256: record.ciphertext_sha256.clone(),
            ciphertext_bytes: record.ciphertext_bytes,
            wrong_sid_rejected: true,
            provider_error: ProviderError::Unavailable.to_string(),
            local_service_sid: LS.into(),
        }
    }
    #[test]
    fn proof_requires_crypto_rejection_and_all_positive_integrity_controls() {
        let record = record();
        assert!(verify_proof(&record, &proof(&record)).is_ok());
        for field in [
            "same_account_before",
            "same_account_after",
            "provider_kind_windows_dpapi",
            "provider_available_after",
            "transport_acl_verified",
            "ciphertext_readable",
            "ciphertext_unchanged",
            "wrong_sid_rejected",
        ] {
            let mut value = serde_json::to_value(proof(&record)).unwrap();
            value[field] = false.into();
            assert!(verify_proof(&record, &serde_json::from_value(value).unwrap()).is_err());
        }
        let mut value = proof(&record);
        value.provider_error = ProviderError::InvalidStorage.to_string();
        assert!(verify_proof(&record, &value).is_err());
        let mut value = proof(&record);
        value.ciphertext_sha256 = "0".repeat(64);
        assert!(verify_proof(&record, &value).is_err());
        let mut value = proof(&record);
        value.local_service_sid = record.operator_sid.clone();
        assert!(verify_proof(&record, &value).is_err());
    }
    #[test]
    fn native_scm_command_is_full_and_contains_no_bundle_or_profile_secret() {
        let record = record();
        let command = record.command().unwrap();
        assert_eq!(
            service::parse(&command).unwrap(),
            vec![
                record.binary().unwrap().to_str().unwrap().to_owned(),
                record.id.clone(),
                "probe-dpapi".into()
            ]
        );
        assert!(!command.contains(std::str::from_utf8(PAYLOAD).unwrap()));
        assert_eq!(
            record.info().unwrap().start_type,
            ServiceStartType::OnDemand
        );
        assert!(record.info().unwrap().account_password.is_none());
    }
    #[test]
    fn pending_disabled_retry_is_read_only_and_keeps_all_other_fields_exact() {
        let mut record = record();
        let mut config = ServiceConfig {
            service_type: ServiceType::OWN_PROCESS,
            start_type: ServiceStartType::Disabled,
            error_control: ServiceErrorControl::Normal,
            executable_path: PathBuf::from(record.command().unwrap()),
            load_order_group: None,
            tag_id: 0,
            dependencies: vec![],
            account_name: Some(r"NT AUTHORITY\LocalService".into()),
            display_name: record.name().into(),
        };
        for phase in [
            Phase::Prepared,
            Phase::Created,
            Phase::Running,
            Phase::Complete,
            Phase::Deleting,
        ] {
            record.phase = phase;
            assert!(record.verify_config(&config, false).is_err());
            assert_eq!(
                record.verify_config(&config, true).is_ok(),
                phase == Phase::Deleting
            );
        }
        config.executable_path = PathBuf::from(format!("{} extra", record.command().unwrap()));
        assert!(record.verify_config(&config, true).is_err());
    }
    #[test]
    fn synthetic_transport_acl_is_exact_and_rejects_extra_sid() {
        let executable = normalized(&std::env::current_exe().unwrap()).unwrap();
        let source = executable.ancestors().nth(4).unwrap();
        let temporary = tempfile::Builder::new()
            .prefix(&format!("dpapi-transport-{}-", Uuid::new_v4()))
            .tempdir_in(source)
            .unwrap();
        let path = temporary.path().join("ciphertext.bin");
        let sid = current_sid().unwrap();
        write_shared(&path, &sid, LS, b"public-synthetic-ciphertext", false).unwrap();
        assert_eq!(
            read_shared(&path, &sid, LS, 64).unwrap(),
            b"public-synthetic-ciphertext"
        );
        let acl = Security::new(&format!(
            "O:{sid}D:P(A;;FA;;;{sid})(A;;FA;;;SY)(A;;FR;;;LS)(A;;FR;;;WD)"
        ))
        .unwrap();
        assert_ne!(
            unsafe {
                SetFileSecurityW(
                    wide(&path).as_ptr(),
                    DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                    acl.attributes.lpSecurityDescriptor,
                )
            },
            0
        );
        assert!(read_shared(&path, &sid, LS, 64).is_err());
    }
}
