//! Durable, top-level TUF trust state for a local file mirror. No installer.
#![cfg(any(unix, windows))]
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::{TryStreamExt, stream};
use jiff::Timestamp;
#[cfg(target_os = "macos")]
use lomi_remote_protocol::{HostId, ipc::IpcProfileId};
#[cfg(any(windows, target_os = "macos"))]
use rusqlite::config::DbConfig;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Instant,
};
#[cfg(unix)]
use std::{
    os::fd::AsRawFd,
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};

use tough::{
    RepositoryLoader, TargetName, Transport, TransportError, TransportErrorKind, TransportStream,
    schema::{Root, Signed, Snapshot, Targets, Timestamp as TufTimestamp},
};
use url::Url;

#[cfg(unix)]
mod activation;
#[cfg(windows)]
mod activation_windows;
#[cfg(windows)]
mod windows_storage;
#[cfg(feature = "release-root")]
mod embedded_root {
    include!(concat!(env!("OUT_DIR"), "/embedded_root.rs"));
}

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;
pub const MAX_METADATA: usize = 1024 * 1024;
/// Maximum size of an authenticated application executable or package.
pub const MAX_TARGET: usize = 256 * 1024 * 1024;
#[cfg(all(target_os = "macos", feature = "release-root"))]
fn verify_macos_activation_image(path: &Path) -> Result<()> {
    let team = embedded_root::MACOS_TEAM_ID
        .ok_or_else(|| invalid("release activation requires the compiled macOS Team ID pin"))?;
    lomi_platform::service_macos::custody::verify_release_image_team(path, team)?;
    Ok(())
}
// 32 root rotations, the current metadata chain, and two bounded Windows
// release targets (CLI plus managed-login host helper).
const MAX_TOTAL: usize = 576 * 1024 * 1024;
const STATE_FILES: [&str; 5] = [
    "root.json",
    "timestamp.json",
    "snapshot.json",
    "targets.json",
    "latest_known_time.json",
];
const BOOTSTRAP_PIN_FILE: &str = "bootstrap-root.sha256";
fn invalid(message: &str) -> Box<dyn std::error::Error + Send + Sync> {
    io::Error::new(io::ErrorKind::InvalidData, message).into()
}
#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}
#[cfg(windows)]
fn sync_dir(path: &Path) -> io::Result<()> {
    windows_storage::sync_dir(path)
}
#[cfg(unix)]
fn private_file(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !m.is_file()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o600
        || m.nlink() != 1
    {
        return Err(invalid("state file must be a private owned regular file"));
    }
    Ok(())
}
#[cfg(windows)]
fn private_file(path: &Path) -> Result<()> {
    windows_storage::private_file(path)
}
#[cfg(unix)]
fn private_dir(path: &Path) -> Result<()> {
    let m = fs::symlink_metadata(path)?;
    if !path.is_absolute()
        || fs::canonicalize(path)? != path
        || !m.is_dir()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o777 != 0o700
    {
        return Err(invalid(
            "trust directory must be canonical, owned and mode 0700",
        ));
    }
    // A private leaf alone is insufficient if another UID can rename an
    // ancestor and replace the lock/database pathname during an update.
    for ancestor in path.ancestors().skip(1) {
        let parent = fs::symlink_metadata(ancestor)?;
        let trusted_owner = parent.uid() == 0 || parent.uid() == unsafe { libc::geteuid() };
        let writable = parent.mode() & 0o022 != 0;
        if !parent.is_dir() || !trusted_owner || (writable && parent.mode() & 0o1000 == 0) {
            return Err(invalid("trust directory has an unsafe ancestor"));
        }
    }
    Ok(())
}
#[cfg(windows)]
fn private_dir(path: &Path) -> Result<()> {
    windows_storage::private_dir(path)
}
#[cfg(unix)]
fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}
#[cfg(windows)]
fn create_private(path: &Path, bytes: &[u8]) -> Result<()> {
    windows_storage::create_private_file(path, bytes)
}
fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}
fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
pub(crate) fn validate_release_custom(
    custom: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<()> {
    let (minimum, maximum) = release_schema_range(custom, platform)?;
    // Schema zero is used by paths that deliberately do not bind a host
    // profile (fresh installs and the Windows file-security broker). The
    // signed platform and schema-range shape remains mandatory there; an
    // existing profile supplies its actual schema before a normal update.
    if profile_schema != 0 && !(minimum..=maximum).contains(&profile_schema) {
        return Err(invalid(
            "release does not support the installed profile schema",
        ));
    }
    Ok(())
}

#[cfg(all(windows, feature = "release-root"))]
fn windows_service_signer(custom: &serde_json::Value) -> Result<String> {
    let policy = custom
        .get("lomiAuthenticode")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid("TUF target lacks signed Authenticode policy"))?;
    if policy.len() != 2
        || !policy.contains_key("format")
        || !policy.contains_key("thumbprint")
        || policy.get("format").and_then(serde_json::Value::as_u64) != Some(1)
    {
        return Err(invalid(
            "signed Authenticode policy has an unsupported shape",
        ));
    }
    let thumbprint = policy
        .get("thumbprint")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| invalid("signed Authenticode policy has no thumbprint"))?;
    if thumbprint.len() != 40 || !thumbprint.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid("signed Authenticode thumbprint is malformed"));
    }
    Ok(thumbprint.to_ascii_uppercase())
}

#[cfg(all(windows, feature = "release-root"))]
fn validate_windows_service_pair(
    primary: &serde_json::Value,
    helper: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<String> {
    validate_release_custom(primary, platform, profile_schema)?;
    validate_release_custom(helper, platform, profile_schema)?;
    if primary.get("lomiRelease") != helper.get("lomiRelease") {
        return Err(invalid(
            "Windows Host targets have different signed release policies",
        ));
    }
    let primary_signer = windows_service_signer(primary)?;
    let helper_signer = windows_service_signer(helper)?;
    if primary_signer != helper_signer {
        return Err(invalid(
            "Windows Host targets have different signed Authenticode signers",
        ));
    }
    Ok(primary_signer)
}

#[cfg(all(windows, feature = "release-root"))]
fn expected_windows_service_platform(platform: &str) -> Result<()> {
    if expected_windows_platform_name()? != platform {
        return Err(invalid(
            "Windows Host release platform does not match this updater",
        ));
    }
    Ok(())
}

#[cfg(all(windows, feature = "release-root"))]
fn expected_windows_platform_name() -> Result<&'static str> {
    match () {
        #[cfg(target_arch = "x86_64")]
        () => Ok("windows-x86_64"),
        #[cfg(target_arch = "aarch64")]
        () => Ok("windows-aarch64"),
        #[allow(unreachable_patterns)]
        _ => Err(invalid("unsupported Windows updater architecture")),
    }
}

#[cfg(all(windows, feature = "release-root"))]
fn admin_host_platform_status(
    account: &str,
    owner_sid: &str,
    cli_sha256: &str,
    helper_sha256: &str,
) -> Result<lomi_platform::windows::service_admin::AdminServiceStatus> {
    let status = lomi_platform::windows::service_admin::inspect(account)?
        .ok_or_else(|| invalid("administrator Host service registration is missing"))?;
    if !status.registered
        || status.account_sid != owner_sid
        || status.cli_sha256 != cli_sha256
        || status.helper_sha256 != helper_sha256
    {
        return Err(invalid(
            "administrator Host service binding differs from the verified pair",
        ));
    }
    if status.running && (!status.ready || status.process_id.is_none()) {
        return Err(invalid(
            "administrator Host has not passed its SCM readiness and process checks",
        ));
    }
    Ok(status)
}

#[cfg(all(windows, feature = "release-root"))]
struct VerifiedWindowsHostPair {
    primary_bytes: Vec<u8>,
    helper_bytes: Vec<u8>,
    primary_sha256: String,
    helper_sha256: String,
    signer: String,
}

#[cfg(all(windows, feature = "release-root"))]
fn load_active_windows_host_pair(
    activation_dir: &Path,
    platform: &str,
    profile_schema: u64,
) -> Result<VerifiedWindowsHostPair> {
    let pair = activation_windows::active_host_pair(activation_dir, platform)?
        .ok_or_else(|| invalid("active Windows Host pair is missing"))?;
    let signer = validate_windows_service_pair(
        &pair.primary_custom,
        &pair.helper_custom,
        platform,
        profile_schema,
    )?;
    let primary_bytes = read_bounded(&pair.primary_path, MAX_TARGET)?;
    let helper_bytes = read_bounded(&pair.helper_path, MAX_TARGET)?;
    let primary_sha256 = digest_hex(&primary_bytes);
    let helper_sha256 = digest_hex(&helper_bytes);
    Ok(VerifiedWindowsHostPair {
        primary_bytes,
        helper_bytes,
        primary_sha256,
        helper_sha256,
        signer,
    })
}

pub(crate) fn require_release_version(custom: &serde_json::Value, expected: &str) -> Result<()> {
    if expected.is_empty()
        || expected.len() > 128
        || custom
            .get("lomiRelease")
            .and_then(|release| release.get("version"))
            .and_then(serde_json::Value::as_str)
            != Some(expected)
    {
        return Err(invalid(
            "signed release does not match the requested version",
        ));
    }
    Ok(())
}

fn release_schema_range(custom: &serde_json::Value, platform: &str) -> Result<(u64, u64)> {
    let release = custom
        .get("lomiRelease")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| invalid("TUF target lacks signed lomiRelease policy"))?;
    let expected_keys = [
        "format",
        "maxProfileSchema",
        "minProfileSchema",
        "platform",
        "version",
    ];
    if release.len() != expected_keys.len()
        || expected_keys.iter().any(|key| !release.contains_key(*key))
        || release.get("format").and_then(serde_json::Value::as_u64) != Some(1)
        || release.get("platform").and_then(serde_json::Value::as_str) != Some(platform)
        || release
            .get("version")
            .and_then(serde_json::Value::as_str)
            .is_none_or(str::is_empty)
    {
        return Err(invalid(
            "signed lomiRelease policy has an unsupported shape or platform",
        ));
    }
    let minimum = release
        .get("minProfileSchema")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("signed release has no minimum profile schema"))?;
    let maximum = release
        .get("maxProfileSchema")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| invalid("signed release has no maximum profile schema"))?;
    if maximum < minimum {
        return Err(invalid(
            "signed release has an invalid profile schema range",
        ));
    }
    Ok((minimum, maximum))
}
#[cfg(unix)]
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    if !f.metadata()?.is_file() || f.metadata()?.len() > limit as u64 {
        return Err(invalid("file exceeds verification limit or is not regular"));
    }
    let mut out = Vec::new();
    f.take(limit as u64 + 1).read_to_end(&mut out)?;
    if out.len() > limit {
        return Err(invalid("file exceeds verification limit"));
    }
    Ok(out)
}
#[cfg(windows)]
fn read_bounded(path: &Path, limit: usize) -> Result<Vec<u8>> {
    windows_storage::read_bounded(path, limit)
}
struct State {
    generation: i64,
    files: [Option<Vec<u8>>; 5],
}

struct VerifiedTarget {
    bytes: Vec<u8>,
    custom: serde_json::Value,
}
impl State {
    fn checksum(&self) -> Vec<u8> {
        let mut h = Sha256::new();
        h.update(b"lomi-update-trust-state-v1");
        h.update(self.generation.to_be_bytes());
        for f in &self.files {
            match f {
                Some(v) => {
                    h.update([1]);
                    h.update((v.len() as u64).to_be_bytes());
                    h.update(v);
                }
                None => h.update([0]),
            }
        }
        h.finalize().to_vec()
    }
    fn root(&self) -> &[u8] {
        self.files[0].as_deref().expect("validated root")
    }
    fn validate(&self) -> Result<()> {
        if self.generation < 0 {
            return Err(invalid("invalid trust generation"));
        }
        for bytes in self.files.iter().flatten() {
            if bytes.is_empty() || bytes.len() > MAX_METADATA {
                return Err(invalid("missing or oversized committed metadata"));
            }
        }
        let root: Signed<Root> = serde_json::from_slice(
            self.files[0]
                .as_deref()
                .ok_or_else(|| invalid("missing committed root"))?,
        )?;
        root.signed.verify_role(&root)?;
        let clock: Timestamp = serde_json::from_slice(
            self.files[4]
                .as_deref()
                .ok_or_else(|| invalid("missing committed clock"))?,
        )?;
        if clock > Timestamp::now() {
            return Err(invalid("clock moved behind committed watermark"));
        }
        if self.generation == 0 {
            if self.files[1..4].iter().any(Option::is_some) {
                return Err(invalid("invalid bootstrap state"));
            }
            return Ok(());
        }
        let timestamp: Signed<TufTimestamp> = serde_json::from_slice(
            self.files[1]
                .as_deref()
                .ok_or_else(|| invalid("missing committed timestamp"))?,
        )?;
        let snapshot: Signed<Snapshot> = serde_json::from_slice(
            self.files[2]
                .as_deref()
                .ok_or_else(|| invalid("missing committed snapshot"))?,
        )?;
        let targets: Signed<Targets> = serde_json::from_slice(
            self.files[3]
                .as_deref()
                .ok_or_else(|| invalid("missing committed targets"))?,
        )?;
        root.signed.verify_role(&timestamp)?;
        root.signed.verify_role(&snapshot)?;
        root.signed.verify_role(&targets)?;
        if timestamp.signed.meta.len() != 1
            || timestamp
                .signed
                .meta
                .get("snapshot.json")
                .is_none_or(|m| m.version != snapshot.signed.version)
            || snapshot
                .signed
                .meta
                .get("targets.json")
                .is_none_or(|m| m.version != targets.signed.version)
        {
            return Err(invalid("committed metadata version mismatch"));
        }
        if targets
            .signed
            .delegations
            .as_ref()
            .is_some_and(|d| !d.roles.is_empty())
        {
            return Err(invalid(
                "delegated roles are not supported by this bounded wrapper",
            ));
        }
        Ok(())
    }
}
/// Holding this handle owns an exclusive, nonblocking OS lock for this directory.
/// A second process receives an error and must retry; no concurrent update proceeds.
pub struct TrustStore {
    db: Connection,
    directory: PathBuf,
    _lock: File,
    #[cfg(windows)]
    admin_host_area: Option<windows_storage::AdminHostReleaseArea>,
}
#[cfg(all(windows, feature = "release-root"))]
pub struct WindowsAdminHostServiceOutcome {
    pub status: lomi_platform::windows::service_admin::AdminServiceStatus,
    pub previously_running: bool,
}

/// Inspect the exact administrator-managed Windows Host registration and
/// authenticate its user-only Host endpoint when SCM reports it running.
/// Call from the selected ordinary account; an elevated administrator must
/// use the SCM-only platform inspection because the Host IPC ACL stays
/// user-only.
#[cfg(all(windows, feature = "release-root"))]
pub fn inspect_admin_host_service(
    account: &str,
) -> Result<Option<lomi_platform::windows::service_admin::AdminServiceStatus>> {
    let mut status = lomi_platform::windows::service_admin::inspect(account)?;
    if let Some(status) = status.as_mut()
        && status.running
    {
        status.ready = status.ready
            && status.process_id.is_some_and(|pid| {
                lomi_platform::windows::service_admin::authenticated_host_status(
                    &status.profile,
                    pid,
                )
            });
    }
    Ok(status)
}

enum ProfileBarrier {
    #[cfg(unix)]
    Unix {
        _lock: lomi_platform::unix::OwnerLock,
    },
    #[cfg(windows)]
    Windows {
        _lock: lomi_platform::windows::OwnerLock,
    },
    #[cfg(target_os = "macos")]
    MacAdminHost {
        _guard: lomi_platform::service_macos::BootMaintenanceGuard,
    },
}
fn acquire_profile_barrier(profile: &Path) -> Result<Option<ProfileBarrier>> {
    match fs::symlink_metadata(profile) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            #[cfg(unix)]
            let barrier = lomi_platform::unix::OwnerLock::acquire(profile)
                .map(|_lock| ProfileBarrier::Unix { _lock })
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            #[cfg(windows)]
            let barrier = lomi_platform::windows::OwnerLock::acquire(profile)
                .map(|_lock| ProfileBarrier::Windows { _lock })
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            Ok(Some(barrier))
        }
    }
}
fn acquire_profile_barrier_for_install(profile: &Path) -> Result<ProfileBarrier> {
    #[cfg(unix)]
    let barrier = lomi_platform::unix::OwnerLock::acquire(profile)
        .map(|_lock| ProfileBarrier::Unix { _lock })
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    #[cfg(windows)]
    let barrier = lomi_platform::windows::OwnerLock::acquire(profile)
        .map(|_lock| ProfileBarrier::Windows { _lock })
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    Ok(barrier)
}

#[cfg(target_os = "macos")]
fn acquire_admin_host_profile_barrier(
    profile: &Path,
    install_dir: &Path,
    selected_account: &str,
    host_mode: lomi_platform::service_macos::AdminHostMode,
    recovery: bool,
    uninstall: bool,
) -> Result<ProfileBarrier> {
    if recovery && uninstall {
        return Err(invalid("admin Host guard mode is ambiguous"));
    }
    let bound_mode = bind_admin_host_profile(profile, install_dir, selected_account, host_mode)?;
    if bound_mode != host_mode {
        return Err(invalid(
            "admin install Host mode does not match its binding",
        ));
    }
    let guard = lomi_platform::service_macos::acquire_admin_maintenance_guard(
        profile,
        &install_dir.join("lomiremote"),
        selected_account,
        bound_mode,
        recovery,
        uninstall,
    )
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    if guard.host_mode() != bound_mode {
        return Err(invalid(
            "admin Host guard mode differs from its install binding",
        ));
    }
    Ok(ProfileBarrier::MacAdminHost { _guard: guard })
}

#[cfg(target_os = "macos")]
fn acquire_admin_host_initial_install_profile_barrier(
    profile: &Path,
    install_dir: &Path,
    selected_account: &str,
    host_mode: lomi_platform::service_macos::AdminHostMode,
) -> Result<ProfileBarrier> {
    let bound_mode = bind_admin_host_profile(profile, install_dir, selected_account, host_mode)?;
    if bound_mode != host_mode {
        return Err(invalid(
            "admin install Host mode does not match its binding",
        ));
    }
    let guard = lomi_platform::service_macos::acquire_admin_initial_install_guard(
        profile,
        &install_dir.join("lomiremote"),
        selected_account,
        bound_mode,
    )
    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    if guard.host_mode() != bound_mode {
        return Err(invalid(
            "admin Host guard mode differs from its install binding",
        ));
    }
    Ok(ProfileBarrier::MacAdminHost { _guard: guard })
}

#[cfg(target_os = "macos")]
fn resume_admin_host_if_was_running(
    profile_barrier: ProfileBarrier,
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
) -> Result<()> {
    let was_running = profile_barrier.admin_host_was_running()?;
    let host_mode = profile_barrier.admin_host_mode()?;
    drop(profile_barrier);
    if was_running {
        lomi_platform::service_macos::run_admin_host(
            profile_dir,
            &install_dir.join("lomiremote"),
            "start",
            host_mode,
            selected_account,
        )
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn fail_admin_host_preflight<T>(
    profile_barrier: ProfileBarrier,
    error: Box<dyn std::error::Error + Send + Sync>,
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
) -> Result<T> {
    if !matches!(admin_host_release_recovery_pending(install_dir), Ok(false)) {
        drop(profile_barrier);
        return Err(error);
    }
    match resume_admin_host_if_was_running(
        profile_barrier,
        profile_dir,
        install_dir,
        selected_account,
    ) {
        Ok(()) => Err(error),
        Err(resume_error) => Err(invalid(&format!(
            "{error}; failed to restore the previously running Host: {resume_error}"
        ))),
    }
}

#[cfg(target_os = "macos")]
fn complete_admin_host_mutation<T>(
    profile_barrier: ProfileBarrier,
    custody_state: lomi_platform::service_macos::AdminHostCustodyMaintenanceState,
    result: Result<T>,
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
) -> Result<T> {
    match result {
        Ok(value) => {
            profile_barrier.finish_admin_host_custody_maintenance(custody_state)?;
            resume_admin_host_if_was_running(
                profile_barrier,
                profile_dir,
                install_dir,
                selected_account,
            )?;
            Ok(value)
        }
        Err(error) => {
            // A pending activation keeps the Host and custodian stopped until
            // the next verified recovery pass. If activation rolled back
            // cleanly, the previous signed image can safely resume its mode.
            if matches!(admin_host_release_recovery_pending(install_dir), Ok(false)) {
                profile_barrier.finish_admin_host_custody_maintenance(custody_state)?;
                resume_admin_host_if_was_running(
                    profile_barrier,
                    profile_dir,
                    install_dir,
                    selected_account,
                )?;
            }
            Err(error)
        }
    }
}
impl ProfileBarrier {
    fn profile_path(&self) -> &Path {
        match self {
            #[cfg(unix)]
            Self::Unix { _lock } => _lock.profile().path(),
            #[cfg(windows)]
            Self::Windows { _lock } => _lock.profile().path(),
            #[cfg(target_os = "macos")]
            Self::MacAdminHost { _guard } => _guard.profile_path(),
        }
    }

    #[cfg(target_os = "macos")]
    fn admin_host_profile_schema(&self, install_dir: &Path) -> Result<u64> {
        match self {
            Self::MacAdminHost { _guard } => read_admin_profile_schema(_guard, install_dir),
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn admin_host_profile_snapshot(
        &self,
        install_dir: &Path,
    ) -> Result<(u64, Option<AdminHostProfileIdentity>)> {
        match self {
            Self::MacAdminHost { _guard } => read_admin_profile_snapshot(_guard, install_dir),
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn verify_admin_host_identity_binding(
        &self,
        identity: &AdminHostProfileIdentity,
    ) -> Result<()> {
        match self {
            Self::MacAdminHost { _guard } => {
                lomi_platform::service_macos::verify_admin_host_identity_binding(
                    _guard,
                    &identity.host_id_text(),
                    &identity.profile_id_text(),
                )
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
            _ => Err(invalid("admin Host profile guard is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn publish_admin_host_identity_binding(
        &self,
        identity: &AdminHostProfileIdentity,
    ) -> Result<()> {
        match self {
            Self::MacAdminHost { _guard } => {
                lomi_platform::service_macos::publish_admin_host_identity_binding(
                    _guard,
                    &identity.host_id_text(),
                    &identity.profile_id_text(),
                )
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
            _ => Err(invalid("admin Host profile guard is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn uninstall_admin_host_service_registration(&mut self) -> Result<()> {
        match self {
            Self::MacAdminHost { _guard } => _guard
                .uninstall_service_registration()
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>),
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn begin_admin_host_custody_maintenance(
        &self,
    ) -> Result<lomi_platform::service_macos::AdminHostCustodyMaintenanceState> {
        match self {
            Self::MacAdminHost { _guard } => {
                lomi_platform::service_macos::begin_admin_host_custody_maintenance(_guard)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn finish_admin_host_custody_maintenance(
        &self,
        state: lomi_platform::service_macos::AdminHostCustodyMaintenanceState,
    ) -> Result<()> {
        match self {
            Self::MacAdminHost { _guard } => {
                lomi_platform::service_macos::finish_admin_host_custody_maintenance(_guard, state)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn uninstall_admin_host_custodian(&self) -> Result<()> {
        match self {
            Self::MacAdminHost { _guard } => {
                lomi_platform::service_macos::uninstall_admin_host_custodian(_guard)
                    .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
            }
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn admin_host_was_running(&self) -> Result<bool> {
        match self {
            Self::MacAdminHost { _guard } => {
                Ok(lomi_platform::service_macos::admin_host_was_running(_guard))
            }
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }

    #[cfg(target_os = "macos")]
    fn admin_host_mode(&self) -> Result<lomi_platform::service_macos::AdminHostMode> {
        match self {
            Self::MacAdminHost { _guard } => Ok(_guard.host_mode()),
            _ => Err(invalid("admin Host profile barrier is unavailable")),
        }
    }
}
fn validate_profile_database_file(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            return Err(invalid(
                "profile database file is not a private owned regular file",
            ));
        }
    }
    #[cfg(windows)]
    {
        windows_storage::private_file(path)?;
    }
    Ok(())
}

/// Read the SQLite schema only while the caller holds OwnerLock. Database and
/// sidecar paths are checked against the profile's native ownership policy
/// before opening SQLite in read-only, no-follow mode.
fn read_profile_database_schema(profile: &Path) -> Result<u64> {
    let mut main_database_present = false;
    let mut sidecar_present = false;
    for name in [
        "host.sqlite3",
        "host.sqlite3-journal",
        "host.sqlite3-wal",
        "host.sqlite3-shm",
    ] {
        let path = profile.join(name);
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                validate_profile_database_file(&path)?;
                if name == "host.sqlite3" {
                    main_database_present = true;
                } else {
                    sidecar_present = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !main_database_present {
        if sidecar_present {
            return Err(invalid(
                "profile SQLite sidecar exists without its main database",
            ));
        }
        return Ok(0);
    }

    let database = Connection::open_with_flags(
        profile.join("host.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    let integrity: String = database.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(invalid("profile SQLite database failed quick_check"));
    }
    let version: i64 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let version = u64::try_from(version)
        .map_err(|_| invalid("profile SQLite schema version is negative or unknown"))?;
    if version == 0 {
        return Err(invalid(
            "schema zero is allowed only when the profile database is absent",
        ));
    }
    Ok(version)
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminHostDatabaseIdentity {
    host_id: String,
    profile_id: String,
}

#[cfg(windows)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct AdminHostDatabaseObservation {
    schema_version: u64,
    identity: Option<AdminHostDatabaseIdentity>,
}

#[cfg(windows)]
fn canonical_database_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
        && value != "00000000-0000-0000-0000-000000000000"
}

#[cfg(windows)]
fn read_admin_host_database_observation(
    snapshot: &lomi_platform::windows::service_admin::HostDatabaseSnapshot,
) -> Result<AdminHostDatabaseObservation> {
    use std::os::windows::fs::MetadataExt;

    // The platform capability omits empty rollback journals and rejects
    // nonempty ones before SQLite can follow a journal-supplied super-journal
    // path. SQLite may mutate only this private copy while recovering WAL.
    snapshot.verify_sources()?;
    let directory = snapshot.path();
    let mut main_present = false;
    let mut sidecar_present = false;
    for name in ["host.sqlite3", "host.sqlite3-journal", "host.sqlite3-wal"] {
        let path = directory.join(name);
        match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                if !metadata.is_file()
                    || metadata.file_attributes()
                        & windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT
                        != 0
                {
                    return Err(invalid("private profile snapshot contains an unsafe file"));
                }
                if name == "host.sqlite3" {
                    main_present = true;
                } else {
                    sidecar_present = true;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    if !main_present {
        if sidecar_present {
            return Err(invalid(
                "profile SQLite sidecar exists without its main database",
            ));
        }
        snapshot.verify_sources()?;
        return Ok(AdminHostDatabaseObservation {
            schema_version: 0,
            identity: None,
        });
    }

    let database = Connection::open_with_flags(
        directory.join("host.sqlite3"),
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX
            | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    if !database.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?
        || database.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?
    {
        return Err(invalid(
            "SQLite snapshot defensive configuration was not applied",
        ));
    }
    let integrity: String = database.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(invalid("profile database snapshot failed quick_check"));
    }
    let version: i64 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
    let version = u64::try_from(version)
        .map_err(|_| invalid("profile SQLite schema version is negative or unknown"))?;
    if version == 0 {
        return Err(invalid("profile database schema zero is unsupported"));
    }
    let metadata_table: bool = database.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata')",
        [],
        |row| row.get(0),
    )?;
    if !metadata_table {
        return Err(invalid("profile database identity metadata is missing"));
    }
    let identity_count: i64 = database.query_row(
        "SELECT COUNT(*) FROM metadata WHERE key='identity'",
        [],
        |row| row.get(0),
    )?;
    if identity_count != 1 {
        return Err(invalid("profile database identity metadata is ambiguous"));
    }
    let identity_length: Option<i64> = database.query_row(
        "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='identity'",
        [],
        |row| row.get(0),
    )?;
    if !identity_length.is_some_and(|length| (1..=4096).contains(&length)) {
        return Err(invalid("profile database identity metadata is invalid"));
    }
    let identity_wire: String = database.query_row(
        "SELECT value FROM metadata WHERE key='identity'",
        [],
        |row| row.get(0),
    )?;
    let identity: AdminHostDatabaseIdentity = serde_json::from_str(&identity_wire)
        .map_err(|_| invalid("profile database identity metadata is malformed"))?;
    if !canonical_database_uuid(&identity.host_id) || !canonical_database_uuid(&identity.profile_id)
    {
        return Err(invalid(
            "profile database identity metadata is not canonical",
        ));
    }
    drop(database);
    snapshot.verify_sources()?;
    Ok(AdminHostDatabaseObservation {
        schema_version: version,
        identity: Some(identity),
    })
}

#[cfg(target_os = "macos")]
const MAX_ADMIN_PROFILE_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;

#[cfg(target_os = "macos")]
struct AdminProfileSnapshot {
    install_dir: PathBuf,
    directory: PathBuf,
    cleaned: bool,
}

#[cfg(target_os = "macos")]
#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
struct AdminHostProfileIdentity {
    host_id: HostId,
    profile_id: IpcProfileId,
}

#[cfg(target_os = "macos")]
impl AdminHostProfileIdentity {
    fn host_id_text(&self) -> String {
        String::from(self.host_id)
    }

    fn profile_id_text(&self) -> String {
        String::from(self.profile_id)
    }
}

#[cfg(target_os = "macos")]
struct AdminProfileComponentSnapshot {
    name: &'static str,
    source: Option<(File, std::fs::Metadata)>,
}

#[cfg(target_os = "macos")]
impl AdminProfileSnapshot {
    fn create(install_dir: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let parent = fs::symlink_metadata(install_dir)?;
        if parent.file_type().is_symlink()
            || !parent.is_dir()
            || parent.uid() != 0
            || parent.mode() & 0o777 != 0o755
        {
            return Err(invalid(
                "admin install directory changed before schema snapshot",
            ));
        }
        static NEXT_SNAPSHOT: AtomicUsize = AtomicUsize::new(0);
        let mut directory = None;
        for _ in 0..64 {
            let candidate = install_dir.join(format!(
                ".profile-schema-{}-{}",
                std::process::id(),
                NEXT_SNAPSHOT.fetch_add(1, Ordering::Relaxed)
            ));
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(&candidate) {
                Ok(()) => {
                    directory = Some(candidate);
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        let directory =
            directory.ok_or_else(|| invalid("could not reserve private schema snapshot"))?;
        let snapshot = Self {
            install_dir: install_dir.to_path_buf(),
            directory,
            cleaned: false,
        };
        sync_dir(install_dir)?;
        let metadata = fs::symlink_metadata(&snapshot.directory)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o700
        {
            return Err(invalid(
                "private schema snapshot has unsafe ownership or mode",
            ));
        }
        Ok(snapshot)
    }

    fn copy_component(
        &self,
        guard: &lomi_platform::service_macos::BootMaintenanceGuard,
        name: &'static str,
        total: &mut u64,
    ) -> Result<AdminProfileComponentSnapshot> {
        use std::os::unix::fs::MetadataExt;

        let Some(mut source) = guard
            .open_database_component(name)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
        else {
            return Ok(AdminProfileComponentSnapshot { name, source: None });
        };
        let before = source.metadata()?;
        if name == "host.sqlite3-journal" {
            // A rollback journal can name an external super-journal which
            // SQLite deletes during recovery. Never recover owner-authored
            // rollback bytes in this elevated process, even from a private copy.
            if before.len() != 0 {
                return Err(invalid(
                    "profile rollback journal requires ordinary-account recovery",
                ));
            }
            return Ok(AdminProfileComponentSnapshot {
                name,
                source: Some((source, before)),
            });
        }
        let next_total = total
            .checked_add(before.len())
            .ok_or_else(|| invalid("profile database snapshot size overflow"))?;
        if next_total > MAX_ADMIN_PROFILE_SNAPSHOT_BYTES {
            return Err(invalid("profile database snapshot exceeds its size bound"));
        }
        let destination = self.directory.join(name);
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&destination)?;
        let mut copied = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let read = source.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            copied = copied
                .checked_add(read as u64)
                .ok_or_else(|| invalid("profile database snapshot size overflow"))?;
            if copied > before.len() || copied > MAX_ADMIN_PROFILE_SNAPSHOT_BYTES {
                return Err(invalid(
                    "profile database file changed size while snapshotting",
                ));
            }
            output.write_all(&buffer[..read])?;
        }
        if copied != before.len() {
            return Err(invalid(
                "profile database file changed size while snapshotting",
            ));
        }
        output.sync_all()?;
        let after = source.metadata()?;
        if !same_profile_file_identity(&before, &after) {
            return Err(invalid("profile database file changed while snapshotting"));
        }
        let current = guard
            .open_database_component(name)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?
            .ok_or_else(|| invalid("profile database component disappeared while snapshotting"))?;
        if !same_profile_file_identity(&before, &current.metadata()?) {
            return Err(invalid(
                "profile database component was replaced while snapshotting",
            ));
        }
        let copied_metadata = output.metadata()?;
        if !copied_metadata.is_file()
            || copied_metadata.uid() != 0
            || copied_metadata.mode() & 0o777 != 0o600
            || copied_metadata.nlink() != 1
            || copied_metadata.len() != copied
        {
            return Err(invalid("private profile database snapshot file is unsafe"));
        }
        *total = next_total;
        sync_dir(&self.directory)?;
        Ok(AdminProfileComponentSnapshot {
            name,
            source: Some((source, before)),
        })
    }

    fn verify_source_set(
        &self,
        guard: &lomi_platform::service_macos::BootMaintenanceGuard,
        components: &[AdminProfileComponentSnapshot],
    ) -> Result<()> {
        for component in components {
            let current = guard
                .open_database_component(component.name)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            match (&component.source, current) {
                (None, None) => {}
                (Some((source, before)), Some(current)) => {
                    if !same_profile_file_identity(before, &source.metadata()?)
                        || !same_profile_file_identity(before, &current.metadata()?)
                    {
                        return Err(invalid(
                            "profile database component changed during snapshot",
                        ));
                    }
                }
                _ => {
                    return Err(invalid(
                        "profile database component set changed during snapshot",
                    ));
                }
            }
        }
        Ok(())
    }

    fn read_schema_and_identity(
        &self,
        guard: &lomi_platform::service_macos::BootMaintenanceGuard,
    ) -> Result<(u64, Option<AdminHostProfileIdentity>)> {
        let mut total = 0u64;
        let mut main_present = false;
        let mut sidecar_present = false;
        let mut components = Vec::with_capacity(4);
        for name in [
            "host.sqlite3",
            "host.sqlite3-journal",
            "host.sqlite3-wal",
            "host.sqlite3-shm",
        ] {
            let component = self.copy_component(guard, name, &mut total)?;
            let present = component.source.is_some();
            if name == "host.sqlite3" {
                main_present = present;
            } else {
                sidecar_present |= present;
            }
            components.push(component);
        }
        self.verify_source_set(guard, &components)?;
        if !main_present {
            if sidecar_present {
                return Err(invalid(
                    "profile SQLite sidecar exists without its main database",
                ));
            }
            return Ok((0, None));
        }
        let database = Connection::open_with_flags(
            self.directory.join("host.sqlite3"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        if !database.set_db_config(DbConfig::SQLITE_DBCONFIG_DEFENSIVE, true)?
            || database.set_db_config(DbConfig::SQLITE_DBCONFIG_TRUSTED_SCHEMA, false)?
        {
            return Err(invalid(
                "profile SQLite snapshot policy could not be enforced",
            ));
        }
        let integrity: String = database.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
        if integrity != "ok" {
            return Err(invalid("profile SQLite snapshot failed quick_check"));
        }
        let version: i64 = database.pragma_query_value(None, "user_version", |row| row.get(0))?;
        let version = u64::try_from(version)
            .map_err(|_| invalid("profile SQLite schema version is negative or unknown"))?;
        if version == 0 {
            return Err(invalid(
                "schema zero is allowed only when the profile database is absent",
            ));
        }
        let identity_length: i64 = database
            .query_row(
                "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key='identity'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| invalid("profile identity is missing from SQLite metadata"))?;
        if !(1..=4096).contains(&identity_length) {
            return Err(invalid(
                "profile identity metadata is outside its size bound",
            ));
        }
        let identity_wire: String = database
            .query_row(
                "SELECT value FROM metadata WHERE key='identity'",
                [],
                |row| row.get(0),
            )
            .map_err(|_| invalid("profile identity is missing from SQLite metadata"))?;
        let identity: AdminHostProfileIdentity = serde_json::from_str(&identity_wire)
            .map_err(|_| invalid("profile identity metadata is malformed"))?;
        if serde_json::to_vec(&identity)? != identity_wire.as_bytes() {
            return Err(invalid(
                "profile database identity metadata is not canonical",
            ));
        }
        self.verify_source_set(guard, &components)?;
        drop(database);
        Ok((version, Some(identity)))
    }

    fn cleanup(&mut self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;

        if self.cleaned {
            return Ok(());
        }
        let directory_metadata = fs::symlink_metadata(&self.directory)?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != 0
            || directory_metadata.mode() & 0o777 != 0o700
        {
            return Err(invalid(
                "refusing to clean an unsafe profile snapshot directory",
            ));
        }
        for entry in fs::read_dir(&self.directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                return Err(invalid("profile snapshot has an unknown file"));
            };
            if !matches!(
                name,
                "host.sqlite3" | "host.sqlite3-journal" | "host.sqlite3-wal" | "host.sqlite3-shm"
            ) {
                return Err(invalid("profile snapshot has an unknown file"));
            }
            let metadata = fs::symlink_metadata(entry.path())?;
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != 0
                || metadata.nlink() != 1
            {
                return Err(invalid(
                    "refusing to remove an unsafe profile snapshot file",
                ));
            }
            fs::remove_file(entry.path())?;
        }
        sync_dir(&self.directory)?;
        fs::remove_dir(&self.directory)?;
        sync_dir(&self.install_dir)?;
        self.cleaned = true;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for AdminProfileSnapshot {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

#[cfg(target_os = "macos")]
fn same_profile_file_identity(before: &std::fs::Metadata, after: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.mode() == after.mode()
        && before.nlink() == after.nlink()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

#[cfg(target_os = "macos")]
fn read_admin_profile_schema(
    guard: &lomi_platform::service_macos::BootMaintenanceGuard,
    install_dir: &Path,
) -> Result<u64> {
    read_admin_profile_snapshot(guard, install_dir).map(|(schema, _)| schema)
}

#[cfg(target_os = "macos")]
fn read_admin_profile_snapshot(
    guard: &lomi_platform::service_macos::BootMaintenanceGuard,
    install_dir: &Path,
) -> Result<(u64, Option<AdminHostProfileIdentity>)> {
    let mut snapshot = AdminProfileSnapshot::create(install_dir)?;
    let result = snapshot.read_schema_and_identity(guard);
    let cleanup = snapshot.cleanup();
    cleanup?;
    result
}

fn require_profile_schema_hint(profile: &Path, hint: u64) -> Result<u64> {
    let actual = read_profile_database_schema(profile)?;
    if actual != hint {
        return Err(invalid(
            "maintenance profile schema does not match the owner-locked database",
        ));
    }
    Ok(actual)
}
/// Remove only updater-owned activation pointers and hash-verified objects.
/// This deliberately remains available even if trust metadata is corrupt, so
/// recovery/uninstall does not depend on accepting the release currently on disk.
#[cfg(unix)]
pub fn uninstall_release(profile_dir: &Path, install_dir: &Path) -> Result<usize> {
    let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
    let _actual_profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
    let _profile_barrier = profile_barrier;
    activation::uninstall(install_dir)
}

/// Remove an ordinary signed installation before its Host was configured.
/// The caller must separately reject managed-service bindings. The affine
/// native proof holds the real owner lock and refuses every profile artifact
/// except that persistent lock, so no Host ID is fabricated from an absent DB.
#[cfg(any(unix, windows))]
pub fn uninstall_uninitialized_release(
    profile: &lomi_platform::empty_profile::EmptyHostProfile,
    install_dir: &Path,
) -> Result<usize> {
    profile.recheck()?;
    #[cfg(unix)]
    let removed = activation::uninstall(install_dir)?;
    #[cfg(windows)]
    let removed = activation_windows::uninstall(install_dir)?;
    profile.recheck()?;
    Ok(removed)
}

/// Validate an existing installer-owned directory without adopting or
/// modifying it. Installers call this before trusting any local updater state.
#[cfg(unix)]
pub fn validate_install_directory(install_dir: &Path) -> Result<()> {
    activation::validate_directory(install_dir)
}
/// Verify the exact activated executable, rather than trusting a regular file
/// or an executable's self-reported root, before invoking maintenance.
#[cfg(unix)]
pub fn verify_installed_maintenance_cli(install_dir: &Path, platform: &str) -> Result<()> {
    activation::verify_maintenance_cli(install_dir, platform, false)
}
#[cfg(target_os = "macos")]
pub fn verify_admin_installed_maintenance_cli(install_dir: &Path, platform: &str) -> Result<()> {
    activation::verify_maintenance_cli(install_dir, platform, true)
}
#[cfg(target_os = "macos")]
pub fn validate_admin_boot_install_directory(install_dir: &Path) -> Result<()> {
    activation::validate_admin_boot_directory(install_dir)
}
#[cfg(target_os = "macos")]
pub fn admin_boot_profile_path(account: &str) -> Result<PathBuf> {
    lomi_platform::service_macos::boot_profile_path_for_account(account)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
}
#[cfg(target_os = "macos")]
pub fn admin_boot_install_path(account: &str) -> Result<PathBuf> {
    lomi_platform::service_macos::boot_install_path_for_account(account)
        .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
}
#[cfg(target_os = "macos")]
pub fn bind_admin_boot_profile(
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
) -> Result<()> {
    bind_admin_host_profile(
        profile_dir,
        install_dir,
        selected_account,
        lomi_platform::service_macos::AdminHostMode::Boot,
    )
    .map(|_| ())
}
#[cfg(target_os = "macos")]
pub fn bind_admin_host_profile(
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
    host_mode: lomi_platform::service_macos::AdminHostMode,
) -> Result<lomi_platform::service_macos::AdminHostMode> {
    activation::validate_admin_boot_directory(install_dir)?;
    let (canonical_profile, account_uid) =
        lomi_platform::service_macos::validate_boot_profile(profile_dir, selected_account)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    let bound_mode = activation::bind_admin_host_identity(
        install_dir,
        account_uid,
        &canonical_profile,
        host_mode.as_str(),
    )?;
    let bound_mode = bound_mode
        .parse::<lomi_platform::service_macos::AdminHostMode>()
        .map_err(|_| invalid("admin install binding has an invalid Host mode"))?;
    if bound_mode != host_mode {
        return Err(invalid(
            "requested Host mode differs from admin install binding",
        ));
    }
    Ok(bound_mode)
}
#[cfg(windows)]
pub fn validate_install_directory(install_dir: &Path) -> Result<()> {
    activation_windows::validate_directory(install_dir)
}
#[cfg(windows)]
pub fn uninstall_release(profile_dir: &Path, install_dir: &Path) -> Result<usize> {
    let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
    let _actual_profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
    let _profile_barrier = profile_barrier;
    activation_windows::uninstall(install_dir)
}

/// Compatibility wrapper for uninstalling the administrator-managed boot Host.
#[cfg(target_os = "macos")]
pub fn uninstall_admin_boot_release(
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
) -> Result<usize> {
    uninstall_admin_host_release(
        profile_dir,
        install_dir,
        selected_account,
        lomi_platform::service_macos::AdminHostMode::Boot,
    )
}

/// Remove a macOS administrator-managed release for its bound Host mode.
#[cfg(target_os = "macos")]
pub fn uninstall_admin_host_release(
    profile_dir: &Path,
    install_dir: &Path,
    selected_account: &str,
    host_mode: lomi_platform::service_macos::AdminHostMode,
) -> Result<usize> {
    activation::validate_admin_boot_directory(install_dir)?;
    bind_admin_host_profile(profile_dir, install_dir, selected_account, host_mode)?;
    if admin_host_release_recovery_pending(install_dir)? {
        return Err(invalid(
            "recover the pending admin Host activation before uninstalling",
        ));
    }
    let mut profile_barrier = acquire_admin_host_profile_barrier(
        profile_dir,
        install_dir,
        selected_account,
        host_mode,
        false,
        true,
    )?;
    let _actual_profile_schema = match profile_barrier.admin_host_profile_schema(install_dir) {
        Ok(schema) => schema,
        Err(error) => {
            return fail_admin_host_preflight(
                profile_barrier,
                error,
                profile_dir,
                install_dir,
                selected_account,
            );
        }
    };
    let _custody_state = profile_barrier.begin_admin_host_custody_maintenance()?;
    profile_barrier.uninstall_admin_host_service_registration()?;
    // Drain custody before either registration is removed. Keeping its
    // registration until after the Host record is gone makes an interrupted
    // uninstall retryable without permitting a Host-without-custody state.
    profile_barrier.uninstall_admin_host_custodian()?;
    let _profile_barrier = profile_barrier;
    activation::uninstall_admin_boot(install_dir)
}

/// Report whether the install directory has a pending activation journal.
/// Installers must use this before launching the installed CLI because its
/// startup guard intentionally denies entry while recovery is pending.
#[cfg(unix)]
pub fn release_recovery_pending(install_dir: &Path) -> Result<bool> {
    activation::recovery_pending(install_dir)
}

/// Selected-account setup may resume an already activated Linux image after
/// recovery. This observes the real schema under the owner barrier and never
/// downloads, repairs, migrates, or replaces application/profile data.
#[cfg(target_os = "linux")]
pub fn validate_active_release(
    profile_dir: &Path,
    install_dir: &Path,
    platform: &str,
) -> Result<Option<PathBuf>> {
    if !platform.starts_with("linux-") {
        return Err(invalid(
            "selected-account release requires a Linux platform",
        ));
    }
    let barrier = acquire_profile_barrier_for_install(profile_dir)?;
    let schema = read_profile_database_schema(barrier.profile_path())?;
    activation::validate_active_release(install_dir, platform, schema)
}
#[cfg(target_os = "macos")]
pub fn admin_boot_release_recovery_pending(install_dir: &Path) -> Result<bool> {
    admin_host_release_recovery_pending(install_dir)
}
#[cfg(target_os = "macos")]
pub fn admin_host_release_recovery_pending(install_dir: &Path) -> Result<bool> {
    activation::recovery_pending_admin_boot(install_dir)
}
#[cfg(windows)]
pub fn release_recovery_pending(install_dir: &Path) -> Result<bool> {
    activation_windows::recovery_pending(install_dir)
}

/// Recover a pending activation without invoking the installed CLI. When a
/// managed service is registered it is stopped through the existing native
/// service adapter first; the owner lock and read-only SQLite schema check are
/// then held across release-policy validation and journal recovery.
pub fn recover_interrupted_release(
    profile_dir: &Path,
    install_dir: &Path,
    platform: &str,
) -> Result<Option<u64>> {
    if !release_recovery_pending(install_dir)? {
        return Ok(None);
    }
    stop_managed_release_service(profile_dir, install_dir, platform)?;
    let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
    let actual_profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
    let _profile_barrier = profile_barrier;
    if !release_recovery_pending(install_dir)? {
        return Ok(Some(actual_profile_schema));
    }
    #[cfg(unix)]
    activation::recover_verified(install_dir, platform, actual_profile_schema)?;
    #[cfg(windows)]
    activation_windows::recover_verified(install_dir, platform, actual_profile_schema)?;
    Ok(Some(actual_profile_schema))
}

/// Compatibility wrapper for recovering the administrator-managed boot Host.
#[cfg(target_os = "macos")]
pub fn recover_interrupted_admin_boot_release(
    profile_dir: &Path,
    install_dir: &Path,
    platform: &str,
    selected_account: &str,
) -> Result<Option<u64>> {
    recover_interrupted_admin_host_release(
        profile_dir,
        install_dir,
        platform,
        selected_account,
        lomi_platform::service_macos::AdminHostMode::Boot,
    )
}

#[cfg(target_os = "macos")]
pub fn recover_interrupted_admin_host_release(
    profile_dir: &Path,
    install_dir: &Path,
    platform: &str,
    selected_account: &str,
    host_mode: lomi_platform::service_macos::AdminHostMode,
) -> Result<Option<u64>> {
    if !platform.starts_with("macos-") {
        return Err(invalid("admin Host recovery requires a macOS target"));
    }
    bind_admin_host_profile(profile_dir, install_dir, selected_account, host_mode)?;
    let (canonical_profile, account_uid) =
        lomi_platform::service_macos::validate_boot_profile(profile_dir, selected_account)
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
    let root_receipt = activation::read_admin_profile_init_receipt(
        install_dir,
        account_uid,
        &canonical_profile,
        host_mode.as_str(),
    )?;
    let activation_pending = admin_host_release_recovery_pending(install_dir)?;
    let pending_profile_init = root_receipt
        .as_ref()
        .is_some_and(|receipt| receipt.is_pending());
    if !activation_pending && !pending_profile_init {
        return Ok(None);
    }
    if pending_profile_init && !activation_pending {
        let receipt = root_receipt
            .as_ref()
            .ok_or_else(|| invalid("pending admin profile initialization receipt disappeared"))?;
        if activation::pending_admin_profile_init_target(
            install_dir,
            receipt,
            account_uid,
            &canonical_profile,
            host_mode.as_str(),
            platform,
        )?
        .is_none()
        {
            // The release is still positively at its untouched initial state;
            // the normal install path must fetch and activate the verified
            // image before any selected-account profile initialization.
            return Ok(None);
        }
    }
    let profile_barrier = acquire_admin_host_profile_barrier(
        profile_dir,
        install_dir,
        selected_account,
        host_mode,
        activation_pending,
        false,
    )?;
    let snapshot = if pending_profile_init && !activation_pending {
        None
    } else {
        Some(
            match profile_barrier.admin_host_profile_snapshot(install_dir) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return fail_admin_host_preflight(
                        profile_barrier,
                        error,
                        profile_dir,
                        install_dir,
                        selected_account,
                    );
                }
            },
        )
    };
    let preflight_identity = snapshot
        .as_ref()
        .and_then(|(_, identity)| identity.as_ref())
        .cloned();
    let identity_validation = (|| -> Result<()> {
        if let Some(receipt) = root_receipt.as_ref()
            && receipt.is_complete()
        {
            let identity = snapshot
                .as_ref()
                .and_then(|(_, identity)| identity.as_ref())
                .ok_or_else(|| invalid("completed admin profile identity is missing"))?;
            if activation::verify_admin_profile_init_identity(
                install_dir,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                &identity.host_id_text(),
                &identity.profile_id_text(),
            )? != Some(activation::AdminProfileInitState::Complete)
            {
                return Err(invalid(
                    "completed admin profile identity receipt is unavailable",
                ));
            }
            profile_barrier.publish_admin_host_identity_binding(identity)?;
        }
        Ok(())
    })();
    if let Err(error) = identity_validation {
        return fail_admin_host_preflight(
            profile_barrier,
            error,
            profile_dir,
            install_dir,
            selected_account,
        );
    }
    let actual_profile_schema = snapshot.as_ref().map_or(0, |value| value.0);
    let custody_state = profile_barrier.begin_admin_host_custody_maintenance()?;
    let mut profile_barrier = profile_barrier;
    let recovered = (|| -> Result<Option<u64>> {
        if activation_pending {
            activation::recover_verified_admin_boot(install_dir, platform, actual_profile_schema)?;
        }
        if pending_profile_init {
            let receipt = root_receipt.as_ref().ok_or_else(|| {
                invalid("pending admin profile initialization receipt disappeared")
            })?;
            let Some(_) = activation::pending_admin_profile_init_target(
                install_dir,
                receipt,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                platform,
            )?
            else {
                return Ok(Some(actual_profile_schema));
            };
            lomi_platform::service_macos::initialize_admin_host_profile_after_pending_activation(
                match &mut profile_barrier {
                    ProfileBarrier::MacAdminHost { _guard } => _guard,
                    _ => return Err(invalid("admin Host profile guard is unavailable")),
                },
            )
            .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
            let (schema, identity) = profile_barrier.admin_host_profile_snapshot(install_dir)?;
            let identity =
                identity.ok_or_else(|| invalid("initialized admin profile identity is missing"))?;
            activation::complete_admin_profile_init_receipt(
                install_dir,
                receipt,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                platform,
                schema,
                &identity.host_id_text(),
                &identity.profile_id_text(),
            )?;
            profile_barrier.publish_admin_host_identity_binding(&identity)?;
            return Ok(Some(schema));
        }
        if let Some(receipt) = root_receipt.as_ref()
            && receipt.is_complete()
        {
            let (_, identity) = profile_barrier.admin_host_profile_snapshot(install_dir)?;
            let identity =
                identity.ok_or_else(|| invalid("completed admin profile identity is missing"))?;
            if activation::verify_admin_profile_init_identity(
                install_dir,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                &identity.host_id_text(),
                &identity.profile_id_text(),
            )? != Some(activation::AdminProfileInitState::Complete)
            {
                return Err(invalid("completed admin profile receipt is not valid"));
            }
            profile_barrier.publish_admin_host_identity_binding(&identity)?;
        } else if activation_pending && root_receipt.is_none() {
            let (schema, identity) = profile_barrier.admin_host_profile_snapshot(install_dir)?;
            let identity = identity.ok_or_else(|| {
                invalid("legacy admin profile identity is missing during migration")
            })?;
            if preflight_identity.as_ref() != Some(&identity) {
                return Err(invalid(
                    "legacy admin profile identity changed during activation recovery",
                ));
            }
            profile_barrier.verify_admin_host_identity_binding(&identity)?;
            activation::adopt_existing_admin_profile_identity(
                install_dir,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                platform,
                schema,
                &identity.host_id_text(),
                &identity.profile_id_text(),
            )?;
            profile_barrier.publish_admin_host_identity_binding(&identity)?;
            return Ok(Some(schema));
        }
        Ok(Some(actual_profile_schema))
    })();
    complete_admin_host_mutation(
        profile_barrier,
        custody_state,
        recovered,
        profile_dir,
        install_dir,
        selected_account,
    )
}

fn stop_managed_release_service(
    profile_dir: &Path,
    install_dir: &Path,
    platform: &str,
) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        if !platform.starts_with("linux-") {
            return Err(invalid(
                "release recovery platform does not match this operating system",
            ));
        }
        let registration = profile_dir.join("service-registration.json");
        match fs::symlink_metadata(&registration) {
            Ok(_) => {
                lomi_platform::service_linux::run(
                    profile_dir,
                    &install_dir.join("lomiremote"),
                    "stop",
                    None,
                    None,
                )
                .map_err(|_| invalid("profile-owned Linux service could not be stopped safely"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(target_os = "macos")]
    {
        if !platform.starts_with("macos-") {
            return Err(invalid(
                "release recovery platform does not match this operating system",
            ));
        }
        let registration = profile_dir.join("service-registration-macos.json");
        match fs::symlink_metadata(&registration) {
            Ok(_) => {
                lomi_platform::service_macos::run(
                    profile_dir,
                    &install_dir.join("lomiremote"),
                    "stop",
                    None,
                    None,
                )
                .map_err(|_| invalid("profile-owned macOS service could not be stopped safely"))?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    #[cfg(windows)]
    {
        if !platform.starts_with("windows-") {
            return Err(invalid(
                "release recovery platform does not match this operating system",
            ));
        }
        let profile_name = profile_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| invalid("Windows profile directory is not canonical"))?;
        let task_registration = profile_dir
            .with_file_name(format!("{profile_name}-service-windows-login"))
            .join("registration.json");
        let service_registration = profile_dir
            .with_file_name(format!("{profile_name}-service-windows"))
            .join("registration.json");
        let login_present = match fs::symlink_metadata(&task_registration) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let service_present = match fs::symlink_metadata(&service_registration) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        let executable = install_dir.join("lomiremote.exe");
        let helper = install_dir.join("lomiremote-host.exe");
        if login_present {
            lomi_platform::service_windows_login::run(profile_dir, &helper, "stop", None).map_err(
                |_| invalid("profile-owned Windows login task could not be stopped safely"),
            )?;
        }
        if service_present {
            lomi_platform::service_windows::run(profile_dir, &executable, &helper, "stop", None)
                .map_err(|_| {
                    invalid("profile-owned Windows service could not be stopped safely")
                })?;
        }
    }
    Ok(())
}

#[cfg(all(any(unix, windows), feature = "release-root"))]
pub fn embedded_root_sha256() -> Result<&'static str> {
    if digest_hex(embedded_root::ROOT) != embedded_root::SHA256 {
        return Err(invalid("embedded public root failed its pinned digest"));
    }
    Ok(embedded_root::SHA256)
}

impl TrustStore {
    /// One-shot bootstrap. Existing directories are deliberately never reset.
    pub fn initialize(directory: &Path, bootstrap: &[u8]) -> Result<Self> {
        if bootstrap.len() > MAX_METADATA {
            return Err(invalid("bootstrap root too large"));
        }
        #[cfg(unix)]
        fs::DirBuilder::new().mode(0o700).create(directory)?;
        #[cfg(windows)]
        windows_storage::create_private_dir(directory)?;
        private_dir(directory)?;
        sync_dir(
            directory
                .parent()
                .ok_or_else(|| invalid("missing parent"))?,
        )?;
        create_private(&directory.join("owner.lock"), b"")?;
        let lock = Self::lock(directory)?;
        create_private(
            &directory.join(BOOTSTRAP_PIN_FILE),
            format!("{}\n", digest_hex(bootstrap)).as_bytes(),
        )?;
        create_private(&directory.join("initialized"), b"lomi-update-trust-v1\n")?;
        // The durable marker is created before SQLite. Interrupted initialization
        // stays fail-closed and requires explicit administrative recovery.
        sync_dir(directory)?;
        create_private(&directory.join("trust.sqlite"), b"")?;
        let mut store = Self::connect(directory, lock)?;
        let state = State {
            generation: 0,
            files: [
                Some(bootstrap.to_vec()),
                None,
                None,
                None,
                Some(serde_json::to_vec(&Timestamp::now())?),
            ],
        };
        state.validate()?;
        let tx = store.db.transaction()?;
        tx.execute_batch("CREATE TABLE trust_state (id INTEGER PRIMARY KEY CHECK(id=1), format INTEGER NOT NULL CHECK(format=1), generation INTEGER NOT NULL, root BLOB NOT NULL, timestamp BLOB, snapshot BLOB, targets BLOB, clock BLOB NOT NULL, checksum BLOB NOT NULL);")?;
        tx.execute(
            "INSERT INTO trust_state VALUES(1,1,?1,?2,?3,?4,?5,?6,?7)",
            params![
                state.generation,
                state.files[0],
                state.files[1],
                state.files[2],
                state.files[3],
                state.files[4],
                state.checksum()
            ],
        )?;
        tx.commit()?;
        sync_dir(directory)?;
        store.read_state()?;
        Ok(store)
    }
    /// Initialize against bytes whose public root digest was pinned into the
    /// release at build time. The caller cannot override that digest at run time.
    pub fn initialize_pinned(
        directory: &Path,
        bootstrap: &[u8],
        expected_sha256: &str,
    ) -> Result<Self> {
        let expected = expected_sha256.to_ascii_lowercase();
        if !valid_digest(&expected) || digest_hex(bootstrap) != expected {
            return Err(invalid(
                "bootstrap root does not match the pinned public digest",
            ));
        }
        Self::initialize(directory, bootstrap)
    }
    /// Initialize against the operator-supplied root embedded when this
    /// release verifier was built. Release binaries expose no root-file option.
    #[cfg(feature = "release-root")]
    pub fn initialize_embedded(directory: &Path) -> Result<Self> {
        Self::initialize_pinned(directory, embedded_root::ROOT, embedded_root::SHA256)
    }
    pub fn open(directory: &Path) -> Result<Self> {
        private_dir(directory)?;
        private_file(&directory.join("owner.lock"))?;
        let lock = Self::lock(directory)?;
        if read_bounded(&directory.join("initialized"), 64)? != b"lomi-update-trust-v1\n" {
            return Err(invalid("missing or corrupt initialization marker"));
        }
        private_file(&directory.join("initialized"))?;
        private_file(&directory.join("trust.sqlite"))?;
        // Reject aliases or unusual modes of any SQLite sidecars before recovery.
        for name in [
            "trust.sqlite-journal",
            "trust.sqlite-wal",
            "trust.sqlite-shm",
        ] {
            let p = directory.join(name);
            match fs::symlink_metadata(&p) {
                Ok(_) => private_file(&p)?,
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
        }
        let store = Self::connect(directory, lock)?;
        let integrity: String = store.db.query_row("PRAGMA quick_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(invalid("corrupt trust database"));
        }
        store.read_state()?;
        Ok(store)
    }
    /// Open an existing trust store and require the release's embedded public
    /// bootstrap-root digest. A store created from another root is never reused.
    pub fn open_pinned(directory: &Path, expected_sha256: &str) -> Result<Self> {
        let expected = expected_sha256.to_ascii_lowercase();
        if !valid_digest(&expected) {
            return Err(invalid("invalid pinned public-root digest"));
        }
        let store = Self::open(directory)?;
        let pin_path = directory.join(BOOTSTRAP_PIN_FILE);
        private_file(&pin_path)?;
        let stored = read_bounded(&pin_path, 128)?;
        let stored = std::str::from_utf8(&stored)
            .map_err(|_| invalid("invalid bootstrap-root pin file"))?
            .trim_end_matches('\n');
        if stored.len() != 64 || !valid_digest(stored) || stored != expected {
            return Err(invalid(
                "trust store was initialized with a different public root",
            ));
        }
        Ok(store)
    }
    /// Open only a trust store originally initialized from this release's
    /// embedded public root.
    #[cfg(feature = "release-root")]
    pub fn open_embedded(directory: &Path) -> Result<Self> {
        let actual = digest_hex(embedded_root::ROOT);
        if actual != embedded_root::SHA256 {
            return Err(invalid("embedded public root failed its pinned digest"));
        }
        Self::open_pinned(directory, embedded_root::SHA256)
    }

    /// Open the native administrator-private TUF area bound to a selected
    /// ordinary SID. This constructor never accepts a caller-supplied path.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn open_admin_host_embedded(owner_sid: &str) -> Result<Self> {
        let area = windows_storage::AdminHostReleaseArea::open_or_create(owner_sid)?;
        Self::open_admin_host_area(area)
    }

    #[cfg(all(windows, feature = "release-root"))]
    pub fn open_admin_host_for_account(account: &str) -> Result<Self> {
        let (owner_sid, _) =
            lomi_platform::windows::service_admin::selected_account_identity(account)?;
        Self::open_admin_host_embedded(&owner_sid)
    }

    #[cfg(all(windows, feature = "release-root"))]
    pub fn admin_host_install_path(&self) -> Result<PathBuf> {
        self.admin_host_area
            .as_ref()
            .map(|area| area.install_path().to_path_buf())
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))
    }

    #[cfg(all(windows, feature = "release-root"))]
    pub fn initialize_admin_host_for_account(account: &str) -> Result<Self> {
        use lomi_platform::windows::service_admin as admin;

        let (owner_sid, _) = admin::selected_account_identity(account)?;
        let area = windows_storage::AdminHostReleaseArea::open_or_create(&owner_sid)?;
        let trust_dir = area.trust_path().to_path_buf();
        match fs::symlink_metadata(&trust_dir) {
            Ok(_) => Self::open_admin_host_area(area),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                // First trust initialization is part of the selected account's
                // first install. Hold the profile owner lease across the empty
                // area check and trust-root publication so another Host cannot
                // appear between those steps.
                let owner_lock = admin::acquire_initial_host_owner_lock(account)?;
                area.require_fresh_install_area()?;
                let mut store = Self::initialize_embedded(&trust_dir)?;
                let mut area = area;
                area.pin_trust()?;
                store.admin_host_area = Some(area);
                drop(owner_lock);
                Ok(store)
            }
            Err(error) => Err(error.into()),
        }
    }

    #[cfg(all(windows, feature = "release-root"))]
    fn open_admin_host_area(mut area: windows_storage::AdminHostReleaseArea) -> Result<Self> {
        let trust_dir = area.trust_path().to_path_buf();
        let store = match fs::symlink_metadata(&trust_dir) {
            Ok(_) => Self::open_embedded(&trust_dir)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(invalid("administrator Host trust state is not initialized"));
            }
            Err(error) => return Err(error.into()),
        };
        area.pin_trust()?;
        let mut store = store;
        store.admin_host_area = Some(area);
        Ok(store)
    }
    fn lock(directory: &Path) -> Result<File> {
        #[cfg(unix)]
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(directory.join("owner.lock"))?;
        #[cfg(windows)]
        let lock = windows_storage::open_private_file(&directory.join("owner.lock"), true)?;
        private_file(&directory.join("owner.lock"))?;
        #[cfg(unix)]
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "trust state owned by another updater",
            )
            .into());
        }
        #[cfg(windows)]
        windows_storage::lock_file(&lock)?;
        Ok(lock)
    }
    fn connect(directory: &Path, lock: File) -> Result<Self> {
        #[cfg(windows)]
        windows_storage::ensure_private_file(&directory.join("trust.sqlite-journal"))?;
        let db = Connection::open_with_flags(
            directory.join("trust.sqlite"),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL; PRAGMA fullfsync=ON; PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;")?;
        Ok(Self {
            db,
            directory: directory.to_path_buf(),
            _lock: lock,
            #[cfg(windows)]
            admin_host_area: None,
        })
    }
    fn read_state(&self) -> Result<State> {
        let count: i64 = self
            .db
            .query_row("SELECT count(*) FROM trust_state", [], |r| r.get(0))?;
        if count != 1 {
            return Err(invalid("missing or duplicate committed trust state"));
        }
        // SQLite length checks happen before allocating BLOB values in Rust.
        let valid:i64=self.db.query_row("SELECT count(*) FROM trust_state WHERE id=1 AND format=1 AND length(root) BETWEEN 1 AND ?1 AND length(clock) BETWEEN 1 AND ?1 AND (timestamp IS NULL OR length(timestamp) BETWEEN 1 AND ?1) AND (snapshot IS NULL OR length(snapshot) BETWEEN 1 AND ?1) AND (targets IS NULL OR length(targets) BETWEEN 1 AND ?1) AND length(checksum)=32",[MAX_METADATA as i64],|r|r.get(0))?;
        if valid != 1 {
            return Err(invalid("corrupt or oversized trust state"));
        }
        let (state,checksum)=self.db.query_row("SELECT generation,root,timestamp,snapshot,targets,clock,checksum FROM trust_state WHERE id=1",[],|r|Ok((State{generation:r.get(0)?,files:[r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?]},r.get::<_,Vec<u8>>(6)?)))?;
        if state.checksum() != checksum {
            return Err(invalid("committed trust-state checksum mismatch"));
        }
        state.validate()?;
        Ok(state)
    }
    pub fn generation(&self) -> Result<i64> {
        Ok(self.read_state()?.generation)
    }
    /// Verify all metadata and an optional target, then atomically commit trust.
    /// No target bytes escape if verification or durable commit fails.
    pub async fn update(
        &mut self,
        metadata: &Path,
        targets: &Path,
        target: Option<&str>,
    ) -> Result<Option<Vec<u8>>> {
        let transport = BoundedLocal::new(metadata, targets)?;
        let metadata_url = transport.metadata.clone();
        let targets_url = transport.targets.clone();
        let verified = self
            .update_inner(
                metadata_url,
                targets_url,
                transport,
                target,
                None,
                None,
                None,
            )
            .await?;
        Ok(verified.into_iter().next().map(|target| target.bytes))
    }

    /// Verify a TUF target, store its bytes under their SHA-256 digest, then
    /// atomically point `install_dir/active` at that content-addressed object.
    ///
    /// Activation is separate from profile/configuration data. It installs
    /// verified bytes as a content-addressed object and atomically changes the
    /// active pointer. It does not itself start or restart a host service.
    #[cfg(unix)]
    pub async fn update_and_activate(
        &mut self,
        metadata: &Path,
        targets: &Path,
        target_name: &str,
        install_dir: &Path,
    ) -> Result<PathBuf> {
        self.update_and_activate_inner(metadata, targets, target_name, install_dir, false)
            .await
    }

    /// Download a platform release over HTTPS, verify its complete TUF target,
    /// enforce the signed platform/profile-schema policy, then atomically make
    /// the verified object active. `release_origin` is fixed by the embedding
    /// installer; it must be an HTTPS directory URL with no query or fragment.
    #[cfg(any(unix, windows))]
    pub async fn install_release_https(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
    ) -> Result<PathBuf> {
        self.install_release_https_inner(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            Some(profile_schema),
            None,
        )
        .await
    }

    /// Bind installation to the version in the authenticated installer rather
    /// than accepting a different version under a reused TUF target name.
    #[cfg(any(unix, windows))]
    pub async fn install_release_https_pinned(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
        expected_version: &str,
    ) -> Result<PathBuf> {
        self.install_release_https_inner(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            Some(profile_schema),
            Some(expected_version),
        )
        .await
    }

    /// Selected-account installation observes the actual database schema
    /// while holding its owner lock. `Some` pins an exact release version;
    /// `None` accepts the version from verified metadata for this target.
    #[cfg(any(unix, windows))]
    pub async fn install_release_https_pinned_auto_schema(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        self.install_release_https_inner(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            None,
            expected_version,
        )
        .await
    }

    #[cfg(any(unix, windows))]
    pub fn install_release_https_pinned_auto_schema_blocking(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(invalid(
                "blocking selected-account installation cannot run inside Tokio",
            ));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.install_release_https_pinned_auto_schema(
                release_origin,
                target_name,
                profile_dir,
                install_dir,
                platform,
                expected_version,
            ))
    }

    #[cfg(any(unix, windows))]
    async fn install_release_https_inner(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        if platform.starts_with("windows-") {
            return Err(invalid(
                "Windows releases require the signed companion host target",
            ));
        }
        let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
        let profile_schema = match schema_hint {
            Some(hint) => require_profile_schema_hint(profile_barrier.profile_path(), hint)?,
            None => read_profile_database_schema(profile_barrier.profile_path())?,
        };
        let _profile_barrier = profile_barrier;
        #[cfg(unix)]
        activation::validate_directory(install_dir)?;
        #[cfg(windows)]
        activation_windows::validate_directory(install_dir)?;
        let transport = BoundedHttps::new(release_origin)?;
        let verified = self
            .update_inner_pinned(
                transport.metadata.clone(),
                transport.targets.clone(),
                transport,
                Some(target_name),
                None,
                Some((platform, profile_schema)),
                None,
                expected_version,
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("verified release target missing"))?;
        #[cfg(unix)]
        return activation::activate_verified_target(
            install_dir,
            &verified.bytes,
            &verified.custom,
            platform,
            profile_schema,
        );
        #[cfg(windows)]
        activation_windows::activate_verified_target(
            install_dir,
            &verified.bytes,
            &verified.custom,
            platform,
            profile_schema,
        )
    }

    /// Compatibility wrapper for the administrator-managed boot service.
    #[cfg(target_os = "macos")]
    pub async fn install_release_admin_boot_https(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
    ) -> Result<PathBuf> {
        self.install_release_admin_host_https(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            schema_hint,
            selected_account,
            lomi_platform::service_macos::AdminHostMode::Boot,
        )
        .await
    }

    /// Install the macOS administrator-managed release for its bound Host
    /// mode while holding the selected account's service and owner barriers.
    #[cfg(target_os = "macos")]
    pub async fn install_release_admin_host_https(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
        host_mode: lomi_platform::service_macos::AdminHostMode,
    ) -> Result<PathBuf> {
        self.install_release_admin_host_https_inner(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            schema_hint,
            selected_account,
            host_mode,
            None,
        )
        .await
    }

    #[cfg(target_os = "macos")]
    pub async fn install_release_admin_host_https_pinned(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
        host_mode: lomi_platform::service_macos::AdminHostMode,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        self.install_release_admin_host_https_inner(
            release_origin,
            target_name,
            profile_dir,
            install_dir,
            platform,
            schema_hint,
            selected_account,
            host_mode,
            expected_version,
        )
        .await
    }

    #[cfg(target_os = "macos")]
    pub fn install_release_admin_host_https_pinned_blocking(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
        host_mode: lomi_platform::service_macos::AdminHostMode,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(invalid(
                "blocking admin Host update cannot run inside Tokio",
            ));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.install_release_admin_host_https_pinned(
                release_origin,
                target_name,
                profile_dir,
                install_dir,
                platform,
                schema_hint,
                selected_account,
                host_mode,
                expected_version,
            ))
    }

    #[cfg(target_os = "macos")]
    async fn install_release_admin_host_https_inner(
        &mut self,
        release_origin: &str,
        target_name: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
        host_mode: lomi_platform::service_macos::AdminHostMode,
        expected_version: Option<&str>,
    ) -> Result<PathBuf> {
        if !platform.starts_with("macos-") {
            return Err(invalid("admin Host release requires a macOS target"));
        }
        activation::validate_admin_boot_directory(install_dir)?;
        bind_admin_host_profile(profile_dir, install_dir, selected_account, host_mode)?;
        let (canonical_profile, account_uid) =
            lomi_platform::service_macos::validate_boot_profile(profile_dir, selected_account)
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
        let root_receipt = activation::read_admin_profile_init_receipt(
            install_dir,
            account_uid,
            &canonical_profile,
            host_mode.as_str(),
        )?;
        let activation_candidate = activation::initial_admin_host_install_candidate(install_dir)?;
        let pending_target = match root_receipt.as_ref() {
            Some(receipt) if receipt.is_pending() => activation::pending_admin_profile_init_target(
                install_dir,
                receipt,
                account_uid,
                &canonical_profile,
                host_mode.as_str(),
                platform,
            )?,
            _ => None,
        };
        let resume_pending_initialization = pending_target.is_some();
        // Uninstall removes only the signed release activation. It retains
        // the root identity receipt, projection, and selected-account DB, so
        // reinstall must prove that exact identity under the no-service
        // initial-install barrier instead of treating it as first-run setup.
        let reinstall_completed_profile = activation_candidate
            && root_receipt
                .as_ref()
                .is_some_and(|receipt| receipt.is_complete());
        let initial_install = activation_candidate
            && (root_receipt.is_none()
                || (root_receipt
                    .as_ref()
                    .is_some_and(|receipt| receipt.is_pending())
                    && !resume_pending_initialization));
        let fresh_activation = initial_install || reinstall_completed_profile;
        if root_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.is_pending())
            && !resume_pending_initialization
            && !initial_install
        {
            return Err(invalid(
                "pending admin initialization has no unambiguous activation state",
            ));
        }
        let profile_barrier = if fresh_activation {
            acquire_admin_host_initial_install_profile_barrier(
                profile_dir,
                install_dir,
                selected_account,
                host_mode,
            )?
        } else {
            acquire_admin_host_profile_barrier(
                profile_dir,
                install_dir,
                selected_account,
                host_mode,
                false,
                false,
            )?
        };
        if fresh_activation && !activation::initial_admin_host_install_candidate(install_dir)? {
            drop(profile_barrier);
            return Err(invalid(
                "admin Host activation state changed while acquiring its fresh-install guard",
            ));
        }
        let (profile_schema, preflight_identity) = if resume_pending_initialization {
            (None, None)
        } else {
            let snapshot = match profile_barrier.admin_host_profile_snapshot(install_dir) {
                Ok(snapshot) => snapshot,
                Err(error) => {
                    return fail_admin_host_preflight(
                        profile_barrier,
                        error,
                        profile_dir,
                        install_dir,
                        selected_account,
                    );
                }
            };
            let identity_validation = (|| -> Result<()> {
                if let Some(receipt) = root_receipt.as_ref()
                    && receipt.is_complete()
                {
                    let identity = snapshot
                        .1
                        .as_ref()
                        .ok_or_else(|| invalid("completed admin profile identity is missing"))?;
                    if activation::verify_admin_profile_init_identity(
                        install_dir,
                        account_uid,
                        &canonical_profile,
                        host_mode.as_str(),
                        &identity.host_id_text(),
                        &identity.profile_id_text(),
                    )? != Some(activation::AdminProfileInitState::Complete)
                    {
                        return Err(invalid(
                            "admin profile initialization receipt is not complete",
                        ));
                    }
                    profile_barrier.publish_admin_host_identity_binding(identity)?;
                }
                Ok(())
            })();
            if let Err(error) = identity_validation {
                return fail_admin_host_preflight(
                    profile_barrier,
                    error,
                    profile_dir,
                    install_dir,
                    selected_account,
                );
            }
            if !initial_install && root_receipt.is_none() && snapshot.1.is_none() {
                return fail_admin_host_preflight(
                    profile_barrier,
                    invalid("legacy admin profile identity is missing during migration"),
                    profile_dir,
                    install_dir,
                    selected_account,
                );
            }
            if root_receipt.is_none()
                && let Some(identity) = snapshot.1.as_ref()
            {
                if let Err(error) = profile_barrier.verify_admin_host_identity_binding(identity) {
                    return fail_admin_host_preflight(
                        profile_barrier,
                        error,
                        profile_dir,
                        install_dir,
                        selected_account,
                    );
                }
            }
            (Some(snapshot.0), snapshot.1)
        };
        let profile_schema = profile_schema.unwrap_or(0);
        if schema_hint.is_some_and(|hint| hint != profile_schema) {
            return fail_admin_host_preflight(
                profile_barrier,
                invalid("maintenance profile schema does not match the owner-locked database"),
                profile_dir,
                install_dir,
                selected_account,
            );
        }
        let custody_state = profile_barrier.begin_admin_host_custody_maintenance()?;
        let mut profile_barrier = profile_barrier;
        let result = async {
            if resume_pending_initialization {
                let receipt = root_receipt
                    .as_ref()
                    .ok_or_else(|| invalid("pending admin profile receipt disappeared"))?;
                let object = activation::pending_admin_profile_init_target(
                    install_dir,
                    receipt,
                    account_uid,
                    &canonical_profile,
                    host_mode.as_str(),
                    platform,
                )?
                .ok_or_else(|| invalid("pending profile release is no longer active"))?;
                if let Some(version) = expected_version {
                    activation::check_object_release_version(install_dir, &object, version)?;
                }
                lomi_platform::service_macos::initialize_admin_host_profile_after_pending_activation(
                    match &mut profile_barrier {
                        ProfileBarrier::MacAdminHost { _guard } => _guard,
                        _ => return Err(invalid("admin Host profile guard is unavailable")),
                    },
                )
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
                let (actual_schema, identity) = profile_barrier.admin_host_profile_snapshot(install_dir)?;
                if schema_hint.is_some_and(|hint| hint != actual_schema) {
                    return Err(invalid(
                        "initialized admin profile schema differs from the requested schema",
                    ));
                }
                let identity = identity
                    .ok_or_else(|| invalid("initialized admin profile identity is missing"))?;
                activation::complete_admin_profile_init_receipt(
                    install_dir,
                    receipt,
                    account_uid,
                    &canonical_profile,
                    host_mode.as_str(),
                    platform,
                    actual_schema,
                    &identity.host_id_text(),
                    &identity.profile_id_text(),
                )?;
                profile_barrier.publish_admin_host_identity_binding(&identity)?;
                return Ok(object);
            }
            let transport = BoundedHttps::new(release_origin)?;
            let verified = self
                .update_inner_pinned(
                    transport.metadata.clone(),
                    transport.targets.clone(),
                    transport,
                    Some(target_name),
                    None,
                    Some((platform, profile_schema)),
                    None,
                    expected_version,
                )
                .await?
                .into_iter()
                .next()
                .ok_or_else(|| invalid("verified release target missing"))?;
            let expected_identity_strings = preflight_identity.as_ref().map(|identity| {
                (identity.host_id_text(), identity.profile_id_text())
            });
            let init_receipt = if initial_install {
                Some(activation::prepare_admin_profile_init_receipt(
                    install_dir,
                    account_uid,
                    &canonical_profile,
                    host_mode.as_str(),
                    &verified.bytes,
                    &verified.custom,
                    expected_identity_strings
                        .as_ref()
                        .map(|(host_id, profile_id)| (host_id.as_str(), profile_id.as_str())),
                )?)
            } else {
                None
            };
            let object = activation::activate_verified_target_admin_boot(
                install_dir,
                &verified.bytes,
                &verified.custom,
                platform,
                profile_schema,
            )?;
            if let Some(receipt) = init_receipt.as_ref() {
                lomi_platform::service_macos::initialize_admin_host_profile_after_activation(
                    match &mut profile_barrier {
                        ProfileBarrier::MacAdminHost { _guard } => _guard,
                        _ => return Err(invalid("admin Host profile guard is unavailable")),
                    },
                )
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)?;
                let (actual_schema, identity) = profile_barrier.admin_host_profile_snapshot(install_dir)?;
                if schema_hint.is_some_and(|hint| hint != actual_schema) {
                    return Err(invalid(
                        "initialized admin profile schema differs from the requested schema",
                    ));
                }
                let identity = identity
                    .ok_or_else(|| invalid("initialized admin profile identity is missing"))?;
                activation::complete_admin_profile_init_receipt(
                    install_dir,
                    receipt,
                    account_uid,
                    &canonical_profile,
                    host_mode.as_str(),
                    platform,
                    actual_schema,
                    &identity.host_id_text(),
                    &identity.profile_id_text(),
                )?;
                profile_barrier.publish_admin_host_identity_binding(&identity)?;
            } else if let Some(receipt) = root_receipt.as_ref()
                && receipt.is_complete()
            {
                let (actual_schema, identity) =
                    profile_barrier.admin_host_profile_snapshot(install_dir)?;
                if schema_hint.is_some_and(|hint| hint != actual_schema) {
                    return Err(invalid(
                        "updated admin profile schema differs from the requested schema",
                    ));
                }
                let identity = identity
                    .ok_or_else(|| invalid("completed admin profile identity is missing"))?;
                if preflight_identity.as_ref() != Some(&identity)
                    || activation::verify_admin_profile_init_identity(
                        install_dir,
                        account_uid,
                        &canonical_profile,
                        host_mode.as_str(),
                        &identity.host_id_text(),
                        &identity.profile_id_text(),
                    )? != Some(activation::AdminProfileInitState::Complete)
                {
                    return Err(invalid(
                        "completed admin profile identity changed during update",
                    ));
                }
                profile_barrier.publish_admin_host_identity_binding(&identity)?;
            } else if root_receipt.is_none() {
                let (actual_schema, identity) =
                    profile_barrier.admin_host_profile_snapshot(install_dir)?;
                if schema_hint.is_some_and(|hint| hint != actual_schema) {
                    return Err(invalid(
                        "migrated admin profile schema differs from the requested schema",
                    ));
                }
                let identity = identity.ok_or_else(|| {
                    invalid("legacy admin profile identity is missing during migration")
                })?;
                if preflight_identity.as_ref() != Some(&identity) {
                    return Err(invalid(
                        "legacy admin profile identity changed during update",
                    ));
                }
                profile_barrier.verify_admin_host_identity_binding(&identity)?;
                activation::adopt_existing_admin_profile_identity(
                    install_dir,
                    account_uid,
                    &canonical_profile,
                    host_mode.as_str(),
                    platform,
                    actual_schema,
                    &identity.host_id_text(),
                    &identity.profile_id_text(),
                )?;
                profile_barrier.publish_admin_host_identity_binding(&identity)?;
            }
            Ok(object)
        }
        .await;
        complete_admin_host_mutation(
            profile_barrier,
            custody_state,
            result,
            profile_dir,
            install_dir,
            selected_account,
        )
    }

    /// Verify the Windows CLI and its managed-login host helper from one
    /// top-level TUF snapshot, require the exact same signed release policy,
    /// then activate both files under one owner barrier and recovery journal.
    #[cfg(windows)]
    pub async fn install_release_pair_https(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        companion_target: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
    ) -> Result<(PathBuf, PathBuf)> {
        self.install_release_pair_https_inner(
            release_origin,
            primary_target,
            companion_target,
            profile_dir,
            install_dir,
            platform,
            Some(profile_schema),
            None,
        )
        .await
    }

    #[cfg(windows)]
    pub async fn install_release_pair_https_pinned(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        companion_target: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
        expected_version: &str,
    ) -> Result<(PathBuf, PathBuf)> {
        self.install_release_pair_https_inner(
            release_origin,
            primary_target,
            companion_target,
            profile_dir,
            install_dir,
            platform,
            Some(profile_schema),
            Some(expected_version),
        )
        .await
    }

    /// Install a Windows release pair while reading the actual profile schema
    /// under the updater's owner lock. An optional version further pins the
    /// verified TUF metadata to an exact release.
    #[cfg(windows)]
    pub async fn install_release_pair_https_pinned_auto_schema(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        companion_target: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        expected_version: Option<&str>,
    ) -> Result<(PathBuf, PathBuf)> {
        self.install_release_pair_https_inner(
            release_origin,
            primary_target,
            companion_target,
            profile_dir,
            install_dir,
            platform,
            None,
            expected_version,
        )
        .await
    }

    #[cfg(windows)]
    pub fn install_release_pair_https_pinned_auto_schema_blocking(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        companion_target: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        expected_version: Option<&str>,
    ) -> Result<(PathBuf, PathBuf)> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(invalid("blocking release update cannot run inside Tokio"));
        }
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?
            .block_on(self.install_release_pair_https_pinned_auto_schema(
                release_origin,
                primary_target,
                companion_target,
                profile_dir,
                install_dir,
                platform,
                expected_version,
            ))
    }

    #[cfg(windows)]
    async fn install_release_pair_https_inner(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        companion_target: &str,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: Option<u64>,
        expected_version: Option<&str>,
    ) -> Result<(PathBuf, PathBuf)> {
        if !platform.starts_with("windows-") {
            return Err(invalid(
                "paired release target is only supported on Windows",
            ));
        }
        let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
        let profile_schema = match profile_schema {
            Some(hint) => require_profile_schema_hint(profile_barrier.profile_path(), hint)?,
            None => read_profile_database_schema(profile_barrier.profile_path())?,
        };
        let _profile_barrier = profile_barrier;
        activation_windows::validate_directory(install_dir)?;
        let transport = BoundedHttps::new(release_origin)?;
        let mut verified = self
            .update_inner_pinned(
                transport.metadata.clone(),
                transport.targets.clone(),
                transport,
                Some(primary_target),
                Some(companion_target),
                Some((platform, profile_schema)),
                None,
                expected_version,
            )
            .await?;
        if verified.len() != 2
            || verified[0].custom.get("lomiRelease") != verified[1].custom.get("lomiRelease")
        {
            return Err(invalid(
                "Windows primary and companion targets have different signed release policies",
            ));
        }
        let companion = verified
            .pop()
            .ok_or_else(|| invalid("missing companion target"))?;
        let primary = verified
            .pop()
            .ok_or_else(|| invalid("missing primary target"))?;
        activation_windows::activate_verified_pair(
            install_dir,
            &primary.bytes,
            &companion.bytes,
            &primary.custom,
            &companion.custom,
            platform,
            profile_schema,
        )
    }

    /// Fetch and verify the single Windows CLI target used to manage the
    /// administrator-installed file-security broker. This path has no host
    /// profile or companion executable, so schema zero validates the signed
    /// release policy shape and exact Windows target platform.
    #[cfg(windows)]
    pub async fn update_file_security_release_https(
        &mut self,
        release_origin: &str,
        target_name: &str,
        platform: &str,
    ) -> Result<Vec<u8>> {
        let expected_platform = match () {
            #[cfg(target_arch = "x86_64")]
            () => Some("windows-x86_64"),
            #[cfg(target_arch = "aarch64")]
            () => Some("windows-aarch64"),
            #[allow(unreachable_patterns)]
            _ => None,
        };
        if expected_platform != Some(platform) {
            return Err(invalid(
                "broker release platform does not match this updater",
            ));
        }
        let transport = BoundedHttps::new(release_origin)?;
        let mut verified = self
            .update_inner(
                transport.metadata.clone(),
                transport.targets.clone(),
                transport,
                Some(target_name),
                None,
                Some((platform, 0)),
                None,
            )
            .await?;
        if verified.len() != 1 {
            return Err(invalid("verified broker release target missing"));
        }
        Ok(verified
            .pop()
            .ok_or_else(|| invalid("verified broker release target missing"))?
            .bytes)
    }

    /// Install or update the administrator-managed Windows Host pair from a
    /// single signed TUF snapshot. The caller must obtain any hidden account
    /// password before calling; it is accepted only for first install or a
    /// credential-repair phase and is never persisted by this updater.
    #[cfg(all(windows, feature = "release-root"))]
    pub async fn install_or_update_admin_host_service_https(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        helper_target: &str,
        platform: &str,
        account: &str,
        password: Option<lomi_platform::windows::service_admin::ServicePassword>,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        self.install_or_update_admin_host_service_https_inner(
            release_origin,
            primary_target,
            helper_target,
            platform,
            account,
            password,
            None,
        )
        .await
    }

    #[cfg(all(windows, feature = "release-root"))]
    async fn install_or_update_admin_host_service_https_inner(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        helper_target: &str,
        platform: &str,
        account: &str,
        password: Option<lomi_platform::windows::service_admin::ServicePassword>,
        expected_version: Option<&str>,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        expected_windows_service_platform(platform)?;
        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        let owner_sid = area.owner_sid().to_owned();
        let activation_dir = area.activation_path().to_path_buf();
        let mut password = password;

        use lomi_platform::windows::service_admin as admin;
        let (selected_sid, _) = admin::selected_account_identity(account)?;
        if selected_sid != owner_sid {
            return Err(invalid(
                "updater area SID differs from the selected account",
            ));
        }

        let mut guard = None;
        let mut retained_owner_lock = None;
        let mut existing = match admin::inspect(account) {
            Ok(status) => status,
            Err(inspect_error) => match if password.is_some() {
                admin::recover_image_update_for_credentials_repair(account)
            } else {
                admin::recover_image_update(account)
            } {
                Ok(recovery) => {
                    guard = Some(recovery);
                    None
                }
                Err(_) => {
                    let owner_lock = admin::acquire_registered_host_owner_lock(account)?;
                    match admin::recover_install_intent(account, &owner_lock) {
                        Ok(Some(status)) => {
                            retained_owner_lock = Some(owner_lock);
                            Some(status)
                        }
                        Ok(None) | Err(_) => return Err(inspect_error.into()),
                    }
                }
            },
        };
        if let Some(status) = existing.as_ref() {
            if status.account_sid != owner_sid
                || status.mode != "boot"
                || status.phase == "deleting"
            {
                return Err(invalid(
                    "administrator Host registration does not match the selected account",
                ));
            }
        }
        let credentialed_candidate = existing
            .as_ref()
            .is_some_and(|status| matches!(status.phase, "intent" | "credentials_required"));
        if (existing.is_none() && guard.is_none() || credentialed_candidate) && password.is_none() {
            return Err(invalid(
                "administrator Host install or credential repair requires a fresh password",
            ));
        }

        // A pending Intent pins the exact pair that was approved before
        // CreateService. Complete that recorded installation first; never
        // replace its image bytes while the old journal still authorizes only
        // the previous hashes. The service is then stopped under a new image
        // update guard before a different signed pair can be published.
        if let Some(pending) = existing
            .as_ref()
            .filter(|status| matches!(status.phase, "intent" | "credentials_required"))
            .cloned()
        {
            let owner_lock = match retained_owner_lock.take() {
                Some(owner_lock) => owner_lock,
                None => admin::acquire_registered_host_owner_lock(account)?,
            };
            if owner_lock.owner_sid() != owner_sid {
                return Err(invalid("HostOwnerLock SID differs from updater state"));
            }
            let database_snapshot = owner_lock.snapshot_database()?;
            let mut profile_observation = read_admin_host_database_observation(&database_snapshot)?;
            let mut profile_schema = profile_observation.schema_version;
            let recorded_pair =
                load_active_windows_host_pair(&activation_dir, platform, profile_schema)?;
            if recorded_pair.primary_sha256 != pending.cli_sha256
                || recorded_pair.helper_sha256 != pending.helper_sha256
            {
                return Err(invalid(
                    "pending administrator Host intent does not match the active signed pair",
                ));
            }
            let recorded_image = admin::VerifiedHostServiceImage::open(
                account,
                &pending.cli_sha256,
                &pending.helper_sha256,
                &recorded_pair.signer,
            )?;
            database_snapshot.verify_sources()?;
            let prior_identity = profile_observation.identity.clone();
            if pending.phase == "credentials_required" && profile_schema != 0 {
                let identity = prior_identity.as_ref().ok_or_else(|| {
                    invalid("credential-repair Host database identity is missing")
                })?;
                admin::bind_credential_repair_identity(
                    account,
                    &recorded_image,
                    &owner_lock,
                    &identity.host_id,
                    &identity.profile_id,
                )?;
            }
            admin::prepare_install_intent(account, &recorded_image, &owner_lock)?;
            let profile = owner_lock.profile_path().to_path_buf();
            drop(database_snapshot);
            drop(owner_lock);
            admin::initialize_first_install_profile(
                account,
                &profile,
                password.as_ref().ok_or_else(|| {
                    invalid("profile initialization requires a fresh account password")
                })?,
                &recorded_image,
            )?;
            let owner_lock = admin::acquire_registered_host_owner_lock(account)?;
            let database_snapshot = owner_lock.snapshot_database()?;
            profile_observation = read_admin_host_database_observation(&database_snapshot)?;
            profile_schema = profile_observation.schema_version;
            if profile_schema == 0 {
                return Err(invalid(
                    "selected-account profile initialization did not create a Host database",
                ));
            }
            let identity = profile_observation
                .identity
                .as_ref()
                .ok_or_else(|| invalid("initialized Host database identity is missing"))?;
            if prior_identity
                .as_ref()
                .is_some_and(|prior| prior != identity)
            {
                return Err(invalid(
                    "selected Host identity changed during first-install recovery",
                ));
            }
            admin::bind_install_intent_identity(
                account,
                &recorded_image,
                &owner_lock,
                &identity.host_id,
                &identity.profile_id,
            )?;
            let initialized_signer = validate_windows_service_pair(
                &recorded_pair.primary_custom,
                &recorded_pair.helper_custom,
                platform,
                profile_schema,
            )?;
            if initialized_signer != recorded_pair.signer {
                return Err(invalid(
                    "initialized Host schema is outside the recorded signed pair policy",
                ));
            }
            database_snapshot.verify_sources()?;
            admin::verify_install_intent(account, &recorded_image, &owner_lock)?;
            drop(database_snapshot);
            drop(owner_lock);

            admin::run("install", account, password.take(), Some(&recorded_image))?;
            drop(recorded_image);
            let completed = admin::inspect(account)?.ok_or_else(|| {
                invalid("pending Host installation did not create a registration")
            })?;
            if !completed.registered
                || !completed.ready
                || completed.account_sid != owner_sid
                || completed.cli_sha256 != pending.cli_sha256
                || completed.helper_sha256 != pending.helper_sha256
            {
                return Err(invalid(
                    "pending Host installation did not become ready with its recorded pair",
                ));
            }
            guard = Some(admin::begin_image_update(account)?);
            existing = Some(completed);
        }
        if let Some(status) = existing.as_ref() {
            if status.phase == "updating" {
                guard = Some(if password.is_some() {
                    admin::recover_image_update_for_credentials_repair(account)?
                } else {
                    admin::recover_image_update(account)?
                });
            } else if status.registered && guard.is_none() {
                guard = Some(if password.is_some() {
                    admin::begin_image_update_for_credentials_repair(account)?
                } else {
                    admin::begin_image_update(account)?
                });
            }
        }

        let first_install = existing.is_none() && guard.is_none();
        let mut credentialed_install = first_install;
        if let Some(status) = existing.as_ref() {
            credentialed_install |= matches!(status.phase, "intent" | "credentials_required");
            if !status.registered
                && !matches!(status.phase, "intent" | "credentials_required")
                && guard.is_none()
            {
                return Err(invalid("administrator Host service object is missing"));
            }
        }
        let mut owner_lock = match retained_owner_lock {
            Some(owner_lock) => owner_lock,
            None if first_install => admin::acquire_initial_host_owner_lock(account)?,
            None => admin::acquire_registered_host_owner_lock(account)?,
        };
        let mut database_snapshot = owner_lock.snapshot_database()?;
        let mut profile_observation = read_admin_host_database_observation(&database_snapshot)?;
        let mut profile_schema = profile_observation.schema_version;
        if profile_schema == 0 && !first_install {
            return Err(invalid(
                "registered Host profile database is missing during update",
            ));
        }
        if let Some(status) = existing.as_ref() {
            let observed = profile_observation.identity.as_ref().ok_or_else(|| {
                invalid("registered Host database identity is missing during update")
            })?;
            match (status.host_id, status.profile_id) {
                (Some(host_id), Some(profile_id)) => {
                    if String::from(host_id) != observed.host_id
                        || String::from(profile_id) != observed.profile_id
                    {
                        return Err(invalid(
                            "registered Host identity differs from the selected database",
                        ));
                    }
                }
                (None, None) => {
                    guard
                        .as_mut()
                        .ok_or_else(|| {
                            invalid("legacy Host identity migration requires a stopped service")
                        })?
                        .bind_existing_host_identity(
                            &owner_lock,
                            &observed.host_id,
                            &observed.profile_id,
                        )?;
                }
                _ => return Err(invalid("registered Host identity pin is incomplete")),
            }
        }

        let mut previous_hashes = if let Some(guard) = guard.as_ref() {
            let (primary, helper) = guard.current_image_hashes();
            Some((primary.to_owned(), helper.to_owned()))
        } else {
            existing
                .as_ref()
                .map(|status| (status.cli_sha256.clone(), status.helper_sha256.clone()))
        };
        if previous_hashes.is_none() {
            if let Some(active) = activation_windows::active_host_pair(&activation_dir, platform)? {
                validate_windows_service_pair(
                    &active.primary_custom,
                    &active.helper_custom,
                    platform,
                    profile_schema,
                )?;
                let primary = read_bounded(&active.primary_path, MAX_TARGET)?;
                let helper = read_bounded(&active.helper_path, MAX_TARGET)?;
                previous_hashes = Some((digest_hex(&primary), digest_hex(&helper)));
            }
        }

        let transport = BoundedHttps::new(release_origin)?;
        let mut verified = self
            .update_inner_pinned(
                transport.metadata.clone(),
                transport.targets.clone(),
                transport,
                Some(primary_target),
                Some(helper_target),
                Some((platform, profile_schema)),
                None,
                expected_version,
            )
            .await?;
        if verified.len() != 2 {
            return Err(invalid("verified Windows Host target pair is incomplete"));
        }
        let helper = verified
            .pop()
            .ok_or_else(|| invalid("verified Windows Host helper target is missing"))?;
        let primary = verified
            .pop()
            .ok_or_else(|| invalid("verified Windows Host primary target is missing"))?;
        let signer = validate_windows_service_pair(
            &primary.custom,
            &helper.custom,
            platform,
            profile_schema,
        )?;

        database_snapshot.verify_sources()?;
        activation_windows::activate_verified_pair(
            &activation_dir,
            &primary.bytes,
            &helper.bytes,
            &primary.custom,
            &helper.custom,
            platform,
            profile_schema,
        )?;
        let active = activation_windows::active_host_pair(&activation_dir, platform)?
            .ok_or_else(|| invalid("active Windows Host pair is missing after activation"))?;
        let active_signer = validate_windows_service_pair(
            &active.primary_custom,
            &active.helper_custom,
            platform,
            profile_schema,
        )?;
        if active_signer != signer {
            return Err(invalid(
                "activated Windows Host signer differs from the TUF pair",
            ));
        }
        let primary_bytes = read_bounded(&active.primary_path, MAX_TARGET)?;
        let helper_bytes = read_bounded(&active.helper_path, MAX_TARGET)?;
        database_snapshot.verify_sources()?;
        let previous = previous_hashes
            .as_ref()
            .map(|(primary, helper)| (primary.as_str(), helper.as_str()));
        let (cli_sha256, helper_sha256) = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("admin Host release area was dropped"))?
            .publish_pair(&primary_bytes, &helper_bytes, previous, first_install)?;
        let image =
            admin::VerifiedHostServiceImage::open(account, &cli_sha256, &helper_sha256, &signer)?;

        let previously_running = guard
            .as_ref()
            .is_some_and(admin::ImageUpdateGuard::previously_running);
        if let Some(guard) = guard {
            guard.complete(&image)?;
        } else {
            admin::prepare_install_intent(account, &image, &owner_lock)?;
            if first_install {
                let profile = owner_lock.profile_path().to_path_buf();
                drop(database_snapshot);
                drop(owner_lock);
                admin::initialize_first_install_profile(
                    account,
                    &profile,
                    password.as_ref().ok_or_else(|| {
                        invalid("profile initialization requires a fresh account password")
                    })?,
                    &image,
                )?;
                owner_lock = admin::acquire_registered_host_owner_lock(account)?;
                database_snapshot = owner_lock.snapshot_database()?;
                profile_observation = read_admin_host_database_observation(&database_snapshot)?;
                profile_schema = profile_observation.schema_version;
                if profile_schema == 0 {
                    return Err(invalid(
                        "selected-account profile initialization did not create a Host database",
                    ));
                }
                let initialized_signer = validate_windows_service_pair(
                    &primary.custom,
                    &helper.custom,
                    platform,
                    profile_schema,
                )?;
                if initialized_signer != signer {
                    return Err(invalid(
                        "initialized Host schema is outside the signed pair policy",
                    ));
                }
                database_snapshot.verify_sources()?;
            }
            if first_install {
                let identity = profile_observation
                    .identity
                    .as_ref()
                    .ok_or_else(|| invalid("first-install Host database identity is missing"))?;
                admin::bind_install_intent_identity(
                    account,
                    &image,
                    &owner_lock,
                    &identity.host_id,
                    &identity.profile_id,
                )?;
            }
            admin::verify_install_intent(account, &image, &owner_lock)?;
        }
        drop(database_snapshot);
        drop(owner_lock);

        if credentialed_install {
            admin::run("install", account, password.take(), Some(&image))?;
        } else if password.is_some() {
            admin::run("repair-credentials", account, password.take(), Some(&image))?;
        } else if previously_running {
            admin::run("start", account, None, None)?;
        }
        let status = admin_host_platform_status(account, &owner_sid, &cli_sha256, &helper_sha256)?;
        Ok(WindowsAdminHostServiceOutcome {
            status,
            previously_running,
        })
    }

    /// Synchronous CLI entry point for the administrator-managed Windows
    /// service updater. The CLI has no Tokio dependency and must call this
    /// outside an existing Tokio runtime.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn install_or_update_admin_host_service_https_blocking(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        helper_target: &str,
        platform: &str,
        account: &str,
        password: Option<lomi_platform::windows::service_admin::ServicePassword>,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(invalid(
                "blocking administrator Host update cannot run inside Tokio",
            ));
        }
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(self.install_or_update_admin_host_service_https(
                release_origin,
                primary_target,
                helper_target,
                platform,
                account,
                password,
            ))
    }

    /// Authenticated bundle installers constrain the final installed pair to
    /// their own release version; direct update callers retain the old API.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn install_or_update_admin_host_service_https_pinned_blocking(
        &mut self,
        release_origin: &str,
        primary_target: &str,
        helper_target: &str,
        platform: &str,
        account: &str,
        password: Option<lomi_platform::windows::service_admin::ServicePassword>,
        expected_version: Option<&str>,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        if tokio::runtime::Handle::try_current().is_ok() {
            return Err(invalid(
                "blocking administrator Host update cannot run inside Tokio",
            ));
        }
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?
            .block_on(self.install_or_update_admin_host_service_https_inner(
                release_origin,
                primary_target,
                helper_target,
                platform,
                account,
                password,
                expected_version,
            ))
    }

    /// Finish a persisted Windows Host `updating` transaction from its
    /// already-activated protected pair. It performs no network fetch and
    /// never retries an uncertain SCM operation except the explicit start
    /// whose prior-running decision is stored in the update guard.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn recover_admin_host_service(
        &mut self,
        account: &str,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        use lomi_platform::windows::service_admin as admin;

        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        let owner_sid = area.owner_sid().to_owned();
        let activation_dir = area.activation_path().to_path_buf();
        let platform = expected_windows_platform_name()?;
        let (selected_sid, _) = admin::selected_account_identity(account)?;
        if selected_sid != owner_sid {
            return Err(invalid(
                "updater area SID differs from the selected account",
            ));
        }

        match admin::inspect(account) {
            Ok(Some(status))
                if matches!(status.phase, "configured" | "starting")
                    && status.resume_after_update
                    && !status.running =>
            {
                let profile_lock = admin::acquire_registered_host_owner_lock(account)?;
                drop(profile_lock);
                admin::run("start", account, None, None)?;
                let status = admin::inspect(account)?
                    .ok_or_else(|| invalid("administrator Host registration disappeared"))?;
                let status = admin_host_platform_status(
                    account,
                    &owner_sid,
                    &status.cli_sha256,
                    &status.helper_sha256,
                )?;
                return Ok(WindowsAdminHostServiceOutcome {
                    status,
                    previously_running: true,
                });
            }
            Ok(Some(status)) if status.phase != "updating" => {
                return Err(invalid(
                    "administrator Host has no recoverable image update",
                ));
            }
            Ok(None) => {
                return Err(invalid(
                    "administrator Host service registration is missing",
                ));
            }
            Ok(Some(_)) | Err(_) => {}
        }

        let mut guard = admin::recover_image_update(account)?;
        let previous_running = guard.previously_running();
        let (old_cli, old_helper) = guard.current_image_hashes();
        let old_cli = old_cli.to_owned();
        let old_helper = old_helper.to_owned();
        let owner_lock = admin::acquire_registered_host_owner_lock(account)?;
        if owner_lock.owner_sid() != owner_sid {
            return Err(invalid("HostOwnerLock SID differs from updater state"));
        }
        let database_snapshot = owner_lock.snapshot_database()?;
        let profile_observation = read_admin_host_database_observation(&database_snapshot)?;
        let profile_schema = profile_observation.schema_version;
        if profile_schema == 0 {
            return Err(invalid(
                "registered Host profile database is missing during recovery",
            ));
        }
        let observed_identity = profile_observation.identity.as_ref().ok_or_else(|| {
            invalid("registered Host database identity is missing during recovery")
        })?;
        guard.bind_existing_host_identity(
            &owner_lock,
            &observed_identity.host_id,
            &observed_identity.profile_id,
        )?;
        let pair = load_active_windows_host_pair(&activation_dir, &platform, profile_schema)?;
        database_snapshot.verify_sources()?;
        let (cli_sha256, helper_sha256) = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("admin Host release area was dropped"))?
            .publish_pair(
                &pair.primary_bytes,
                &pair.helper_bytes,
                Some((&old_cli, &old_helper)),
                false,
            )?;
        let image = admin::VerifiedHostServiceImage::open(
            account,
            &cli_sha256,
            &helper_sha256,
            &pair.signer,
        )?;
        guard.complete(&image)?;
        drop(database_snapshot);
        drop(owner_lock);
        if previous_running {
            admin::run("start", account, None, None)?;
        }
        let status = admin_host_platform_status(account, &owner_sid, &cli_sha256, &helper_sha256)?;
        Ok(WindowsAdminHostServiceOutcome {
            status,
            previously_running: previous_running,
        })
    }

    /// Recover the protected Windows Host's TUF activation and SCM image
    /// binding as one operation. A pending activation is resolved against the
    /// actual selected Host database schema while the service is fenced and
    /// its OwnerLock is held. The exact recovered signed pair is then rebound
    /// to the service through the existing durable image-update guard.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn recover_admin_host_maintenance(
        &mut self,
        account: &str,
        platform: &str,
    ) -> Result<bool> {
        use lomi_platform::windows::service_admin as admin;

        expected_windows_service_platform(platform)?;
        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        let area_owner = area.owner_sid().to_owned();
        let activation_dir = area.activation_path().to_path_buf();
        let (selected_sid, canonical_account) = admin::selected_account_identity(account)?;
        if selected_sid != area_owner {
            return Err(invalid(
                "admin Host release area differs from the selected account",
            ));
        }
        let activation_pending = activation_windows::recovery_pending(&activation_dir)?;
        let service = admin::inspect(account)?;
        let service_pending = service.as_ref().is_some_and(|status| {
            status.phase == "updating" || (status.phase == "starting" && status.resume_after_update)
        });
        if !activation_pending && !service_pending {
            return Ok(false);
        }
        if !activation_pending {
            self.recover_admin_host_service(account)?;
            return Ok(true);
        }
        let service = service.ok_or_else(|| {
            invalid("pending admin Host activation has no registered service identity")
        })?;
        if !service.registered
            || service.account_sid != area_owner
            || service.mode != "boot"
            || service.phase == "deleting"
        {
            return Err(invalid(
                "pending activation does not match the selected Host service",
            ));
        }
        let mut guard = if service.phase == "updating" {
            admin::recover_image_update(account)?
        } else {
            admin::begin_image_update(account)?
        };
        let owner_lock = admin::acquire_registered_host_owner_lock(account)?;
        if owner_lock.owner_sid() != area_owner {
            return Err(invalid("HostOwnerLock SID differs from updater state"));
        }
        let database_snapshot = owner_lock.snapshot_database()?;
        let observation = read_admin_host_database_observation(&database_snapshot)?;
        if observation.schema_version == 0 {
            return Err(invalid(
                "Host database schema is unavailable during recovery",
            ));
        }
        let identity = observation
            .identity
            .as_ref()
            .ok_or_else(|| invalid("Host database identity is missing during recovery"))?;
        if service
            .host_id
            .is_some_and(|host_id| String::from(host_id) != identity.host_id)
            || service
                .profile_id
                .is_some_and(|profile_id| String::from(profile_id) != identity.profile_id)
        {
            return Err(invalid(
                "Host database identity differs from service registration",
            ));
        }
        guard.bind_existing_host_identity(&owner_lock, &identity.host_id, &identity.profile_id)?;

        activation_windows::recover_verified(
            &activation_dir,
            platform,
            observation.schema_version,
        )?;
        let pair =
            load_active_windows_host_pair(&activation_dir, platform, observation.schema_version)?;
        database_snapshot.verify_sources()?;
        let (old_cli, old_helper) = guard.current_image_hashes();
        let (cli_sha256, helper_sha256) = area.publish_pair(
            &pair.primary_bytes,
            &pair.helper_bytes,
            Some((old_cli, old_helper)),
            false,
        )?;
        let image = admin::VerifiedHostServiceImage::open(
            account,
            &cli_sha256,
            &helper_sha256,
            &pair.signer,
        )?;
        let previously_running = guard.previously_running();
        database_snapshot.verify_sources()?;
        guard.complete(&image)?;
        drop(database_snapshot);
        drop(owner_lock);
        if previously_running {
            admin::run("start", &canonical_account, None, None)?;
        }
        let status = admin_host_platform_status(
            &canonical_account,
            &area_owner,
            &cli_sha256,
            &helper_sha256,
        )?;
        if previously_running && !status.running {
            return Err(invalid(
                "recovered admin Host did not return to its prior running state",
            ));
        }
        Ok(true)
    }

    #[cfg(all(windows, feature = "release-root"))]
    pub fn admin_host_activation_recovery_pending(&self) -> Result<bool> {
        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        activation_windows::recovery_pending(area.activation_path())
    }

    /// Roll back to the protected previous TUF-verified Windows Host pair.
    /// The registered service is stopped and durably fenced before either
    /// stable image is replaced.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn rollback_admin_host_service(
        &mut self,
        account: &str,
    ) -> Result<WindowsAdminHostServiceOutcome> {
        use lomi_platform::windows::service_admin as admin;

        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        let owner_sid = area.owner_sid().to_owned();
        let activation_dir = area.activation_path().to_path_buf();
        let platform = expected_windows_platform_name()?;
        let (selected_sid, _) = admin::selected_account_identity(account)?;
        if selected_sid != owner_sid {
            return Err(invalid(
                "updater area SID differs from the selected account",
            ));
        }

        let status = admin::inspect(account)?
            .ok_or_else(|| invalid("administrator Host service registration is missing"))?;
        if status.account_sid != owner_sid || status.phase == "deleting" {
            return Err(invalid(
                "administrator Host registration does not match the selected account",
            ));
        }
        let mut guard = if status.phase == "updating" {
            admin::recover_image_update(account)?
        } else {
            admin::begin_image_update(account)?
        };
        let previously_running = guard.previously_running();
        let (old_cli, old_helper) = guard.current_image_hashes();
        let old_cli = old_cli.to_owned();
        let old_helper = old_helper.to_owned();
        let owner_lock = admin::acquire_registered_host_owner_lock(account)?;
        if owner_lock.owner_sid() != owner_sid {
            return Err(invalid("HostOwnerLock SID differs from updater state"));
        }
        let database_snapshot = owner_lock.snapshot_database()?;
        let profile_observation = read_admin_host_database_observation(&database_snapshot)?;
        let profile_schema = profile_observation.schema_version;
        if profile_schema == 0 {
            return Err(invalid(
                "registered Host profile database is missing during rollback",
            ));
        }
        let observed_identity = profile_observation.identity.as_ref().ok_or_else(|| {
            invalid("registered Host database identity is missing during rollback")
        })?;
        guard.bind_existing_host_identity(
            &owner_lock,
            &observed_identity.host_id,
            &observed_identity.profile_id,
        )?;
        database_snapshot.verify_sources()?;
        let rolled =
            activation_windows::rollback_host_pair(&activation_dir, &platform, profile_schema)?;
        let signer = validate_windows_service_pair(
            &rolled.primary_custom,
            &rolled.helper_custom,
            &platform,
            profile_schema,
        )?;
        let primary_bytes = read_bounded(&rolled.primary_path, MAX_TARGET)?;
        let helper_bytes = read_bounded(&rolled.helper_path, MAX_TARGET)?;
        database_snapshot.verify_sources()?;
        let (cli_sha256, helper_sha256) = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("admin Host release area was dropped"))?
            .publish_pair(
                &primary_bytes,
                &helper_bytes,
                Some((&old_cli, &old_helper)),
                false,
            )?;
        let image =
            admin::VerifiedHostServiceImage::open(account, &cli_sha256, &helper_sha256, &signer)?;
        guard.complete(&image)?;
        drop(database_snapshot);
        drop(owner_lock);
        if previously_running {
            admin::run("start", account, None, None)?;
        }
        let status = admin_host_platform_status(account, &owner_sid, &cli_sha256, &helper_sha256)?;
        Ok(WindowsAdminHostServiceOutcome {
            status,
            previously_running,
        })
    }

    /// Stop and unregister the exact service, then remove only its two
    /// registered stable image paths and updater-owned activation objects.
    /// The TUF metadata and per-user Host profile remain for safe reinstall.
    #[cfg(all(windows, feature = "release-root"))]
    pub fn uninstall_admin_host_service(&mut self, account: &str) -> Result<usize> {
        use lomi_platform::windows::service_admin as admin;

        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("updater is not bound to the admin Host release area"))?;
        let owner_sid = area.owner_sid().to_owned();
        let activation_dir = area.activation_path().to_path_buf();
        let (selected_sid, _) = admin::selected_account_identity(account)?;
        if selected_sid != owner_sid {
            return Err(invalid(
                "updater area SID differs from the selected account",
            ));
        }
        let status = admin::inspect(account)?;
        let platform = expected_windows_platform_name()?;
        let active = activation_windows::active_host_pair(&activation_dir, &platform)?;
        let (expected_cli, expected_helper) = if let Some(status) = status.as_ref() {
            if status.account_sid != owner_sid
                || status.phase == "updating"
                || status.phase == "deleting"
            {
                return Err(invalid(
                    "recover the administrator Host before uninstalling",
                ));
            }
            (status.cli_sha256.clone(), status.helper_sha256.clone())
        } else if let Some(active) = active.as_ref() {
            let primary = read_bounded(&active.primary_path, MAX_TARGET)?;
            let helper = read_bounded(&active.helper_path, MAX_TARGET)?;
            (digest_hex(&primary), digest_hex(&helper))
        } else {
            (String::new(), String::new())
        };

        let owner_lock = if let Some(status) = status.as_ref() {
            if status.registered && status.running {
                admin::run("stop", account, None, None)?;
            }
            admin::acquire_registered_host_owner_lock(account)?
        } else {
            admin::acquire_initial_host_owner_lock(account)?
        };
        if owner_lock.owner_sid() != owner_sid {
            return Err(invalid("HostOwnerLock SID differs from updater state"));
        }
        if status.is_some() {
            admin::run("uninstall", account, None, None)?;
        }
        let area = self
            .admin_host_area
            .as_ref()
            .ok_or_else(|| invalid("admin Host release area was dropped"))?;
        area.remove_pair(&expected_cli, &expected_helper)?;
        let removed_objects = activation_windows::uninstall(&activation_dir)?;
        drop(owner_lock);
        Ok(removed_objects)
    }

    #[cfg(all(unix, feature = "fault-injection"))]
    pub async fn update_and_activate_fault(
        &mut self,
        metadata: &Path,
        targets: &Path,
        target_name: &str,
        install_dir: &Path,
        fault: &str,
    ) -> Result<PathBuf> {
        if fault != "before-pointer-swap" {
            return Err(invalid("unknown activation fault point"));
        }
        self.update_and_activate_inner(metadata, targets, target_name, install_dir, true)
            .await
    }

    /// Restore the previous verified executable and retain the current target
    /// as the next rollback point.
    #[cfg(unix)]
    pub fn rollback_activation(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
    ) -> Result<PathBuf> {
        let profile_barrier = acquire_profile_barrier(profile_dir)?.ok_or_else(|| {
            invalid("cannot roll back without the existing profile owner barrier")
        })?;
        let profile_schema =
            require_profile_schema_hint(profile_barrier.profile_path(), profile_schema)?;
        let _profile_barrier = profile_barrier;
        activation::rollback(install_dir, platform, profile_schema)
    }
    #[cfg(unix)]
    pub fn rollback_activation_auto_schema(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
    ) -> Result<PathBuf> {
        let profile_barrier = acquire_profile_barrier(profile_dir)?.ok_or_else(|| {
            invalid("cannot roll back without the existing profile owner barrier")
        })?;
        let profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
        let _profile_barrier = profile_barrier;
        activation::rollback(install_dir, platform, profile_schema)
    }
    #[cfg(windows)]
    pub fn rollback_activation(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        profile_schema: u64,
    ) -> Result<PathBuf> {
        let profile_barrier = acquire_profile_barrier(profile_dir)?.ok_or_else(|| {
            invalid("cannot roll back without the existing profile owner barrier")
        })?;
        let profile_schema =
            require_profile_schema_hint(profile_barrier.profile_path(), profile_schema)?;
        let _profile_barrier = profile_barrier;
        activation_windows::rollback(install_dir, platform, profile_schema)
    }

    /// Roll back the Windows CLI and managed Host helper as one verified
    /// release pair using the actual schema observed under the profile lock.
    #[cfg(windows)]
    pub fn rollback_activation_pair_auto_schema(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
    ) -> Result<(PathBuf, PathBuf)> {
        let profile_barrier = acquire_profile_barrier(profile_dir)?.ok_or_else(|| {
            invalid("cannot roll back without the existing profile owner barrier")
        })?;
        let profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
        let _profile_barrier = profile_barrier;
        let pair = activation_windows::rollback_host_pair(install_dir, platform, profile_schema)?;
        Ok((pair.primary_path, pair.helper_path))
    }
    #[cfg(windows)]
    pub fn rollback_activation_auto_schema(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
    ) -> Result<PathBuf> {
        let profile_barrier = acquire_profile_barrier(profile_dir)?.ok_or_else(|| {
            invalid("cannot roll back without the existing profile owner barrier")
        })?;
        let profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
        let _profile_barrier = profile_barrier;
        activation_windows::rollback(install_dir, platform, profile_schema)
    }

    /// Compatibility wrapper for the administrator-managed boot service.
    #[cfg(target_os = "macos")]
    pub fn rollback_admin_boot_activation(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
    ) -> Result<PathBuf> {
        self.rollback_admin_host_activation(
            profile_dir,
            install_dir,
            platform,
            schema_hint,
            selected_account,
            lomi_platform::service_macos::AdminHostMode::Boot,
        )
    }

    /// Schema-checked rollback for a macOS admin Host mode.
    #[cfg(target_os = "macos")]
    pub fn rollback_admin_host_activation(
        &self,
        profile_dir: &Path,
        install_dir: &Path,
        platform: &str,
        schema_hint: Option<u64>,
        selected_account: &str,
        host_mode: lomi_platform::service_macos::AdminHostMode,
    ) -> Result<PathBuf> {
        if !platform.starts_with("macos-") {
            return Err(invalid("admin Host rollback requires a macOS target"));
        }
        activation::validate_admin_boot_directory(install_dir)?;
        let profile_barrier = acquire_admin_host_profile_barrier(
            profile_dir,
            install_dir,
            selected_account,
            host_mode,
            false,
            false,
        )?;
        let profile_schema = match profile_barrier.admin_host_profile_schema(install_dir) {
            Ok(schema) => schema,
            Err(error) => {
                return fail_admin_host_preflight(
                    profile_barrier,
                    error,
                    profile_dir,
                    install_dir,
                    selected_account,
                );
            }
        };
        if schema_hint.is_some_and(|hint| hint != profile_schema) {
            return fail_admin_host_preflight(
                profile_barrier,
                invalid("maintenance profile schema does not match the owner-locked database"),
                profile_dir,
                install_dir,
                selected_account,
            );
        }
        let custody_state = profile_barrier.begin_admin_host_custody_maintenance()?;
        let result = activation::rollback_admin_boot(install_dir, platform, profile_schema);
        complete_admin_host_mutation(
            profile_barrier,
            custody_state,
            result,
            profile_dir,
            install_dir,
            selected_account,
        )
    }

    /// Remove installer-owned active pointers and verified content objects.
    /// Unknown files and the host profile are never recursively removed.
    #[cfg(unix)]
    pub fn uninstall_activation(&self, profile_dir: &Path, install_dir: &Path) -> Result<usize> {
        let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
        let _actual_profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
        let _profile_barrier = profile_barrier;
        activation::uninstall(install_dir)
    }
    #[cfg(windows)]
    pub fn uninstall_activation(&self, profile_dir: &Path, install_dir: &Path) -> Result<usize> {
        let profile_barrier = acquire_profile_barrier_for_install(profile_dir)?;
        let _actual_profile_schema = read_profile_database_schema(profile_barrier.profile_path())?;
        let _profile_barrier = profile_barrier;
        activation_windows::uninstall(install_dir)
    }

    #[cfg(unix)]
    async fn update_and_activate_inner(
        &mut self,
        metadata: &Path,
        targets: &Path,
        target_name: &str,
        install_dir: &Path,
        inject_failure: bool,
    ) -> Result<PathBuf> {
        activation::validate_directory(install_dir)?;
        let transport = BoundedLocal::new(metadata, targets)?;
        let bytes = self
            .update_inner(
                transport.metadata.clone(),
                transport.targets.clone(),
                transport,
                Some(target_name),
                None,
                None,
                None,
            )
            .await?
            .into_iter()
            .next()
            .ok_or_else(|| invalid("verified target missing"))?
            .bytes;
        #[cfg(all(unix, feature = "fault-injection"))]
        if inject_failure {
            return Err(invalid("injected failure before active pointer swap"));
        }
        #[cfg(not(all(unix, feature = "fault-injection")))]
        let _ = inject_failure;
        activation::activate_verified_bytes(install_dir, &bytes)
    }
    #[cfg(feature = "fault-injection")]
    pub async fn update_fault(
        &mut self,
        metadata: &Path,
        targets: &Path,
        target: Option<&str>,
        fault: &str,
    ) -> Result<Option<Vec<u8>>> {
        if !["before-commit", "after-commit"].contains(&fault) {
            return Err(invalid("unknown fault point"));
        }
        let transport = BoundedLocal::new(metadata, targets)?;
        self.update_inner(
            transport.metadata.clone(),
            transport.targets.clone(),
            transport,
            target,
            None,
            None,
            Some(fault),
        )
        .await
        .map(|verified| verified.into_iter().next().map(|target| target.bytes))
    }
    async fn update_inner<T: Transport + 'static>(
        &mut self,
        metadata: Url,
        targets: Url,
        transport: T,
        target: Option<&str>,
        companion_target: Option<&str>,
        release_policy: Option<(&str, u64)>,
        fault: Option<&str>,
    ) -> Result<Vec<VerifiedTarget>> {
        self.update_inner_pinned(
            metadata,
            targets,
            transport,
            target,
            companion_target,
            release_policy,
            fault,
            None,
        )
        .await
    }

    async fn update_inner_pinned<T: Transport + 'static>(
        &mut self,
        metadata: Url,
        targets: Url,
        transport: T,
        target: Option<&str>,
        companion_target: Option<&str>,
        release_policy: Option<(&str, u64)>,
        fault: Option<&str>,
        expected_version: Option<&str>,
    ) -> Result<Vec<VerifiedTarget>> {
        if expected_version.is_some_and(|version| version.is_empty() || version.len() > 128) {
            return Err(invalid("requested release version is invalid"));
        }
        let previous = self.read_state()?;
        #[cfg(unix)]
        let stage = tempfile::Builder::new()
            .prefix("verify-")
            .tempdir_in(&self.directory)?;
        #[cfg(windows)]
        let stage = windows_storage::create_private_tempdir(&self.directory, "verify-")?;
        for (name, bytes) in STATE_FILES.iter().zip(&previous.files) {
            if let Some(bytes) = bytes {
                create_private(&stage.path().join(name), bytes)?;
            }
        }
        let repo = RepositoryLoader::new(&previous.root(), metadata, targets)
            .transport(transport)
            .limits(tough::Limits {
                max_root_size: MAX_METADATA as u64,
                max_timestamp_size: MAX_METADATA as u64,
                max_snapshot_size: MAX_METADATA as u64,
                max_targets_size: MAX_METADATA as u64,
                max_root_updates: 32,
            })
            .datastore(stage.path())
            .load()
            .await?;
        if repo
            .targets()
            .signed
            .delegations
            .as_ref()
            .is_some_and(|d| !d.roles.is_empty())
        {
            return Err(invalid("delegated roles unsupported"));
        }
        if target.is_some() && target == companion_target {
            return Err(invalid("primary and companion release targets must differ"));
        }
        let mut verified = Vec::new();
        for target_name in [target, companion_target].into_iter().flatten() {
            let name = TargetName::new(target_name)?;
            let described = repo
                .targets()
                .signed
                .targets
                .get(&name)
                .ok_or_else(|| invalid("target not described by top-level metadata"))?;
            if described.length > MAX_TARGET as u64 {
                return Err(invalid("target exceeds allocation limit"));
            }
            let custom = serde_json::to_value(&described.custom)?;
            if let Some((platform, profile_schema)) = release_policy {
                validate_release_custom(&custom, platform, profile_schema)?;
            }
            if let Some(expected) = expected_version {
                require_release_version(&custom, expected)?;
            }
            let mut stream = repo
                .read_target(&name)
                .await?
                .ok_or_else(|| invalid("missing target"))?;
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.try_next().await? {
                if bytes.len().saturating_add(chunk.len()) > MAX_TARGET {
                    return Err(invalid("target exceeds allocation limit"));
                }
                bytes.extend_from_slice(&chunk);
            }
            verified.push(VerifiedTarget { bytes, custom });
        }
        let mut next = State {
            generation: previous
                .generation
                .checked_add(1)
                .ok_or_else(|| invalid("trust generation overflow"))?,
            files: std::array::from_fn(|_| None),
        };
        for (i, name) in STATE_FILES.iter().enumerate() {
            next.files[i] = Some(read_bounded(&stage.path().join(name), MAX_METADATA)?);
        }
        next.validate()?;
        let old_clock: Timestamp = serde_json::from_slice(previous.files[4].as_ref().unwrap())?;
        let new_clock: Timestamp = serde_json::from_slice(next.files[4].as_ref().unwrap())?;
        let commit_clock = Timestamp::now();
        if new_clock < old_clock || commit_clock < new_clock {
            return Err(invalid("clock watermark regressed"));
        }
        // A target read may outlive the metadata's validity window. Recheck
        // expiration after full hash verification and persist the final time.
        if [
            repo.root().signed.expires,
            repo.timestamp().signed.expires,
            repo.snapshot().signed.expires,
            repo.targets().signed.expires,
        ]
        .into_iter()
        .any(|expiry| expiry <= commit_clock)
        {
            return Err(invalid("metadata expired before trust commit"));
        }
        next.files[4] = Some(serde_json::to_vec(&commit_clock)?);
        #[cfg(windows)]
        windows_storage::ensure_private_file(&self.directory.join("trust.sqlite-journal"))?;
        let tx = self.db.transaction()?;
        let changed=tx.execute("UPDATE trust_state SET generation=?1,root=?2,timestamp=?3,snapshot=?4,targets=?5,clock=?6,checksum=?7 WHERE id=1 AND generation=?8",params![next.generation,next.files[0],next.files[1],next.files[2],next.files[3],next.files[4],next.checksum(),previous.generation])?;
        if changed != 1 {
            return Err(invalid("concurrent trust state changed"));
        }
        fault_point(fault, "before-commit");
        tx.commit()?;
        fault_point(fault, "after-commit");
        sync_dir(&self.directory)?;
        Ok(verified)
    }
}

fn fault_point(fault: Option<&str>, point: &str) {
    #[cfg(feature = "fault-injection")]
    if fault == Some(point) {
        unsafe { libc::_exit(if point == "before-commit" { 91 } else { 92 }) }
    }
    #[cfg(not(feature = "fault-injection"))]
    let _ = (fault, point);
}
#[derive(Debug, Clone)]
struct BoundedLocal {
    metadata: Url,
    targets: Url,
    total: Arc<AtomicUsize>,
}
impl BoundedLocal {
    fn new(metadata: &Path, targets: &Path) -> Result<Self> {
        let metadata = Url::from_directory_path(fs::canonicalize(metadata)?)
            .map_err(|_| invalid("invalid mirror directory"))?;
        let targets = Url::from_directory_path(fs::canonicalize(targets)?)
            .map_err(|_| invalid("invalid mirror directory"))?;
        Ok(Self {
            metadata,
            targets,
            total: Arc::new(AtomicUsize::new(0)),
        })
    }
}
#[derive(Clone, Debug)]
struct BoundedHttps {
    origin: Url,
    metadata: Url,
    targets: Url,
    total: Arc<AtomicUsize>,
    started: Arc<Instant>,
    agent: ureq::Agent,
}
impl BoundedHttps {
    fn new(origin: &str) -> Result<Self> {
        let origin = Url::parse(origin)?;
        if origin.scheme() != "https"
            || origin.host_str().is_none()
            || !origin.username().is_empty()
            || origin.password().is_some()
            || origin.query().is_some()
            || origin.fragment().is_some()
            || !origin.path().ends_with('/')
        {
            return Err(invalid(
                "release origin must be a credential-free HTTPS directory URL",
            ));
        }
        let metadata = origin.join("metadata/")?;
        let targets = origin.join("targets/")?;
        let agent = ureq::Agent::config_builder()
            .https_only(true)
            .max_redirects(0)
            .max_redirects_will_error(false)
            .http_status_as_error(false)
            .timeout_global(Some(std::time::Duration::from_secs(120)))
            .proxy(None)
            .build()
            .new_agent();
        Ok(Self {
            origin,
            metadata,
            targets,
            total: Arc::new(AtomicUsize::new(0)),
            started: Arc::new(Instant::now()),
            agent,
        })
    }

    fn allowed(&self, url: &Url) -> bool {
        url.scheme() == "https"
            && url.host_str() == self.origin.host_str()
            && url.port_or_known_default() == self.origin.port_or_known_default()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && (url.path().starts_with(self.metadata.path())
                || url.path().starts_with(self.targets.path()))
    }

    fn fetch_blocking(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let fail = |error: Box<dyn std::error::Error + Send + Sync>| {
            TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
        };
        if !self.allowed(&url) {
            let error = fail(invalid("release fetch escaped the configured HTTPS origin"));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        if self.started.elapsed() > std::time::Duration::from_secs(15 * 60) {
            let error = fail(invalid(
                "release verification exceeded its total time budget",
            ));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        let cap = if url.path().starts_with(self.metadata.path()) {
            MAX_METADATA
        } else {
            MAX_TARGET
        };
        let response = match self.agent.get(url.as_str()).call() {
            Ok(response) => response,
            Err(error) => {
                let error = fail(Box::new(error));
                return Ok(Box::pin(stream::once(async move { Err(error) })));
            }
        };
        if response.status().as_u16() == 404 {
            return Err(TransportError::new(
                TransportErrorKind::FileNotFound,
                url.as_str(),
            ));
        }
        if response.status().as_u16() != 200 {
            let status = response.status().as_u16();
            let error = fail(invalid(if (300..400).contains(&status) {
                "release server redirects are forbidden"
            } else {
                "release server returned a non-success response"
            }));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        let (parts, body) = response.into_parts();
        let content_length = body.content_length();
        if content_length.is_some_and(|length| length > cap as u64) {
            let error = fail(invalid("release response exceeds its bounded size"));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        let mut reader = body.into_with_config().limit(cap as u64).reader();
        let mut bytes =
            Vec::with_capacity(content_length.map_or(0, |length| (length as usize).min(cap)));
        if let Err(error) = reader.by_ref().take(cap as u64 + 1).read_to_end(&mut bytes) {
            let error = fail(Box::new(error));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        if bytes.len() > cap {
            let error = fail(invalid("release response exceeds its bounded size"));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        if self
            .total
            .fetch_add(bytes.len(), Ordering::Relaxed)
            .saturating_add(bytes.len())
            > MAX_TOTAL
        {
            let error = fail(invalid("release verification fetch budget exceeded"));
            return Ok(Box::pin(stream::once(async move { Err(error) })));
        }
        let _ = parts;
        Ok(Box::pin(stream::once(
            async move { Ok(Bytes::from(bytes)) },
        )))
    }
}
#[async_trait]
impl Transport for BoundedLocal {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let fail = |e: Box<dyn std::error::Error + Send + Sync>| {
            TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), e)
        };
        let path = url.to_file_path().map_err(|_| {
            TransportError::new(TransportErrorKind::UnsupportedUrlScheme, url.as_str())
        })?;
        let metadata_fetch = url.scheme() == "file"
            && url.host_str() == self.metadata.host_str()
            && url.path().starts_with(self.metadata.path());
        let target_fetch = url.scheme() == "file"
            && url.host_str() == self.targets.host_str()
            && url.path().starts_with(self.targets.path());
        let cap = if metadata_fetch {
            MAX_METADATA
        } else if target_fetch {
            MAX_TARGET
        } else {
            return Err(fail(invalid("mirror path outside configured directories")));
        };
        let bytes = match read_bounded(&path, cap) {
            Ok(v) => v,
            Err(e) => {
                if e.downcast_ref::<io::Error>()
                    .is_some_and(|e| e.kind() == io::ErrorKind::NotFound)
                {
                    return Err(TransportError::new(
                        TransportErrorKind::FileNotFound,
                        url.as_str(),
                    ));
                }
                // Tough treats fetch-level errors for the next root as absence.
                // Deliver policy/I/O failures through the stream so only a real
                // FileNotFound can be interpreted as a missing rotation file.
                let error = fail(e);
                return Ok(Box::pin(stream::once(async move { Err(error) })));
            }
        };
        if self
            .total
            .fetch_add(bytes.len(), Ordering::Relaxed)
            .saturating_add(bytes.len())
            > MAX_TOTAL
        {
            return Err(fail(invalid("verification fetch budget exceeded")));
        }
        Ok(Box::pin(stream::once(
            async move { Ok(Bytes::from(bytes)) },
        )))
    }
}
#[async_trait]
impl Transport for BoundedHttps {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        let client = self.clone();
        let request_url = url.clone();
        tokio::task::spawn_blocking(move || client.fetch_blocking(request_url))
            .await
            .map_err(|error| {
                TransportError::new_with_cause(
                    TransportErrorKind::Other,
                    url.as_str(),
                    Box::new(error),
                )
            })?
    }
}
