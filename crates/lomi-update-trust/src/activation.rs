//! Crash-recoverable, content-addressed executable activation.
//!
//! The activation directory is deliberately separate from the host profile.
//! A small durable journal lets the next updater restore both pointers if a
//! process is interrupted between their individual atomic renames.

use crate::{MAX_TARGET, Result, invalid, read_bounded, sync_dir};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt, symlink},
    },
    path::{Path, PathBuf},
    sync::atomic::{AtomicUsize, Ordering},
};

const ACTIVE: &str = "active";
const PREVIOUS: &str = "previous";
const ACTIVE_COMPANION: &str = "active-helper";
const PREVIOUS_COMPANION: &str = "previous-helper";
const JOURNAL: &str = "activation.pending";
const ACTIVATION_LOCK: &str = ".activation.lock";
const ADMIN_OWNER_BINDING: &str = "admin-owner.json";
const ADMIN_PROFILE_INIT: &str = "admin-profile-init.json";
const ADMIN_PROFILE_INIT_TEMP: &str = ".admin-profile-init.tmp";
const MAX_ADMIN_PROFILE_INIT_BYTES: usize = 16 * 1024;
// A regular executable path remains stable for OS service registrations. The
// `active` symlink remains an internal pointer and is never given to a service
// manager as its executable path.
const STABLE_EXECUTABLE: &str = "lomiremote";
const STABLE_COMPANION: &str = "lomiremote-host";

fn uid() -> u32 {
    unsafe { libc::geteuid() }
}

pub(crate) fn validate_directory(path: &Path) -> Result<()> {
    validate_directory_mode(path, uid(), 0o700)
}

pub(crate) fn validate_admin_boot_directory(path: &Path) -> Result<()> {
    if uid() != 0 {
        return Err(invalid("admin boot activation requires root"));
    }
    validate_directory_mode(path, 0, 0o755)
}

fn validate_directory_mode(path: &Path, expected_uid: u32, expected_mode: u32) -> Result<()> {
    if !path.is_absolute() || fs::canonicalize(path)? != path {
        return Err(invalid(
            "activation directory must be absolute and canonical",
        ));
    }
    let mut current = PathBuf::from("/");
    for component in path.components().skip(1) {
        current.push(component.as_os_str());
        let metadata = fs::symlink_metadata(&current)?;
        let trusted_owner = metadata.uid() == 0 || metadata.uid() == uid();
        let writable = metadata.mode() & 0o022 != 0;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !trusted_owner
            || (writable && metadata.mode() & 0o1000 == 0)
        {
            return Err(invalid(
                "activation path has an unsafe owner, mode or component",
            ));
        }
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != expected_uid || metadata.mode() & 0o777 != expected_mode {
        return Err(invalid("activation directory has unexpected owner or mode"));
    }
    Ok(())
}

fn stable_mode(root: &Path) -> Result<u32> {
    let metadata = fs::symlink_metadata(root)?;
    if metadata.uid() == 0 && metadata.mode() & 0o777 == 0o755 {
        Ok(0o555)
    } else {
        Ok(0o500)
    }
}

fn private_regular(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "activation state must be a private owned regular file",
        ));
    }
    Ok(())
}

fn lock(path: &Path) -> Result<File> {
    let lock_path = path.join(ACTIVATION_LOCK);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&lock_path)?;
    private_regular(&lock_path)?;
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::WouldBlock,
            "activation is owned by another updater",
        )
        .into());
    }
    Ok(file)
}

/// Bind this protected install directory to one selected Host lifecycle mode.
/// Format 1 predates mode selection and is accepted only as Boot.
pub(crate) fn bind_admin_host_identity(
    root: &Path,
    account_uid: u32,
    canonical_profile: &Path,
    host_mode: &str,
) -> Result<String> {
    validate_admin_boot_directory(root)?;
    if uid() != 0
        || account_uid == 0
        || !matches!(host_mode, "manual" | "login" | "boot")
        || !canonical_profile.is_absolute()
        || fs::canonicalize(canonical_profile)? != canonical_profile
    {
        return Err(invalid("invalid selected admin profile identity"));
    }
    let profile = canonical_profile
        .to_str()
        .ok_or_else(|| invalid("selected profile path is not UTF-8"))?;
    let legacy_boot = serde_json::to_vec(&serde_json::json!({
        "format": 1,
        "accountUid": account_uid,
        "profilePath": profile,
    }))?;
    let expected = serde_json::to_vec(&serde_json::json!({
        "format": 2,
        "accountUid": account_uid,
        "hostMode": host_mode,
        "profilePath": profile,
    }))?;
    let _lock = lock(root)?;
    let binding = root.join(ADMIN_OWNER_BINDING);
    match fs::symlink_metadata(&binding) {
        Ok(_) => {
            private_regular(&binding)?;
            let stored = read_bounded(&binding, 16 * 1024)?;
            let stored_mode = if stored == legacy_boot {
                "boot"
            } else if stored == expected {
                host_mode
            } else {
                return Err(invalid(
                    "admin install directory is bound to another account, profile, or Host mode",
                ));
            };
            if stored_mode != host_mode {
                return Err(invalid(
                    "admin install directory is bound to another Host mode",
                ));
            }
            Ok(stored_mode.to_owned())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // A missing binding can only initialize a genuinely empty admin
            // install directory. Existing releases must never be adopted by
            // whichever account happens to run the updater first.
            for entry in fs::read_dir(root)? {
                let name = entry?.file_name();
                if name != ACTIVATION_LOCK && name != ADMIN_OWNER_BINDING {
                    return Err(invalid(
                        "unbound admin install directory contains existing state",
                    ));
                }
            }
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(&binding)?;
            let result = (|| -> Result<()> {
                file.write_all(&expected)?;
                file.sync_all()?;
                sync_dir(root)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&binding);
                let _ = sync_dir(root);
            }
            result.map(|()| host_mode.to_owned())
        }
        Err(error) => Err(error.into()),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AdminProfileInitState {
    Pending,
    Complete,
}

/// Root-private proof that a protected admin release is allowed to initialize
/// a selected account's profile exactly once after its first activation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminProfileInitReceipt {
    version: u8,
    state: AdminProfileInitState,
    install_path: String,
    profile_path: String,
    account_uid: u32,
    host_mode: String,
    target: String,
    policy_sha256: String,
    host_id: Option<String>,
    profile_id: Option<String>,
}

impl AdminProfileInitReceipt {
    pub(crate) fn is_pending(&self) -> bool {
        self.state == AdminProfileInitState::Pending
    }

    pub(crate) fn is_complete(&self) -> bool {
        self.state == AdminProfileInitState::Complete
    }
}

fn admin_owner_binding_bytes(account_uid: u32, profile: &Path, mode: &str) -> Result<Vec<u8>> {
    if account_uid == 0
        || !matches!(mode, "manual" | "login" | "boot")
        || !profile.is_absolute()
        || profile.to_str().is_none()
    {
        return Err(invalid("invalid admin profile initialization binding"));
    }
    Ok(serde_json::to_vec(&serde_json::json!({
        "format": 2,
        "accountUid": account_uid,
        "hostMode": mode,
        "profilePath": profile.to_str().expect("validated UTF-8 profile"),
    }))?)
}

fn verify_admin_owner_binding(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
) -> Result<()> {
    let path = root.join(ADMIN_OWNER_BINDING);
    private_regular(&path)?;
    if read_bounded(&path, MAX_ADMIN_PROFILE_INIT_BYTES)?
        != admin_owner_binding_bytes(account_uid, profile, mode)?
    {
        return Err(invalid(
            "profile initialization receipt does not match admin owner binding",
        ));
    }
    Ok(())
}

fn validate_admin_profile_init_receipt(
    root: &Path,
    receipt: &AdminProfileInitReceipt,
    account_uid: u32,
    profile: &Path,
    mode: &str,
) -> Result<()> {
    if receipt.version != 1
        || receipt.install_path != root.to_str().unwrap_or_default()
        || receipt.profile_path != profile.to_str().unwrap_or_default()
        || receipt.account_uid != account_uid
        || receipt.host_mode != mode
        || !matches!(mode, "manual" | "login" | "boot")
    {
        return Err(invalid(
            "admin profile initialization receipt binding is mismatched",
        ));
    }
    pointer_target(&receipt.target)?;
    parse_digest(&receipt.policy_sha256)?;
    match receipt.state {
        AdminProfileInitState::Pending
            if receipt.host_id.is_none() && receipt.profile_id.is_none() => {}
        AdminProfileInitState::Pending
            if receipt.host_id.is_some() && receipt.profile_id.is_some() =>
        {
            validate_canonical_uuid(receipt.host_id.as_deref())?;
            validate_canonical_uuid(receipt.profile_id.as_deref())?;
        }
        AdminProfileInitState::Complete => {
            validate_canonical_uuid(receipt.host_id.as_deref())?;
            validate_canonical_uuid(receipt.profile_id.as_deref())?;
        }
        _ => {
            return Err(invalid(
                "admin profile initialization receipt has invalid state",
            ));
        }
    }
    verify_admin_owner_binding(root, account_uid, profile, mode)
}

pub(crate) fn validate_canonical_uuid(value: Option<&str>) -> Result<()> {
    let Some(value) = value else {
        return Err(invalid("admin profile initialization identity is missing"));
    };
    if value.len() != 36
        || [8, 13, 18, 23]
            .iter()
            .any(|&index| value.as_bytes().get(index) != Some(&b'-'))
        || value
            .bytes()
            .enumerate()
            .any(|(index, byte)| ![8, 13, 18, 23].contains(&index) && !byte.is_ascii_hexdigit())
        || value.bytes().any(|byte| byte.is_ascii_uppercase())
        || value == "00000000-0000-0000-0000-000000000000"
    {
        return Err(invalid(
            "admin profile initialization identity is malformed",
        ));
    }
    Ok(())
}

fn read_admin_profile_init_locked(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
) -> Result<Option<AdminProfileInitReceipt>> {
    let path = root.join(ADMIN_PROFILE_INIT);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    private_regular(&path)?;
    let bytes = read_bounded(&path, MAX_ADMIN_PROFILE_INIT_BYTES)?;
    let wire: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| invalid("admin profile initialization receipt is malformed"))?;
    let object = wire
        .as_object()
        .ok_or_else(|| invalid("admin profile initialization receipt is not an object"))?;
    if object.len() != 10 {
        return Err(invalid(
            "admin profile initialization receipt has unknown fields",
        ));
    }
    let required_string = |key: &str| -> Result<String> {
        object
            .get(key)
            .and_then(serde_json::Value::as_str)
            .map(ToOwned::to_owned)
            .ok_or_else(|| invalid("admin profile initialization receipt is malformed"))
    };
    let optional_string = |key: &str| -> Result<Option<String>> {
        match object.get(key) {
            Some(serde_json::Value::Null) => Ok(None),
            Some(serde_json::Value::String(value)) => Ok(Some(value.clone())),
            _ => Err(invalid("admin profile initialization receipt is malformed")),
        }
    };
    let version = object
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .and_then(|value| u8::try_from(value).ok())
        .ok_or_else(|| invalid("admin profile initialization receipt is malformed"))?;
    let state = match required_string("state")?.as_str() {
        "pending" => AdminProfileInitState::Pending,
        "complete" => AdminProfileInitState::Complete,
        _ => return Err(invalid("admin profile initialization state is invalid")),
    };
    let receipt = AdminProfileInitReceipt {
        version,
        state,
        install_path: required_string("installPath")?,
        profile_path: required_string("profilePath")?,
        account_uid: object
            .get("accountUid")
            .and_then(serde_json::Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| invalid("admin profile initialization receipt is malformed"))?,
        host_mode: required_string("hostMode")?,
        target: required_string("target")?,
        policy_sha256: required_string("policySha256")?,
        host_id: optional_string("hostId")?,
        profile_id: optional_string("profileId")?,
    };
    if receipt_json(&receipt) != wire || serde_json::to_vec(&wire)? != bytes {
        return Err(invalid(
            "admin profile initialization receipt is not canonical",
        ));
    }
    validate_admin_profile_init_receipt(root, &receipt, account_uid, profile, mode)?;
    Ok(Some(receipt))
}

fn write_admin_profile_init_locked(root: &Path, receipt: &AdminProfileInitReceipt) -> Result<()> {
    let bytes = serde_json::to_vec(&receipt_json(receipt))?;
    if bytes.is_empty() || bytes.len() > MAX_ADMIN_PROFILE_INIT_BYTES {
        return Err(invalid("admin profile initialization receipt is oversized"));
    }
    let destination = root.join(ADMIN_PROFILE_INIT);
    let stage_path = root.join(ADMIN_PROFILE_INIT_TEMP);
    match fs::symlink_metadata(&stage_path) {
        Ok(_) => {
            private_regular(&stage_path)?;
            let staged_bytes = read_bounded(&stage_path, MAX_ADMIN_PROFILE_INIT_BYTES)?;
            if staged_bytes.is_empty() {
                return Err(invalid("admin profile receipt stage is empty"));
            }
            fs::remove_file(&stage_path)?;
            sync_dir(root)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&stage_path)?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&stage_path, &destination)?;
        sync_dir(root)?;
        private_regular(&destination)?;
        Ok(())
    })();
    if result.is_err() {
        if fs::symlink_metadata(&stage_path).is_ok() {
            private_regular(&stage_path)?;
            fs::remove_file(&stage_path)?;
            sync_dir(root)?;
        }
    }
    result
}

fn receipt_json(receipt: &AdminProfileInitReceipt) -> serde_json::Value {
    serde_json::json!({
        "version": receipt.version,
        "state": match receipt.state {
            AdminProfileInitState::Pending => "pending",
            AdminProfileInitState::Complete => "complete",
        },
        "installPath": receipt.install_path,
        "profilePath": receipt.profile_path,
        "accountUid": receipt.account_uid,
        "hostMode": receipt.host_mode,
        "target": receipt.target,
        "policySha256": receipt.policy_sha256,
        "hostId": receipt.host_id,
        "profileId": receipt.profile_id,
    })
}

/// Read the exact root-private first-profile receipt for a selected admin Host.
pub(crate) fn read_admin_profile_init_receipt(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
) -> Result<Option<AdminProfileInitReceipt>> {
    validate_admin_boot_directory(root)?;
    if uid() != 0 {
        return Err(invalid("admin profile receipt requires root"));
    }
    let _lock = lock(root)?;
    read_admin_profile_init_locked(root, account_uid, profile, mode)
}

/// Conjunctively compare a completed root initialization receipt with the
/// selected-account database identity observed from a defensive snapshot.
pub(crate) fn verify_admin_profile_init_identity(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
    host_id: &str,
    profile_id: &str,
) -> Result<Option<AdminProfileInitState>> {
    validate_canonical_uuid(Some(host_id))?;
    validate_canonical_uuid(Some(profile_id))?;
    validate_admin_boot_directory(root)?;
    let _lock = lock(root)?;
    match read_admin_profile_init_locked(root, account_uid, profile, mode)? {
        None => Ok(None),
        Some(receipt) if receipt.state == AdminProfileInitState::Pending => {
            Ok(Some(AdminProfileInitState::Pending))
        }
        Some(receipt)
            if receipt.host_id.as_deref() == Some(host_id)
                && receipt.profile_id.as_deref() == Some(profile_id) =>
        {
            Ok(Some(AdminProfileInitState::Complete))
        }
        Some(_) => Err(invalid(
            "completed admin profile identity does not match the database",
        )),
    }
}

/// Durably record the exact verified release intent before its first
/// activation. Replacing an interrupted target is allowed only after the
/// activation directory is positively back in its initial empty state.
pub(crate) fn prepare_admin_profile_init_receipt(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
    bytes: &[u8],
    custom: &serde_json::Value,
    expected_identity: Option<(&str, &str)>,
) -> Result<AdminProfileInitReceipt> {
    validate_admin_boot_directory(root)?;
    if uid() != 0 || bytes.is_empty() || bytes.len() > MAX_TARGET {
        return Err(invalid("invalid initial admin release intent"));
    }
    let _lock = lock(root)?;
    verify_admin_owner_binding(root, account_uid, profile, mode)?;
    let target = format!("objects/sha256/{}", digest_hex(bytes));
    let policy_sha256 = digest_hex(&serde_json::to_vec(custom)?);
    let path = root
        .to_str()
        .ok_or_else(|| invalid("install path is not UTF-8"))?;
    let mut receipt = AdminProfileInitReceipt {
        version: 1,
        state: AdminProfileInitState::Pending,
        install_path: path.to_owned(),
        profile_path: profile
            .to_str()
            .ok_or_else(|| invalid("profile path is not UTF-8"))?
            .to_owned(),
        account_uid,
        host_mode: mode.to_owned(),
        target,
        policy_sha256,
        host_id: expected_identity.map(|(host_id, _)| host_id.to_owned()),
        profile_id: expected_identity.map(|(_, profile_id)| profile_id.to_owned()),
    };
    validate_admin_profile_init_receipt(root, &receipt, account_uid, profile, mode)?;
    match read_admin_profile_init_locked(root, account_uid, profile, mode)? {
        Some(existing) if existing.state == AdminProfileInitState::Complete => {
            return Err(invalid(
                "admin Host profile initialization is already complete",
            ));
        }
        Some(existing) if existing == receipt => return Ok(existing),
        Some(existing)
            if existing.state == AdminProfileInitState::Pending
                && (existing.host_id.as_deref() != receipt.host_id.as_deref()
                    || existing.profile_id.as_deref() != receipt.profile_id.as_deref()) =>
        {
            return Err(invalid(
                "pending profile identity changed before admin activation",
            ));
        }
        Some(_) if initial_admin_host_install_candidate_locked(root)? => {}
        Some(_) => {
            return Err(invalid(
                "cannot replace pending profile intent after release activation",
            ));
        }
        None if initial_admin_host_install_candidate_locked(root)? => {}
        None => {
            return Err(invalid(
                "profile initialization intent is allowed only for a fresh admin install",
            ));
        }
    }
    // Ensure the intent names an exact image and policy that will be staged by
    // the following activation call.
    receipt.state = AdminProfileInitState::Pending;
    write_admin_profile_init_locked(root, &receipt)?;
    Ok(receipt)
}

fn pending_admin_profile_init_target_locked(
    root: &Path,
    receipt: &AdminProfileInitReceipt,
    platform: &str,
) -> Result<Option<PathBuf>> {
    let active = read_pointer(root, ACTIVE)?;
    let Some(active) = active else {
        if initial_admin_host_install_candidate_locked(root)? {
            return Ok(None);
        }
        return Err(invalid(
            "pending profile initialization has ambiguous activation state",
        ));
    };
    if active != receipt.target
        || read_pointer(root, PREVIOUS)?.is_some()
        || read_pointer(root, ACTIVE_COMPANION)?.is_some()
        || read_pointer(root, PREVIOUS_COMPANION)?.is_some()
        || stable_digest(root, STABLE_EXECUTABLE)?.as_deref()
            != Some(target_digest(&receipt.target)?)
        || stable_digest(root, STABLE_COMPANION)?.is_some()
    {
        return Err(invalid(
            "active release does not match pending profile initialization",
        ));
    }
    let custom = release_custom(root, &receipt.target)?;
    if digest_hex(&serde_json::to_vec(&custom)?) != receipt.policy_sha256 {
        return Err(invalid("active release policy differs from init receipt"));
    }
    crate::validate_release_custom(&custom, platform, 0)?;
    verify_object(root, &receipt.target).map(Some)
}

/// Return the active object if a pending first-profile intent has committed.
/// `None` means the activation is still positively at its initial state.
pub(crate) fn pending_admin_profile_init_target(
    root: &Path,
    receipt: &AdminProfileInitReceipt,
    account_uid: u32,
    profile: &Path,
    mode: &str,
    platform: &str,
) -> Result<Option<PathBuf>> {
    validate_admin_boot_directory(root)?;
    let _lock = lock(root)?;
    let current = read_admin_profile_init_locked(root, account_uid, profile, mode)?
        .ok_or_else(|| invalid("pending admin profile receipt disappeared"))?;
    if current != *receipt || current.state != AdminProfileInitState::Pending {
        return Err(invalid("pending admin profile receipt changed"));
    }
    pending_admin_profile_init_target_locked(root, receipt, platform)
}

/// Complete a pending initialization only after the selected-account helper
/// succeeded and the active signed policy supports the resulting DB schema.
pub(crate) fn complete_admin_profile_init_receipt(
    root: &Path,
    receipt: &AdminProfileInitReceipt,
    account_uid: u32,
    profile: &Path,
    mode: &str,
    platform: &str,
    actual_schema: u64,
    host_id: &str,
    profile_id: &str,
) -> Result<PathBuf> {
    validate_admin_boot_directory(root)?;
    validate_canonical_uuid(Some(host_id))?;
    validate_canonical_uuid(Some(profile_id))?;
    let _lock = lock(root)?;
    let mut current = read_admin_profile_init_locked(root, account_uid, profile, mode)?
        .ok_or_else(|| invalid("admin profile initialization receipt disappeared"))?;
    if current.state == AdminProfileInitState::Complete {
        let mut pending_form = current.clone();
        pending_form.state = AdminProfileInitState::Pending;
        if receipt.host_id.is_none() && receipt.profile_id.is_none() {
            pending_form.host_id = None;
            pending_form.profile_id = None;
        }
        if pending_form == *receipt
            && current.host_id.as_deref() == Some(host_id)
            && current.profile_id.as_deref() == Some(profile_id)
        {
            return verify_object(root, &current.target);
        }
        return Err(invalid("completed profile initialization identity changed"));
    }
    if current != *receipt {
        return Err(invalid("admin profile initialization receipt changed"));
    }
    if current.state != AdminProfileInitState::Pending {
        return Err(invalid("admin profile initialization is not pending"));
    }
    if current
        .host_id
        .as_deref()
        .is_some_and(|expected| expected != host_id)
        || current
            .profile_id
            .as_deref()
            .is_some_and(|expected| expected != profile_id)
    {
        return Err(invalid(
            "selected-account initializer changed the preflight identity",
        ));
    }
    let object = pending_admin_profile_init_target_locked(root, &current, platform)?
        .ok_or_else(|| invalid("admin profile cannot complete before activation"))?;
    let custom = release_custom(root, &current.target)?;
    crate::validate_release_custom(&custom, platform, actual_schema)?;
    current.state = AdminProfileInitState::Complete;
    current.host_id = Some(host_id.to_owned());
    current.profile_id = Some(profile_id.to_owned());
    validate_admin_profile_init_receipt(root, &current, account_uid, profile, mode)?;
    write_admin_profile_init_locked(root, &current)?;
    Ok(object)
}

/// Explicitly adopt an already initialized legacy admin profile after a
/// verified updater operation. Startup never calls this function. It refuses
/// an existing root receipt and pins only the identity observed by the caller
/// from its owner-locked defensive database snapshot.
pub(crate) fn adopt_existing_admin_profile_identity(
    root: &Path,
    account_uid: u32,
    profile: &Path,
    mode: &str,
    platform: &str,
    profile_schema: u64,
    host_id: &str,
    profile_id: &str,
) -> Result<()> {
    validate_admin_boot_directory(root)?;
    if uid() != 0 {
        return Err(invalid("admin profile identity adoption requires root"));
    }
    validate_canonical_uuid(Some(host_id))?;
    validate_canonical_uuid(Some(profile_id))?;
    let _lock = lock(root)?;
    verify_admin_owner_binding(root, account_uid, profile, mode)?;
    if read_admin_profile_init_locked(root, account_uid, profile, mode)?.is_some() {
        return Err(invalid(
            "admin profile identity adoption cannot replace an existing receipt",
        ));
    }
    match fs::symlink_metadata(root.join(JOURNAL)) {
        Ok(_) => {
            return Err(invalid(
                "admin profile identity adoption requires a recovered activation",
            ));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let target = read_pointer(root, ACTIVE)?
        .ok_or_else(|| invalid("admin profile identity adoption requires an active release"))?;
    stable_matches(root, STABLE_EXECUTABLE, Some(&target))?;
    verify_object(root, &target)?;
    let custom = release_custom(root, &target)?;
    crate::validate_release_custom(&custom, platform, profile_schema)?;
    let install_path = root
        .to_str()
        .ok_or_else(|| invalid("admin install path is not UTF-8"))?;
    let profile_path = profile
        .to_str()
        .ok_or_else(|| invalid("admin profile path is not UTF-8"))?;
    let receipt = AdminProfileInitReceipt {
        version: 1,
        state: AdminProfileInitState::Complete,
        install_path: install_path.to_owned(),
        profile_path: profile_path.to_owned(),
        account_uid,
        host_mode: mode.to_owned(),
        target,
        policy_sha256: digest_hex(&serde_json::to_vec(&custom)?),
        host_id: Some(host_id.to_owned()),
        profile_id: Some(profile_id.to_owned()),
    };
    validate_admin_profile_init_receipt(root, &receipt, account_uid, profile, mode)?;
    write_admin_profile_init_locked(root, &receipt)
}

fn parse_digest(value: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid("activation pointer has a malformed digest"));
    }
    Ok(())
}

fn pointer_target(value: &str) -> Result<()> {
    let Some(digest) = value.strip_prefix("objects/sha256/") else {
        return Err(invalid(
            "activation pointer is not a relative content object link",
        ));
    };
    parse_digest(digest)
}

fn object_path(root: &Path, target: &str) -> Result<PathBuf> {
    pointer_target(target)?;
    Ok(root.join(target))
}

fn verify_object(root: &Path, target: &str) -> Result<PathBuf> {
    for directory in [root.join("objects"), root.join("objects/sha256")] {
        let directory_metadata = fs::symlink_metadata(&directory)?;
        if directory_metadata.file_type().is_symlink()
            || !directory_metadata.is_dir()
            || directory_metadata.uid() != uid()
            || directory_metadata.mode() & 0o777 != 0o700
        {
            return Err(invalid(
                "activation object path has unsafe directory ownership or mode",
            ));
        }
    }
    let path = object_path(root, target)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o500
        || metadata.nlink() != 1
        || metadata.len() > MAX_TARGET as u64
    {
        return Err(invalid(
            "activation object has unsafe ownership, mode or size",
        ));
    }
    let bytes = read_bounded(&path, MAX_TARGET)?;
    let expected = target
        .rsplit('/')
        .next()
        .ok_or_else(|| invalid("invalid object path"))?;
    let actual = Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    if actual != expected {
        return Err(invalid("activation object content hash mismatch"));
    }
    #[cfg(all(target_os = "macos", feature = "release-root"))]
    crate::verify_macos_activation_image(&path)?;
    Ok(path)
}

fn stable_digest(root: &Path, name: &str) -> Result<Option<String>> {
    let path = root.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != stable_mode(root)?
        || metadata.nlink() != 1
        || metadata.len() > MAX_TARGET as u64
    {
        return Err(invalid(
            "stable executable has unsafe ownership, mode, link count or size",
        ));
    }
    let bytes = read_bounded(&path, MAX_TARGET)?;
    Ok(Some(
        Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
    ))
}

fn target_digest(target: &str) -> Result<&str> {
    pointer_target(target)?;
    target
        .rsplit('/')
        .next()
        .ok_or_else(|| invalid("activation target has no digest"))
}

fn digest_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn replace_stable_executable(
    root: &Path,
    name: &str,
    target: Option<&str>,
    permitted_existing: &[Option<String>],
) -> Result<()> {
    let existing = stable_digest(root, name)?;
    if let Some(existing) = existing.as_deref() {
        let allowed = permitted_existing
            .iter()
            .flatten()
            .map(|candidate| target_digest(candidate))
            .collect::<Result<Vec<_>>>()?;
        if !allowed.contains(&existing) {
            return Err(invalid(
                "stable executable does not match an authenticated activation object",
            ));
        }
    }
    let Some(target) = target else {
        if existing.is_some() {
            fs::remove_file(root.join(name))?;
            sync_dir(root)?;
        }
        return Ok(());
    };
    let object = verify_object(root, target)?;
    let bytes = read_bounded(&object, MAX_TARGET)?;
    if digest_hex(&bytes) != target_digest(target)? {
        return Err(invalid("stable executable source hash mismatch"));
    }
    static NEXT_STAGE: AtomicUsize = AtomicUsize::new(0);
    let mut staged = None;
    for _ in 0..32 {
        let path = root.join(format!(
            ".{name}-stage-{}-{}",
            std::process::id(),
            NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                staged = Some((path, file));
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let (stage_path, mut stage) =
        staged.ok_or_else(|| invalid("could not allocate stable executable stage"))?;
    let result = (|| -> Result<()> {
        stage.write_all(&bytes)?;
        stage.set_permissions(fs::Permissions::from_mode(stable_mode(root)?))?;
        stage.sync_all()?;
        fs::rename(&stage_path, root.join(name))?;
        sync_dir(root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(stage_path);
    }
    result
}

fn stable_matches(root: &Path, name: &str, target: Option<&str>) -> Result<()> {
    let existing = stable_digest(root, name)?;
    match (target, existing.as_deref()) {
        (Some(target), Some(existing)) if target_digest(target)? == existing => Ok(()),
        (Some(target), None) => replace_stable_executable(root, name, Some(target), &[None]),
        (None, None) => Ok(()),
        (Some(_), Some(_)) => Err(invalid(
            "stable executable does not match the active activation pointer",
        )),
        (None, Some(_)) => Err(invalid(
            "stable executable exists without an active activation pointer",
        )),
    }
}

fn release_sidecar(root: &Path, target: &str) -> Result<PathBuf> {
    let object = object_path(root, target)?;
    let name = object
        .file_name()
        .ok_or_else(|| invalid("content object has no file name"))?
        .to_string_lossy();
    Ok(object.with_file_name(format!("{name}.release.json")))
}

fn write_release_sidecar(root: &Path, target: &str, custom: &serde_json::Value) -> Result<()> {
    let bytes = serde_json::to_vec(custom)?;
    if bytes.is_empty() || bytes.len() > 16 * 1024 {
        return Err(invalid("release target metadata is empty or oversized"));
    }
    let path = release_sidecar(root, target)?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.uid() != uid()
                || metadata.mode() & 0o777 != 0o400
                || metadata.nlink() != 1
                || read_bounded(&path, 16 * 1024)? != bytes
            {
                return Err(invalid("existing release metadata is unsafe or mismatched"));
            }
            return Ok(());
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    static NEXT_SIDECAR: AtomicUsize = AtomicUsize::new(0);
    let mut staged_file = None;
    let mut staged_path = None;
    for _ in 0..32 {
        let candidate = path.with_file_name(format!(
            ".release-{}-{}",
            std::process::id(),
            NEXT_SIDECAR.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&candidate)
        {
            Ok(file) => {
                staged_file = Some(file);
                staged_path = Some(candidate);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let mut file =
        staged_file.ok_or_else(|| invalid("could not allocate release metadata stage"))?;
    let stage = staged_path.ok_or_else(|| invalid("missing release metadata stage"))?;
    let result = (|| -> Result<()> {
        file.write_all(&bytes)?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        file.sync_all()?;
        fs::rename(&stage, &path)?;
        sync_dir(
            path.parent()
                .ok_or_else(|| invalid("release metadata has no parent"))?,
        )?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(stage);
    }
    result
}

fn release_custom(root: &Path, target: &str) -> Result<serde_json::Value> {
    verify_object(root, target)?;
    let path = release_sidecar(root, target)?;
    let metadata = fs::symlink_metadata(&path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o400
        || metadata.nlink() != 1
    {
        return Err(invalid(
            "release metadata sidecar has unsafe ownership or mode",
        ));
    }
    Ok(serde_json::from_slice(&read_bounded(&path, 16 * 1024)?)?)
}

pub(crate) fn check_release_compatibility(
    root: &Path,
    target: &str,
    platform: &str,
    profile_schema: u64,
) -> Result<()> {
    let custom = release_custom(root, target)?;
    crate::validate_release_custom(&custom, platform, profile_schema)
}

fn read_pointer(root: &Path, name: &str) -> Result<Option<String>> {
    let path = root.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if !metadata.file_type().is_symlink() || metadata.uid() != uid() {
        return Err(invalid("activation pointer is not an owned symlink"));
    }
    let value = fs::read_link(path)?
        .to_str()
        .ok_or_else(|| invalid("activation pointer is not UTF-8"))?
        .to_owned();
    verify_object(root, &value)?;
    Ok(Some(value))
}

fn replace_pointer(root: &Path, name: &str, target: Option<&str>) -> Result<()> {
    let destination = root.join(name);
    match fs::symlink_metadata(&destination) {
        Ok(metadata) => {
            if !metadata.file_type().is_symlink() || metadata.uid() != uid() {
                return Err(invalid(
                    "refusing to replace a non-owned activation pointer",
                ));
            }
            // Validate the existing link before replacing it, even when a
            // transaction is recovering from an interrupted pointer swap.
            let previous = fs::read_link(&destination)?;
            let previous = previous
                .to_str()
                .ok_or_else(|| invalid("activation pointer is not UTF-8"))?;
            verify_object(root, previous)?;
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let Some(target) = target else {
        match fs::remove_file(&destination) {
            Ok(()) => sync_dir(root)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        return Ok(());
    };
    verify_object(root, target)?;
    static NEXT_LINK: AtomicUsize = AtomicUsize::new(0);
    let staged = root.join(format!(
        ".{name}-{}-{}",
        std::process::id(),
        NEXT_LINK.fetch_add(1, Ordering::Relaxed)
    ));
    symlink(Path::new(target), &staged)?;
    if let Err(error) = fs::rename(&staged, &destination) {
        let _ = fs::remove_file(&staged);
        return Err(error.into());
    }
    sync_dir(root)?;
    Ok(())
}

#[derive(Clone, Debug)]
struct PointerState {
    active: Option<String>,
    previous: Option<String>,
    companion: Option<String>,
    previous_companion: Option<String>,
}

impl PointerState {
    fn encode(&self) -> Vec<u8> {
        format!(
            "lomi-activation-v2\nactive={}\nprevious={}\ncompanion={}\nprevious_companion={}\n",
            self.active.as_deref().unwrap_or("-"),
            self.previous.as_deref().unwrap_or("-"),
            self.companion.as_deref().unwrap_or("-"),
            self.previous_companion.as_deref().unwrap_or("-")
        )
        .into_bytes()
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let text =
            std::str::from_utf8(bytes).map_err(|_| invalid("activation journal is not UTF-8"))?;
        let mut lines = text.lines();
        let version = lines.next();
        if !matches!(version, Some("lomi-activation-v1" | "lomi-activation-v2")) {
            return Err(invalid("activation journal has an unsupported format"));
        }
        let active = lines
            .next()
            .and_then(|line| line.strip_prefix("active="))
            .ok_or_else(|| invalid("activation journal has no active pointer"))?;
        let previous = lines
            .next()
            .and_then(|line| line.strip_prefix("previous="))
            .ok_or_else(|| invalid("activation journal has no previous pointer"))?;
        let parse = |value: &str| -> Result<Option<String>> {
            if value == "-" {
                Ok(None)
            } else {
                pointer_target(value)?;
                Ok(Some(value.to_owned()))
            }
        };
        let (companion, previous_companion) = if version == Some("lomi-activation-v2") {
            let companion = lines
                .next()
                .and_then(|line| line.strip_prefix("companion="))
                .ok_or_else(|| invalid("activation journal has no companion pointer"))?;
            let previous_companion = lines
                .next()
                .and_then(|line| line.strip_prefix("previous_companion="))
                .ok_or_else(|| invalid("activation journal has no previous companion pointer"))?;
            (parse(companion)?, parse(previous_companion)?)
        } else {
            (None, None)
        };
        if lines.next().is_some() {
            return Err(invalid("activation journal has trailing data"));
        }
        Ok(Self {
            active: parse(active)?,
            previous: parse(previous)?,
            companion,
            previous_companion,
        })
    }
}

fn read_journal(root: &Path) -> Result<Option<PointerState>> {
    let path = root.join(JOURNAL);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
        Ok(_) => {
            private_regular(&path)?;
            PointerState::decode(&read_bounded(&path, 1024)?).map(Some)
        }
    }
}

fn write_journal(root: &Path, state: &PointerState) -> Result<()> {
    static NEXT_JOURNAL: AtomicUsize = AtomicUsize::new(0);
    let mut staged_file = None;
    let mut staged_path = None;
    for _ in 0..32 {
        let path = root.join(format!(
            ".activation-pending-{}-{}",
            std::process::id(),
            NEXT_JOURNAL.fetch_add(1, Ordering::Relaxed)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
        {
            Ok(file) => {
                staged_file = Some(file);
                staged_path = Some(path);
                break;
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let mut file = staged_file.ok_or_else(|| invalid("could not allocate activation journal"))?;
    let path = staged_path.ok_or_else(|| invalid("missing activation journal stage"))?;
    let result = (|| -> Result<()> {
        file.write_all(&state.encode())?;
        file.sync_all()?;
        fs::rename(&path, root.join(JOURNAL))?;
        sync_dir(root)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

fn clear_journal(root: &Path) -> Result<()> {
    match fs::remove_file(root.join(JOURNAL)) {
        Ok(()) => sync_dir(root)?,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

fn recover(root: &Path) -> Result<()> {
    let Some(state) = read_journal(root)? else {
        let active = read_pointer(root, ACTIVE)?;
        let companion = read_pointer(root, ACTIVE_COMPANION)?;
        for target in [active.as_deref(), companion.as_deref()]
            .into_iter()
            .flatten()
        {
            verify_object(root, target)?;
        }
        stable_matches(root, STABLE_EXECUTABLE, active.as_deref())?;
        return stable_matches(root, STABLE_COMPANION, companion.as_deref());
    };
    for target in [
        state.active.as_deref(),
        state.previous.as_deref(),
        state.companion.as_deref(),
        state.previous_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        verify_object(root, target)?;
    }
    let current_active = read_pointer(root, ACTIVE)?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    // Restore stable files while the pointers still retain the interrupted
    // generation digests. If recovery itself is interrupted, the next pass
    // can again recognize either the before or partially installed stable
    // object and finish idempotently.
    replace_stable_executable(
        root,
        STABLE_EXECUTABLE,
        state.active.as_deref(),
        &[state.active.clone(), current_active.clone()],
    )?;
    replace_stable_executable(
        root,
        STABLE_COMPANION,
        state.companion.as_deref(),
        &[state.companion.clone(), current_companion.clone()],
    )?;
    replace_pointer(root, PREVIOUS, state.previous.as_deref())?;
    replace_pointer(
        root,
        PREVIOUS_COMPANION,
        state.previous_companion.as_deref(),
    )?;
    replace_pointer(root, ACTIVE, state.active.as_deref())?;
    replace_pointer(root, ACTIVE_COMPANION, state.companion.as_deref())?;
    clear_journal(root)
}

pub(crate) fn recovery_pending(root: &Path) -> Result<bool> {
    validate_directory(root)?;
    read_journal(root).map(|journal| journal.is_some())
}

/// Observe a complete private activation without repairing missing files or
/// pointers. Callers hold the profile owner barrier while supplying its schema.
#[cfg(target_os = "linux")]
pub(crate) fn validate_active_release(
    root: &Path,
    platform: &str,
    profile_schema: u64,
) -> Result<Option<PathBuf>> {
    validate_directory(root)?;
    let _lock = lock(root)?;
    if read_journal(root)?.is_some() {
        return Err(invalid("release activation requires recovery"));
    }
    let active = read_pointer(root, ACTIVE)?;
    let previous = read_pointer(root, PREVIOUS)?;
    let companion = read_pointer(root, ACTIVE_COMPANION)?;
    let previous_companion = read_pointer(root, PREVIOUS_COMPANION)?;
    if companion.is_some() || previous_companion.is_some() {
        return Err(invalid(
            "private Unix release has unexpected companion state",
        ));
    }
    let stable = stable_digest(root, STABLE_EXECUTABLE)?;
    if stable_digest(root, STABLE_COMPANION)?.is_some() {
        return Err(invalid(
            "private Unix release has an unexpected companion executable",
        ));
    }
    match (active, stable) {
        (None, None) if previous.is_none() => Ok(None),
        (Some(target), Some(digest)) if target_digest(&target)? == digest => {
            check_release_compatibility(root, &target, platform, profile_schema)?;
            Ok(Some(root.join(STABLE_EXECUTABLE)))
        }
        _ => Err(invalid("active release and stable executable do not agree")),
    }
}

/// Authenticate the stable CLI before an installer executes a lifecycle
/// command. This does not open a Host profile, repair activation, or require
/// online metadata freshness. During interrupted activation the stable image
/// may match the current pointer or the journal's exact prior active object.
pub(crate) fn verify_maintenance_cli(root: &Path, platform: &str, admin: bool) -> Result<()> {
    if admin {
        validate_admin_boot_directory(root)?;
    } else {
        validate_directory(root)?;
    }
    let _lock = lock(root)?;
    let journal = read_journal(root)?;
    let active = read_pointer(root, ACTIVE)?;
    let stable = stable_digest(root, STABLE_EXECUTABLE)?
        .ok_or_else(|| invalid("installed maintenance CLI is missing"))?;
    for target in [active, journal.and_then(|state| state.active)]
        .into_iter()
        .flatten()
    {
        verify_object(root, &target)?;
        if target_digest(&target)? == stable {
            // Schema compatibility is checked later under the actual profile
            // lock. Zero validates the signed platform/range shape here.
            check_release_compatibility(root, &target, platform, 0)?;
            return Ok(());
        }
    }
    Err(invalid(
        "installed maintenance CLI does not match its activated release",
    ))
}

#[cfg(target_os = "macos")]
pub(crate) fn check_object_release_version(
    root: &Path,
    object: &Path,
    expected: &str,
) -> Result<()> {
    let target = object
        .strip_prefix(root)
        .ok()
        .and_then(Path::to_str)
        .ok_or_else(|| invalid("release object is outside its activation directory"))?;
    crate::require_release_version(&release_custom(root, target)?, expected)
}

pub(crate) fn recovery_pending_admin_boot(root: &Path) -> Result<bool> {
    validate_admin_boot_directory(root)?;
    read_journal(root).map(|journal| journal.is_some())
}

/// Return whether an admin install directory has no activated executable
/// generation yet. The activation lock makes the pointer, journal, and stable
/// executable observations one consistent snapshot. This is only a candidate
/// check; callers must repeat it after acquiring the Host/profile guard.
pub(crate) fn initial_admin_host_install_candidate(root: &Path) -> Result<bool> {
    validate_admin_boot_directory(root)?;
    let _lock = lock(root)?;
    initial_admin_host_install_candidate_locked(root)
}

fn initial_admin_host_install_candidate_locked(root: &Path) -> Result<bool> {
    if read_journal(root)?.is_some() {
        return Ok(false);
    }
    for name in [ACTIVE, PREVIOUS, ACTIVE_COMPANION, PREVIOUS_COMPANION] {
        if read_pointer(root, name)?.is_some() {
            return Ok(false);
        }
    }
    if stable_digest(root, STABLE_EXECUTABLE)?.is_some()
        || stable_digest(root, STABLE_COMPANION)?.is_some()
    {
        return Ok(false);
    }
    Ok(true)
}

pub(crate) fn recover_verified(root: &Path, platform: &str, profile_schema: u64) -> Result<()> {
    validate_directory(root)?;
    recover_verified_inner(root, platform, profile_schema)
}

pub(crate) fn recover_verified_admin_boot(
    root: &Path,
    platform: &str,
    profile_schema: u64,
) -> Result<()> {
    validate_admin_boot_directory(root)?;
    recover_verified_inner(root, platform, profile_schema)
}

fn recover_verified_inner(root: &Path, platform: &str, profile_schema: u64) -> Result<()> {
    let _lock = lock(root)?;
    let Some(state) = read_journal(root)? else {
        return Err(invalid("no interrupted release activation is pending"));
    };

    let current_active = read_pointer(root, ACTIVE)?;
    let current_previous = read_pointer(root, PREVIOUS)?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    let current_previous_companion = read_pointer(root, PREVIOUS_COMPANION)?;
    for target in [
        state.active.as_deref(),
        state.previous.as_deref(),
        state.companion.as_deref(),
        state.previous_companion.as_deref(),
        current_active.as_deref(),
        current_previous.as_deref(),
        current_companion.as_deref(),
        current_previous_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        let custom = release_custom(root, target)?;
        crate::release_schema_range(&custom, platform)?;
    }
    for target in [
        state.active.as_deref(),
        state.companion.as_deref(),
        current_active.as_deref(),
        current_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        check_release_compatibility(root, target, platform, profile_schema)?;
    }
    for (main, helper) in [
        (state.active.as_deref(), state.companion.as_deref()),
        (
            state.previous.as_deref(),
            state.previous_companion.as_deref(),
        ),
    ] {
        if let (Some(main), Some(helper)) = (main, helper)
            && release_custom(root, main)?.get("lomiRelease")
                != release_custom(root, helper)?.get("lomiRelease")
        {
            return Err(invalid(
                "interrupted executable pair has mismatched release policy",
            ));
        }
    }
    recover(root)
}

fn commit_pointers(
    root: &Path,
    active: Option<String>,
    previous: Option<String>,
    companion: Option<String>,
    previous_companion: Option<String>,
) -> Result<()> {
    recover(root)?;
    for target in [
        active.as_deref(),
        previous.as_deref(),
        companion.as_deref(),
        previous_companion.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        verify_object(root, target)?;
    }
    let before = PointerState {
        active: read_pointer(root, ACTIVE)?,
        previous: read_pointer(root, PREVIOUS)?,
        companion: read_pointer(root, ACTIVE_COMPANION)?,
        previous_companion: read_pointer(root, PREVIOUS_COMPANION)?,
    };
    stable_matches(root, STABLE_EXECUTABLE, before.active.as_deref())?;
    stable_matches(root, STABLE_COMPANION, before.companion.as_deref())?;
    let after = PointerState {
        active,
        previous,
        companion,
        previous_companion,
    };
    write_journal(root, &before)?;
    let result = (|| -> Result<()> {
        // Record the recovery state first. If either rename is interrupted,
        // recovery restores the complete old pair before another operation.
        replace_pointer(root, PREVIOUS, after.previous.as_deref())?;
        replace_pointer(
            root,
            PREVIOUS_COMPANION,
            after.previous_companion.as_deref(),
        )?;
        replace_pointer(root, ACTIVE, after.active.as_deref())?;
        replace_pointer(root, ACTIVE_COMPANION, after.companion.as_deref())?;
        // The regular executable is the last visible activation step. Service
        // registrations keep these pathnames across releases and rollbacks.
        replace_stable_executable(
            root,
            STABLE_EXECUTABLE,
            after.active.as_deref(),
            &[before.active.clone(), after.active.clone()],
        )?;
        replace_stable_executable(
            root,
            STABLE_COMPANION,
            after.companion.as_deref(),
            &[before.companion.clone(), after.companion.clone()],
        )?;
        clear_journal(root)
    })();
    if result.is_err() {
        // Leave a durable journal if restoration itself cannot complete.
        let _ = recover(root);
    }
    result
}

pub(crate) fn activate_verified_bytes(root: &Path, bytes: &[u8]) -> Result<PathBuf> {
    activate(root, bytes, None, false)
}

pub(crate) fn activate_verified_target(
    root: &Path,
    bytes: &[u8],
    custom: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<PathBuf> {
    crate::validate_release_custom(custom, platform, profile_schema)?;
    activate(root, bytes, Some(custom), false)
}

pub(crate) fn activate_verified_target_admin_boot(
    root: &Path,
    bytes: &[u8],
    custom: &serde_json::Value,
    platform: &str,
    profile_schema: u64,
) -> Result<PathBuf> {
    crate::validate_release_custom(custom, platform, profile_schema)?;
    activate(root, bytes, Some(custom), true)
}

fn activate(
    root: &Path,
    bytes: &[u8],
    custom: Option<&serde_json::Value>,
    admin_boot: bool,
) -> Result<PathBuf> {
    if admin_boot {
        validate_admin_boot_directory(root)?;
    } else {
        validate_directory(root)?;
    }
    if bytes.is_empty() || bytes.len() > MAX_TARGET {
        return Err(invalid("verified target is empty or oversized"));
    }
    let _lock = lock(root)?;
    recover(root)?;
    let current = read_pointer(root, ACTIVE)?;
    // Validate `previous` before changing any state.
    let _ = read_pointer(root, PREVIOUS)?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    let _ = read_pointer(root, PREVIOUS_COMPANION)?;

    let objects = root.join("objects");
    let hashes = objects.join("sha256");
    create_or_check_private_dir(&objects)?;
    create_or_check_private_dir(&hashes)?;

    let digest = Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let target = format!("objects/sha256/{digest}");
    let object = root.join(&target);
    match fs::symlink_metadata(&object) {
        Ok(_) => {
            if verify_object(root, &target)? != object {
                return Err(invalid("content-addressed object path mismatch"));
            }
            if read_bounded(&object, MAX_TARGET)? != bytes {
                return Err(invalid("existing content object is corrupt"));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            static NEXT_STAGE: AtomicUsize = AtomicUsize::new(0);
            let mut staged_file = None;
            let mut staged_path = None;
            for _ in 0..32 {
                let path = hashes.join(format!(
                    ".stage-{}-{}",
                    std::process::id(),
                    NEXT_STAGE.fetch_add(1, Ordering::Relaxed)
                ));
                match OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                    .open(&path)
                {
                    Ok(file) => {
                        staged_file = Some(file);
                        staged_path = Some(path);
                        break;
                    }
                    Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                    Err(error) => return Err(error.into()),
                }
            }
            let mut staged =
                staged_file.ok_or_else(|| invalid("could not allocate object stage"))?;
            let stage_path = staged_path.ok_or_else(|| invalid("missing object stage"))?;
            let result = (|| -> Result<()> {
                staged.write_all(bytes)?;
                staged.set_permissions(fs::Permissions::from_mode(0o500))?;
                staged.sync_all()?;
                fs::rename(&stage_path, &object)?;
                sync_dir(&hashes)?;
                Ok(())
            })();
            if result.is_err() {
                let _ = fs::remove_file(&stage_path);
            }
            result?;
        }
        Err(error) => return Err(error.into()),
    }
    if let Some(custom) = custom {
        write_release_sidecar(root, &target, custom)?;
    }
    let previous = current.clone();
    commit_pointers(
        root,
        Some(target),
        previous,
        current_companion.clone(),
        current_companion,
    )?;
    Ok(object)
}

pub(crate) fn rollback(root: &Path, platform: &str, profile_schema: u64) -> Result<PathBuf> {
    validate_directory(root)?;
    rollback_inner(root, platform, profile_schema)
}

pub(crate) fn rollback_admin_boot(
    root: &Path,
    platform: &str,
    profile_schema: u64,
) -> Result<PathBuf> {
    validate_admin_boot_directory(root)?;
    rollback_inner(root, platform, profile_schema)
}

fn rollback_inner(root: &Path, platform: &str, profile_schema: u64) -> Result<PathBuf> {
    let _lock = lock(root)?;
    recover(root)?;
    let current =
        read_pointer(root, ACTIVE)?.ok_or_else(|| invalid("no active release to roll back"))?;
    let previous =
        read_pointer(root, PREVIOUS)?.ok_or_else(|| invalid("no previously active release"))?;
    let current_companion = read_pointer(root, ACTIVE_COMPANION)?;
    let previous_companion = read_pointer(root, PREVIOUS_COMPANION)?;
    check_release_compatibility(root, &previous, platform, profile_schema)?;
    let destination = verify_object(root, &previous)?;
    commit_pointers(
        root,
        Some(previous),
        Some(current),
        previous_companion,
        current_companion,
    )?;
    Ok(destination)
}

pub(crate) fn uninstall(root: &Path) -> Result<usize> {
    validate_directory(root)?;
    uninstall_inner(root)
}

pub(crate) fn uninstall_admin_boot(root: &Path) -> Result<usize> {
    validate_admin_boot_directory(root)?;
    uninstall_inner(root)
}

fn uninstall_inner(root: &Path) -> Result<usize> {
    let _lock = lock(root)?;
    recover(root)?;
    let _ = read_pointer(root, ACTIVE)?;
    let _ = read_pointer(root, PREVIOUS)?;
    let _ = read_pointer(root, ACTIVE_COMPANION)?;
    let _ = read_pointer(root, PREVIOUS_COMPANION)?;
    commit_pointers(root, None, None, None, None)?;

    let hashes = root.join("objects/sha256");
    let metadata = match fs::symlink_metadata(&hashes) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(invalid("refusing to remove an unsafe object directory"));
    }
    let mut removed = 0usize;
    for entry in fs::read_dir(&hashes)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(digest) = name.to_str() else {
            continue;
        };
        if parse_digest(digest).is_err() {
            continue;
        }
        let target = format!("objects/sha256/{digest}");
        if verify_object(root, &target).is_ok() {
            let sidecar = release_sidecar(root, &target)?;
            match fs::symlink_metadata(&sidecar) {
                Ok(sidecar_metadata) => {
                    if sidecar_metadata.file_type().is_symlink()
                        || !sidecar_metadata.is_file()
                        || sidecar_metadata.uid() != uid()
                        || sidecar_metadata.mode() & 0o777 != 0o400
                        || sidecar_metadata.nlink() != 1
                        || sidecar_metadata.len() > 16 * 1024
                    {
                        return Err(invalid("refusing to remove unsafe release metadata"));
                    }
                    fs::remove_file(&sidecar)?;
                }
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
            fs::remove_file(entry.path())?;
            removed += 1;
        }
    }
    sync_dir(&hashes)?;
    Ok(removed)
}

fn create_or_check_private_dir(path: &Path) -> Result<()> {
    match fs::create_dir(path) {
        Ok(()) => {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            sync_dir(path.parent().ok_or_else(|| invalid("missing parent"))?)?;
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != uid()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err(invalid(
            "activation object directory must be owned and mode 0700",
        ));
    }
    Ok(())
}
