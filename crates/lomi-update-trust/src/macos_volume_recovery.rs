//! Explicit administrator recovery of legacy, mount-number-bound receipts.
//!
//! Ordinary readers continue to reject a stale v1 device number. Only this
//! maintenance operation may enroll the current volume, after the activated
//! image, root identity receipts and locked database identity agree.
use super::*;
use lomi_platform::service_macos::{self, AdminHostMode};
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "platform", rename_all = "snake_case", deny_unknown_fields)]
enum ReceiptOwner {
    Unix {
        uid: u32,
        gid: u32,
        device: u64,
        inode: u64,
        #[serde(
            rename = "volumeUuid",
            default,
            skip_serializing_if = "Option::is_none"
        )]
        volume_uuid: Option<String>,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct InitializationReceipt {
    version: u8,
    state: String,
    profile_path: String,
    owner: ReceiptOwner,
    host_id: Option<String>,
    profile_id: Option<String>,
}

struct ProfileContext<'a> {
    path: &'a Path,
    uid: u32,
    gid: u32,
    device: u64,
    inode: u64,
    volume_uuid: &'a str,
    host_id: &'a str,
    profile_id: &'a str,
}

fn migrated_receipt(
    bytes: &[u8],
    context: &ProfileContext<'_>,
    allow_device_drift: bool,
) -> Result<Option<Vec<u8>>> {
    let mut receipt: InitializationReceipt = serde_json::from_slice(bytes)?;
    if serde_json::to_vec(&receipt)? != bytes
        || receipt.state != "complete"
        || receipt.profile_path != context.path.to_str().unwrap_or("")
        || receipt.host_id.as_deref() != Some(context.host_id)
        || receipt.profile_id.as_deref() != Some(context.profile_id)
    {
        return Err(invalid(
            "legacy profile receipt does not match the root-pinned identity",
        ));
    }
    let ReceiptOwner::Unix {
        uid,
        gid,
        device,
        inode,
        volume_uuid,
    } = &mut receipt.owner;
    if *uid != context.uid || *gid != context.gid || *inode != context.inode {
        return Err(invalid("legacy profile receipt account or inode changed"));
    }
    let uuid = uuid::Uuid::parse_str(context.volume_uuid)?;
    if uuid.is_nil() || uuid.to_string() != context.volume_uuid {
        return Err(invalid("current profile volume UUID is invalid"));
    }
    match receipt.version {
        1 if volume_uuid.is_none() => {
            if *device != context.device && !allow_device_drift {
                return Err(invalid(
                    "legacy profile device changed outside explicit recovery",
                ));
            }
            receipt.version = 2;
            *volume_uuid = Some(context.volume_uuid.to_owned());
            // Preserve the historical observation, just like custody's journal
            // crosslinks. v2 uses the UUID to authenticate the live volume.
            Ok(Some(serde_json::to_vec(&receipt)?))
        }
        2 if volume_uuid.as_deref() == Some(context.volume_uuid) => Ok(None),
        _ => Err(invalid("profile receipt volume binding is invalid")),
    }
}

fn legacy_receipt_device_drift(bytes: &[u8], context: &ProfileContext<'_>) -> Result<bool> {
    // Fully validate the candidate even though this preflight makes no writes.
    migrated_receipt(bytes, context, true)?;
    let receipt: InitializationReceipt = serde_json::from_slice(bytes)?;
    let ReceiptOwner::Unix { device, .. } = receipt.owner;
    Ok(receipt.version == 1 && device != context.device)
}

/// A valid v1 receipt can be promoted while the normal authenticated update
/// already holds its owner lock. This path never permits device drift.
pub(super) fn upgrade_valid_initialization_receipt(
    guard: &service_macos::BootMaintenanceGuard,
    identity: &AdminHostProfileIdentity,
) -> Result<()> {
    let bytes = guard
        .read_host_initialization_receipt()?
        .ok_or_else(|| invalid("initialized profile receipt is missing"))?;
    let metadata = fs::symlink_metadata(guard.profile_path())?;
    let (device, inode) = guard.profile_identity();
    let volume_uuid = guard.profile_volume_uuid()?;
    let host_id = identity.host_id_text();
    let profile_id = identity.profile_id_text();
    let context = ProfileContext {
        path: guard.profile_path(),
        uid: guard.owner_uid(),
        gid: metadata.gid(),
        device,
        inode,
        volume_uuid: &volume_uuid,
        host_id: &host_id,
        profile_id: &profile_id,
    };
    if let Some(replacement) = migrated_receipt(&bytes, &context, false)? {
        guard.replace_host_initialization_receipt(&bytes, &replacement)?;
    }
    Ok(())
}

pub(super) fn host_receipt_uses_volume_identity(
    guard: &service_macos::BootMaintenanceGuard,
) -> Result<bool> {
    let bytes = guard
        .read_host_initialization_receipt()?
        .ok_or_else(|| invalid("initialized profile receipt is missing"))?;
    let receipt: InitializationReceipt = serde_json::from_slice(&bytes)?;
    if serde_json::to_vec(&receipt)? != bytes {
        return Err(invalid("initialized profile receipt is not canonical"));
    }
    Ok(receipt.version == 2)
}

fn read_receipt_candidate(profile: &Path, uid: u32, gid: u32) -> Result<Vec<u8>> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(profile.join("host-init.json"))?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.gid() != gid
        || metadata.nlink() != 1
        || metadata.mode() & 0o7777 != 0o600
    {
        return Err(invalid(
            "profile initialization receipt has unsafe metadata",
        ));
    }
    let mut bytes = Vec::new();
    (&mut file).take(32 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 32 * 1024 {
        return Err(invalid("profile initialization receipt is too large"));
    }
    Ok(bytes)
}

/// Read-only preflight for both independently published legacy receipts. It
/// also catches a retry interrupted between custody and Host receipt writes.
pub fn admin_legacy_volume_binding_repair_needed(
    profile: &Path,
    install: &Path,
    platform: &str,
    account: &str,
    mode: AdminHostMode,
) -> Result<bool> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid(
            "legacy volume preflight requires administrator authorization",
        ));
    }
    verify_admin_installed_maintenance_cli(install, platform)?;
    let executable = install.join("lomiremote");
    let identity =
        service_macos::read_admin_host_identity_binding(profile, &executable, account, mode)?;
    let (profile, uid) = service_macos::validate_boot_profile(profile, account)?;
    let descriptor = File::open(&profile)?;
    let metadata = descriptor.metadata()?;
    let volume_uuid = lomi_platform::volume_identity::volume_uuid(&descriptor)?;
    let bytes = read_receipt_candidate(&profile, uid, metadata.gid())?;
    let host_id = String::from(identity.host_id());
    let profile_id = String::from(identity.profile_id());
    let context = ProfileContext {
        path: &profile,
        uid,
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        volume_uuid: &volume_uuid,
        host_id: &host_id,
        profile_id: &profile_id,
    };
    let receipt_drift = legacy_receipt_device_drift(&bytes, &context)?;
    let custody_drift =
        service_macos::legacy_custody_volume_repair_needed(&profile, &executable, account, mode)?;
    Ok(receipt_drift || custody_drift)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminVolumeBindingState {
    Clear,
    RepairNeeded,
    RuntimeUpgradeNeeded,
}

/// Retain recovery intent across a failed download after receipt migration.
/// Both independent receipt domains are validated before combining their
/// formats; an already-migrated receipt never authorizes repeat enrollment.
pub fn admin_volume_binding_state(
    profile: &Path,
    install: &Path,
    platform: &str,
    account: &str,
    mode: AdminHostMode,
) -> Result<AdminVolumeBindingState> {
    if admin_legacy_volume_binding_repair_needed(profile, install, platform, account, mode)? {
        return Ok(AdminVolumeBindingState::RepairNeeded);
    }
    let (profile, uid) = service_macos::validate_boot_profile(profile, account)?;
    let metadata = fs::symlink_metadata(&profile)?;
    let receipt: InitializationReceipt =
        serde_json::from_slice(&read_receipt_candidate(&profile, uid, metadata.gid())?)?;
    let custody_v2 = service_macos::custody::admin_custody_uses_volume_identity(
        &profile,
        &install.join("lomiremote"),
        account,
        mode,
    )?;
    if !activation::active_supports_volume_identity(install)?
        && (receipt.version == 2 || custody_v2)
    {
        Ok(AdminVolumeBindingState::RuntimeUpgradeNeeded)
    } else {
        Ok(AdminVolumeBindingState::Clear)
    }
}

/// Repair only a legacy device-number drift, never a different account,
/// profile, volume UUID, inode, executable image or Host identity.
pub fn repair_admin_legacy_volume_bindings(
    profile: &Path,
    install: &Path,
    platform: &str,
    account: &str,
    mode: AdminHostMode,
) -> Result<bool> {
    if unsafe { libc::geteuid() } != 0 {
        return Err(invalid(
            "legacy volume recovery requires administrator authorization",
        ));
    }
    verify_admin_installed_maintenance_cli(install, platform)?;
    let executable = install.join("lomiremote");
    let identity =
        service_macos::read_admin_host_identity_binding(profile, &executable, account, mode)?;
    let (canonical_profile, uid) = service_macos::validate_boot_profile(profile, account)?;
    let descriptor = File::open(&canonical_profile)?;
    let metadata = descriptor.metadata()?;
    let volume_uuid = lomi_platform::volume_identity::volume_uuid(&descriptor)?;
    let host_id = String::from(identity.host_id());
    let profile_id = String::from(identity.profile_id());
    let bytes = read_receipt_candidate(&canonical_profile, uid, metadata.gid())?;
    let context = ProfileContext {
        path: &canonical_profile,
        uid,
        gid: metadata.gid(),
        device: metadata.dev(),
        inode: metadata.ino(),
        volume_uuid: &volume_uuid,
        host_id: &host_id,
        profile_id: &profile_id,
    };
    let receipt_needed = legacy_receipt_device_drift(&bytes, &context)?;
    let custody_needed = service_macos::legacy_custody_volume_repair_needed(
        &canonical_profile,
        &executable,
        account,
        mode,
    )?;
    // A stale v1 custody record is read only through the explicit legacy
    // preflight above. Its repair already stops the old job under both locks.
    let runtime_upgrade_needed = !custody_needed
        && !activation::active_supports_volume_identity(install)?
        && (serde_json::from_slice::<InitializationReceipt>(&bytes)?.version == 2
            || service_macos::custody::admin_custody_uses_volume_identity(
                &canonical_profile,
                &executable,
                account,
                mode,
            )?);
    if !receipt_needed && !custody_needed && !runtime_upgrade_needed {
        return Err(invalid(
            "status failure is not a recoverable legacy volume binding",
        ));
    }

    // This is a mutation barrier, not a relaxed status read. It verifies and
    // stops only this selected Host and retains its native service/owner locks.
    let guard = service_macos::acquire_admin_maintenance_guard(
        &canonical_profile,
        &executable,
        account,
        mode,
        true,
        false,
    )?;
    verify_admin_installed_maintenance_cli(install, platform)?;
    let (_, database_identity) = read_admin_profile_snapshot(&guard, install)?;
    let database_identity =
        database_identity.ok_or_else(|| invalid("locked profile has no Host identity"))?;
    if database_identity.host_id_text() != host_id
        || database_identity.profile_id_text() != profile_id
        || activation::verify_admin_profile_init_identity(
            install,
            uid,
            &canonical_profile,
            mode.as_str(),
            &host_id,
            &profile_id,
        )? != Some(activation::AdminProfileInitState::Complete)
    {
        return Err(invalid(
            "legacy recovery requires matching completed root and database identities",
        ));
    }
    service_macos::verify_admin_host_identity_binding(&guard, &host_id, &profile_id)?;
    let locked_bytes = guard
        .read_host_initialization_receipt()?
        .ok_or_else(|| invalid("locked profile initialization receipt is missing"))?;
    if locked_bytes != bytes {
        return Err(invalid("profile receipt changed during legacy recovery"));
    }
    let (device, inode) = guard.profile_identity();
    let locked_uuid = guard.profile_volume_uuid()?;
    let locked_context = ProfileContext {
        path: guard.profile_path(),
        uid: guard.owner_uid(),
        gid: metadata.gid(),
        device,
        inode,
        volume_uuid: &locked_uuid,
        host_id: &host_id,
        profile_id: &profile_id,
    };
    let replacement = migrated_receipt(&locked_bytes, &locked_context, true)?;
    let custody_repaired = service_macos::repair_legacy_custody_volume_binding(&guard)?;
    if runtime_upgrade_needed {
        service_macos::custody::prepare_legacy_custody_runtime_upgrade(&guard)?;
    }
    if let Some(replacement) = replacement.as_ref() {
        guard.replace_host_initialization_receipt(&locked_bytes, replacement)?;
    }
    Ok(custody_repaired || replacement.is_some() || runtime_upgrade_needed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> ProfileContext<'static> {
        ProfileContext {
            path: Path::new("/Users/test/profile"),
            uid: 501,
            gid: 20,
            device: 22,
            inode: 1234,
            volume_uuid: "12345678-1234-5678-9012-123456789abc",
            host_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        }
    }
    fn receipt() -> Vec<u8> {
        serde_json::to_vec(&InitializationReceipt {
            version: 1,
            state: "complete".into(),
            profile_path: "/Users/test/profile".into(),
            owner: ReceiptOwner::Unix {
                uid: 501,
                gid: 20,
                device: 11,
                inode: 1234,
                volume_uuid: None,
            },
            host_id: Some(context().host_id.into()),
            profile_id: Some(context().profile_id.into()),
        })
        .unwrap()
    }
    #[test]
    fn explicit_recovery_adds_uuid_but_preserves_history_and_identity() {
        let bytes = migrated_receipt(&receipt(), &context(), true)
            .unwrap()
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["owner"]["device"], 11);
        assert_eq!(value["owner"]["volumeUuid"], context().volume_uuid);
        assert!(
            migrated_receipt(&bytes, &context(), true)
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn explicit_recovery_rejects_changed_identity_or_inode() {
        for field in ["uid", "gid", "inode"] {
            let mut value: serde_json::Value = serde_json::from_slice(&receipt()).unwrap();
            value["owner"][field] = 999.into();
            let mut receipt: InitializationReceipt = serde_json::from_value(value).unwrap();
            // Canonical typed encoding distinguishes validation from JSON order.
            assert!(
                migrated_receipt(&serde_json::to_vec(&receipt).unwrap(), &context(), true).is_err()
            );
            receipt.host_id = Some("cccccccc-cccc-4ccc-8ccc-cccccccccccc".into());
            assert!(
                migrated_receipt(&serde_json::to_vec(&receipt).unwrap(), &context(), true).is_err()
            );
        }
    }
    #[test]
    fn v2_cannot_reenroll_another_volume() {
        let bytes = migrated_receipt(&receipt(), &context(), true)
            .unwrap()
            .unwrap();
        let mut changed = context();
        changed.volume_uuid = "99999999-1234-5678-9012-123456789abc";
        assert!(migrated_receipt(&bytes, &changed, true).is_err());
    }
    #[test]
    fn unchanged_legacy_device_is_not_a_repair_candidate() {
        let mut unchanged = context();
        unchanged.device = 11;
        assert!(!legacy_receipt_device_drift(&receipt(), &unchanged).unwrap());
        assert!(
            migrated_receipt(&receipt(), &unchanged, false)
                .unwrap()
                .is_some()
        );
        assert!(migrated_receipt(&receipt(), &context(), false).is_err());
    }
}
