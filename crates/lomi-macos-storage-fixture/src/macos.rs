//! E0 legacy file-keychain probe, not a product credential adapter.
mod product;
use std::{
    ffi::{CString, c_char, c_void},
    io::Read,
    ptr,
};
type Ref = *mut c_void;
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
    fn SecKeychainCreate(
        path: *const c_char,
        len: u32,
        password: *const c_void,
        prompt: u8,
        access: Ref,
        keychain: *mut Ref,
    ) -> i32;
    fn SecKeychainUnlock(keychain: Ref, len: u32, password: *const c_void, use_password: u8)
    -> i32;
    fn SecKeychainLock(keychain: Ref) -> i32;
    fn SecKeychainGetStatus(keychain: Ref, status: *mut u32) -> i32;
    fn SecKeychainGetPath(keychain: Ref, length: *mut u32, path: *mut c_char) -> i32;
    fn SecKeychainItemDelete(item: Ref) -> i32;
    fn SecKeychainItemModifyAttributesAndData(
        item: Ref,
        attrs: Ref,
        len: u32,
        data: *const c_void,
    ) -> i32;
    fn SecKeychainDelete(keychain: Ref) -> i32;
    fn SecKeychainCopySearchList(list: *mut Ref) -> i32;
    fn SecKeychainCopyDefault(keychain: *mut Ref) -> i32;
    fn SecKeychainAddGenericPassword(
        keychain: Ref,
        slen: u32,
        service: *const c_char,
        alen: u32,
        account: *const c_char,
        plen: u32,
        password: *const c_void,
        item: *mut Ref,
    ) -> i32;
    fn SecKeychainFindGenericPassword(
        keychain: Ref,
        slen: u32,
        service: *const c_char,
        alen: u32,
        account: *const c_char,
        plen: *mut u32,
        password: *mut Ref,
        item: *mut Ref,
    ) -> i32;
    fn SecKeychainItemFreeContent(attrs: Ref, data: Ref) -> i32;
}
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFRelease(value: Ref);
    fn CFEqual(a: Ref, b: Ref) -> u8;
}
fn check(status: i32) -> Result<(), String> {
    if status == 0 {
        Ok(())
    } else {
        Err(format!("osstatus:{status}"))
    }
}
struct Owned(Ref);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}
struct Keychain {
    reference: Owned,
    deleted: bool,
}
impl Keychain {
    fn delete(&mut self) -> Result<(), String> {
        check(unsafe { SecKeychainDelete(self.reference.0) })?;
        self.deleted = true;
        Ok(())
    }
}
impl Drop for Keychain {
    fn drop(&mut self) {
        if !self.deleted {
            let _ = self.delete();
        }
    }
}
struct Secret([u8; 64]);
impl Secret {
    fn random(ascii: bool) -> Result<Self, String> {
        let mut value = Self([0; 64]);
        std::fs::File::open("/dev/urandom")
            .and_then(|mut f| f.read_exact(&mut value.0))
            .map_err(|_| "random_failed")?;
        if ascii {
            for byte in &mut value.0 {
                *byte = b'a' + *byte % 26;
            }
        }
        Ok(value)
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        for byte in &mut self.0 {
            unsafe { ptr::write_volatile(byte, 0) };
        }
    }
}
struct Snapshot {
    list: Owned,
    default: Owned,
    default_status: i32,
}
impl Snapshot {
    fn read() -> Result<Self, String> {
        let mut list = Owned(ptr::null_mut());
        let mut default = Owned(ptr::null_mut());
        check(unsafe { SecKeychainCopySearchList(&mut list.0) })?;
        let default_status = unsafe { SecKeychainCopyDefault(&mut default.0) };
        if default_status != 0 || default.0.is_null() || list.0.is_null() {
            return Err(format!("default_snapshot:{default_status}"));
        }
        Ok(Self {
            list,
            default,
            default_status,
        })
    }
    fn equals(&self, other: &Self) -> bool {
        self.default_status == other.default_status
            && unsafe { CFEqual(self.list.0, other.list.0) != 0 }
            && (self.default.0.is_null() && other.default.0.is_null()
                || !self.default.0.is_null()
                    && !other.default.0.is_null()
                    && unsafe { CFEqual(self.default.0, other.default.0) != 0 })
    }
}
fn read(keychain: Ref, name: &CString, expected: &Secret) -> Result<i32, String> {
    let mut len = 0;
    let mut data = ptr::null_mut();
    let status = unsafe {
        SecKeychainFindGenericPassword(
            keychain,
            name.as_bytes().len() as u32,
            name.as_ptr(),
            name.as_bytes().len() as u32,
            name.as_ptr(),
            &mut len,
            &mut data,
            ptr::null_mut(),
        )
    };
    if status == 0 {
        let equal = !data.is_null()
            && len == expected.0.len() as u32
            && unsafe { std::slice::from_raw_parts(data.cast::<u8>(), len as usize) == expected.0 };
        if !data.is_null() {
            for i in 0..len as usize {
                unsafe { ptr::write_volatile(data.cast::<u8>().add(i), 0) };
            }
            check(unsafe { SecKeychainItemFreeContent(ptr::null_mut(), data) })?;
        }
        if !equal {
            return Err("secret_comparison_failed".into());
        }
    } else if !data.is_null() || len != 0 {
        return Err("failed_read_returned_data".into());
    }
    Ok(status)
}
pub fn run() -> Result<(), String> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3
        || !matches!(
            args[1].as_str(),
            "--synthetic-private-keychain" | "--product-private-keychain"
        )
    {
        return Err("explicit_fixture_flag_and_private_parent_required".into());
    }
    let parent = std::path::Path::new(&args[2]);
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let metadata = std::fs::symlink_metadata(parent).map_err(|_| "parent_metadata_failed")?;
    if !parent.is_absolute()
        || std::fs::canonicalize(parent).map_err(|_| "parent_canonical_failed")? != parent
        || !metadata.is_dir()
        || metadata.mode() & 0o777 != 0o700
    {
        return Err("private_canonical_parent_required".into());
    }
    check(unsafe { SecKeychainSetUserInteractionAllowed(0) })?;
    let before = Snapshot::read()?;
    let dir = tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .prefix("lomi-e0-keychain-")
        .tempdir_in(parent)
        .map_err(|_| "tempdir_failed")?
        .keep();
    let name = CString::new(format!("fixture-{}", uuid::Uuid::new_v4())).unwrap();
    let path = dir.join(format!("{}.keychain", name.to_str().unwrap()));
    let cpath = CString::new(path.to_str().ok_or("path_encoding")?).unwrap();
    let password = Secret::random(true)?;
    let secret = Secret::random(false)?;
    let mut reference = Owned(ptr::null_mut());
    let creation = check(unsafe {
        SecKeychainCreate(
            cpath.as_ptr(),
            64,
            password.0.as_ptr().cast(),
            0,
            ptr::null_mut(),
            &mut reference.0,
        )
    });
    if let Err(error) = creation {
        if !before.equals(&Snapshot::read()?) {
            return Err("configuration_changed_after_failed_create".into());
        }
        return Err(error);
    }
    if reference.0.is_null() {
        return Err("missing_keychain_reference".into());
    }
    let mut keychain = Keychain {
        reference,
        deleted: false,
    };
    let operation = (|| {
        if !before.equals(&Snapshot::read()?) {
            return Err("configuration_changed_after_create".into());
        }
        check(unsafe {
            SecKeychainUnlock(keychain.reference.0, 64, password.0.as_ptr().cast(), 1)
        })?;
        if args[1] == "--product-private-keychain" {
            return product::run(keychain.reference.0, &dir, &password).map(i32::from);
        }
        check(unsafe {
            SecKeychainAddGenericPassword(
                keychain.reference.0,
                name.as_bytes().len() as u32,
                name.as_ptr(),
                name.as_bytes().len() as u32,
                name.as_ptr(),
                64,
                secret.0.as_ptr().cast(),
                ptr::null_mut(),
            )
        })?;
        check(read(keychain.reference.0, &name, &secret)?)?;
        check(unsafe { SecKeychainLock(keychain.reference.0) })?;
        let mut native_status = 0;
        check(unsafe { SecKeychainGetStatus(keychain.reference.0, &mut native_status) })?;
        if native_status & 1 != 0 {
            return Err("keychain_did_not_lock".into());
        }
        let locked_status = read(keychain.reference.0, &name, &secret)?;
        if !locked_denied(locked_status) {
            return Err(format!(
                "locked_read_expected_authentication_or_interaction_denial:{locked_status}"
            ));
        }
        check(unsafe {
            SecKeychainUnlock(keychain.reference.0, 64, password.0.as_ptr().cast(), 1)
        })?;
        check(unsafe { SecKeychainGetStatus(keychain.reference.0, &mut native_status) })?;
        if native_status & 1 == 0 {
            return Err("keychain_did_not_unlock".into());
        }
        check(read(keychain.reference.0, &name, &secret)?)?;
        Ok(locked_status)
    })();
    let deletion = keychain.delete();
    let after = Snapshot::read();
    if deletion.is_err() || after.is_err() {
        return Err("cleanup_or_configuration_snapshot_failed_resource_preserved".into());
    }
    let unchanged = before.equals(&after?);
    if !unchanged {
        return Err("configuration_changed_after_delete".into());
    }
    let locked = operation?;
    if std::fs::read_dir(&dir)
        .map_err(|_| "cleanup_read_failed")?
        .next()
        .is_some()
    {
        return Err("keychain_files_remain".into());
    }
    std::fs::remove_dir(&dir).map_err(|_| "tempdir_cleanup_failed")?;
    if args[1] == "--product-private-keychain" {
        println!(
            "{{\"fixture\":true,\"productProvider\":true,\"backend\":\"temporary-file-keychain\",\"roundTripAndReopen\":true,\"lockedFreshHelperDenied\":true,\"tamperAndMissingKeyDenied\":true,\"profileBindingAndExclusiveLock\":true,\"sameKeyDifferentProfileAadDenied\":true,\"validDifferentKeyAuthenticationDenied\":true,\"originalKeyRestoredPositive\":true,\"defaultAndSearchListUnchanged\":true,\"keychainDeleted\":true,\"temporaryDirectoryRemoved\":true,\"keychainDatabaseObjectChangedDuringInitialAdd\":{}}}",
            locked != 0
        );
        return Ok(());
    }
    println!(
        "{{\"fixture\":true,\"backend\":\"temporary-file-keychain\",\"createdReadLockedDeniedUnlockedRead\":true,\"lockedOSStatus\":{locked},\"interactionAllowed\":false,\"defaultAndSearchListUnchanged\":true,\"keychainDeleted\":true,\"temporaryDirectoryRemoved\":true}}"
    );
    Ok(())
}

fn locked_denied(status: i32) -> bool {
    matches!(status, -25293 | -25308)
}
#[cfg(test)]
mod tests {
    #[test]
    fn locked_storage_rejects_success_not_found_and_unrelated_errors() {
        assert!(super::locked_denied(-25293));
        assert!(super::locked_denied(-25308));
        for status in [0, -25300, -25291, -50, 1] {
            assert!(!super::locked_denied(status));
        }
    }
}
