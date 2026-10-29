//! Controlled product-provider adapter; owns only its newly created Keychain
//! and private profiles. Credentials and comparisons stay in memory.
use super::*;
use lomi_platform::{
    secrets::{Error, ProtectedFileAcknowledgement, SecretBundle, SecretStorage, Selection},
    unix::{OwnerLock, keychain::MacOsKeychain, secrets::ProtectedFile},
};
use lomi_remote_protocol::ipc::IpcProfileId;
use std::{fs, path::Path};

fn expect(value: bool, label: &'static str) -> Result<(), String> {
    if value { Ok(()) } else { Err(label.into()) }
}
pub(super) fn run(keychain: Ref, dir: &Path, password: &Secret) -> Result<bool, String> {
    let mut returned = [0u8; 1025];
    let mut len = returned.len() as u32;
    check(unsafe { SecKeychainGetPath(keychain, &mut len, returned.as_mut_ptr().cast()) })?;
    let reported =
        std::ffi::CStr::from_bytes_until_nul(&returned).map_err(|_| "keychain_path_invalid")?;
    use std::os::unix::ffi::OsStrExt;
    let reported = Path::new(std::ffi::OsStr::from_bytes(reported.to_bytes()));
    let path = if reported.exists() {
        reported.to_path_buf()
    } else {
        std::path::PathBuf::from(format!(
            "{}-db",
            reported.to_str().ok_or("keychain_path_encoding")?
        ))
    };
    let path = path
        .canonicalize()
        .map_err(|_| "keychain_realpath_failed")?;
    let profiles = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .prefix("product-")
        .tempdir_in(dir)
        .map_err(|_| "profiles_create_failed")?;
    let owner = OwnerLock::acquire(&profiles.path().join("first")).map_err(|_| "owner_failed")?;
    let id = IpcProfileId::try_from(uuid::Uuid::new_v4().to_string()).unwrap();
    let second_id = IpcProfileId::try_from(uuid::Uuid::new_v4().to_string()).unwrap();
    let own_account = CString::new(String::from(id)).unwrap();
    let service = CString::new("app.lomi.host-secrets.static-kek.v1").unwrap();
    let plain = Secret::random(false)?;
    let bundle = SecretBundle::new(plain.0.to_vec()).map_err(|_| "bundle_failed")?;
    expect(
        MacOsKeychain::open(owner.profile(), Selection::SecretService, id, &path).is_err(),
        "wrong_selection",
    )?;
    expect(
        !owner.profile().path().join("host-secrets.lock").exists(),
        "wrong_selection_effect",
    )?;
    let mut store = MacOsKeychain::open(owner.profile(), Selection::MacOsKeychain, id, &path)
        .map_err(|_| "provider_open")?;
    expect(
        store.load().map_err(|_| "empty_load")?.is_none(),
        "empty_not_empty",
    )?;
    expect(
        matches!(
            ProtectedFile::open(
                owner.profile(),
                Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly)
            ),
            Err(Error::Locked)
        ),
        "exclusive_provider_lock",
    )?;
    let before_keychain = fs::metadata(&path).map_err(|_| "keychain_metadata")?;
    store.replace(&bundle).map_err(|error| {
        use std::os::unix::fs::MetadataExt;
        let changed = fs::metadata(&path)
            .map(|after| {
                (before_keychain.dev(), before_keychain.ino()) != (after.dev(), after.ino())
            })
            .unwrap_or(true);
        format!("first_replace:{error}:keychainObjectChanged={changed}")
    })?;
    use std::os::unix::fs::MetadataExt;
    let after_keychain = fs::metadata(&path).map_err(|_| "keychain_metadata_after_add")?;
    let native_database_object_changed = (before_keychain.dev(), before_keychain.ino())
        != (after_keychain.dev(), after_keychain.ino());
    expect(
        store.load().map_err(|_| "first_load")?.unwrap().expose() == bundle.expose(),
        "roundtrip",
    )?;
    let mut maximum = Vec::with_capacity(lomi_platform::secrets::MAX_BUNDLE_BYTES);
    for _ in 0..lomi_platform::secrets::MAX_BUNDLE_BYTES / plain.0.len() {
        maximum.extend_from_slice(&plain.0);
    }
    let maximum = SecretBundle::new(maximum).map_err(|_| "max_bundle")?;
    store.replace(&maximum).map_err(|_| "max_replace")?;
    expect(
        store.load().map_err(|_| "max_load")?.unwrap().expose() == maximum.expose(),
        "max_roundtrip",
    )?;
    store.replace(&bundle).map_err(|_| "restore_small")?;
    let cipher_path = owner.profile().path().join("host-secrets.keychain.bundle");
    let ciphertext = fs::read(&cipher_path).map_err(|_| "cipher_read")?;
    expect(
        !ciphertext.windows(plain.0.len()).any(|v| v == plain.0),
        "plaintext_on_disk",
    )?;
    let mut length = 0;
    let mut data = ptr::null_mut();
    let mut item = Owned(ptr::null_mut());
    check(unsafe {
        SecKeychainFindGenericPassword(
            keychain,
            service.as_bytes().len() as u32,
            service.as_ptr(),
            own_account.as_bytes().len() as u32,
            own_account.as_ptr(),
            &mut length,
            &mut data,
            &mut item.0,
        )
    })?;
    expect(
        length == 32 && !data.is_null() && !item.0.is_null(),
        "owned_item_key_shape",
    )?;
    // Test item is owned by this fixture. Compare without exposing its key.
    expect(
        !ciphertext
            .windows(32)
            .any(|v| v == unsafe { std::slice::from_raw_parts(data.cast::<u8>(), 32) }),
        "key_on_disk",
    )?;
    let mut original_key = Secret([0; 64]);
    original_key.0[..32]
        .copy_from_slice(unsafe { std::slice::from_raw_parts(data.cast::<u8>(), 32) });
    for i in 0..length as usize {
        unsafe { ptr::write_volatile(data.cast::<u8>().add(i), 0) };
    }
    check(unsafe { SecKeychainItemFreeContent(ptr::null_mut(), data) })?;
    let second_owner =
        OwnerLock::acquire(&profiles.path().join("second")).map_err(|_| "second_owner")?;
    let second_account = CString::new(String::from(second_id)).unwrap();
    let mut second_item = Owned(ptr::null_mut());
    // Both accounts and this Keychain belong exclusively to this fixture.
    // Install the SAME key so rejection exercises profile AAD, not a missing
    // item, a malformed key, or a different key's authentication failure.
    check(unsafe {
        SecKeychainAddGenericPassword(
            keychain,
            service.as_bytes().len() as u32,
            service.as_ptr(),
            second_account.as_bytes().len() as u32,
            second_account.as_ptr(),
            32,
            original_key.0.as_ptr().cast(),
            &mut second_item.0,
        )
    })?;
    expect(!second_item.0.is_null(), "second_owned_item_missing")?;
    let mut second_store = MacOsKeychain::open(
        second_owner.profile(),
        Selection::MacOsKeychain,
        second_id,
        &path,
    )
    .map_err(|_| "second_same_key_provider_open")?;
    second_store
        .replace(&bundle)
        .map_err(|_| "second_same_key_positive_replace")?;
    expect(
        second_store
            .load()
            .map_err(|_| "second_same_key_positive_load")?
            .unwrap()
            .expose()
            == bundle.expose(),
        "second_same_key_positive",
    )?;
    fs::write(
        second_owner
            .profile()
            .path()
            .join("host-secrets.keychain.bundle"),
        &ciphertext,
    )
    .map_err(|_| "copy_cipher")?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        second_owner
            .profile()
            .path()
            .join("host-secrets.keychain.bundle"),
        fs::Permissions::from_mode(0o600),
    )
    .map_err(|_| "copy_permissions")?;
    expect(
        matches!(second_store.load(), Err(Error::InvalidBundle)),
        "same_key_different_profile_load",
    )?;
    expect(
        matches!(second_store.replace(&bundle), Err(Error::InvalidBundle)),
        "same_key_different_profile_replace",
    )?;
    drop(second_store);
    expect(
        matches!(
            MacOsKeychain::open(
                second_owner.profile(),
                Selection::MacOsKeychain,
                second_id,
                &path
            ),
            Err(Error::InvalidBundle)
        ),
        "same_key_different_profile_aad",
    )?;
    expect(
        fs::read(
            second_owner
                .profile()
                .path()
                .join("host-secrets.keychain.bundle"),
        )
        .map_err(|_| "second_cipher_read")?
            == ciphertext,
        "aad_failure_changed_second_cipher",
    )?;
    expect(
        store
            .load()
            .map_err(|_| "original_after_aad_failure")?
            .unwrap()
            .expose()
            == bundle.expose(),
        "aad_failure_changed_original_profile",
    )?;
    expect(
        fs::read(&cipher_path).map_err(|_| "original_after_aad_cipher_read")? == ciphertext,
        "aad_failure_changed_original_cipher",
    )?;
    check(unsafe { SecKeychainItemDelete(second_item.0) })?;
    check(unsafe { SecKeychainLock(keychain) })?;
    expect(matches!(store.load(), Err(Error::Locked)), "locked_read")?;
    expect(
        matches!(store.replace(&bundle), Err(Error::Locked)),
        "locked_write",
    )?;
    expect(
        fs::read(&cipher_path).map_err(|_| "locked_cipher_read")? == ciphertext,
        "locked_cipher_changed",
    )?;
    check(unsafe { SecKeychainUnlock(keychain, 64, password.0.as_ptr().cast(), 1) })?;
    expect(
        store.load().map_err(|_| "unlocked_read")?.unwrap().expose() == bundle.expose(),
        "unlock_recovery",
    )?;
    drop(store);
    let mut store = MacOsKeychain::open(owner.profile(), Selection::MacOsKeychain, id, &path)
        .map_err(|_| "reopen")?;
    let mut tampered = ciphertext.clone();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&cipher_path, &tampered).map_err(|_| "tamper_write")?;
    expect(
        matches!(store.load(), Err(Error::InvalidBundle)),
        "tag_tamper",
    )?;
    expect(store.replace(&bundle).is_err(), "tamper_overwrite")?;
    fs::write(&cipher_path, &ciphertext).map_err(|_| "cipher_restore")?;
    // A valid, different 256-bit key must reach AEAD authentication and fail
    // with InvalidBundle. Retain the original only in this wiping RAM buffer.
    let mut wrong_key = Secret([0; 64]);
    wrong_key.0[..32].copy_from_slice(&original_key.0[..32]);
    wrong_key.0[0] ^= 1;
    check(unsafe {
        SecKeychainItemModifyAttributesAndData(
            item.0,
            ptr::null_mut(),
            32,
            wrong_key.0.as_ptr().cast(),
        )
    })?;
    expect(
        matches!(store.load(), Err(Error::InvalidBundle)),
        "valid_wrong_key_load",
    )?;
    expect(
        matches!(store.replace(&bundle), Err(Error::InvalidBundle)),
        "valid_wrong_key_replace",
    )?;
    expect(
        fs::read(&cipher_path).map_err(|_| "wrong_key_cipher_read")? == ciphertext,
        "valid_wrong_key_changed_cipher",
    )?;
    check(unsafe {
        SecKeychainItemModifyAttributesAndData(
            item.0,
            ptr::null_mut(),
            32,
            original_key.0.as_ptr().cast(),
        )
    })?;
    expect(
        store
            .load()
            .map_err(|_| "restored_original_key_load")?
            .unwrap()
            .expose()
            == bundle.expose(),
        "restored_original_key_positive",
    )?;
    expect(
        fs::read(&cipher_path).map_err(|_| "restored_key_cipher_read")? == ciphertext,
        "restored_key_changed_cipher",
    )?;
    let bad = [0u8; 31];
    check(unsafe {
        SecKeychainItemModifyAttributesAndData(item.0, ptr::null_mut(), 31, bad.as_ptr().cast())
    })?;
    expect(
        matches!(store.load(), Err(Error::InvalidStorage)),
        "bad_key_size",
    )?;
    expect(store.replace(&bundle).is_err(), "bad_key_reminted")?;
    check(unsafe { SecKeychainItemDelete(item.0) })?;
    expect(
        matches!(store.load(), Err(Error::InvalidStorage)),
        "missing_key",
    )?;
    expect(store.replace(&bundle).is_err(), "missing_key_reminted")?;
    expect(
        unsafe {
            SecKeychainFindGenericPassword(
                keychain,
                service.as_bytes().len() as u32,
                service.as_ptr(),
                own_account.as_bytes().len() as u32,
                own_account.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        } == -25300,
        "missing_key_was_recreated",
    )?;
    expect(
        fs::read(&cipher_path).map_err(|_| "final_cipher_read")? == ciphertext,
        "failed_write_changed_cipher",
    )?;
    drop(store);
    drop(second_owner);
    drop(owner);
    profiles.close().map_err(|_| "profiles_cleanup")?;
    Ok(native_database_object_changed)
}
