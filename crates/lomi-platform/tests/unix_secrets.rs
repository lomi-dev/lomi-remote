#![cfg(unix)]
use lomi_platform::{
    secrets::{
        Error, MAX_BUNDLE_BYTES, ProtectedFileAcknowledgement, SecretBundle, SecretStorage,
        Selection, StorageState,
    },
    unix::{OwnerLock, secrets::ProtectedFile},
};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};
fn selection() -> Selection {
    Selection::ProtectedFile(ProtectedFileAcknowledgement::OsPermissionsOnly)
}
fn profile() -> (tempfile::TempDir, OwnerLock) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let owner = OwnerLock::acquire(&root.path().canonicalize().unwrap()).unwrap();
    (root, owner)
}
#[test]
fn explicit_selection_no_fallback_and_redacted_debug() {
    let (root, owner) = profile();
    for (selection, error) in [
        (Selection::Unconfigured, Error::Unconfigured),
        (Selection::MacOsKeychain, Error::Unavailable),
        (Selection::WindowsDpapi, Error::Unavailable),
        (Selection::SecretService, Error::Unavailable),
    ] {
        assert!(matches!(ProtectedFile::open(owner.profile(), selection), Err(e) if e == error));
        assert_ne!(selection.status().state, StorageState::Available);
    }
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 1);
    let secret = SecretBundle::new(b"fixture-private-value".to_vec()).unwrap();
    assert_eq!(format!("{secret:?}"), "SecretBundle([REDACTED])");
    assert!(SecretBundle::new(vec![1; MAX_BUNDLE_BYTES + 1]).is_err());
    assert!(SecretBundle::new(vec![]).is_err());
}
#[test]
fn native_round_trip_rotation_and_exclusive_lock() {
    let (root, owner) = profile();
    let mut store = ProtectedFile::open(owner.profile(), selection()).unwrap();
    assert_eq!(store.status().state, StorageState::Available);
    assert!(store.load().unwrap().is_none());
    assert!(matches!(
        ProtectedFile::open(owner.profile(), selection()),
        Err(Error::Locked)
    ));
    for bytes in [b"first".as_slice(), &[42; MAX_BUNDLE_BYTES]] {
        store
            .replace(&SecretBundle::new(bytes.to_vec()).unwrap())
            .unwrap();
        assert_eq!(store.load().unwrap().unwrap().expose(), bytes);
    }
    assert_eq!(
        fs::metadata(root.path().join("host-secrets.bundle"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(store);
    let reopened = ProtectedFile::open(owner.profile(), selection()).unwrap();
    assert_eq!(
        reopened.load().unwrap().unwrap().expose().len(),
        MAX_BUNDLE_BYTES
    );
}
#[test]
fn rejects_unsafe_entries_without_following_or_blocking() {
    for name in ["host-secrets.bundle", "host-secrets.lock"] {
        for kind in ["symlink", "hardlink", "fifo", "directory", "mode"] {
            let (root, owner) = profile();
            let path = root.path().join(name);
            let external = root.path().join("external");
            fs::write(&external, b"untouched-fixture").unwrap();
            fs::set_permissions(&external, fs::Permissions::from_mode(0o600)).unwrap();
            match kind {
                "symlink" => symlink(&external, &path).unwrap(),
                "hardlink" => fs::hard_link(&external, &path).unwrap(),
                "fifo" => {
                    let name = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
                    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
                }
                "directory" => fs::create_dir(&path).unwrap(),
                _ => {
                    fs::write(&path, b"fixture").unwrap();
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
                }
            }
            assert!(
                ProtectedFile::open(owner.profile(), selection()).is_err(),
                "{kind}"
            );
            assert_eq!(fs::read(&external).unwrap(), b"untouched-fixture");
        }
    }
}
#[test]
fn rejects_sparse_oversize_bad_header_and_truncation() {
    for size in [0, 12, 13, 12 + MAX_BUNDLE_BYTES as u64 + 1, 1 << 32] {
        let (root, owner) = profile();
        let path = root.path().join("host-secrets.bundle");
        let file = fs::File::create(&path).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_len(size).unwrap();
        assert!(
            matches!(
                ProtectedFile::open(owner.profile(), selection()),
                Err(Error::InvalidBundle)
            ),
            "{size}"
        );
    }
}
#[test]
fn profile_and_lock_replacement_fail_closed_before_write() {
    let (root, owner) = profile();
    let mut store = ProtectedFile::open(owner.profile(), selection()).unwrap();
    let bundle = SecretBundle::new(b"fixture".to_vec()).unwrap();
    store.replace(&bundle).unwrap();
    let before = fs::read(root.path().join("host-secrets.bundle")).unwrap();
    fs::remove_file(root.path().join("host-secrets.lock")).unwrap();
    fs::write(root.path().join("host-secrets.lock"), []).unwrap();
    fs::set_permissions(
        root.path().join("host-secrets.lock"),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert_eq!(store.replace(&bundle), Err(Error::InvalidStorage));
    assert_eq!(store.status().state, StorageState::Unavailable);
    assert_eq!(
        fs::read(root.path().join("host-secrets.bundle")).unwrap(),
        before
    );
}
#[test]
fn header_length_must_match_exact_file_extent() {
    use std::io::Write;
    for declared in [0u32, 2, MAX_BUNDLE_BYTES as u32 + 1] {
        let (root, owner) = profile();
        let path = root.path().join("host-secrets.bundle");
        let mut file = fs::File::create(path).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        file.write_all(b"LMSECRET").unwrap();
        file.write_all(&declared.to_be_bytes()).unwrap();
        file.write_all(b"x").unwrap();
        assert!(matches!(
            ProtectedFile::open(owner.profile(), selection()),
            Err(Error::InvalidBundle)
        ));
    }
}
#[test]
fn changed_profile_permissions_prevent_secret_effects() {
    let (root, owner) = profile();
    let mut store = ProtectedFile::open(owner.profile(), selection()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        store.replace(&SecretBundle::new(b"fixture".to_vec()).unwrap()),
        Err(Error::InvalidStorage)
    );
    assert!(!root.path().join("host-secrets.bundle").exists());
}
#[cfg(target_os = "macos")]
#[test]
fn native_extended_acl_grant_is_rejected() {
    let (root, owner) = profile();
    let status = std::process::Command::new("/bin/chmod")
        .args(["+a", "everyone allow read"])
        .arg(root.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(matches!(
        ProtectedFile::open(owner.profile(), selection()),
        Err(Error::InvalidStorage)
    ));
}
