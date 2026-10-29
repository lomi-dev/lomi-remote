use super::*;
use crate::windows::{OwnerLock, Security, normalized};
use windows_sys::Win32::Security::Authorization::*;
fn fixture() -> (tempfile::TempDir, OwnerLock) {
    let root = tempfile::Builder::new()
        .prefix("lomi-public-native-")
        .tempdir_in(std::env::var_os("USERPROFILE").unwrap())
        .unwrap();
    let path = normalized(&root.path().canonicalize().unwrap())
        .unwrap()
        .join("profile");
    let owner = OwnerLock::acquire(&path).unwrap();
    (root, owner)
}
fn config(revision: u64) -> Configuration {
    Configuration {
        version: 1,
        revision,
        authentication: None,
    }
}
fn committed(outcome: CommitOutcome) -> Snapshot {
    match outcome {
        CommitOutcome::Committed(snapshot) => snapshot,
        CommitOutcome::Uncertain(_) => panic!("unexpected publication uncertainty"),
    }
}
#[test]
fn native_public_exact_revision_roundtrip_and_recovery_refreshes_token() {
    let (_root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    assert!(file.load().unwrap().is_none());
    let first = committed(file.replace(None, &config(1)).unwrap());
    file.confirm(&first).unwrap();
    let loaded = file.load().unwrap().unwrap();
    let prior = loaded.identity().unwrap();
    file.confirm(&loaded).unwrap();
    assert_ne!(loaded.identity().unwrap(), prior);
    assert!(file.load().unwrap().as_ref() == Some(&loaded));
    assert_eq!(loaded.source(), public_config::encode(&config(1)).unwrap());
    assert_eq!(loaded.configuration().revision, 1);
    assert!(matches!(
        file.replace(Some(&first), &config(2)),
        Err(Error::Stale)
    ));
    let second = committed(file.replace(Some(&loaded), &config(2)).unwrap());
    file.confirm(&second).unwrap();
    assert_eq!(second.configuration().revision, 2);
}
#[test]
fn native_public_faults_before_and_after_rename_preserve_recoverable_revision() {
    for step in [Step::AfterTemp, Step::BeforeRename, Step::AfterRename] {
        let (_root, owner) = fixture();
        let file = PublicFile::new(owner.profile()).unwrap();
        let old = committed(file.replace_with(None, &config(1), |_| Ok(())).unwrap());
        let result = file.replace_with(Some(&old), &config(2), |current| {
            if current == step {
                Err(Error::Io)
            } else {
                Ok(())
            }
        });
        if step == Step::AfterRename {
            assert!(matches!(result, Ok(CommitOutcome::Uncertain(_))));
            let observed = file.load().unwrap().unwrap();
            assert_eq!(observed.configuration().revision, 2);
            file.confirm(&observed).unwrap();
            assert!(file.load().unwrap().as_ref() == Some(&observed));
        } else {
            assert!(matches!(result, Err(Error::Io)));
            assert!(file.load().unwrap().as_ref() == Some(&old));
            assert!(
                !std::fs::read_dir(owner.profile().path())
                    .unwrap()
                    .any(|entry| entry
                        .unwrap()
                        .file_name()
                        .to_string_lossy()
                        .starts_with(".host-public-"))
            );
        }
    }
}
#[test]
fn native_public_rename_failure_is_uncertain_and_retains_owned_remnant() {
    let (_root, owner) = fixture();
    let file = PublicFile::new(owner.profile()).unwrap();
    let old = committed(file.replace_with(None, &config(1), |_| Ok(())).unwrap());
    // An actual non-DELETE-share open forces the native rename failure after
    // publication was attempted. It must not become a definite rollback claim.
    let held = open_file(
        owner.profile(),
        &owner.profile().path.join(NAME),
        false,
        OPEN_EXISTING,
    )
    .unwrap_or_else(|_| panic!());
    assert!(matches!(
        file.replace_with(Some(&old), &config(2), |_| Ok(())),
        Ok(CommitOutcome::Uncertain(_))
    ));
    drop(held);
    assert!(file.load().unwrap().as_ref() == Some(&old));
    assert!(
        std::fs::read_dir(owner.profile().path())
            .unwrap()
            .any(|entry| entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".host-public-"))
    );
    file.confirm(&old).unwrap();
}
#[test]
fn native_public_same_revision_edits_bounded_bytes_and_hardlinks_reject() {
    let (_root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    let old = committed(file.replace(None, &config(1)).unwrap());
    let path = owner.profile().path.join(NAME);
    std::fs::write(&path, b"version = 1\nrevision = 1\n# manual edit\n").unwrap();
    assert!(matches!(
        file.replace(Some(&old), &config(2)),
        Err(Error::Stale)
    ));
    assert!(matches!(file.confirm(&old), Err(Error::Stale)));
    std::fs::write(&path, vec![b'x'; public_config::MAX_BYTES + 1]).unwrap();
    assert!(matches!(file.load(), Err(Error::TooLarge)));
    std::fs::write(&path, public_config::encode(&config(1)).unwrap()).unwrap();
    std::fs::hard_link(&path, owner.profile().path.join("public-hardlink")).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
}
fn set_acl(path: &std::path::Path, sid: &str, directory: bool, broad: bool) {
    let sd = Security::new(&format!(
        "O:{sid}D:P(A;{};FA;;;{sid}){}",
        if directory { "OICI" } else { "" },
        if broad { "(A;;GR;;;WD)" } else { "" }
    ))
    .unwrap();
    let handle = Handle::new(unsafe {
        CreateFileW(
            wide(path).as_ptr(),
            READ_CONTROL | WRITE_DAC,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_OPEN_REPARSE_POINT
                | if directory {
                    FILE_FLAG_BACKUP_SEMANTICS
                } else {
                    0
                },
            ptr::null_mut(),
        )
    })
    .unwrap();
    let (mut acl, mut present, mut defaulted) = (ptr::null_mut(), 0, 0);
    assert_ne!(
        unsafe {
            GetSecurityDescriptorDacl(
                sd.attributes.lpSecurityDescriptor,
                &mut present,
                &mut acl,
                &mut defaulted,
            )
        },
        0
    );
    assert_eq!(
        unsafe {
            SetSecurityInfo(
                handle.0,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null_mut(),
            )
        },
        ERROR_SUCCESS
    );
}
#[test]
fn native_public_rejects_broad_file_acl_and_changed_profile_acl() {
    let (_root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    committed(file.replace(None, &config(1)).unwrap());
    let path = owner.profile().path.join(NAME);
    set_acl(&path, &owner.profile().sid, false, true);
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
    set_acl(&path, &owner.profile().sid, false, false);
    set_acl(owner.profile().path(), &owner.profile().sid, true, true);
    assert!(matches!(
        PublicFile::new(owner.profile()),
        Err(Error::InvalidStorage)
    ));
    set_acl(owner.profile().path(), &owner.profile().sid, true, false);
}
#[test]
fn native_public_profile_ancestry_remains_pinned_and_reparse_is_not_followed() {
    let (_root, owner) = fixture();
    let profile = owner.profile().path();
    assert!(std::fs::rename(profile, profile.with_extension("moved")).is_err());
    let target = profile.join("target");
    std::fs::write(&target, public_config::encode(&config(1)).unwrap()).unwrap();
    // Native symlinks need Developer Mode or the OS privilege. A qualified
    // Windows run must record an unavailable setup rather than claim coverage.
    match std::os::windows::fs::symlink_file(&target, profile.join(NAME)) {
        Ok(()) => assert!(matches!(
            PublicFile::new(owner.profile()).unwrap().load(),
            Err(Error::InvalidStorage)
        )),
        Err(error) if error.raw_os_error() == Some(ERROR_PRIVILEGE_NOT_HELD as i32) => {
            eprintln!("native reparse fault unavailable: Windows symlink privilege not enabled");
        }
        Err(error) => panic!("native reparse setup failed: {error}"),
    }
}
