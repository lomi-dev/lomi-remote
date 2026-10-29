use super::*;
use crate::unix::OwnerLock;
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
};

fn fixture() -> (tempfile::TempDir, OwnerLock) {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let owner = OwnerLock::acquire(&root.path().canonicalize().unwrap()).unwrap();
    (root, owner)
}
fn value(revision: u64) -> Configuration {
    Configuration {
        version: 1,
        revision,
        authentication: None,
    }
}
fn committed(outcome: CommitOutcome) -> Snapshot {
    match outcome {
        CommitOutcome::Committed(snapshot) => snapshot,
        CommitOutcome::Uncertain(_) => panic!("unexpected uncertainty"),
    }
}
#[test]
fn stale_revision_same_revision_edit_and_replaced_inode_are_rejected() {
    let (root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    assert!(file.load().unwrap().is_none());
    let first = committed(file.replace(None, &value(1)).unwrap());
    assert!(matches!(file.replace(None, &value(1)), Err(Error::Stale)));
    assert!(matches!(
        file.replace(Some(&first), &value(1)),
        Err(Error::Stale)
    ));
    let second = committed(file.replace(Some(&first), &value(2)).unwrap());
    assert!(matches!(
        file.replace(Some(&first), &value(2)),
        Err(Error::Stale)
    ));
    let path = root.path().join("host-public.toml");
    fs::write(&path, b"version=1\nrevision=2\n# hand edit\n").unwrap();
    assert!(matches!(
        file.replace(Some(&second), &value(3)),
        Err(Error::Stale)
    ));
    let edited = file.load().unwrap().unwrap();
    fs::rename(&path, root.path().join("old")).unwrap();
    fs::write(&path, &edited.bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(matches!(
        file.replace(Some(&edited), &value(3)),
        Err(Error::Stale)
    ));
}
#[test]
fn symlinks_hardlinks_wrong_mode_nonregular_and_oversize_fail_closed() {
    let (root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    committed(file.replace(None, &value(1)).unwrap());
    let path = root.path().join("host-public.toml");
    let saved = root.path().join("saved");
    fs::rename(&path, &saved).unwrap();
    symlink(&saved, &path).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
    fs::remove_file(&path).unwrap();
    fs::hard_link(&saved, &path).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
    fs::remove_file(&path).unwrap();
    fs::rename(&saved, &path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, vec![b' '; public_config::MAX_BYTES + 1]).unwrap();
    assert!(matches!(file.load(), Err(Error::TooLarge)));
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
}
#[test]
fn failure_before_publication_preserves_original_and_cleans_only_owned_temp() {
    let (root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    let first = committed(file.replace(None, &value(1)).unwrap());
    let path = root.path().join("host-public.toml");
    let before = fs::read(&path).unwrap();
    for failure in [Step::AfterTemp, Step::BeforeRename] {
        assert!(matches!(
            file.replace_with(Some(&first), &value(2), |step| {
                if step == failure {
                    Err(Error::Io)
                } else {
                    Ok(())
                }
            }),
            Err(Error::Io)
        ));
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(!fs::read_dir(root.path()).unwrap().any(|entry| {
            entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".host-public-")
        }));
    }
    let mut foreign = None;
    assert!(matches!(
        file.replace_with(Some(&first), &value(2), |step| {
            if step == Step::BeforeRename {
                let entry = fs::read_dir(root.path())
                    .unwrap()
                    .map(|entry| entry.unwrap().path())
                    .find(|path| {
                        path.file_name()
                            .unwrap()
                            .to_string_lossy()
                            .starts_with(".host-public-")
                    })
                    .unwrap();
                fs::rename(&entry, root.path().join("our-moved-temp")).unwrap();
                fs::write(&entry, b"foreign fixture").unwrap();
                foreign = Some(entry);
                return Err(Error::Io);
            }
            Ok(())
        }),
        Err(Error::Io)
    ));
    assert_eq!(fs::read(foreign.unwrap()).unwrap(), b"foreign fixture");
    assert_eq!(fs::read(&path).unwrap(), before);
}
#[test]
fn after_rename_fault_reports_uncertain_without_rollback() {
    let (root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    let first = committed(file.replace(None, &value(1)).unwrap());
    let outcome = file
        .replace_with(Some(&first), &value(2), |step| {
            if step == Step::AfterRename {
                Err(Error::Io)
            } else {
                Ok(())
            }
        })
        .unwrap();
    let CommitOutcome::Uncertain(snapshot) = outcome else {
        panic!("must be uncertain")
    };
    assert_eq!(snapshot.configuration().revision, 2);
    assert_eq!(file.load().unwrap().unwrap().configuration().revision, 2);
    assert_eq!(
        public_config::decode(&fs::read(root.path().join("host-public.toml")).unwrap())
            .unwrap()
            .revision,
        2
    );
}
#[test]
fn directory_replacement_invalidates_the_pinned_profile() {
    let (root, owner) = fixture();
    let file = PublicFile::new(owner.profile()).unwrap();
    let moved = root.path().with_extension("moved-public-config-test");
    fs::rename(root.path(), &moved).unwrap();
    fs::create_dir(root.path()).unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(file.load(), Err(Error::InvalidStorage)));
    fs::remove_dir(root.path()).unwrap();
    fs::rename(&moved, root.path()).unwrap();
}
#[test]
fn final_revalidation_preserves_an_intervening_edit() {
    let (root, owner) = fixture();
    let mut file = PublicFile::new(owner.profile()).unwrap();
    let first = committed(file.replace(None, &value(1)).unwrap());
    let path = root.path().join("host-public.toml");
    let edited = b"version=1\nrevision=1\n# intervening edit\n";
    assert!(matches!(
        file.replace_with(Some(&first), &value(2), |step| {
            if step == Step::BeforeRename {
                fs::write(&path, edited).unwrap();
            }
            Ok(())
        }),
        Err(Error::Stale)
    ));
    assert_eq!(fs::read(path).unwrap(), edited);
}
