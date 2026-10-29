use super::*;
use crate::{
    GitFilePrecondition, GitFinalFile, GitFinalTarget, GitObjectFile, GitPublication,
    GitPublishOutcome,
};
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};
use tempfile::TempDir;

#[cfg(target_os = "linux")]
#[test]
fn inotify_queue_overflow_is_a_reconciliation_error() {
    let event = libc::inotify_event {
        wd: -1,
        mask: libc::IN_Q_OVERFLOW,
        cookie: 0,
        len: 0,
    };
    let mut bytes = vec![0u8; std::mem::size_of::<libc::inotify_event>()];
    unsafe {
        std::ptr::write_unaligned(bytes.as_mut_ptr().cast::<libc::inotify_event>(), event);
    }
    assert!(matches!(scan_inotify_events(&bytes), Err(Error::Limit)));
}

#[cfg(target_os = "linux")]
#[test]
fn child_inotify_watch_survives_temporary_fd_close_and_catches_same_mtime_write() {
    use std::os::unix::fs::MetadataExt;

    let (dir, _outside, root) = fixture();
    let path = dir.path().join("watched");
    fs::write(&path, b"before").unwrap();
    let watcher = root.watch_directory(root.root_entry()).unwrap();
    // The watcher owns the directory fd and inotify descriptors, but no child
    // file fds. A notification therefore proves inotify retains the inode watch
    // after the temporary O_PATH fd used by watch_directory has been dropped.
    assert_eq!(watcher.watch_descriptors.len(), 2);

    let old = fs::metadata(&path).unwrap();
    fs::write(&path, b"after!").unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let times = [
        libc::timespec {
            tv_sec: old.atime() as libc::time_t,
            tv_nsec: old.atime_nsec() as libc::c_long,
        },
        libc::timespec {
            tv_sec: old.mtime() as libc::time_t,
            tv_nsec: old.mtime_nsec() as libc::c_long,
        },
    ];
    assert_eq!(
        unsafe { libc::futimens(std::os::fd::AsRawFd::as_raw_fd(&file), times.as_ptr()) },
        0
    );
    assert!(watcher.changed().unwrap());

    drop(watcher);
}

#[cfg(target_os = "linux")]
#[test]
fn directory_watches_cap_direct_child_watches() {
    let (dir, _outside, root) = fixture();
    for i in 0..(MAX_CHILD_WATCHES + 32) {
        fs::write(dir.path().join(format!("f{i:04}")), b"x").unwrap();
    }
    let watcher = root.watch_directory(root.root_entry()).unwrap();
    // One watch belongs to the directory itself; the rest are bounded child
    // watches. Fingerprint reconciliation still covers every directory entry.
    assert!(watcher.watch_descriptors.len() <= MAX_CHILD_WATCHES + 1);
}

#[cfg(target_os = "macos")]
#[test]
fn vnode_watch_keeps_directory_watching_when_child_fd_budget_is_low() {
    const CHILD_MODE: &str = "LOMI_LOW_FD_VNODE_WATCH_CHILD";
    if let Some(path) = std::env::var_os(CHILD_MODE) {
        let root = FileRoot::open(std::path::Path::new(&path), &[]).unwrap();
        let mut current: libc::rlimit = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) },
            0
        );
        let open_fds = fs::read_dir("/dev/fd").unwrap().count() as libc::rlim_t;
        let target = (open_fds + 32).min(current.rlim_max);
        assert!(target > open_fds + 4, "enough fds for the directory watch");
        let limited = libc::rlimit {
            rlim_cur: target,
            rlim_max: current.rlim_max,
        };
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limited) }, 0);

        let watcher = root.watch_directory(root.root_entry()).unwrap();
        assert!(!watcher.changed().unwrap());
        // The caller can still reconcile the listing after the partial child
        // registration has stopped at the descriptor limit.
        assert!(root.list(root.root_entry(), None, 200).is_ok());
        return;
    }

    let dir = tempfile::tempdir().unwrap();
    for index in 0..96 {
        fs::write(dir.path().join(format!("file-{index:03}")), b"x").unwrap();
    }
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("unix::tests::vnode_watch_keeps_directory_watching_when_child_fd_budget_is_low")
        .arg("--nocapture")
        .env(CHILD_MODE, dir.path())
        .status()
        .unwrap();
    assert!(status.success(), "low-fd child process must pass");
}

fn fixture() -> (TempDir, TempDir, FileRoot) {
    let outside = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = FileRoot::open(dir.path(), &[]).unwrap();
    (dir, outside, root)
}

fn find(root: &FileRoot, parent: EntryRef, name: &str) -> Meta {
    let page = root.list(parent, None, 200).unwrap();
    page.entries
        .into_iter()
        .find(|m| m.name == name.as_bytes())
        .unwrap_or_else(|| panic!("{name} not listed"))
}

fn root_rev(root: &FileRoot) -> String {
    root.stat(root.root_entry(), None).unwrap().revision
}

fn git_publication_fixture() -> (TempDir, FileRoot, GitPublication) {
    let directory = tempfile::tempdir().unwrap();
    let git_path = directory.path().join(".git");
    fs::create_dir_all(git_path.join("objects")).unwrap();
    fs::write(git_path.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    fs::write(git_path.join("index"), b"previous-index").unwrap();
    let root = FileRoot::open(directory.path(), &[]).unwrap();
    root.protect(&git_path).unwrap();
    let git = find(&root, root.root_entry(), ".git");
    let head = find(&root, git.entry, "HEAD");
    let index = find(&root, git.entry, "index");
    let head_condition = GitFilePrecondition {
        parent: git.entry,
        name: b"HEAD".to_vec(),
        entry: Some(head.entry),
        revision: Some(head.revision),
    };
    let index_condition = GitFilePrecondition {
        parent: git.entry,
        name: b"index".to_vec(),
        entry: Some(index.entry),
        revision: Some(index.revision),
    };
    let object_id = "0123456789012345678901234567890123456789".to_owned();
    let publication = GitPublication {
        git_dir: git.entry,
        common_dir: git.entry,
        preconditions: vec![head_condition],
        worktree_preconditions: Vec::new(),
        objects: vec![GitObjectFile {
            object_id,
            bytes: b"compressed loose object".to_vec(),
        }],
        final_file: GitFinalFile {
            target: GitFinalTarget::Index,
            parent: git.entry,
            parent_suffix: Vec::new(),
            expected: index_condition,
            bytes: b"replacement-index".to_vec(),
        },
    };
    (directory, root, publication)
}

#[test]
fn git_publication_installs_objects_then_atomically_replaces_the_index() {
    let (directory, root, publication) = git_publication_fixture();
    assert_eq!(
        root.publish_git(&publication, || true).unwrap(),
        GitPublishOutcome::Published
    );
    let git = directory.path().join(".git");
    assert_eq!(fs::read(git.join("index")).unwrap(), b"replacement-index");
    assert!(!git.join("index.lock").exists());
    assert_eq!(
        fs::read(git.join("objects/01/23456789012345678901234567890123456789")).unwrap(),
        b"compressed loose object"
    );
}

#[test]
fn git_publication_retries_directory_fsync_after_fanout_or_object_entry_failure() {
    for fail_after in [1, 2] {
        let (directory, root, publication) = git_publication_fixture();
        FAIL_GIT_DIRECTORY_FSYNC_AFTER.store(fail_after, std::sync::atomic::Ordering::SeqCst);
        let first = root.publish_git(&publication, || true);
        assert!(
            first.is_err(),
            "failure injection {fail_after} did not trip: {first:?}"
        );
        assert_eq!(
            fs::read(directory.path().join(".git/index")).unwrap(),
            b"previous-index"
        );
        assert!(!directory.path().join(".git/index.lock").exists());

        assert_eq!(
            root.publish_git(&publication, || true).unwrap(),
            GitPublishOutcome::Published
        );
        assert_eq!(
            fs::read(directory.path().join(".git/index")).unwrap(),
            b"replacement-index"
        );
    }
}

fn nested_branch_publication() -> (TempDir, FileRoot, GitPublication) {
    let (directory, root, mut publication) = git_publication_fixture();
    fs::create_dir(directory.path().join(".git/refs")).unwrap();
    let git = find(&root, root.root_entry(), ".git");
    let refs = find(&root, git.entry, "refs");
    publication.final_file = GitFinalFile {
        target: GitFinalTarget::BranchHead {
            reference: vec![b"refs".to_vec(), b"heads".to_vec(), b"main".to_vec()],
        },
        parent: refs.entry,
        parent_suffix: vec![b"heads".to_vec()],
        expected: GitFilePrecondition {
            parent: refs.entry,
            name: b"heads".to_vec(),
            entry: None,
            revision: None,
        },
        bytes: b"0123456789012345678901234567890123456789\n".to_vec(),
    };
    (directory, root, publication)
}

#[test]
fn git_publication_creates_a_missing_branch_parent_and_publishes_the_ref() {
    let (directory, root, publication) = nested_branch_publication();
    assert_eq!(
        root.publish_git(&publication, || true).unwrap(),
        GitPublishOutcome::Published
    );
    assert_eq!(
        fs::read(directory.path().join(".git/refs/heads/main")).unwrap(),
        publication.final_file.bytes
    );
    assert!(!directory.path().join(".git/refs/heads/main.lock").exists());
}

#[test]
fn git_publication_cleans_owned_nested_parents_when_cancelled_before_ref_rename() {
    let (directory, root, publication) = nested_branch_publication();
    let lock_path = directory.path().join(".git/refs/heads/main.lock");
    let result = root
        .publish_git(&publication, || {
            !fs::read(&lock_path).is_ok_and(|bytes| bytes == publication.final_file.bytes)
        })
        .unwrap();
    assert_eq!(result, GitPublishOutcome::AbortedBeforeFinalRename);
    assert!(!directory.path().join(".git/refs/heads").exists());
    assert!(!lock_path.exists());
}

#[test]
fn git_publication_rechecks_metadata_and_cleans_up_a_cancelled_index_lock() {
    let (directory, root, publication) = git_publication_fixture();
    fs::write(
        directory.path().join(".git/HEAD"),
        b"ref: refs/heads/changed\n",
    )
    .unwrap();
    assert_eq!(root.publish_git(&publication, || true), Err(Error::Changed));
    assert!(!directory.path().join(".git/index.lock").exists());
    assert!(!directory.path().join(".git/objects/01").exists());

    let (directory, root, publication) = git_publication_fixture();
    let mut checks = 0;
    let result = root
        .publish_git(&publication, || {
            checks += 1;
            checks < 2
        })
        .unwrap();
    assert_eq!(result, GitPublishOutcome::AbortedBeforeFinalRename);
    let git = directory.path().join(".git");
    assert_eq!(fs::read(git.join("index")).unwrap(), b"previous-index");
    assert!(!git.join("index.lock").exists());
    assert!(!git.join("objects/01").exists());
}

#[test]
fn git_publication_rechecks_staged_worktree_file_and_deletion_preconditions() {
    let (directory, root, mut publication) = git_publication_fixture();
    fs::write(directory.path().join("tracked.txt"), b"original\n").unwrap();
    let worktree_file = find(&root, root.root_entry(), "tracked.txt");
    publication
        .worktree_preconditions
        .push(GitWorktreePrecondition {
            parent: root.root_entry(),
            name: b"tracked.txt".to_vec(),
            entry: Some(worktree_file.entry),
            revision: Some(worktree_file.revision),
        });
    fs::write(directory.path().join("tracked.txt"), b"changed\n").unwrap();
    assert_eq!(root.publish_git(&publication, || true), Err(Error::Changed));
    assert_eq!(
        fs::read(directory.path().join(".git/index")).unwrap(),
        b"previous-index"
    );

    publication.worktree_preconditions = vec![GitWorktreePrecondition {
        parent: root.root_entry(),
        name: b"new-file.txt".to_vec(),
        entry: None,
        revision: None,
    }];
    fs::write(directory.path().join("new-file.txt"), b"appeared\n").unwrap();
    assert_eq!(root.publish_git(&publication, || true), Err(Error::Changed));
}

#[test]
fn git_publication_aborts_before_index_visibility_after_object_install() {
    let (directory, root, publication) = git_publication_fixture();
    let mut checks = 0;
    let result = root
        .publish_git(&publication, || {
            checks += 1;
            checks < 8
        })
        .unwrap();
    assert_eq!(result, GitPublishOutcome::AbortedBeforeFinalRename);
    let git = directory.path().join(".git");
    assert_eq!(fs::read(git.join("index")).unwrap(), b"previous-index");
    assert!(!git.join("index.lock").exists());
}

#[test]
fn git_publication_rejects_and_preserves_a_replaced_index_lock() {
    for replace_with_symlink in [false, true] {
        let (directory, root, publication) = git_publication_fixture();
        let git = directory.path().join(".git");
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), b"outside target").unwrap();
        let lock_path = git.join("index.lock");
        let mut replaced = false;
        let result = root.publish_git(&publication, || {
            if !replaced && fs::read(&lock_path).is_ok_and(|bytes| bytes == b"replacement-index") {
                fs::remove_file(&lock_path).unwrap();
                if replace_with_symlink {
                    symlink(outside.path(), &lock_path).unwrap();
                } else {
                    fs::write(&lock_path, b"attacker replacement").unwrap();
                }
                replaced = true;
            }
            true
        });
        assert!(
            replaced,
            "test callback must replace the completed lock file"
        );
        assert_eq!(result, Err(Error::Changed));
        assert_eq!(fs::read(git.join("index")).unwrap(), b"previous-index");
        if replace_with_symlink {
            assert!(
                fs::symlink_metadata(&lock_path)
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read(outside.path()).unwrap(), b"outside target");
        } else {
            assert_eq!(fs::read(&lock_path).unwrap(), b"attacker replacement");
        }
    }
}

#[test]
fn git_publication_rejects_a_replaced_object_temporary_file() {
    let (directory, root, publication) = git_publication_fixture();
    let object_dir = directory.path().join(".git/objects/01");
    let mut replacement_path = None;
    let result = root.publish_git(&publication, || {
        if replacement_path.is_none() {
            if let Ok(entries) = fs::read_dir(&object_dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    let name = entry.file_name();
                    if name.to_string_lossy().starts_with(".lomi-object-")
                        && fs::read(&path).is_ok_and(|bytes| bytes == b"compressed loose object")
                    {
                        fs::remove_file(&path).unwrap();
                        fs::write(&path, b"attacker object replacement").unwrap();
                        replacement_path = Some(path);
                        break;
                    }
                }
            }
        }
        true
    });
    let replacement_path = replacement_path.expect("callback must replace the completed temp");
    assert_eq!(result, Err(Error::Changed));
    assert_eq!(
        fs::read(directory.path().join(".git/index")).unwrap(),
        b"previous-index"
    );
    assert!(
        !directory
            .path()
            .join(".git/objects/01/23456789012345678901234567890123456789")
            .exists()
    );
    assert_eq!(
        fs::read(replacement_path).unwrap(),
        b"attacker object replacement"
    );
}

#[test]
fn git_publication_refuses_unprotected_roots_symlinks_and_index_lock_collisions() {
    let (directory, root, publication) = git_publication_fixture();
    let unprotected = find(&root, root.root_entry(), ".git");
    // `.git` is protected by identity; a normal workspace directory cannot be
    // substituted as the Git metadata directory.
    let mut outside = publication.clone();
    outside.git_dir = root.root_entry();
    assert_eq!(root.publish_git(&outside, || true), Err(Error::Protected));

    fs::write(directory.path().join(".git/index.lock"), b"busy").unwrap();
    assert_eq!(root.publish_git(&publication, || true), Err(Error::Exists));
    assert_eq!(
        fs::read(directory.path().join(".git/index")).unwrap(),
        b"previous-index"
    );
    let _ = unprotected;

    let (directory, root, publication) = git_publication_fixture();
    let outside = tempfile::tempdir().unwrap();
    symlink(outside.path(), directory.path().join(".git/objects/01")).unwrap();
    assert!(root.publish_git(&publication, || true).is_err());
    assert!(
        !outside
            .path()
            .join("23456789012345678901234567890123456789")
            .exists()
    );
    assert_eq!(
        fs::read(directory.path().join(".git/index")).unwrap(),
        b"previous-index"
    );
}

#[test]
fn list_is_sorted_paginated_and_ids_are_stable() {
    let (dir, _o, root) = fixture();
    for name in ["c", "a", "b", "d", "e"] {
        fs::write(dir.path().join(name), name).unwrap();
    }
    let first = root.list(root.root_entry(), None, 2).unwrap();
    assert_eq!(
        first
            .entries
            .iter()
            .map(|m| m.name.clone())
            .collect::<Vec<_>>(),
        vec![b"a".to_vec(), b"b".to_vec()]
    );
    assert!(first.truncated);
    let second = root
        .list(root.root_entry(), first.next.as_deref(), 2)
        .unwrap();
    assert_eq!(second.entries[0].name, b"c");
    let third = root
        .list(root.root_entry(), second.next.as_deref(), 2)
        .unwrap();
    assert_eq!(third.entries.len(), 1);
    assert!(!third.truncated && third.next.is_none());
    let again = root.list(root.root_entry(), None, 2).unwrap();
    assert_eq!(again.entries[0].entry, first.entries[0].entry);
}

#[test]
fn symlinks_are_shown_as_links_and_never_followed() {
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("secret"), "top secret").unwrap();
    symlink(outside.path(), dir.path().join("out")).unwrap();
    symlink(
        outside.path().join("secret"),
        dir.path().join("secret-link"),
    )
    .unwrap();
    let dir_link = find(&root, root.root_entry(), "out");
    let file_link = find(&root, root.root_entry(), "secret-link");
    assert_eq!(dir_link.kind, Kind::Symlink);
    assert_eq!(file_link.kind, Kind::Symlink);
    assert_eq!(
        root.read(file_link.entry, None, 0, 100),
        Err(Error::Invalid)
    );
    assert!(root.list(dir_link.entry, None, 10).is_err());
    assert_eq!(
        root.create_file(dir_link.entry, &dir_link.revision, b"x"),
        Err(Error::Changed)
    );
    assert!(!outside.path().join("x").exists());
}

#[test]
fn replacing_an_ancestor_with_a_symlink_is_changed_not_followed() {
    let (dir, outside, root) = fixture();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/file"), "inside").unwrap();
    fs::write(outside.path().join("file"), "outside").unwrap();
    let sub = find(&root, root.root_entry(), "sub");
    let file = find(&root, sub.entry, "file");
    fs::remove_dir_all(dir.path().join("sub")).unwrap();
    symlink(outside.path(), dir.path().join("sub")).unwrap();
    assert_eq!(root.read(file.entry, None, 0, 100), Err(Error::Changed));
    assert_eq!(root.stat(file.entry, None), Err(Error::Changed));
    assert_eq!(root.list(sub.entry, None, 10), Err(Error::Changed));
}

#[test]
fn replacing_a_file_with_another_is_changed() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("f"), "one").unwrap();
    let file = find(&root, root.root_entry(), "f");
    fs::remove_file(dir.path().join("f")).unwrap();
    fs::write(dir.path().join("f"), "two").unwrap();
    assert_eq!(root.read(file.entry, None, 0, 10), Err(Error::Changed));
}

#[test]
fn stale_entry_never_aliases_a_recreated_file() {
    let (dir, _outside, root) = fixture();
    let path = dir.path().join("reused");
    fs::write(&path, "original").unwrap();
    let stale = find(&root, root.root_entry(), "reused");
    for index in 0..128 {
        fs::remove_file(&path).unwrap();
        fs::write(&path, format!("replacement-{index}")).unwrap();
        assert_eq!(root.read(stale.entry, None, 0, 64), Err(Error::Changed));
    }
}

#[test]
fn revision_precondition_detects_modification() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("f"), "one").unwrap();
    let file = find(&root, root.root_entry(), "f");
    assert!(root.stat(file.entry, Some(&file.revision)).is_ok());
    std::thread::sleep(std::time::Duration::from_millis(20));
    fs::write(dir.path().join("f"), "changed").unwrap();
    assert_eq!(
        root.stat(file.entry, Some(&file.revision)),
        Err(Error::Changed)
    );
    assert_eq!(
        root.read(file.entry, Some(&file.revision), 0, 10),
        Err(Error::Changed)
    );
}

#[test]
fn hard_linked_files_are_listed_but_refuse_read_and_mutation() {
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("target"), "shared content").unwrap();
    fs::hard_link(outside.path().join("target"), dir.path().join("linked")).unwrap();
    let linked = find(&root, root.root_entry(), "linked");
    assert_eq!(linked.nlink, 2);
    assert_eq!(root.read(linked.entry, None, 0, 100), Err(Error::Protected));
    assert_eq!(
        root.remove(
            linked.entry,
            &linked.revision,
            root.root_entry(),
            &root_rev(&root)
        ),
        Err(Error::Protected)
    );
    assert!(dir.path().join("linked").exists());
}

#[test]
fn fifo_and_directories_are_never_read() {
    let (dir, _o, root) = fixture();
    let fifo = dir.path().join("fifo");
    let c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
    fs::create_dir(dir.path().join("d")).unwrap();
    let fifo = find(&root, root.root_entry(), "fifo");
    assert_eq!(fifo.kind, Kind::Other);
    assert_eq!(root.read(fifo.entry, None, 0, 10), Err(Error::Invalid));
    let d = find(&root, root.root_entry(), "d");
    assert_eq!(root.read(d.entry, None, 0, 10), Err(Error::Invalid));
}

#[test]
fn read_reports_encoding_line_endings_window_and_withholds_binary() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("lf"), "a\nb\n").unwrap();
    fs::write(dir.path().join("crlf"), "a\r\nb\r\n").unwrap();
    fs::write(dir.path().join("mixed"), "a\r\nb\n").unwrap();
    fs::write(dir.path().join("bin"), [0u8, 1, 2, 3]).unwrap();
    fs::write(dir.path().join("big"), vec![b'x'; 5000]).unwrap();
    fs::write(dir.path().join("euro"), "€€€").unwrap();
    let utf16: Vec<u8> = [0xFF, 0xFE]
        .into_iter()
        .chain("hi\r\n".encode_utf16().flat_map(|u| u.to_le_bytes()))
        .collect();
    fs::write(dir.path().join("u16"), utf16).unwrap();
    let read = |name: &str, offset, max| {
        let m = find(&root, root.root_entry(), name);
        root.read(m.entry, None, offset, max).unwrap()
    };
    assert_eq!(read("lf", 0, 100).line_endings, LineEndings::Lf);
    assert_eq!(read("crlf", 0, 100).line_endings, LineEndings::CrLf);
    assert_eq!(read("mixed", 0, 100).line_endings, LineEndings::Mixed);
    let bin = read("bin", 0, 100);
    assert_eq!(bin.encoding, Encoding::Binary);
    assert!(bin.bytes.is_empty() && bin.truncated);
    let big = read("big", 0, 1000);
    assert_eq!((big.bytes.len(), big.truncated), (1000, true));
    let tail = read("big", 4500, 1000);
    assert_eq!((tail.bytes.len(), tail.truncated), (500, false));
    assert!(read("big", 9999, 10).bytes.is_empty());
    // A window that cuts a multi-byte scalar is still UTF-8.
    let euro = read("euro", 0, 4);
    assert_eq!((euro.encoding, euro.truncated), (Encoding::Utf8, true));
    let u16 = read("u16", 0, 100);
    assert_eq!(u16.encoding, Encoding::Utf16Le);
    assert_eq!(u16.line_endings, LineEndings::CrLf);
}

#[test]
fn search_is_bounded_deterministic_and_skips_git_and_links() {
    let (dir, outside, root) = fixture();
    fs::create_dir_all(dir.path().join("a/b")).unwrap();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join("a/needle1.txt"), "").unwrap();
    fs::write(dir.path().join("a/b/NEEDLE2.txt"), "").unwrap();
    fs::write(dir.path().join(".git/needle3"), "").unwrap();
    fs::write(outside.path().join("needle4"), "").unwrap();
    symlink(outside.path(), dir.path().join("a/link")).unwrap();
    let all = root
        .search_names(root.root_entry(), "needle", None, 50)
        .unwrap();
    let mut names: Vec<_> = all.entries.iter().map(|m| m.name.clone()).collect();
    names.sort();
    assert_eq!(
        names,
        vec![b"NEEDLE2.txt".to_vec(), b"needle1.txt".to_vec()]
    );
    let first = root
        .search_names(root.root_entry(), "needle", None, 1)
        .unwrap();
    assert!(first.truncated);
    let second = root
        .search_names(root.root_entry(), "needle", first.next.as_deref(), 1)
        .unwrap();
    assert_eq!(second.entries.len(), 1);
    assert_ne!(first.entries[0].entry, second.entries[0].entry);
    assert_eq!(
        root.search_names(root.root_entry(), "", None, 1),
        Err(Error::Invalid)
    );
}

#[test]
fn create_makes_an_empty_non_executable_file_only_when_absent() {
    let (dir, _o, root) = fixture();
    let created = root
        .create_file(root.root_entry(), &root_rev(&root), b"new.txt")
        .unwrap();
    assert_eq!((created.kind, created.size), (Kind::File, 0));
    let mode = fs::metadata(dir.path().join("new.txt"))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0);
    assert_eq!(
        root.create_file(root.root_entry(), &root_rev(&root), b"new.txt"),
        Err(Error::Exists)
    );
    // Stale parent revision.
    let stale = root_rev(&root);
    root.mkdir(root.root_entry(), &stale, b"d").unwrap();
    assert_eq!(
        root.create_file(root.root_entry(), &stale, b"other"),
        Err(Error::Changed)
    );
    for bad in [&b"a/b"[..], b"..", b".", b"", b"nul\0byte"] {
        assert_eq!(
            root.create_file(root.root_entry(), &root_rev(&root), bad),
            Err(Error::Invalid)
        );
    }
}

#[test]
fn git_metadata_and_aliases_are_never_mutable() {
    let (dir, _o, root) = fixture();
    fs::create_dir(dir.path().join(".git")).unwrap();
    fs::write(dir.path().join(".git/HEAD"), "ref").unwrap();
    fs::create_dir(dir.path().join("work")).unwrap();
    fs::write(dir.path().join("work/f"), "").unwrap();
    let git = find(&root, root.root_entry(), ".git");
    let head = find(&root, git.entry, "HEAD");
    let work = find(&root, root.root_entry(), "work");
    let f = find(&root, work.entry, "f");
    let rr = || root_rev(&root);
    assert_eq!(
        root.create_file(git.entry, &git.revision, b"x"),
        Err(Error::Protected)
    );
    assert_eq!(
        root.remove(head.entry, &head.revision, git.entry, &git.revision),
        Err(Error::Protected)
    );
    assert_eq!(
        root.remove(git.entry, &git.revision, root.root_entry(), &rr()),
        Err(Error::Protected)
    );
    // Creating or renaming TO a .git name (any case) is refused.
    assert_eq!(
        root.mkdir(root.root_entry(), &rr(), b".GIT"),
        Err(Error::Protected)
    );
    assert_eq!(
        root.rename(
            f.entry,
            &f.revision,
            work.entry,
            &work.revision,
            work.entry,
            &work.revision,
            b".git"
        ),
        Err(Error::Protected)
    );
    // Moving something INTO .git is refused.
    assert_eq!(
        root.rename(
            f.entry,
            &f.revision,
            work.entry,
            &work.revision,
            git.entry,
            &git.revision,
            b"moved"
        ),
        Err(Error::Protected)
    );
    assert!(dir.path().join(".git/HEAD").exists());
}

#[test]
fn approved_gitdirs_are_protected_by_identity_and_the_root_itself_is_immutable() {
    let (dir, outside, root) = fixture();
    fs::create_dir(dir.path().join("worktree-gitdir")).unwrap();
    fs::write(dir.path().join("worktree-gitdir/index"), "").unwrap();
    root.protect(&dir.path().join("worktree-gitdir")).unwrap();
    let gitdir = find(&root, root.root_entry(), "worktree-gitdir");
    let index = find(&root, gitdir.entry, "index");
    assert_eq!(
        root.remove(index.entry, &index.revision, gitdir.entry, &gitdir.revision),
        Err(Error::Protected)
    );
    // Renaming the protected directory away would defeat a text-path check.
    assert_eq!(
        root.rename(
            gitdir.entry,
            &gitdir.revision,
            root.root_entry(),
            &root_rev(&root),
            root.root_entry(),
            &root_rev(&root),
            b"renamed"
        ),
        Err(Error::Protected)
    );
    assert_eq!(
        root.remove(root.root_entry(), "x", root.root_entry(), &root_rev(&root)),
        Err(Error::Protected)
    );
    drop(outside);
}

#[test]
fn rename_never_overwrites_and_moves_across_directories() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("a"), "A").unwrap();
    fs::write(dir.path().join("b"), "B").unwrap();
    fs::create_dir(dir.path().join("d")).unwrap();
    let a = find(&root, root.root_entry(), "a");
    let d = find(&root, root.root_entry(), "d");
    let rr = root_rev(&root);
    assert_eq!(
        root.rename(
            a.entry,
            &a.revision,
            root.root_entry(),
            &rr,
            root.root_entry(),
            &rr,
            b"b"
        ),
        Err(Error::Exists)
    );
    assert_eq!(fs::read_to_string(dir.path().join("b")).unwrap(), "B");
    let moved = root
        .rename(
            a.entry,
            &a.revision,
            root.root_entry(),
            &rr,
            d.entry,
            &d.revision,
            b"a2",
        )
        .unwrap();
    assert_eq!(moved.entry, a.entry);
    assert_eq!(fs::read_to_string(dir.path().join("d/a2")).unwrap(), "A");
    assert!(!dir.path().join("a").exists());
    assert_eq!(root.read(moved.entry, None, 0, 10).unwrap().bytes, b"A");
}

#[test]
fn remove_deletes_file_link_and_empty_directory_but_never_recurses_or_follows() {
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("victim"), "keep").unwrap();
    symlink(outside.path(), dir.path().join("link")).unwrap();
    fs::write(dir.path().join("f"), "").unwrap();
    fs::create_dir(dir.path().join("empty")).unwrap();
    fs::create_dir(dir.path().join("full")).unwrap();
    fs::write(dir.path().join("full/x"), "").unwrap();
    let remove = |name: &str| {
        let m = find(&root, root.root_entry(), name);
        root.remove(m.entry, &m.revision, root.root_entry(), &root_rev(&root))
    };
    assert_eq!(remove("link"), Ok(()));
    assert!(
        outside.path().join("victim").exists(),
        "target must survive"
    );
    assert_eq!(remove("f"), Ok(()));
    assert_eq!(remove("empty"), Ok(()));
    assert_eq!(remove("full"), Err(Error::NotEmpty));
    assert!(dir.path().join("full/x").exists());
}

#[test]
fn remove_requires_current_entry_and_parent_revisions() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("f"), "").unwrap();
    let f = find(&root, root.root_entry(), "f");
    let stale_parent = root_rev(&root);
    fs::write(dir.path().join("other"), "").unwrap();
    assert_eq!(
        root.remove(f.entry, &f.revision, root.root_entry(), &stale_parent),
        Err(Error::Changed)
    );
    assert_eq!(
        root.remove(f.entry, "rdeadbeef", root.root_entry(), &root_rev(&root)),
        Err(Error::Changed)
    );
    assert!(dir.path().join("f").exists());
    assert_eq!(
        root.remove(f.entry, &f.revision, root.root_entry(), &root_rev(&root)),
        Ok(())
    );
}

#[test]
fn host_data_inside_or_around_the_root_is_refused_by_identity() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("root");
    fs::create_dir_all(root.join("nested/secrets")).unwrap();
    // Protected path inside the root.
    assert_eq!(
        FileRoot::open(&root, &[&root.join("nested/secrets")]).err(),
        Some(Error::Protected)
    );
    // Root inside a protected directory.
    assert_eq!(
        FileRoot::open(&root.join("nested"), &[base.path()]).err(),
        Some(Error::Protected)
    );
    // A symlinked alias of the protected directory is caught by canonical/identity checks.
    symlink(root.join("nested/secrets"), base.path().join("alias")).unwrap();
    assert_eq!(
        FileRoot::open(&root, &[&base.path().join("alias")]).err(),
        Some(Error::Protected)
    );
    // Unrelated host data is fine.
    let host = tempfile::tempdir().unwrap();
    assert!(FileRoot::open(&root, &[host.path()]).is_ok());
}

#[test]
fn configured_host_protected_path_must_be_resolvable() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("root");
    fs::create_dir(&root).unwrap();
    let missing = base.path().join("missing-protected-path");
    assert_eq!(
        FileRoot::open(&root, &[missing.as_path()]).err(),
        Some(Error::NotFound)
    );
}

#[test]
fn birth_time_is_part_of_file_identity() {
    let original = Ident {
        dev: 7,
        ino: 11,
        birth_sec: 13,
        birth_nsec: 17,
    };
    let same_object = Ident { ..original };
    let reused_inode = Ident {
        birth_nsec: 18,
        ..original
    };
    assert_eq!(original, same_object);
    assert_ne!(original, reused_inode);
}

#[cfg(target_os = "linux")]
#[test]
fn non_utf8_names_round_trip_without_loss() {
    use std::ffi::OsStr;
    let (dir, _o, root) = fixture();
    let raw: &[u8] = b"bad-\xff\xfe-name";
    fs::write(dir.path().join(OsStr::from_bytes(raw)), "x").unwrap();
    let page = root.list(root.root_entry(), None, 10).unwrap();
    assert_eq!(page.entries[0].name, raw);
    assert_eq!(
        root.read(page.entries[0].entry, None, 0, 10).unwrap().bytes,
        b"x"
    );
}

#[test]
fn unknown_and_foreign_entry_ids_are_not_found() {
    let (_d, _o, root) = fixture();
    let (_d2, _o2, other) = fixture();
    assert_eq!(root.stat(other.root_entry(), None), Err(Error::NotFound));
    assert_eq!(root.list(other.root_entry(), None, 1), Err(Error::NotFound));
    assert_eq!(
        root.read(EntryRef::from_bytes([7; 16]), None, 0, 1),
        Err(Error::NotFound)
    );
}

#[test]
fn concurrent_ancestor_swap_never_reads_or_writes_outside_the_root() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("file"), "OUTSIDE").unwrap();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/file"), "inside").unwrap();
    let sub = find(&root, root.root_entry(), "sub");
    let file = find(&root, sub.entry, "file");
    let stop = Arc::new(AtomicBool::new(false));
    let swapper = {
        let (stop, base, out) = (
            stop.clone(),
            dir.path().to_path_buf(),
            outside.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::rename(base.join("sub"), base.join("sub.real"));
                let _ = symlink(&out, base.join("sub"));
                std::thread::yield_now();
                let _ = fs::remove_file(base.join("sub"));
                let _ = fs::rename(base.join("sub.real"), base.join("sub"));
                std::thread::yield_now();
            }
        })
    };
    for round in 0..2000 {
        if let Ok(read) = root.read(file.entry, None, 0, 32) {
            assert_eq!(read.bytes, b"inside", "read escaped the root");
        }
        if let Ok(read) = root.read_snapshot_chunk(file.entry, &file.revision, 0, 32) {
            assert_eq!(read.bytes, b"inside", "snapshot read escaped the root");
        }
        let _ = root.create_file(sub.entry, "rwrong", format!("new{round}").as_bytes());
        if let Ok(meta) = root.stat(sub.entry, None) {
            let _ = root.create_file(sub.entry, &meta.revision, format!("c{round}").as_bytes());
        }
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();
    let leaked: Vec<_> = fs::read_dir(outside.path())
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .filter(|n| n != "file")
        .collect();
    assert!(leaked.is_empty(), "created outside the root: {leaked:?}");
}

#[test]
fn concurrent_hardlink_to_outside_content_is_never_disclosed() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("target"), "OUTSIDE").unwrap();
    fs::write(dir.path().join("f"), "inside").unwrap();
    let f = find(&root, root.root_entry(), "f");
    let stop = Arc::new(AtomicBool::new(false));
    let linker = {
        let (stop, base, out) = (
            stop.clone(),
            dir.path().to_path_buf(),
            outside.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Replace the entry with a hard link to the outside file, then
                // restore a private file, as fast as possible.
                let _ = fs::remove_file(base.join("f"));
                let _ = fs::hard_link(out.join("target"), base.join("f"));
                std::thread::yield_now();
                let _ = fs::remove_file(base.join("f"));
                let _ = fs::write(base.join("f"), "inside");
                std::thread::yield_now();
            }
        })
    };
    for _ in 0..3000 {
        if let Ok(read) = root.read(f.entry, None, 0, 32) {
            assert_eq!(
                read.bytes, b"inside",
                "hard-linked outside content disclosed"
            );
        }
        if let Ok(read) = root.read_snapshot_chunk(f.entry, &f.revision, 0, 32) {
            assert_eq!(
                read.bytes, b"inside",
                "raw snapshot disclosed hard-linked outside content"
            );
        }
    }
    stop.store(true, Ordering::Relaxed);
    linker.join().unwrap();
}

#[test]
fn git_snapshot_chunk_reads_binary_but_keeps_no_follow_and_hardlink_guards() {
    let (dir, outside, root) = fixture();
    let binary = [0x00, 0xff, 0x01, 0xfe];
    fs::write(dir.path().join("index"), binary).unwrap();
    let index = find(&root, root.root_entry(), "index");

    let explorer_read = root
        .read(index.entry, Some(&index.revision), 0, 16)
        .unwrap();
    assert_eq!(explorer_read.bytes, Vec::<u8>::new());
    assert_eq!(explorer_read.encoding, Encoding::Binary);

    let snapshot_read = root
        .read_snapshot_chunk(index.entry, &index.revision, 0, 16)
        .unwrap();
    assert_eq!(snapshot_read.bytes, binary);
    assert_eq!(snapshot_read.encoding, Encoding::Binary);
    assert!(!snapshot_read.truncated);

    fs::write(outside.path().join("linked-pack"), binary).unwrap();
    fs::remove_file(dir.path().join("index")).unwrap();
    fs::hard_link(outside.path().join("linked-pack"), dir.path().join("index")).unwrap();
    assert!(matches!(
        root.read_snapshot_chunk(index.entry, &index.revision, 0, 16),
        Err(Error::Changed | Error::Protected)
    ));
}
