use super::*;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn fixture() -> (TempDir, TempDir, FileRoot) {
    let outside = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let root = FileRoot::open(dir.path(), &[]).unwrap();
    (dir, outside, root)
}

/// A directory junction needs no privilege, unlike a symbolic link.
fn junction(link: &Path, target: &Path) {
    // cmd reads a forward slash as a switch, so normalise separators.
    let normal = |path: &Path| path.to_string_lossy().replace('/', "\\");
    let output = Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(normal(link))
        .arg(normal(target))
        .output()
        .unwrap();
    assert!(output.status.success(), "mklink /J failed: {output:?}");
}

fn remove_junction(link: &Path) {
    // Removes only the junction, never its target.
    let _ = fs::remove_dir(link);
}

#[test]
fn overlapped_watch_stays_open_while_idle_then_reports_child_content() {
    let (dir, _outside, root) = fixture();
    let path = dir.path().join("watched");
    fs::write(&path, b"before").unwrap();
    let watcher = root.watch_directory(root.root_entry()).unwrap();

    for _ in 0..5 {
        assert!(
            !watcher.changed().unwrap(),
            "an idle request remains pending"
        );
    }

    let original = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, b"after!").unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    let times = std::fs::FileTimes::new().set_modified(original);
    file.set_times(times).unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if watcher.changed().unwrap() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "same-size write with restored mtime must notify the directory watcher"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    // The completed request must be rearmed before changed() returns.
    fs::write(&path, b"again!").unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(original))
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if watcher.changed().unwrap() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the same watcher must report a second event after rearming"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn overlapped_watch_opens_nested_directory_relative_to_the_root() {
    let (dir, _outside, root) = fixture();
    let child_path = dir.path().join("child");
    fs::create_dir(&child_path).unwrap();
    let path = child_path.join("watched");
    fs::write(&path, b"before").unwrap();
    let child = find(&root, root.root_entry(), "child");
    let watcher = root.watch_directory(child.entry).unwrap();

    for _ in 0..5 {
        assert!(
            !watcher.changed().unwrap(),
            "an idle request remains pending"
        );
    }

    let original = fs::metadata(&path).unwrap().modified().unwrap();
    fs::write(&path, b"after!").unwrap();
    let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.set_times(std::fs::FileTimes::new().set_modified(original))
        .unwrap();

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    loop {
        if watcher.changed().unwrap() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "same-size write with restored mtime must notify the nested watcher"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

#[test]
fn repeated_idle_overlapped_watch_drops_cancel_the_pending_request() {
    let (_dir, _outside, root) = fixture();

    for _ in 0..8 {
        let watcher = root.watch_directory(root.root_entry()).unwrap();
        assert!(!watcher.changed().unwrap(), "the new request is still idle");
        drop(watcher);
    }
}

/// Symbolic links need Developer Mode or elevation; `None` when unavailable.
fn file_symlink(target: &Path, link: &Path) -> Option<()> {
    std::os::windows::fs::symlink_file(target, link).ok()
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

// Directory timestamps tick coarsely; external edits need a tick between them.
fn tick() {
    std::thread::sleep(std::time::Duration::from_millis(40));
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
fn reparse_points_are_shown_as_links_and_never_followed() {
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("secret"), "top secret").unwrap();
    junction(&dir.path().join("out"), outside.path());
    let dir_link = find(&root, root.root_entry(), "out");
    assert_eq!(dir_link.kind, Kind::Symlink);
    assert!(root.list(dir_link.entry, None, 10).is_err());
    assert_eq!(
        root.create_file(dir_link.entry, &dir_link.revision, b"x"),
        Err(Error::Changed)
    );
    assert!(!outside.path().join("x").exists());
    assert!(outside.path().join("secret").exists());
    if file_symlink(
        &outside.path().join("secret"),
        &dir.path().join("secret-link"),
    )
    .is_some()
    {
        let file_link = find(&root, root.root_entry(), "secret-link");
        assert_eq!(file_link.kind, Kind::Symlink);
        assert_eq!(
            root.read(file_link.entry, None, 0, 100),
            Err(Error::Invalid)
        );
    } else {
        eprintln!("skipped file symlink half: needs Developer Mode or elevation");
    }
    remove_junction(&dir.path().join("out"));
}

#[test]
fn replacing_an_ancestor_with_a_junction_is_changed_not_followed() {
    let (dir, outside, root) = fixture();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/file"), "inside").unwrap();
    fs::write(outside.path().join("file"), "outside").unwrap();
    let sub = find(&root, root.root_entry(), "sub");
    let file = find(&root, sub.entry, "file");
    fs::remove_dir_all(dir.path().join("sub")).unwrap();
    junction(&dir.path().join("sub"), outside.path());
    assert_eq!(root.read(file.entry, None, 0, 100), Err(Error::Changed));
    assert_eq!(root.stat(file.entry, None), Err(Error::Changed));
    assert_eq!(root.list(sub.entry, None, 10), Err(Error::Changed));
    remove_junction(&dir.path().join("sub"));
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
fn revision_precondition_detects_modification() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("f"), "one").unwrap();
    let file = find(&root, root.root_entry(), "f");
    assert!(root.stat(file.entry, Some(&file.revision)).is_ok());
    tick();
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
fn directories_are_never_read() {
    let (dir, _o, root) = fixture();
    fs::create_dir(dir.path().join("d")).unwrap();
    let d = find(&root, root.root_entry(), "d");
    assert_eq!(d.kind, Kind::Directory);
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
    junction(&dir.path().join("a/link"), outside.path());
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
    remove_junction(&dir.path().join("a/link"));
}

#[test]
fn create_makes_an_empty_file_only_when_absent() {
    let (dir, _o, root) = fixture();
    let created = root
        .create_file(root.root_entry(), &root_rev(&root), b"new.txt")
        .unwrap();
    assert_eq!((created.kind, created.size), (Kind::File, 0));
    assert_eq!(fs::metadata(dir.path().join("new.txt")).unwrap().len(), 0);
    assert_eq!(
        root.create_file(root.root_entry(), &root_rev(&root), b"new.txt"),
        Err(Error::Exists)
    );
    // The same name in another case is the same NTFS entry.
    assert_eq!(
        root.create_file(root.root_entry(), &root_rev(&root), b"NEW.TXT"),
        Err(Error::Exists)
    );
    // Stale parent revision, even within one filesystem clock tick.
    let stale = root_rev(&root);
    root.mkdir(root.root_entry(), &stale, b"d").unwrap();
    assert_eq!(
        root.create_file(root.root_entry(), &stale, b"other"),
        Err(Error::Changed)
    );
    assert!(!dir.path().join("other").exists());
}

#[test]
fn names_that_win32_or_ntfs_would_reinterpret_are_invalid() {
    let (dir, _o, root) = fixture();
    let bad: &[&[u8]] = &[
        b"a/b",
        b"a\\b",
        b"..",
        b".",
        b"",
        b"nul\0byte",
        // Alternate data streams and directory index aliases.
        b"file.txt:stream",
        b"file.txt:stream:$DATA",
        b"dir::$INDEX_ALLOCATION",
        b"C:evil",
        // Trailing dots/spaces are stripped by Win32 and so alias another name.
        b"trailing.",
        b"trailing ",
        // DOS device names, with or without extension, any case.
        b"CON",
        b"con.txt",
        b"NUL",
        b"nul.tar.gz",
        b"PRN",
        b"AUX",
        b"COM1",
        b"lpt9.log",
        b"CONIN$",
        b"CONOUT$",
        // Wildcards, quotes and control characters.
        b"star*",
        b"what?",
        b"a<b",
        b"a>b",
        b"a|b",
        b"say\"hi\"",
        b"tab\tname",
        b"bell\x07",
        // Not valid UTF-8 and so not addressable.
        b"bad-\xff-name",
    ];
    for name in bad {
        let rev = root_rev(&root);
        assert_eq!(
            root.create_file(root.root_entry(), &rev, name),
            Err(Error::Invalid),
            "{:?}",
            String::from_utf8_lossy(name)
        );
        assert_eq!(
            root.mkdir(root.root_entry(), &rev, name),
            Err(Error::Invalid),
            "{:?}",
            String::from_utf8_lossy(name)
        );
    }
    let rev = root_rev(&root);
    assert_eq!(
        root.create_file(root.root_entry(), &rev, &[b'x'; 256]),
        Err(Error::Invalid)
    );
    // Nothing leaked into the directory, nor onto a stream of some entry.
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    // Names that merely look similar remain valid.
    for ok in ["COM", "console", "nul-device", "a b", ".hidden", "dir.name"] {
        let rev = root_rev(&root);
        assert!(
            root.create_file(root.root_entry(), &rev, ok.as_bytes())
                .is_ok(),
            "{ok}"
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
    // Creating or renaming TO a .git name (any case, 8.3 alias) is refused.
    for alias in [&b".GIT"[..], b".Git", b"GIT~1", b"git~2"] {
        assert_eq!(
            root.mkdir(root.root_entry(), &rr(), alias),
            Err(Error::Protected),
            "{}",
            String::from_utf8_lossy(alias)
        );
    }
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
    // Case-insensitive collision with an existing entry is also refused.
    assert_eq!(
        root.rename(
            a.entry,
            &a.revision,
            root.root_entry(),
            &rr,
            root.root_entry(),
            &rr,
            b"B"
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
fn rename_refuses_invalid_target_names_and_leaves_the_source() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("a"), "A").unwrap();
    let a = find(&root, root.root_entry(), "a");
    for bad in [&b"a:stream"[..], b"NUL", b"x.", b"sub\\a", b"a/b"] {
        let rr = root_rev(&root);
        assert_eq!(
            root.rename(
                a.entry,
                &a.revision,
                root.root_entry(),
                &rr,
                root.root_entry(),
                &rr,
                bad
            ),
            Err(Error::Invalid),
            "{}",
            String::from_utf8_lossy(bad)
        );
    }
    assert!(dir.path().join("a").exists());
}

#[test]
fn remove_deletes_file_link_and_empty_directory_but_never_recurses_or_follows() {
    let (dir, outside, root) = fixture();
    fs::write(outside.path().join("victim"), "keep").unwrap();
    junction(&dir.path().join("link"), outside.path());
    fs::write(dir.path().join("f"), "").unwrap();
    fs::create_dir(dir.path().join("empty")).unwrap();
    fs::create_dir(dir.path().join("full")).unwrap();
    fs::write(dir.path().join("full/x"), "").unwrap();
    let remove = |name: &str| {
        let m = find(&root, root.root_entry(), name);
        root.remove(m.entry, &m.revision, root.root_entry(), &root_rev(&root))
    };
    assert_eq!(remove("link"), Ok(()));
    assert!(!dir.path().join("link").exists());
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
// Clearing the read-only attribute is exactly right on Windows.
#[allow(clippy::permissions_set_readonly_false)]
fn remove_deletes_a_read_only_file_like_unlink_does() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("ro"), "x").unwrap();
    let mut permissions = fs::metadata(dir.path().join("ro")).unwrap().permissions();
    permissions.set_readonly(true);
    fs::set_permissions(dir.path().join("ro"), permissions).unwrap();
    let m = find(&root, root.root_entry(), "ro");
    let result = root.remove(m.entry, &m.revision, root.root_entry(), &root_rev(&root));
    if result.is_err() {
        // Older systems lack POSIX delete semantics; make the fixture removable.
        let mut permissions = fs::metadata(dir.path().join("ro")).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(dir.path().join("ro"), permissions).unwrap();
    }
    assert_eq!(result, Ok(()));
    assert!(!dir.path().join("ro").exists());
}

#[test]
fn remove_requires_current_entry_and_parent_revisions() {
    let (dir, _o, root) = fixture();
    fs::write(dir.path().join("f"), "").unwrap();
    let f = find(&root, root.root_entry(), "f");
    let stale_parent = root_rev(&root);
    tick();
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
fn consecutive_engine_mutations_always_change_the_parent_revision() {
    let (_dir, _o, root) = fixture();
    // Far faster than one filesystem clock tick.
    let mut seen = std::collections::HashSet::new();
    for index in 0..40 {
        let revision = root_rev(&root);
        assert!(seen.insert(revision.clone()), "revision repeated");
        root.create_file(root.root_entry(), &revision, format!("f{index}").as_bytes())
            .unwrap();
    }
}

#[test]
fn host_data_inside_or_around_the_root_is_refused_by_identity() {
    let base = tempfile::tempdir().unwrap();
    let root = base.path().join("root");
    fs::create_dir_all(root.join("nested/secrets")).unwrap();
    assert_eq!(
        FileRoot::open(&root, &[&root.join("nested/secrets")]).err(),
        Some(Error::Protected)
    );
    assert_eq!(
        FileRoot::open(&root.join("nested"), &[base.path()]).err(),
        Some(Error::Protected)
    );
    // A junction alias of the protected directory is caught by canonical paths.
    junction(&base.path().join("alias"), &root.join("nested/secrets"));
    assert_eq!(
        FileRoot::open(&root, &[&base.path().join("alias")]).err(),
        Some(Error::Protected)
    );
    remove_junction(&base.path().join("alias"));
    let host = tempfile::tempdir().unwrap();
    assert!(FileRoot::open(&root, &[host.path()]).is_ok());
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
fn opening_a_file_or_a_missing_path_as_root_fails() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f"), "x").unwrap();
    assert!(FileRoot::open(&dir.path().join("f"), &[]).is_err());
    assert_eq!(
        FileRoot::open(&dir.path().join("missing"), &[]).err(),
        Some(Error::NotFound)
    );
}

#[test]
fn entries_open_by_handle_stay_correct_while_the_directory_is_renamed() {
    let (dir, _o, root) = fixture();
    fs::create_dir(dir.path().join("sub")).unwrap();
    fs::write(dir.path().join("sub/file"), "inside").unwrap();
    let sub = find(&root, root.root_entry(), "sub");
    let file = find(&root, sub.entry, "file");
    // The directory keeps its identity when renamed externally: the recorded
    // name no longer resolves, so the engine reports a change, never a guess.
    fs::rename(dir.path().join("sub"), dir.path().join("moved")).unwrap();
    let result = root.read(file.entry, None, 0, 10);
    assert!(
        matches!(result, Err(Error::NotFound) | Err(Error::Changed)),
        "{result:?}"
    );
    // A fresh listing finds it under its new name and reads it.
    let moved = find(&root, root.root_entry(), "moved");
    let again = find(&root, moved.entry, "file");
    assert_eq!(
        root.read(again.entry, None, 0, 10).unwrap().bytes,
        b"inside"
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
        let (stop, base, out): (_, PathBuf, PathBuf) = (
            stop.clone(),
            dir.path().to_path_buf(),
            outside.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::rename(base.join("sub"), base.join("sub.real"));
                let _ = Command::new("cmd")
                    .args(["/C", "mklink", "/J"])
                    .arg(base.join("sub"))
                    .arg(&out)
                    .output();
                std::thread::yield_now();
                let _ = fs::remove_dir(base.join("sub"));
                let _ = fs::rename(base.join("sub.real"), base.join("sub"));
                std::thread::yield_now();
            }
        })
    };
    for round in 0..300 {
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
        let (stop, base, out): (_, PathBuf, PathBuf) = (
            stop.clone(),
            dir.path().to_path_buf(),
            outside.path().to_path_buf(),
        );
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                let _ = fs::remove_file(base.join("f"));
                let _ = fs::hard_link(out.join("target"), base.join("f"));
                std::thread::yield_now();
                let _ = fs::remove_file(base.join("f"));
                let _ = fs::write(base.join("f"), "inside");
                std::thread::yield_now();
            }
        })
    };
    for _ in 0..1500 {
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
