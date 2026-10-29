#![cfg(unix)]
use jiff::Timestamp;
use lomi_update_trust::{MAX_METADATA, MAX_TARGET};
use rusqlite::Connection;
use std::{
    fs,
    io::{BufRead, BufReader},
    num::NonZeroU64,
    os::unix::fs::{PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};
use tempfile::TempDir;
use tough::{
    editor::{RepositoryEditor, signed::PathExists},
    key_source::{KeySource, LocalKeySource},
};
const PAYLOAD: &[u8] = b"synthetic verified bytes; never executed\n";
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/release/fixtures")
}
fn temp() -> TempDir {
    let base = fs::canonicalize(std::env::temp_dir()).unwrap();
    let temp = TempDir::new_in(&base).unwrap();
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
    temp
}
fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_lomi-update-trust"))
        .args(args)
        .output()
        .unwrap()
}
fn path(p: &Path) -> &str {
    p.to_str().unwrap()
}
fn ok(out: Output) -> Output {
    assert!(
        out.status.success(),
        "stderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    out
}
fn initialize(p: &Path, root: &Path) {
    ok(cli(&["initialize", path(p), path(root)]));
}
struct Repo {
    _temp: TempDir,
    metadata: PathBuf,
    targets: PathBuf,
}
impl Repo {
    async fn new(version: u64, expired: bool, payload: &[u8]) -> Self {
        let temp = temp();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("synthetic.bin"), payload).unwrap();
        let mut editor = RepositoryEditor::new(fixtures().join("root.json"))
            .await
            .unwrap();
        let future: Timestamp = "2099-01-01T00:00:00Z".parse().unwrap();
        let expiry = if expired {
            "2000-01-01T00:00:00Z".parse().unwrap()
        } else {
            future
        };
        let v = NonZeroU64::new(version).unwrap();
        editor
            .targets_expires(future)
            .unwrap()
            .targets_version(v)
            .unwrap()
            .snapshot_expires(future)
            .snapshot_version(v)
            .timestamp_expires(expiry)
            .timestamp_version(v)
            .add_target_paths(vec![source.join("synthetic.bin")])
            .await
            .unwrap();
        let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource {
            path: fixtures().join("snakeoil.pem"),
        })];
        let signed = editor.sign(&keys).await.unwrap();
        let metadata = temp.path().join("metadata");
        let targets = temp.path().join("targets");
        signed.write(&metadata).await.unwrap();
        signed
            .copy_targets(&source, &targets, PathExists::Fail)
            .await
            .unwrap();
        Self {
            _temp: temp,
            metadata,
            targets,
        }
    }
    fn update(&self, store: &Path) -> Output {
        cli(&[
            "update",
            path(store),
            path(&self.metadata),
            path(&self.targets),
            "synthetic.bin",
        ])
    }
    fn crash(&self, store: &Path, point: &str) -> Output {
        cli(&[
            "update",
            path(store),
            path(&self.metadata),
            path(&self.targets),
            "synthetic.bin",
            point,
        ])
    }
}
type Committed = (i64, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>);
fn committed(store: &Path) -> Committed {
    let db = Connection::open(store.join("trust.sqlite")).unwrap();
    db.query_row(
        "SELECT generation,root,timestamp,snapshot,targets,clock,checksum FROM trust_state",
        [],
        |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
            ))
        },
    )
    .unwrap()
}
#[tokio::test]
async fn verified_bytes_and_failed_verification_preserve_all_committed_state() {
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let repo = Repo::new(1, false, PAYLOAD).await;
    let result = ok(repo.update(&state));
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["verifiedTargetBytes"], PAYLOAD.len());
    let baseline = committed(&state);
    assert_eq!(baseline.0, 1);
    let file = fs::read_dir(&repo.targets)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut tampered = PAYLOAD.to_vec();
    tampered[0] ^= 1;
    fs::write(&file, tampered).unwrap();
    let rejected = repo.update(&state);
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty());
    assert_eq!(committed(&state), baseline);
    fs::write(file, PAYLOAD).unwrap();
    let timestamp = repo.metadata.join("timestamp.json");
    let original = fs::read(&timestamp).unwrap();
    let mut invalid: serde_json::Value = serde_json::from_slice(&original).unwrap();
    for sig in invalid["signatures"].as_array_mut().unwrap() {
        sig["sig"] = serde_json::Value::String("0".repeat(sig["sig"].as_str().unwrap().len()));
    }
    fs::write(&timestamp, serde_json::to_vec(&invalid).unwrap()).unwrap();
    assert!(!repo.update(&state).status.success());
    assert_eq!(committed(&state), baseline);
    fs::write(timestamp, original).unwrap();
    let expired = Repo::new(2, true, PAYLOAD).await;
    assert!(!expired.update(&state).status.success());
    assert_eq!(committed(&state), baseline);
}
#[tokio::test]
async fn stale_metadata_is_rejected_across_process_restart() {
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let newer = Repo::new(2, false, PAYLOAD).await;
    ok(newer.update(&state));
    let baseline = committed(&state);
    let stale = Repo::new(1, false, PAYLOAD).await;
    assert!(!stale.update(&state).status.success());
    assert_eq!(committed(&state), baseline);
    assert_eq!(
        String::from_utf8(ok(cli(&["status", path(&state)])).stdout)
            .unwrap()
            .trim(),
        "1"
    );
}
#[tokio::test]
async fn corrupt_missing_and_truncated_initialized_state_is_never_reset() {
    let repo = Repo::new(2, false, PAYLOAD).await;
    for column in ["root", "timestamp", "snapshot", "targets", "clock"] {
        let temp = temp();
        let state = temp.path().join("trust");
        initialize(&state, &fixtures().join("root.json"));
        ok(repo.update(&state));
        let db = Connection::open(state.join("trust.sqlite")).unwrap();
        db.execute(
            &format!("UPDATE trust_state SET {column}=?1"),
            [b"{".as_slice()],
        )
        .unwrap();
        drop(db);
        assert!(!cli(&["status", path(&state)]).status.success(), "{column}");
        assert!(!repo.update(&state).status.success(), "{column}");
        assert!(
            !cli(&[
                "initialize",
                path(&state),
                path(&fixtures().join("root.json"))
            ])
            .status
            .success()
        );
    }
    for action in [
        "missing-db",
        "truncated-db",
        "missing-row",
        "missing-clock",
        "missing-marker",
    ] {
        let temp = temp();
        let state = temp.path().join("trust");
        initialize(&state, &fixtures().join("root.json"));
        ok(repo.update(&state));
        match action {
            "missing-db" => fs::remove_file(state.join("trust.sqlite")).unwrap(),
            "truncated-db" => fs::write(state.join("trust.sqlite"), b"SQLite").unwrap(),
            "missing-row" => {
                Connection::open(state.join("trust.sqlite"))
                    .unwrap()
                    .execute("DELETE FROM trust_state", [])
                    .unwrap();
            }
            "missing-clock" => {
                Connection::open(state.join("trust.sqlite"))
                    .unwrap()
                    .execute("UPDATE trust_state SET clock=x''", [])
                    .unwrap();
            }
            "missing-marker" => fs::remove_file(state.join("initialized")).unwrap(),
            _ => unreachable!(),
        }
        assert!(!cli(&["status", path(&state)]).status.success(), "{action}");
        assert!(!repo.update(&state).status.success(), "{action}");
        assert!(
            !cli(&[
                "initialize",
                path(&state),
                path(&fixtures().join("root.json"))
            ])
            .status
            .success(),
            "{action}"
        );
    }
}
#[tokio::test]
async fn rotated_root_survives_process_restart_without_rotation_refetch() {
    let temp = temp();
    let mirror = temp.path().join("mirror");
    fs::create_dir(&mirror).unwrap();
    for f in fs::read_dir(fixtures().join("rotated-root")).unwrap() {
        let f = f.unwrap();
        fs::copy(f.path(), mirror.join(f.file_name())).unwrap();
    }
    let state = temp.path().join("trust");
    initialize(&state, &mirror.join("1.root.json"));
    ok(cli(&["update", path(&state), path(&mirror), path(&mirror)]));
    let first = committed(&state);
    let root: serde_json::Value = serde_json::from_slice(&first.1).unwrap();
    assert_eq!(root["signed"]["version"], 2);
    fs::remove_file(mirror.join("2.root.json")).unwrap();
    ok(cli(&["update", path(&state), path(&mirror), path(&mirror)]));
    let second = committed(&state);
    assert_eq!(second.0, 2);
    let second_root: serde_json::Value = serde_json::from_slice(&second.1).unwrap();
    assert_eq!(root, second_root);
}
#[tokio::test]
async fn concurrent_process_cannot_update_while_owner_lock_is_held() {
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let mut holder = Command::new(env!("CARGO_BIN_EXE_lomi-update-trust"))
        .args(["hold-lock", path(&state)])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(holder.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "locked");
    let repo = Repo::new(2, false, PAYLOAD).await;
    let rejected = repo.update(&state);
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("another updater"));
    drop(holder.stdin.take());
    assert!(holder.wait().unwrap().success());
    ok(repo.update(&state));
    assert_eq!(committed(&state).0, 1);
}
#[tokio::test]
async fn real_process_crashes_preserve_previous_or_complete_next_transaction() {
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let first = Repo::new(1, false, PAYLOAD).await;
    let next = Repo::new(2, false, PAYLOAD).await;
    ok(first.update(&state));
    let baseline = committed(&state);
    let crash = next.crash(&state, "before-commit");
    assert_eq!(crash.status.code(), Some(91));
    assert!(crash.stdout.is_empty());
    ok(cli(&["status", path(&state)]));
    assert_eq!(committed(&state), baseline);
    let crash = next.crash(&state, "after-commit");
    assert_eq!(crash.status.code(), Some(92));
    assert!(crash.stdout.is_empty());
    ok(cli(&["status", path(&state)]));
    let latest = committed(&state);
    assert_eq!(latest.0, 2);
    let timestamp: serde_json::Value = serde_json::from_slice(&latest.2).unwrap();
    assert_eq!(timestamp["signed"]["version"], 2);
    let old_clock: Timestamp = serde_json::from_slice(&baseline.5).unwrap();
    let new_clock: Timestamp = serde_json::from_slice(&latest.5).unwrap();
    assert!(new_clock >= old_clock);
    assert!(!first.update(&state).status.success());
    assert_eq!(committed(&state), latest);
}
#[tokio::test]
async fn metadata_target_and_committed_blob_allocations_are_bounded() {
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let good = Repo::new(1, false, PAYLOAD).await;
    ok(good.update(&state));
    let baseline = committed(&state);
    fs::write(
        good.metadata.join("timestamp.json"),
        vec![b' '; MAX_METADATA + 1],
    )
    .unwrap();
    assert!(!good.update(&state).status.success());
    assert_eq!(committed(&state), baseline);
    let large = Repo::new(2, false, &vec![0; MAX_TARGET + 1]).await;
    assert!(!large.update(&state).status.success());
    assert_eq!(committed(&state), baseline);
    Connection::open(state.join("trust.sqlite"))
        .unwrap()
        .execute(
            "UPDATE trust_state SET targets=zeroblob(?1)",
            [MAX_METADATA as i64 + 1],
        )
        .unwrap();
    assert!(!cli(&["status", path(&state)]).status.success());
}
#[test]
fn initialization_and_private_directory_checks_fail_closed() {
    let temp = temp();
    let state = temp.path().join("trust");
    let invalid_root = temp.path().join("invalid-root");
    fs::write(&invalid_root, b"{").unwrap();
    assert!(
        !cli(&["initialize", path(&state), path(&invalid_root)])
            .status
            .success()
    );
    assert!(
        !cli(&[
            "initialize",
            path(&state),
            path(&fixtures().join("root.json"))
        ])
        .status
        .success()
    );
    assert!(!cli(&["status", path(&state)]).status.success());
    let unsafe_parent = temp.path().join("unsafe-parent");
    fs::create_dir(&unsafe_parent).unwrap();
    fs::set_permissions(&unsafe_parent, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(
        !cli(&[
            "initialize",
            path(&unsafe_parent.join("trust")),
            path(&fixtures().join("root.json"))
        ])
        .status
        .success()
    );
    let good = temp.path().join("good");
    initialize(&good, &fixtures().join("root.json"));
    fs::set_permissions(&good, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(!cli(&["status", path(&good)]).status.success());
    fs::set_permissions(&good, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(good.join("trust.sqlite"), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(!cli(&["status", path(&good)]).status.success());
    fs::set_permissions(good.join("trust.sqlite"), fs::Permissions::from_mode(0o600)).unwrap();
    let alias = temp.path().join("alias");
    symlink(&good, &alias).unwrap();
    assert!(!cli(&["status", path(&alias)]).status.success());
    let db_alias = temp.path().join("db-alias");
    fs::hard_link(good.join("trust.sqlite"), &db_alias).unwrap();
    assert!(!cli(&["status", path(&good)]).status.success());
    fs::remove_file(db_alias).unwrap();
    let real_lock = good.join("real-lock");
    fs::rename(good.join("owner.lock"), &real_lock).unwrap();
    symlink(&real_lock, good.join("owner.lock")).unwrap();
    assert!(!cli(&["status", path(&good)]).status.success());
}

#[tokio::test]
async fn library_exposes_only_fully_verified_bytes_after_commit() {
    let temp = temp();
    let state = temp.path().join("trust");
    let bootstrap = fs::read(fixtures().join("root.json")).unwrap();
    let mut store = lomi_update_trust::TrustStore::initialize(&state, &bootstrap).unwrap();
    let repo = Repo::new(1, false, PAYLOAD).await;
    let bytes = store
        .update(&repo.metadata, &repo.targets, Some("synthetic.bin"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(bytes, PAYLOAD);
    assert_eq!(store.generation().unwrap(), 1);
    let baseline = committed(&state);
    let file = fs::read_dir(&repo.targets)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    fs::write(file, vec![0; PAYLOAD.len()]).unwrap();
    assert!(
        store
            .update(&repo.metadata, &repo.targets, Some("synthetic.bin"))
            .await
            .is_err()
    );
    assert_eq!(committed(&state), baseline);
}

#[tokio::test]
async fn fifo_mirror_paths_reject_before_blocking_or_releasing_unverified_bytes() {
    use std::{
        ffi::CString,
        os::unix::ffi::OsStrExt,
        thread,
        time::{Duration, Instant},
    };
    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let good = Repo::new(1, false, PAYLOAD).await;
    ok(good.update(&state));
    let baseline = committed(&state);
    for kind in ["next-root", "timestamp", "target"] {
        let repo = Repo::new(2, false, PAYLOAD).await;
        let file = match kind {
            "next-root" => repo.metadata.join("2.root.json"),
            "timestamp" => repo.metadata.join("timestamp.json"),
            _ => fs::read_dir(&repo.targets)
                .unwrap()
                .next()
                .unwrap()
                .unwrap()
                .path(),
        };
        if file.exists() {
            fs::remove_file(&file).unwrap();
        }
        let name = CString::new(file.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        let mut child = Command::new(env!("CARGO_BIN_EXE_lomi-update-trust"))
            .args([
                "update",
                path(&state),
                path(&repo.metadata),
                path(&repo.targets),
                "synthetic.bin",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(3);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("FIFO {kind} blocked the updater");
            }
            thread::sleep(Duration::from_millis(10));
        }
        let result = child.wait_with_output().unwrap();
        assert!(!result.status.success(), "FIFO {kind} must fail closed");
        assert!(result.stdout.is_empty());
        assert_eq!(committed(&state), baseline);
        ok(cli(&["status", path(&state)]));
    }
}

#[cfg(target_os = "linux")]
fn private_install_dir(path: &Path) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn activation_uses_only_verified_target_bytes_and_swaps_relative_pointer() {
    use lomi_update_trust::TrustStore;
    use std::os::unix::fs::symlink;

    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let install = temp.path().join("install");
    private_install_dir(&install);
    let repo = Repo::new(1, false, PAYLOAD).await;
    let mut store = TrustStore::open(&state).unwrap();
    let object = store
        .update_and_activate(&repo.metadata, &repo.targets, "synthetic.bin", &install)
        .await
        .unwrap();
    assert_eq!(fs::read(&object).unwrap(), PAYLOAD);
    assert_eq!(
        fs::read_link(install.join("active")).unwrap(),
        object.strip_prefix(&install).unwrap()
    );

    // A caller cannot supply bytes through this API. A tampered mirror target
    // fails TUF verification before the currently active pointer can change.
    let previous = fs::read_link(install.join("active")).unwrap();
    let tampered_repo = Repo::new(2, false, PAYLOAD).await;
    let file = fs::read_dir(&tampered_repo.targets)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let mut tampered = PAYLOAD.to_vec();
    tampered[0] ^= 1;
    fs::write(&file, tampered).unwrap();
    assert!(
        store
            .update_and_activate(
                &tampered_repo.metadata,
                &tampered_repo.targets,
                "synthetic.bin",
                &install,
            )
            .await
            .is_err()
    );
    assert_eq!(fs::read_link(install.join("active")).unwrap(), previous);
    // Symlink objects are rejected as install directories.
    let alias = temp.path().join("install-alias");
    symlink(&install, &alias).unwrap();
    assert!(
        store
            .update_and_activate(&repo.metadata, &repo.targets, "synthetic.bin", &alias)
            .await
            .is_err()
    );
    assert_eq!(fs::read_link(install.join("active")).unwrap(), previous);
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn activation_rejects_writable_nonsticky_ancestor_without_changing_pointer() {
    use lomi_update_trust::TrustStore;

    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let ancestor = temp.path().join("activation-parent");
    private_install_dir(&ancestor);
    let install = ancestor.join("install");
    private_install_dir(&install);

    let first = Repo::new(1, false, PAYLOAD).await;
    let mut store = TrustStore::open(&state).unwrap();
    store
        .update_and_activate(&first.metadata, &first.targets, "synthetic.bin", &install)
        .await
        .unwrap();
    let previous = fs::read_link(install.join("active")).unwrap();

    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o777)).unwrap();
    let next = Repo::new(2, false, b"next synthetic verified bytes\n").await;
    assert!(
        store
            .update_and_activate(&next.metadata, &next.targets, "synthetic.bin", &install)
            .await
            .is_err()
    );
    assert_eq!(fs::read_link(install.join("active")).unwrap(), previous);
    assert_eq!(store.generation().unwrap(), 1);
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(all(target_os = "linux", feature = "fault-injection"))]
#[tokio::test]
async fn activation_failure_before_pointer_swap_preserves_prior_active_target() {
    use lomi_update_trust::TrustStore;

    let temp = temp();
    let state = temp.path().join("trust");
    initialize(&state, &fixtures().join("root.json"));
    let install = temp.path().join("install");
    private_install_dir(&install);
    let first = Repo::new(1, false, PAYLOAD).await;
    let mut store = TrustStore::open(&state).unwrap();
    store
        .update_and_activate(&first.metadata, &first.targets, "synthetic.bin", &install)
        .await
        .unwrap();
    let previous = fs::read_link(install.join("active")).unwrap();

    let next_payload = b"next synthetic verified bytes\n";
    let second = Repo::new(2, false, next_payload).await;
    let generation_before = store.generation().unwrap();
    assert!(
        store
            .update_and_activate_fault(
                &second.metadata,
                &second.targets,
                "synthetic.bin",
                &install,
                "before-pointer-swap",
            )
            .await
            .is_err()
    );
    assert_eq!(fs::read_link(install.join("active")).unwrap(), previous);
    assert_eq!(fs::read(install.join(previous)).unwrap(), PAYLOAD);
    assert_eq!(store.generation().unwrap(), generation_before + 1);

    // The durable trust state committed before the injected activation error.
    // Re-running the identical verified metadata and target performs activation.
    let activated = store
        .update_and_activate(&second.metadata, &second.targets, "synthetic.bin", &install)
        .await
        .unwrap();
    assert_eq!(fs::read(&activated).unwrap(), next_payload);
    assert_eq!(
        fs::read_link(install.join("active")).unwrap(),
        activated.strip_prefix(&install).unwrap()
    );
}
