//! Unexecuted migration source follows the existing child-process crash pattern.
use super::*;
use std::os::unix::fs::PermissionsExt;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lomi-public-v4-{}", Uuid::new_v4()));
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn database(&self) -> PathBuf {
        self.0.join("host.sqlite")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn v3() -> Directory {
    let directory = Directory::new();
    drop(HostStore::open(&directory.database(), Limits::default()).unwrap());
    let db = Connection::open(directory.database()).unwrap();
    db.execute_batch("PRAGMA user_version=3;").unwrap();
    directory
}
#[test]
fn fresh_store_uses_v4_without_a_redundant_v3_backup() {
    let root = Directory::new();
    let store = HostStore::open(&root.database(), Limits::default()).unwrap();
    assert_eq!(
        store
            .db
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        4
    );
    assert!(!root.database().with_extension("before-v4.sqlite").exists());
    assert!(store.public_configuration_state().unwrap().is_none());
}
#[test]
fn v3_backup_preserves_authorization_and_v4_exceeds_old_binary_boundary() {
    let root = v3();
    let path = root.database();
    let db = Connection::open(&path).unwrap();
    db.execute("UPDATE authorization_state SET generation='17',locked=1,pending_cloud_revoke=1,clock_floor='29'", []).unwrap();
    let before = database_rows(&db, "SELECT * FROM authorization_state").unwrap();
    drop(db);
    let store = HostStore::open(&path, Limits::default()).unwrap();
    let actual = store
        .db
        .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(actual, 4);
    // Exact acceptance predicate used by the previous v3 HostStore::open.
    assert!(!(0..=3).contains(&actual));
    assert_eq!(
        database_rows(&store.db, "SELECT * FROM authorization_state").unwrap(),
        before
    );
    let backup = Connection::open(path.with_extension("before-v4.sqlite")).unwrap();
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
    assert_eq!(
        database_rows(&backup, "SELECT * FROM authorization_state").unwrap(),
        before
    );
}
#[test]
fn changed_authorization_state_rejects_an_otherwise_identical_v3_backup() {
    let root = v3();
    let path = root.database();
    let backup_path = path.with_extension("before-v4.sqlite");
    let db = Connection::open(&path).unwrap();
    migration_backup(&db, &backup_path, 3).unwrap();
    let saved = std::fs::read(&backup_path).unwrap();
    db.execute("UPDATE authorization_state SET clock_floor='123'", [])
        .unwrap();
    drop(db);
    assert!(matches!(
        HostStore::open(&path, Limits::default()),
        Err(StoreError::Backup)
    ));
    assert_eq!(std::fs::read(&backup_path).unwrap(), saved);
    let db = Connection::open(path).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
}
#[test]
fn crash_before_v4_commit() {
    let Some(path) = std::env::var_os("LOMI_TEST_PUBLIC_V4_DATABASE") else {
        return;
    };
    let _ = HostStore::open(Path::new(&path), Limits::default());
    panic!("v4 crash hook did not terminate child");
}
#[test]
fn crashed_v4_transaction_rolls_back_and_reuses_only_the_exact_backup() {
    let root = v3();
    let path = root.database();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "public_schema_tests::crash_before_v4_commit",
            "--nocapture",
        ])
        .env("LOMI_TEST_PUBLIC_V4_DATABASE", &path)
        .env("LOMI_TEST_CRASH_MIGRATION_V4", "1")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(73));
    let backup_path = path.with_extension("before-v4.sqlite");
    let before = std::fs::read(&backup_path).unwrap();
    let db = Connection::open(&path).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        3
    );
    drop(db);
    let store = HostStore::open(&path, Limits::default()).unwrap();
    assert_eq!(
        store
            .db
            .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
            .unwrap(),
        4
    );
    assert_eq!(std::fs::read(backup_path).unwrap(), before);
}
#[test]
fn v1_and_v2_reach_v3_before_the_v4_backup_and_barrier() {
    for version in [1, 2] {
        let root = Directory::new();
        let path = root.database();
        drop(HostStore::open(&path, Limits::default()).unwrap());
        let db = Connection::open(&path).unwrap();
        db.execute_batch(if version == 1 {
            "DROP TABLE authorization_state; DROP TABLE default_shell; PRAGMA user_version=1;"
        } else {
            "DROP TABLE authorization_state; PRAGMA user_version=2;"
        })
        .unwrap();
        drop(db);
        let store = HostStore::open(&path, Limits::default()).unwrap();
        assert_eq!(
            store
                .db
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            4
        );
        let backup = Connection::open(path.with_extension("before-v4.sqlite")).unwrap();
        assert_eq!(
            backup
                .pragma_query_value::<i64, _>(None, "user_version", |row| row.get(0))
                .unwrap(),
            3
        );
        assert_eq!(
            database_rows(&backup, "SELECT * FROM authorization_state").unwrap(),
            database_rows(&store.db, "SELECT * FROM authorization_state").unwrap()
        );
    }
}
