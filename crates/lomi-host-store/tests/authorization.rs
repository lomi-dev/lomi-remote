use lomi_host_store::*;
use lomi_remote_protocol::{rpc::*, *};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use uuid::Uuid;

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let path = std::env::temp_dir().join(format!("lomi-authorization-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-authorization-{}", Uuid::new_v4()));
        #[cfg(not(windows))]
        let builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        #[cfg(not(windows))]
        builder.create(&path).unwrap();
        #[cfg(windows)]
        lomi_platform::windows::OwnerLock::acquire(&path)
            .unwrap()
            .prepare_database()
            .unwrap();
        Self(path)
    }
    fn db(&self) -> PathBuf {
        #[cfg(windows)]
        return self.0.join("host.sqlite3");
        #[cfg(not(windows))]
        self.0.join("host.sqlite")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn add(store: &mut HostStore, path: &Path, name: &str) -> ProjectRecord {
    let root = path.join(name);
    std::fs::create_dir(&root).unwrap();
    store
        .add_project(&root, name.to_owned().try_into().unwrap())
        .unwrap()
}
fn v2(path: &Path) {
    Connection::open(path)
        .unwrap()
        .execute_batch("DROP TABLE authorization_state; PRAGMA user_version=2;")
        .unwrap();
}
fn backup(db: &Connection, path: &Path, destination: &Path) {
    #[cfg(windows)]
    let guard = lomi_platform::windows::backup::Destination::new(path, destination).unwrap();
    #[cfg(windows)]
    let file = guard.create().unwrap();
    #[cfg(not(windows))]
    let _ = path;
    db.backup(rusqlite::MAIN_DB, destination, None).unwrap();
    #[cfg(windows)]
    guard.sync(&file).unwrap();
}

#[test]
fn logout_fences_shared_and_unshared_at_capacity_and_stale_cloud_work() {
    let dir = Directory::new();
    let limits = Limits {
        events: 3,
        operations: 4,
        workspaces: 2,
    };
    let mut store = HostStore::open(&dir.db(), limits).unwrap();
    assert_eq!(
        store.authorization_state().unwrap(),
        AuthorizationState {
            generation: 0,
            locked: true,
            pending_cloud_revoke: false,
            clock_floor: 0,
        }
    );
    let a = add(&mut store, &dir.0, "A");
    let b = add(&mut store, &dir.0, "B");
    store.enable_authorization(0).unwrap();
    store.share(a.state.context.workspace_id, 0).unwrap();
    let a = store.workspace(a.state.context.workspace_id).unwrap();
    let stale = store.pending_publications().unwrap().pop().unwrap();
    store.observe_authorization_clock(123).unwrap();
    let state = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(state.generation, 1);
    assert!(state.locked && state.pending_cloud_revoke);
    for (old, fence) in [(&a, 2), (&b, 1)] {
        let new = store.workspace(old.state.context.workspace_id).unwrap();
        assert!(!new.consent);
        assert_eq!(new.fence, fence);
        assert_eq!(new.state, old.state);
        assert_eq!(new.local_root, old.local_root);
    }
    let pending = store.pending_publications().unwrap();
    assert_eq!(pending.len(), 2);
    assert!(pending.iter().all(|p| !p.enabled));
    let page = store.events_after(0).unwrap();
    assert!(page.resync_required);
    assert_eq!(page.events.len(), 3);
    assert_eq!(store.enable_authorization(0), Err(StoreError::Fenced));
    assert_eq!(
        store.acknowledge_authorization_revoke(0),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_publication_for_authorization(0, &stale),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.acknowledge_publication_for_authorization(1, &pending[0]),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.enable_authorization(1), Err(StoreError::Fenced));
    drop(store);
    let mut store = HostStore::open(&dir.db(), limits).unwrap();
    assert_eq!(store.authorization_state().unwrap(), state);
    assert_eq!(store.observe_authorization_clock(50).unwrap(), 123);
    let pending = store.pending_publications().unwrap();
    let acked = store.acknowledge_authorization_revoke(1).unwrap();
    assert!(acked.locked && !acked.pending_cloud_revoke);
    assert_eq!(
        store.acknowledge_publication_for_authorization(1, &pending[0]),
        Err(StoreError::Fenced)
    );
    store.enable_authorization(1).unwrap();
    assert!(store.list_projects().unwrap().iter().all(|p| !p.consent));
    assert!(
        !store
            .acknowledge_publication_for_authorization(1, &stale)
            .unwrap()
    );
    assert!(
        store
            .acknowledge_publication_for_authorization(1, &pending[0])
            .unwrap()
    );
    let rejected = store
        .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
        .unwrap();
    assert!(rejected.locked && !rejected.pending_cloud_revoke);
    let logout = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    let rejected = store
        .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
        .unwrap();
    assert!(rejected.pending_cloud_revoke);
    assert_eq!(rejected.generation, logout.generation + 1);
    assert_eq!(rejected.clock_floor, 123);
    drop(store);
    let store = HostStore::open(&dir.db(), limits).unwrap();
    assert_eq!(store.authorization_state().unwrap(), rejected);
}

#[test]
fn second_project_storage_failure_rolls_back_the_entire_logout() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    add(&mut store, &dir.0, "A");
    add(&mut store, &dir.0, "B");
    store.enable_authorization(0).unwrap();
    let before = store.list_projects().unwrap();
    let events = store.events_after(0).unwrap().events.len();
    drop(store);
    let db = Connection::open(dir.db()).unwrap();
    // The second update aborts after the first project and global state changed.
    db.execute_batch(
        "CREATE TABLE injection(n INTEGER); INSERT INTO injection VALUES(0);
CREATE TRIGGER fail_second BEFORE UPDATE OF consent ON projects WHEN NEW.fence <> OLD.fence BEGIN
UPDATE injection SET n=n+1;
SELECT CASE WHEN (SELECT n FROM injection)=2 THEN RAISE(ABORT,'injected') END;
END;",
    )
    .unwrap();
    drop(db);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(
        store.fence_authorization(AuthorizationFenceReason::LocalLogout),
        Err(StoreError::Storage)
    );
    assert_eq!(store.authorization_state().unwrap().generation, 0);
    // SQL rolls back, while the process-local gate remains sealed after failure.
    assert!(store.authorization_state().unwrap().locked);
    assert_eq!(store.events_after(0).unwrap().events.len(), events);
    assert!(store.pending_publications().unwrap().is_empty());
    for old in before {
        let new = store.workspace(old.state.context.workspace_id).unwrap();
        assert_eq!(new.fence, old.fence);
        assert_eq!(new.consent, old.consent);
        assert_eq!(new.state.tabs, old.state.tabs);
    }
}

#[test]
fn generation_and_workspace_overflow_are_atomic() {
    for global in [true, false] {
        let dir = Directory::new();
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        add(&mut store, &dir.0, "A");
        add(&mut store, &dir.0, "B");
        store.enable_authorization(0).unwrap();
        drop(store);
        let db = Connection::open(dir.db()).unwrap();
        let sql = if global {
            "UPDATE authorization_state SET generation=?1"
        } else {
            "UPDATE projects SET fence=?1 WHERE workspace=(SELECT max(workspace) FROM projects)"
        };
        db.execute(sql, [u64::MAX.to_string()]).unwrap();
        drop(db);
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let state = store.authorization_state().unwrap();
        let before = store.list_projects().unwrap();
        assert_eq!(
            store.fence_authorization(AuthorizationFenceReason::LocalLogout),
            Err(StoreError::ResourceExhausted)
        );
        assert_eq!(
            store.authorization_state().unwrap(),
            AuthorizationState {
                locked: true,
                ..state
            }
        );
        assert!(store.pending_publications().unwrap().is_empty());
        for old in before {
            assert_eq!(
                store
                    .workspace(old.state.context.workspace_id)
                    .unwrap()
                    .fence,
                old.fence
            );
        }
    }
}

#[test]
fn malformed_or_missing_authorization_state_fails_closed() {
    for sql in [
        "UPDATE authorization_state SET generation='01'",
        "UPDATE authorization_state SET clock_floor='18446744073709551616'",
        "UPDATE authorization_state SET clock_floor='-1'",
        "DELETE FROM authorization_state",
        "PRAGMA ignore_check_constraints=ON; UPDATE authorization_state SET locked=2",
        "UPDATE authorization_state SET locked=0,pending_cloud_revoke=1",
    ] {
        let dir = Directory::new();
        drop(HostStore::open(&dir.db(), Limits::default()).unwrap());
        Connection::open(dir.db())
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        assert!(matches!(
            HostStore::open(&dir.db(), Limits::default()),
            Err(StoreError::Storage)
        ));
    }
}

#[test]
fn v2_upgrade_preserves_domain_receipts_shell_and_exact_backup() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let identity = store.identity().clone();
    let p = add(&mut store, &dir.0, "A");
    let id = p.state.context.workspace_id;
    let shell = DefaultShellProfile {
        executable: dir.0.join("shell"),
        args: vec!["--login".into()],
    };
    store.initialize_default_shell(shell.clone()).unwrap();
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([1; 16]).unwrap(),
            ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
            id,
            Method::FilesCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: parameter_hash(&"migration").unwrap(),
    };
    store.admit_external(&binding, DecimalU64(0)).unwrap();
    let receipt = store
        .cancel_operation(
            binding.rights.actor(),
            id,
            binding.rights.operation_id(),
            &CapabilitySet::control_with_workspace_tools(),
        )
        .unwrap()
        .unwrap();
    store.share(id, 0).unwrap();
    let stale = store.pending_publications().unwrap().pop().unwrap();
    drop(store);
    v2(&dir.db());
    let db = Connection::open(dir.db()).unwrap();
    let destination = dir.db().with_extension("before-v3.sqlite");
    backup(&db, &dir.db(), &destination);
    let bytes = std::fs::read(&destination).unwrap();
    drop(db);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(store.identity(), &identity);
    assert_eq!(store.default_shell().unwrap(), Some(shell));
    let after = store.workspace(id).unwrap();
    assert!(!after.consent);
    assert_eq!(after.fence, 2);
    assert_eq!(
        store.authorization_state().unwrap(),
        AuthorizationState {
            generation: 1,
            locked: true,
            pending_cloud_revoke: false,
            clock_floor: 0,
        }
    );
    assert!(!store.acknowledge_publication(&stale).unwrap());
    assert!(
        store
            .pending_publications()
            .unwrap()
            .iter()
            .all(|publication| !publication.enabled)
    );
    assert!(store.acknowledge_authorization_revoke(1).unwrap().locked);
    store.enable_authorization(1).unwrap();
    assert!(!store.workspace(id).unwrap().consent);
    assert_eq!(after.local_root, p.local_root);
    assert_eq!(after.state.tabs, p.state.tabs);
    assert_eq!(after.state.name, p.state.name);
    assert_eq!(
        store
            .lookup(&binding, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap(),
        receipt
    );
    assert_eq!(std::fs::read(&destination).unwrap(), bytes);
    drop(store);
    let db = Connection::open(dir.db()).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        if cfg!(any(unix, windows)) { 4 } else { 3 }
    );
}

#[test]
fn v2_backup_rejects_stale_shell_domain_identity_and_receipts() {
    for sql in [
        "INSERT INTO default_shell VALUES(1,'{\"executable\":\"/bin/sh\",\"args\":[]}')",
        "UPDATE metadata SET value='changed' WHERE key='identity'",
        "UPDATE projects SET fence='9'",
        "UPDATE operations SET revision='9'",
    ] {
        let dir = Directory::new();
        let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
        let p = add(&mut store, &dir.0, "A");
        let binding = OperationBinding {
            rights: StoredOperationRights::new(
                OperationId::from_bytes([1; 16]).unwrap(),
                ConsumerAuthorizationId::from_bytes([2; 16]).unwrap(),
                p.state.context.workspace_id,
                Method::FilesCreate,
                CapabilitySet::control_with_workspace_tools(),
                false,
            )
            .unwrap(),
            parameter_hash: parameter_hash(&"backup").unwrap(),
        };
        store.admit_external(&binding, DecimalU64(0)).unwrap();
        drop(store);
        v2(&dir.db());
        let db = Connection::open(dir.db()).unwrap();
        let destination = dir.db().with_extension("before-v3.sqlite");
        backup(&db, &dir.db(), &destination);
        let bytes = std::fs::read(&destination).unwrap();
        assert!(db.execute(sql, []).unwrap() > 0);
        drop(db);
        assert!(matches!(
            HostStore::open(&dir.db(), Limits::default()),
            Err(StoreError::Backup)
        ));
        assert_eq!(std::fs::read(destination).unwrap(), bytes);
    }
}

#[test]
fn logout_preserves_running_terminal_projection_receipt_and_configuration() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = add(&mut store, &dir.0, "A");
    let id = p.state.context.workspace_id;
    let binding = OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([11; 16]).unwrap(),
            ConsumerAuthorizationId::from_bytes([12; 16]).unwrap(),
            id,
            Method::TerminalCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: parameter_hash(&"running terminal").unwrap(),
    };
    store.admit_external(&binding, DecimalU64(0)).unwrap();
    let permit = store.start_external(&binding).unwrap();
    let mut state = p.state;
    state.domain_revision = DecimalU64(1);
    let pane_id = PaneId::from_bytes([13; 16]).unwrap();
    let session_id = TerminalSessionId::from_bytes([14; 16]).unwrap();
    let session_epoch = SessionEpoch::from_bytes([15; 16]).unwrap();
    state.tabs = BoundedList(vec![TerminalTab {
        tab_id: TabId::from_bytes([16; 16]).unwrap(),
        name: "Running".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                state: PaneState::Running,
                session: Some(TerminalContext {
                    workspace: state.context.clone(),
                    pane_id,
                    session_id,
                    session_epoch,
                    profile: TerminalProfile::ExperimentalRustGridV1,
                }),
            },
        },
    }]);
    let receipt = store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: DecimalU64(1),
                pane_id,
                session_id,
                session_epoch,
            }),
            Some(state.clone()),
        )
        .unwrap();
    let shell = DefaultShellProfile {
        executable: dir.0.join("shell"),
        args: vec![],
    };
    store.initialize_default_shell(shell.clone()).unwrap();
    store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(store.workspace(id).unwrap().state, state);
    assert_eq!(
        store.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Running
    );
    assert_eq!(
        store
            .lookup(&binding, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap(),
        receipt
    );
    assert_eq!(store.default_shell().unwrap(), Some(shell.clone()));
    store.record_clean_shutdown().unwrap();
    store.share(id, 1).unwrap();
    let before = store.workspace(id).unwrap();
    let stale = store.pending_publications().unwrap().pop().unwrap();
    drop(store);
    v2(&dir.db());
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let after = store.workspace(id).unwrap();
    assert_eq!(after.state.tabs, before.state.tabs);
    assert_eq!(after.local_root, before.local_root);
    assert_eq!(after.fence, before.fence + 1);
    assert!(!after.consent);
    assert_eq!(
        store.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Stopped
    );
    assert_eq!(
        store
            .lookup(&binding, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap(),
        receipt
    );
    assert_eq!(store.default_shell().unwrap(), Some(shell));
    assert!(!store.acknowledge_publication(&stale).unwrap());
}

#[test]
fn migration_fencing_failure_rolls_back_schema_and_every_workspace() {
    for overflow in [false, true] {
        let dir = Directory::new();
        let limits = Limits {
            events: 3,
            operations: 4,
            workspaces: 2,
        };
        let mut store = HostStore::open(&dir.db(), limits).unwrap();
        let first = add(&mut store, &dir.0, "A");
        add(&mut store, &dir.0, "B");
        store.share(first.state.context.workspace_id, 0).unwrap();
        drop(store);
        v2(&dir.db());
        let db = Connection::open(dir.db()).unwrap();
        if overflow {
            db.execute("UPDATE projects SET fence=?1 WHERE workspace=(SELECT max(workspace) FROM projects)", [u64::MAX.to_string()]).unwrap();
        } else {
            db.execute_batch(
                "CREATE TABLE injection(n INTEGER); INSERT INTO injection VALUES(0);
CREATE TRIGGER fail_second BEFORE UPDATE OF consent ON projects BEGIN
UPDATE injection SET n=n+1;
SELECT CASE WHEN (SELECT n FROM injection)=2 THEN RAISE(ABORT,'injected') END;
END;",
            )
            .unwrap();
        }
        let before: Vec<(String, bool, String)> = db
            .prepare("SELECT workspace,consent,fence FROM projects ORDER BY workspace")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let publications: Vec<String> = db
            .prepare("SELECT publication FROM outbox ORDER BY workspace")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        drop(db);
        let error = if overflow {
            StoreError::ResourceExhausted
        } else {
            StoreError::Storage
        };
        assert!(matches!(HostStore::open(&dir.db(), limits), Err(actual) if actual == error));
        let db = Connection::open(dir.db()).unwrap();
        assert_eq!(
            db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
                .unwrap(),
            2
        );
        assert_eq!(
            db.query_row::<i64, _, _>(
                "SELECT count(*) FROM sqlite_master WHERE name='authorization_state'",
                [],
                |r| r.get(0)
            )
            .unwrap(),
            0
        );
        let after: Vec<(String, bool, String)> = db
            .prepare("SELECT workspace,consent,fence FROM projects ORDER BY workspace")
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        let after_publications: Vec<String> = db
            .prepare("SELECT publication FROM outbox ORDER BY workspace")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        assert_eq!(after, before);
        assert_eq!(after_publications, publications);
    }
}
