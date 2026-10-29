use lomi_host_store::*;
use lomi_remote_protocol::{rpc::*, *};
use std::{path::PathBuf, process::Command};
use uuid::Uuid;
struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let p = std::env::temp_dir().join(format!("lomi-host-store-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let p = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-host-store-{}", Uuid::new_v4()));
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
        builder.create(&p).unwrap();
        #[cfg(windows)]
        lomi_platform::windows::OwnerLock::acquire(&p)
            .unwrap()
            .prepare_database()
            .unwrap();
        Self(p)
    }
    fn write_backup(&self, path: &std::path::Path, bytes: &[u8]) {
        #[cfg(windows)]
        let destination =
            lomi_platform::windows::backup::Destination::new(&self.db(), path).unwrap();
        #[cfg(windows)]
        let file = destination.create().unwrap();
        std::fs::write(path, bytes).unwrap();
        #[cfg(windows)]
        destination.sync(&file).unwrap();
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
fn actor() -> ConsumerAuthorizationId {
    ConsumerAuthorizationId::from_bytes([7; 16]).unwrap()
}
fn binding(workspace: WorkspaceId, method: Method, n: u8) -> OperationBinding {
    OperationBinding {
        rights: StoredOperationRights::new(
            OperationId::from_bytes([n; 16]).unwrap(),
            actor(),
            workspace,
            method,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: parameter_hash(&(method, n)).unwrap(),
    }
}
fn setup(store: &mut HostStore, root: &std::path::Path) -> ProjectRecord {
    let p = store
        .add_project(root, DisplayText::try_from("Project".to_string()).unwrap())
        .unwrap();
    let b = binding(p.state.context.workspace_id, Method::TerminalCreate, 1);
    assert!(
        store
            .admit_external(&b, DecimalU64(0))
            .unwrap()
            .newly_admitted
    );
    let permit = store.start_external(&b).unwrap();
    let mut state = p.state.clone();
    state.domain_revision = DecimalU64(1);
    let pane_id = PaneId::from_bytes([2; 16]).unwrap();
    let session_id = TerminalSessionId::from_bytes([3; 16]).unwrap();
    let session_epoch = SessionEpoch::from_bytes([4; 16]).unwrap();
    state.tabs = BoundedList(vec![TerminalTab {
        tab_id: TabId::from_bytes([5; 16]).unwrap(),
        name: DisplayText::try_from("Terminal".to_string()).unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                session: Some(TerminalContext {
                    workspace: state.context.clone(),
                    pane_id,
                    session_id,
                    session_epoch,
                    profile: TerminalProfile::ExperimentalRustGridV1,
                }),
                state: PaneState::Running,
            },
        },
    }]);
    store
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
            Some(state),
        )
        .unwrap();
    store.workspace(p.state.context.workspace_id).unwrap()
}
#[test]
fn durable_identity_domain_cas_and_deduplication() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut s, &dir.0);
    let id = p.state.context.workspace_id;
    let identity = s.identity().clone();
    let runtime = s.runtime_id();
    let b = binding(id, Method::TerminalRename, 8);
    let tab = p.state.tabs.0[0].tab_id;
    let result = s
        .rename_tab(
            &b,
            DecimalU64(1),
            tab,
            DisplayText::try_from("Renamed".to_string()).unwrap(),
        )
        .unwrap();
    assert_eq!(result.receipt.state(), OperationState::Succeeded);
    assert!(
        !s.rename_tab(
            &b,
            DecimalU64(1),
            tab,
            DisplayText::try_from("Renamed".to_string()).unwrap()
        )
        .unwrap()
        .newly_admitted
    );
    let other = binding(id, Method::TerminalRename, 9);
    assert!(matches!(
        s.rename_tab(
            &other,
            DecimalU64(1),
            tab,
            DisplayText::try_from("Stale".to_string()).unwrap()
        ),
        Err(StoreError::RevisionConflict)
    ));
    let mut conflict = b.clone();
    conflict.parameter_hash = parameter_hash(&"changed").unwrap();
    assert!(matches!(
        s.rename_tab(
            &conflict,
            DecimalU64(2),
            tab,
            DisplayText::try_from("Changed".to_string()).unwrap()
        ),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(
        s.lookup(&conflict, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        s.workspace(id).unwrap().state.domain_revision,
        DecimalU64(2)
    );
    drop(s);
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(&identity, s.identity());
    assert_ne!(runtime, s.runtime_id());
    let p = s.workspace(id).unwrap();
    assert_eq!(
        p.state.tabs.0[0].name,
        DisplayText::try_from("Renamed".to_string()).unwrap()
    );
    assert_eq!(p.state.domain_revision, DecimalU64(3));
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Lost
    );
    assert_eq!(
        s.lookup(&b, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap()
            .state(),
        OperationState::Succeeded
    );
}
#[test]
fn unshare_supersedes_delayed_publication_at_full_capacity() {
    let dir = Directory::new();
    let limits = Limits {
        events: 3,
        operations: 4,
        workspaces: 1,
    };
    let mut s = HostStore::open(&dir.db(), limits).unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let id = p.state.context.workspace_id;
    assert_eq!(s.share(id, 0).unwrap(), 1);
    let shared_epoch = s.workspace(id).unwrap().state.context.workspace_epoch;
    assert_ne!(shared_epoch, p.state.context.workspace_epoch);
    let stale = s.pending_publications().unwrap().pop().unwrap();
    assert_eq!(s.unshare(id).unwrap(), 2);
    let revoked_epoch = s.workspace(id).unwrap().state.context.workspace_epoch;
    assert_ne!(revoked_epoch, shared_epoch);
    assert_eq!(s.unshare(id).unwrap(), 3);
    let final_epoch = s.workspace(id).unwrap().state.context.workspace_epoch;
    assert_ne!(final_epoch, revoked_epoch);
    assert!(!s.acknowledge_publication(&stale).unwrap());
    let pending = s.pending_publications().unwrap();
    assert_eq!(pending.len(), 1);
    assert!(!pending[0].enabled);
    assert_eq!(pending[0].fence, 3);
    let page = s.events_after(0).unwrap();
    assert!(page.resync_required);
    assert_eq!(page.events.len(), 3);
    drop(s);
    let s = HostStore::open(&dir.db(), limits).unwrap();
    let p = s.workspace(id).unwrap();
    assert!(!p.consent);
    assert_eq!(p.state.context.workspace_epoch, final_epoch);
    assert_eq!(p.fence, 3);
    assert!(!s.pending_publications().unwrap()[0].enabled);
}
#[test]
fn single_sqlite_owner_backup_and_future_schema() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    s.add_project(
        &dir.0,
        DisplayText::try_from("Project".to_string()).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        HostStore::open(&dir.db(), Limits::default()),
        Err(StoreError::Busy)
    ));
    let backup = dir.0.join("backup.sqlite");
    s.checked_backup(&backup).unwrap();
    assert!(matches!(s.checked_backup(&backup), Err(StoreError::Backup)));
    let check = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        check
            .query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap(),
        "ok"
    );
    check.pragma_update(None, "user_version", 99).unwrap();
    drop(check);
    drop(s);
    assert!(matches!(
        HostStore::open(&backup, Limits::default()),
        Err(StoreError::SchemaVersion)
    ));
    let check = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        check
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        99
    );
}
#[test]
fn atomic_admit_start_yields_one_permit_and_matches_two_step_accounting() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut s, &dir.0);
    let id = p.state.context.workspace_id;
    let revision = p.state.domain_revision;
    let events_before = s.events_after(0).unwrap().events.len();

    let b = binding(id, Method::TerminalCreate, 41);
    let (admission, permit) = s.admit_start_external(&b, revision).unwrap();
    assert!(admission.newly_admitted);
    assert_eq!(admission.receipt.state(), OperationState::Running);
    assert_eq!(admission.receipt.effect(), Effect::None);
    let permit = permit.expect("a new operation owns the only permit");
    s.check_external_fence(&permit).unwrap();
    assert_eq!(
        s.events_after(0).unwrap().events.len(),
        events_before + 2,
        "admission + start events; completion stays reserved"
    );

    // A duplicate never mints a second permit and never repeats the start.
    let (again, second) = s.admit_start_external(&b, revision).unwrap();
    assert!(!again.newly_admitted);
    assert!(second.is_none());
    assert_eq!(again.receipt, admission.receipt);
    assert!(matches!(
        s.start_external(&b),
        Err(StoreError::AlreadyStarted)
    ));

    // A different parameter hash under the same operation id is a conflict.
    let mut changed = b.clone();
    changed.parameter_hash = parameter_hash(&"different").unwrap();
    assert!(matches!(
        s.admit_start_external(&changed, revision),
        Err(StoreError::IdempotencyConflict)
    ));

    // The completion consumes the reserved event, exactly like the two-step path.
    let receipt = s
        .complete_external(&permit, OperationState::Failed, Effect::None, None, None)
        .unwrap();
    assert_eq!(receipt.state(), OperationState::Failed);
    assert_eq!(s.events_after(0).unwrap().events.len(), events_before + 3);
    assert!(matches!(
        s.complete_external(&permit, OperationState::Failed, Effect::None, None, None),
        Err(StoreError::AlreadyStarted)
    ));
}
#[test]
fn atomic_admit_start_rejects_stale_revision_and_non_durable_methods_without_residue() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut s, &dir.0);
    let id = p.state.context.workspace_id;
    let events_before = s.events_after(0).unwrap().events.len();

    let stale = binding(id, Method::TerminalCreate, 42);
    assert!(matches!(
        s.admit_start_external(&stale, DecimalU64(p.state.domain_revision.0 + 1)),
        Err(StoreError::RevisionConflict)
    ));
    let not_durable = binding(id, Method::WorkspaceGet, 43);
    assert!(matches!(
        s.admit_start_external(&not_durable, p.state.domain_revision),
        Err(StoreError::Invalid)
    ));
    assert_eq!(s.events_after(0).unwrap().events.len(), events_before);
    // No residue: the same id is still free for a correct attempt.
    assert!(
        s.admit_start_external(&stale, p.state.domain_revision)
            .unwrap()
            .1
            .is_some()
    );
}
#[test]
fn capacity_is_rejected_before_external_start_and_reserved_finalization_survives_unshare() {
    let dir = Directory::new();
    let limits = Limits {
        events: 4,
        operations: 4,
        workspaces: 1,
    };
    let mut s = HostStore::open(&dir.db(), limits).unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let id = p.state.context.workspace_id;
    let b = binding(id, Method::FilesCreate, 11);
    s.admit_external(&b, DecimalU64(0)).unwrap();
    assert!(matches!(
        s.admit_external(&binding(id, Method::FilesCreate, 12), DecimalU64(0)),
        Err(StoreError::ResourceExhausted)
    ));
    let permit = s.start_external(&b).unwrap();
    assert!(matches!(
        s.start_external(&b),
        Err(StoreError::AlreadyStarted)
    ));
    s.unshare(id).unwrap();
    assert!(matches!(
        s.check_external_fence(&permit),
        Err(StoreError::Fenced)
    ));
    let receipt = s
        .complete_external(
            &permit,
            OperationState::OutcomeUnknown,
            Effect::Unknown,
            None,
            None,
        )
        .unwrap();
    assert_eq!(receipt.state(), OperationState::OutcomeUnknown);
    assert!(s.events_after(0).unwrap().events.len() <= limits.events);
}
#[test]
fn failed_finalization_rolls_back_state_and_descriptors() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut s, &dir.0);
    let id = p.state.context.workspace_id;
    let b = binding(id, Method::FilesCreate, 12);
    s.admit_external(&b, p.state.domain_revision).unwrap();
    let permit = s.start_external(&b).unwrap();
    let mut next = p.state.clone();
    next.domain_revision = DecimalU64(2);
    next.name = DisplayText::try_from("Must roll back".to_string()).unwrap();
    // Wrong result kind is checked after state/descriptor SQL writes. Dropping
    // the failed transaction must undo all of them, while keeping running intent.
    assert!(matches!(
        s.complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Domain {
                domain_revision: DecimalU64(2)
            }),
            Some(next)
        ),
        Err(StoreError::Invalid)
    ));
    assert_eq!(s.workspace(id).unwrap().state, p.state);
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Running
    );
    assert_eq!(
        s.lookup(&b, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap()
            .state(),
        OperationState::Running
    );
}
#[test]
fn crash_child() {
    let Some(path) = std::env::var_os("LOMI_STORE_CRASH_DB") else {
        return;
    };
    let path = PathBuf::from(path);
    let mut s = HostStore::open(&path, Limits::default()).unwrap();
    let p = setup(&mut s, path.parent().unwrap());
    let id = p.state.context.workspace_id;
    let running = binding(id, Method::FilesCreate, 21);
    s.admit_external(&running, p.state.domain_revision).unwrap();
    let _permit = s.start_external(&running).unwrap();
    assert!(
        s.cancel_operation(
            actor(),
            id,
            running.rights.operation_id(),
            &CapabilitySet::control_with_workspace_tools()
        )
        .unwrap()
        .unwrap()
        .cancel_requested()
    );
    let accepted = binding(id, Method::FilesCreate, 22);
    s.admit_external(&accepted, p.state.domain_revision)
        .unwrap();
    // No Drop/destructor/checkpoint: model owner death after durable admission.
    std::process::exit(23);
}
#[test]
fn subprocess_owner_death_never_replays_operations_or_adopts_sessions() {
    let dir = Directory::new();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child", "--nocapture"])
        .env("LOMI_STORE_CRASH_DB", dir.db())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(23));
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = s.list_projects().unwrap().pop().unwrap();
    let id = p.state.context.workspace_id;
    let running = binding(id, Method::FilesCreate, 21);
    let accepted = binding(id, Method::FilesCreate, 22);
    assert!(
        s.lookup_operation(
            actor(),
            id,
            running.rights.operation_id(),
            &CapabilitySet::control_with_workspace_tools()
        )
        .unwrap()
        .unwrap()
        .cancel_requested()
    );
    assert_eq!(
        s.lookup(&running, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap()
            .state(),
        OperationState::OutcomeUnknown
    );
    assert_eq!(
        s.lookup(&accepted, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .unwrap()
            .state(),
        OperationState::Cancelled
    );
    assert!(matches!(
        s.start_external(&running),
        Err(StoreError::AlreadyStarted)
    ));
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Lost
    );
    let revision = p.state.domain_revision;
    drop(s);
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(s.workspace(id).unwrap().state.domain_revision, revision);
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Lost
    );
}
#[test]
fn initialization_migration_requires_checked_backup_and_preserves_on_failure() {
    let dir = Directory::new();
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    db.execute_batch("PRAGMA user_version=0;").unwrap();
    drop(db);
    let backup = dir.db().with_extension("before-v1.sqlite");
    dir.write_backup(&backup, b"keep existing backup");
    assert!(matches!(
        HostStore::open(&dir.db(), Limits::default()),
        Err(StoreError::Backup)
    ));
    assert_eq!(std::fs::read(&backup).unwrap(), b"keep existing backup");
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row::<i64, _, _>(
            "SELECT count(*) FROM sqlite_master WHERE type='table'",
            [],
            |r| r.get(0)
        )
        .unwrap(),
        0
    );
    drop(db);
    std::fs::remove_file(&backup).unwrap();
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let backup_db = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        backup_db
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        0
    );
    assert_eq!(
        backup_db
            .query_row::<String, _, _>("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap(),
        "ok"
    );
    drop(s);
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    // Mirrors the production schema version: unix/windows hosts include the
    // public-configuration migration (v4); other targets stop at v3.
    #[cfg(any(unix, windows))]
    let current_schema = 4;
    #[cfg(not(any(unix, windows)))]
    let current_schema = 3;
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        current_schema
    );
}
#[test]
fn absent_foreign_actor_and_wrong_method_hash_lookups_are_opaque() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let b = binding(p.state.context.workspace_id, Method::FilesCreate, 40);
    s.admit_external(&b, DecimalU64(0)).unwrap();
    let foreign = OperationBinding {
        rights: StoredOperationRights::new(
            b.rights.operation_id(),
            ConsumerAuthorizationId::from_bytes([99; 16]).unwrap(),
            b.rights.workspace(),
            Method::FilesCreate,
            CapabilitySet::control_with_workspace_tools(),
            false,
        )
        .unwrap(),
        parameter_hash: b.parameter_hash.clone(),
    };
    assert!(
        s.lookup(&foreign, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .is_none()
    );
    assert!(
        s.lookup(
            &binding(b.rights.workspace(), Method::FilesCreate, 41),
            &CapabilitySet::control_with_workspace_tools()
        )
        .unwrap()
        .is_none()
    );
    let weak = CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap();
    assert!(s.lookup(&b, &weak).unwrap().is_none());
}
#[test]
fn remove_only_empty_registration_preserves_disk_fence_and_revoke() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = s
        .add_project(&dir.0, DisplayText::try_from("Empty".to_string()).unwrap())
        .unwrap();
    let id = p.state.context.workspace_id;
    s.share(id, 0).unwrap();
    let stale = s.pending_publications().unwrap().pop().unwrap();
    assert_eq!(s.remove_project(id).unwrap(), 2);
    assert!(dir.0.is_dir());
    assert!(s.list_projects().unwrap().is_empty());
    assert!(matches!(s.workspace(id), Err(StoreError::NotFound)));
    assert!(!s.acknowledge_publication(&stale).unwrap());
    let revoke = s.pending_publications().unwrap().pop().unwrap();
    assert!(!revoke.enabled);
    assert_eq!(revoke.fence, 2);
    assert!(s.acknowledge_publication(&revoke).unwrap());
    drop(s);
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert!(s.list_projects().unwrap().is_empty());
    drop(s);
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let replacement = s
        .add_project(
            &dir.0,
            DisplayText::try_from("New registration".to_string()).unwrap(),
        )
        .unwrap();
    assert_ne!(replacement.state.context.workspace_id, id);
    assert_ne!(
        replacement.state.context.workspace_epoch,
        p.state.context.workspace_epoch
    );
    let active_dir = Directory::new();
    let mut s = HostStore::open(&active_dir.db(), Limits::default()).unwrap();
    let active = setup(&mut s, &active_dir.0);
    assert!(matches!(
        s.remove_project(active.state.context.workspace_id),
        Err(StoreError::Busy)
    ));
    assert!(s.workspace(active.state.context.workspace_id).is_ok());
}
#[test]
fn owner_probe_child() {
    let Some(path) = std::env::var_os("LOMI_STORE_PROBE_DB") else {
        return;
    };
    let blocked = matches!(
        HostStore::open(&PathBuf::from(path), Limits::default()),
        Err(StoreError::Busy)
    );
    std::process::exit(if blocked { 24 } else { 25 });
}
#[test]
fn exclusive_owner_is_enforced_between_processes() {
    let dir = Directory::new();
    let _store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let status = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "owner_probe_child", "--nocapture"])
        .env("LOMI_STORE_PROBE_DB", dir.db())
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(24));
}
#[test]
fn admitted_execution_rights_cannot_be_downgraded_by_retry_or_start() {
    let dir = Directory::new();
    let mut s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let weak = binding(p.state.context.workspace_id, Method::GitCommit, 61);
    let strong = OperationBinding {
        rights: StoredOperationRights::new(
            weak.rights.operation_id(),
            actor(),
            weak.rights.workspace(),
            Method::GitCommit,
            CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap(),
            true,
        )
        .unwrap(),
        parameter_hash: weak.parameter_hash.clone(),
    };
    s.admit_external(&strong, DecimalU64(0)).unwrap();
    assert!(
        s.lookup_operation(
            actor(),
            weak.rights.workspace(),
            weak.rights.operation_id(),
            &CapabilitySet::control_with_workspace_tools()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        s.cancel_operation(
            actor(),
            weak.rights.workspace(),
            weak.rights.operation_id(),
            &CapabilitySet::control_with_workspace_tools()
        )
        .unwrap()
        .is_none()
    );
    assert!(matches!(
        s.admit_external(&weak, DecimalU64(0)),
        Err(StoreError::IdempotencyConflict)
    ));
    assert!(
        s.lookup(&weak, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        s.start_external(&weak),
        Err(StoreError::IdempotencyConflict)
    ));
    let original = s
        .lookup(
            &strong,
            &CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap(),
        )
        .unwrap()
        .unwrap();
    assert_eq!(original.state(), OperationState::Accepted);
    assert!(original.stored_rights().repository_execution());
    assert!(
        original
            .stored_rights()
            .actual_rights()
            .contains(Capability::GitExecute)
    );
    let permit = s.start_external(&strong).unwrap();
    assert!(
        s.lookup(&strong, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .is_none()
    );
    let final_receipt = s
        .complete_external(
            &permit,
            OperationState::OutcomeUnknown,
            Effect::Unknown,
            None,
            None,
        )
        .unwrap();
    assert!(final_receipt.stored_rights().repository_execution());
    assert!(
        final_receipt
            .stored_rights()
            .actual_rights()
            .contains(Capability::GitExecute)
    );
    drop(s);
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert!(
        s.lookup(
            &weak,
            &CapabilitySet::try_from(Capability::ALL.to_vec()).unwrap()
        )
        .unwrap()
        .is_none()
    );
    assert!(
        s.lookup(&strong, &CapabilitySet::control_with_workspace_tools())
            .unwrap()
            .is_none()
    );
}
#[test]
fn backup_is_private_and_rejects_other_destination_directories() {
    let dir = Directory::new();
    let other = Directory::new();
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let destination = other.0.join("export.sqlite");
    assert!(matches!(
        s.checked_backup(&destination),
        Err(StoreError::Backup)
    ));
    assert!(!destination.exists());
    let backup = dir.0.join("private.sqlite");
    s.checked_backup(&backup).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
#[cfg(unix)]
#[test]
fn backup_rejects_non_private_database_parent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Directory::new();
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let backup = dir.0.join("unsafe.sqlite");
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    let result = s.checked_backup(&backup);
    std::fs::set_permissions(&dir.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(matches!(result, Err(StoreError::Backup)));
    assert!(!backup.exists());
}
#[cfg(target_os = "macos")]
#[test]
fn backup_rejects_darwin_extended_allow_acl_on_private_parent() {
    use std::os::unix::fs::PermissionsExt;
    let dir = Directory::new();
    let s = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let backup = dir.0.join("acl-unsafe.sqlite");
    assert!(
        Command::new("/bin/chmod")
            .args(["+a", "everyone allow read,search"])
            .arg(&dir.0)
            .status()
            .unwrap()
            .success()
    );
    assert_eq!(
        std::fs::metadata(&dir.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let result = s.checked_backup(&backup);
    assert!(
        Command::new("/bin/chmod")
            .args(["-a#", "0"])
            .arg(&dir.0)
            .status()
            .unwrap()
            .success()
    );
    assert!(matches!(result, Err(StoreError::Backup)));
    assert!(!backup.exists());
}
#[test]
fn operation_id_lookup_uses_stored_rights_and_cancel_does_not_claim_completion() {
    let dir = Directory::new();
    let mut s = HostStore::open(
        &dir.db(),
        Limits {
            events: 4,
            operations: 8,
            workspaces: 1,
        },
    )
    .unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let id = p.state.context.workspace_id;
    let b = binding(id, Method::FilesCreate, 71);
    let current = CapabilitySet::control_with_workspace_tools();
    s.admit_external(&b, DecimalU64(0)).unwrap();
    let weak = CapabilitySet::try_from(vec![Capability::WorkspaceRead]).unwrap();
    assert!(
        s.lookup_operation(actor(), id, b.rights.operation_id(), &weak)
            .unwrap()
            .is_none()
    );
    assert!(
        s.cancel_operation(actor(), id, b.rights.operation_id(), &weak)
            .unwrap()
            .is_none()
    );
    let permit = s.start_external(&b).unwrap();
    let cancelled = s
        .cancel_operation(actor(), id, b.rights.operation_id(), &current)
        .unwrap()
        .unwrap();
    assert_eq!(cancelled.state(), OperationState::Running);
    assert!(cancelled.cancel_requested());
    assert_eq!(cancelled.effect(), Effect::None);
    s.check_external_fence(&permit).unwrap();
    let event_count = s.events_after(0).unwrap().events.len();
    assert!(
        s.cancel_operation(actor(), id, b.rights.operation_id(), &current)
            .unwrap()
            .unwrap()
            .cancel_requested()
    );
    assert_eq!(s.events_after(0).unwrap().events.len(), event_count);
    let finished = s
        .complete_external(
            &permit,
            OperationState::OutcomeUnknown,
            Effect::Unknown,
            None,
            None,
        )
        .unwrap();
    assert!(finished.cancel_requested());
    let unchanged = s
        .cancel_operation(actor(), id, b.rights.operation_id(), &current)
        .unwrap()
        .unwrap();
    assert_eq!(unchanged.state(), OperationState::OutcomeUnknown);
    assert!(unchanged.cancel_requested());
    assert!(s.events_after(0).unwrap().resync_required);
}
#[test]
fn accepted_cancel_releases_capacity_and_stale_fence_cannot_mutate_running_receipt() {
    let dir = Directory::new();
    let mut s = HostStore::open(
        &dir.db(),
        Limits {
            events: 4,
            operations: 8,
            workspaces: 1,
        },
    )
    .unwrap();
    let p = s
        .add_project(
            &dir.0,
            DisplayText::try_from("Project".to_string()).unwrap(),
        )
        .unwrap();
    let id = p.state.context.workspace_id;
    let current = CapabilitySet::control_with_workspace_tools();
    let b = binding(id, Method::FilesCreate, 72);
    s.admit_external(&b, DecimalU64(0)).unwrap();
    assert_eq!(
        s.cancel_operation(actor(), id, b.rights.operation_id(), &current)
            .unwrap()
            .unwrap()
            .state(),
        OperationState::Cancelled
    );
    assert!(matches!(
        s.start_external(&b),
        Err(StoreError::AlreadyStarted)
    ));
    let page = s.events_after(0).unwrap();
    s.prune_events_through(page.events.last().unwrap().sequence)
        .unwrap();
    let b = binding(id, Method::FilesCreate, 73);
    s.admit_external(&b, DecimalU64(0)).unwrap();
    let _permit = s.start_external(&b).unwrap();
    s.unshare(id).unwrap();
    assert!(matches!(
        s.cancel_operation(actor(), id, b.rights.operation_id(), &current),
        Err(StoreError::Fenced)
    ));
    assert!(
        !s.lookup_operation(actor(), id, b.rights.operation_id(), &current)
            .unwrap()
            .unwrap()
            .cancel_requested()
    );
}
#[test]
fn confirmed_clean_shutdown_records_stopped_while_crash_records_lost() {
    let dir = Directory::new();
    let limits = Limits {
        events: 4,
        operations: 8,
        workspaces: 1,
    };
    let mut s = HostStore::open(&dir.db(), limits).unwrap();
    let p = setup(&mut s, &dir.0);
    let id = p.state.context.workspace_id;
    s.record_clean_shutdown().unwrap();
    let stopped = s.workspace(id).unwrap();
    assert_eq!(stopped.state.domain_revision, DecimalU64(2));
    match &stopped.state.tabs.0[0].layout {
        TerminalLayout::Pane { pane } => {
            assert_eq!(pane.state, PaneState::Stopped);
            assert!(pane.session.is_none());
        }
        _ => panic!("expected pane"),
    };
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Stopped
    );
    assert!(s.events_after(0).unwrap().resync_required);
    s.record_clean_shutdown().unwrap();
    assert_eq!(
        s.workspace(id).unwrap().state.domain_revision,
        DecimalU64(2)
    );
    drop(s);
    let s = HostStore::open(&dir.db(), limits).unwrap();
    assert_eq!(
        s.workspace(id).unwrap().state.domain_revision,
        DecimalU64(2)
    );
    assert_eq!(
        s.terminal_descriptors(id).unwrap()[0].status,
        TerminalStatus::Stopped
    );
    let crash_dir = Directory::new();
    let mut crashed = HostStore::open(&crash_dir.db(), Limits::default()).unwrap();
    let p = setup(&mut crashed, &crash_dir.0);
    let id = p.state.context.workspace_id;
    drop(crashed);
    let crashed = HostStore::open(&crash_dir.db(), Limits::default()).unwrap();
    match &crashed.workspace(id).unwrap().state.tabs.0[0].layout {
        TerminalLayout::Pane { pane } => {
            assert_eq!(pane.state, PaneState::Lost);
            assert!(pane.session.is_none());
        }
        _ => panic!("expected pane"),
    };
}

#[test]
fn uncertain_restart_can_only_project_exactly_one_known_stopped_pane() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let project = setup(&mut store, &dir.0);
    let workspace = project.state.context.workspace_id;
    let restart = binding(workspace, Method::TerminalRestart, 88);
    store
        .admit_external(&restart, project.state.domain_revision)
        .unwrap();
    let permit = store.start_external(&restart).unwrap();
    let mut stopped = project.state.clone();
    stopped.domain_revision = DecimalU64(stopped.domain_revision.0 + 1);
    let TerminalLayout::Pane { pane } = &mut stopped.tabs.0[0].layout else {
        panic!()
    };
    pane.session = None;
    pane.state = PaneState::Stopped;
    let mut renamed = stopped.clone();
    renamed.tabs.0[0].name = "Changed".to_owned().try_into().unwrap();
    let mut lost = stopped.clone();
    let TerminalLayout::Pane { pane } = &mut lost.tabs.0[0].layout else {
        panic!()
    };
    pane.state = PaneState::Lost;
    let mut unchanged = project.state.clone();
    unchanged.domain_revision = stopped.domain_revision;
    for invalid in [renamed, lost, unchanged] {
        assert!(
            store
                .complete_external(
                    &permit,
                    OperationState::OutcomeUnknown,
                    Effect::Unknown,
                    None,
                    Some(invalid)
                )
                .is_err()
        );
        assert_eq!(store.workspace(workspace).unwrap().state, project.state);
    }
    // The narrow exception cannot carry a fabricated known result or apply
    // to another mutation method.
    assert!(
        store
            .complete_external(
                &permit,
                OperationState::OutcomeUnknown,
                Effect::Unknown,
                Some(OperationResult::Domain {
                    domain_revision: stopped.domain_revision
                }),
                Some(stopped.clone())
            )
            .is_err()
    );
    let rename = binding(workspace, Method::TerminalRename, 89);
    store
        .admit_external(&rename, project.state.domain_revision)
        .unwrap();
    let rename_permit = store.start_external(&rename).unwrap();
    assert!(
        store
            .complete_external(
                &rename_permit,
                OperationState::OutcomeUnknown,
                Effect::Unknown,
                None,
                Some(stopped.clone())
            )
            .is_err()
    );
    let receipt = store
        .complete_external(
            &permit,
            OperationState::OutcomeUnknown,
            Effect::Unknown,
            None,
            Some(stopped.clone()),
        )
        .unwrap();
    assert_eq!(receipt.state(), OperationState::OutcomeUnknown);
    assert_eq!(store.workspace(workspace).unwrap().state, stopped);
    drop(store);
    let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let reopened = store.workspace(workspace).unwrap().state;
    assert_eq!(reopened.tabs, stopped.tabs);
    assert_eq!(reopened.domain_revision, stopped.domain_revision);
}

#[test]
fn uncertain_restart_cannot_stop_two_existing_panes_in_one_projection() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let project = setup(&mut store, &dir.0);
    let workspace = project.state.context.workspace_id;
    let add = binding(workspace, Method::TerminalCreate, 90);
    store
        .admit_external(&add, project.state.domain_revision)
        .unwrap();
    let permit = store.start_external(&add).unwrap();
    let mut two = project.state;
    two.domain_revision = DecimalU64(2);
    let pane_id = PaneId::from_bytes([16; 16]).unwrap();
    let session_id = TerminalSessionId::from_bytes([17; 16]).unwrap();
    let session_epoch = SessionEpoch::from_bytes([18; 16]).unwrap();
    two.tabs.0.push(TerminalTab {
        tab_id: TabId::from_bytes([19; 16]).unwrap(),
        name: "Other".to_owned().try_into().unwrap(),
        layout: TerminalLayout::Pane {
            pane: TerminalPane {
                pane_id,
                state: PaneState::Running,
                session: Some(TerminalContext {
                    workspace: two.context.clone(),
                    pane_id,
                    session_id,
                    session_epoch,
                    profile: TerminalProfile::ExperimentalRustGridV1,
                }),
            },
        },
    });
    store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: two.domain_revision,
                pane_id,
                session_id,
                session_epoch,
            }),
            Some(two.clone()),
        )
        .unwrap();
    let restart = binding(workspace, Method::TerminalRestart, 91);
    store.admit_external(&restart, two.domain_revision).unwrap();
    let permit = store.start_external(&restart).unwrap();
    let mut both = two.clone();
    both.domain_revision = DecimalU64(3);
    for tab in &mut both.tabs.0 {
        let TerminalLayout::Pane { pane } = &mut tab.layout else {
            panic!()
        };
        pane.session = None;
        pane.state = PaneState::Stopped;
    }
    assert!(
        store
            .complete_external(
                &permit,
                OperationState::OutcomeUnknown,
                Effect::Unknown,
                None,
                Some(both.clone())
            )
            .is_err()
    );
    assert_eq!(store.workspace(workspace).unwrap().state, two);
    both.tabs.0[1] = two.tabs.0[1].clone();
    store
        .complete_external(
            &permit,
            OperationState::OutcomeUnknown,
            Effect::Unknown,
            None,
            Some(both.clone()),
        )
        .unwrap();
    assert_eq!(store.workspace(workspace).unwrap().state, both);
}

#[test]
fn terminal_exit_is_exact_session_cas_idempotent_and_cleared_on_owner_restart() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut store, &dir.0);
    let TerminalLayout::Pane { pane } = &p.state.tabs.0[0].layout else {
        panic!()
    };
    let terminal = pane.session.clone().unwrap();
    let mut stale = terminal.clone();
    stale.session_epoch = SessionEpoch::from_bytes([23; 16]).unwrap();
    assert!(!store.record_terminal_exit(&stale).unwrap());
    assert_eq!(
        store
            .workspace(terminal.workspace.workspace_id)
            .unwrap()
            .state,
        p.state
    );
    let events_before = store.events_after(0).unwrap().events.len();
    assert!(store.record_terminal_exit(&terminal).unwrap());
    assert_eq!(
        store.events_after(0).unwrap().events.len(),
        events_before + 1
    );
    let exited = store
        .workspace(terminal.workspace.workspace_id)
        .unwrap()
        .state;
    assert_eq!(exited.domain_revision, DecimalU64(2));
    assert!(!store.record_terminal_exit(&terminal).unwrap());
    assert_eq!(
        store.events_after(0).unwrap().events.len(),
        events_before + 1
    );
    assert_eq!(
        store
            .workspace(terminal.workspace.workspace_id)
            .unwrap()
            .state,
        exited
    );
    drop(store);
    let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let recovered = store
        .workspace(terminal.workspace.workspace_id)
        .unwrap()
        .state;
    let TerminalLayout::Pane { pane } = &recovered.tabs.0[0].layout else {
        panic!()
    };
    assert_eq!(pane.state, PaneState::Exited);
    assert!(pane.session.is_none());
    assert_eq!(recovered.domain_revision, DecimalU64(3));
}

#[test]
fn old_exit_observation_cannot_overwrite_replacement_projection() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let p = setup(&mut store, &dir.0);
    let TerminalLayout::Pane { pane } = &p.state.tabs.0[0].layout else {
        panic!()
    };
    let old = pane.session.clone().unwrap();
    let operation = binding(old.workspace.workspace_id, Method::TerminalRestart, 95);
    store
        .admit_external(&operation, p.state.domain_revision)
        .unwrap();
    let permit = store.start_external(&operation).unwrap();
    let mut next = p.state.clone();
    next.domain_revision = DecimalU64(2);
    let TerminalLayout::Pane { pane } = &mut next.tabs.0[0].layout else {
        panic!()
    };
    let mut replacement = old.clone();
    replacement.session_id = TerminalSessionId::from_bytes([24; 16]).unwrap();
    replacement.session_epoch = SessionEpoch::from_bytes([25; 16]).unwrap();
    pane.session = Some(replacement.clone());
    store
        .complete_external(
            &permit,
            OperationState::Succeeded,
            Effect::Committed,
            Some(OperationResult::Terminal {
                domain_revision: next.domain_revision,
                pane_id: replacement.pane_id,
                session_id: replacement.session_id,
                session_epoch: replacement.session_epoch,
            }),
            Some(next.clone()),
        )
        .unwrap();
    assert!(!store.record_terminal_exit(&old).unwrap());
    assert!(!store.record_terminal_retired(&old).unwrap());
    assert_eq!(
        store.workspace(old.workspace.workspace_id).unwrap().state,
        next
    );
}

#[test]
fn default_shell_is_initialized_once_persisted_and_included_in_checked_backup() {
    let dir = Directory::new();
    let profile = DefaultShellProfile {
        executable: dir.0.join("trusted-shell"),
        args: vec!["--login".into()],
    };
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(store.default_shell().unwrap(), None);
    assert_eq!(
        store.initialize_default_shell(profile.clone()).unwrap(),
        profile
    );
    drop(store);
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let changed = DefaultShellProfile {
        executable: dir.0.join("changed-shell"),
        args: vec![],
    };
    assert_eq!(store.initialize_default_shell(changed).unwrap(), profile);
    let backup = dir.0.join("backup.sqlite");
    store.checked_backup(&backup).unwrap();
    let backup = HostStore::open(&backup, Limits::default()).unwrap();
    assert_eq!(backup.default_shell().unwrap(), Some(profile));
}

#[test]
fn version_one_upgrade_checks_backup_and_preserves_identity_and_projects() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    let identity = store.identity().clone();
    let workspace = store
        .add_project(&dir.0, "Existing".to_owned().try_into().unwrap())
        .unwrap()
        .state
        .context
        .workspace_id;
    drop(store);
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    db.execute_batch(
        "DROP TABLE authorization_state; DROP TABLE default_shell; PRAGMA user_version=1;",
    )
    .unwrap();
    drop(db);
    let backup = dir.db().with_extension("before-v2.sqlite");
    dir.write_backup(&backup, b"preserve");
    assert!(matches!(
        HostStore::open(&dir.db(), Limits::default()),
        Err(StoreError::Backup)
    ));
    assert_eq!(std::fs::read(&backup).unwrap(), b"preserve");
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    drop(db);
    std::fs::remove_file(&backup).unwrap();
    let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(store.identity(), &identity);
    assert_eq!(
        store.workspace(workspace).unwrap().state.name,
        "Existing".to_owned().try_into().unwrap()
    );
    assert_eq!(store.default_shell().unwrap(), None);
    let backup = rusqlite::Connection::open(&backup).unwrap();
    assert_eq!(
        backup
            .pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
    assert_eq!(
        backup
            .query_row::<String, _, _>("SELECT value FROM metadata WHERE key='identity'", [], |r| r
                .get(0))
            .unwrap(),
        serde_json::to_string(&identity).unwrap()
    );
}

#[test]
fn malformed_local_shell_configuration_is_rejected() {
    let dir = Directory::new();
    let mut store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(
        store.initialize_default_shell(DefaultShellProfile {
            executable: "relative-shell".into(),
            args: vec![],
        }),
        Err(StoreError::Invalid)
    );
    assert!(store.default_shell().unwrap().is_none());
    drop(store);
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    db.execute(
        "INSERT INTO default_shell VALUES(1,?1)",
        [r#"{"executable":"relative","args":[]}"#],
    )
    .unwrap();
    drop(db);
    let store = HostStore::open(&dir.db(), Limits::default()).unwrap();
    assert_eq!(store.default_shell(), Err(StoreError::Storage));
}

#[test]
fn version_one_upgrade_preserves_but_rejects_stale_valid_backup() {
    let dir = Directory::new();
    drop(HostStore::open(&dir.db(), Limits::default()).unwrap());
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    db.execute_batch(
        "DROP TABLE authorization_state; DROP TABLE default_shell; PRAGMA user_version=1;",
    )
    .unwrap();
    let backup = dir.db().with_extension("before-v2.sqlite");
    #[cfg(windows)]
    let destination = lomi_platform::windows::backup::Destination::new(&dir.db(), &backup).unwrap();
    #[cfg(windows)]
    let file = destination.create().unwrap();
    db.backup(rusqlite::MAIN_DB, &backup, None).unwrap();
    #[cfg(windows)]
    destination.sync(&file).unwrap();
    let backup_bytes = std::fs::read(&backup).unwrap();
    db.execute(
        "UPDATE metadata SET value='42' WHERE key='owner_generation'",
        [],
    )
    .unwrap();
    drop(db);
    assert!(matches!(
        HostStore::open(&dir.db(), Limits::default()),
        Err(StoreError::Backup)
    ));
    assert_eq!(std::fs::read(&backup).unwrap(), backup_bytes);
    let db = rusqlite::Connection::open(dir.db()).unwrap();
    assert_eq!(
        db.pragma_query_value::<i64, _>(None, "user_version", |r| r.get(0))
            .unwrap(),
        1
    );
}
