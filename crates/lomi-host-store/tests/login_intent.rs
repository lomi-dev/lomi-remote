#![cfg(unix)]
use lomi_host_store::*;
use lomi_remote_protocol::{OperationId, ipc::*};
use std::os::unix::fs::DirBuilderExt;
use uuid::Uuid;

struct Directory(std::path::PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("lomi-login-{}", Uuid::new_v4()));
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .unwrap();
        Self(path)
    }
    fn db(&self) -> std::path::PathBuf {
        self.0.join("host.sqlite")
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn configuration() -> LocalAuthConfiguration {
    LocalAuthConfiguration {
        version: 1,
        origin: "https://identity.example".to_owned().try_into().unwrap(),
        remote_api_origin: None,
        relay_endpoint: None,
        client_id: "lomi-remote-host".to_owned().try_into().unwrap(),
        provider: LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(LocalFileAcknowledgement::OsPermissionsOnly),
    }
}
fn operation() -> OperationId {
    OperationId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap()
}
fn add_project(store: &mut HostStore, directory: &Directory) -> ProjectRecord {
    let root = directory.0.join("workspace");
    std::fs::create_dir(&root).unwrap();
    store
        .add_project(&root, "Workspace".to_owned().try_into().unwrap())
        .unwrap()
}
#[test]
fn restart_resumes_exact_intent_and_logout_atomically_invalidates_it() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    let first = store.begin_login(operation()).unwrap();
    assert_eq!(store.begin_login(operation()).unwrap(), first);
    drop(store);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.login_intent().unwrap(), Some(first));
    store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.complete_login(first), Err(StoreError::Fenced));
    assert_eq!(store.begin_login(operation()), Err(StoreError::Fenced));
    let state = store.authorization_state().unwrap();
    store
        .acknowledge_authorization_revoke(state.generation)
        .unwrap();
    let next = store.begin_login(operation()).unwrap();
    assert_ne!(next.generation, first.generation);
    assert_eq!(store.complete_login(first), Err(StoreError::Fenced));
    assert!(!store.complete_login(next).unwrap().locked);
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.complete_login(next), Err(StoreError::Fenced));
}
#[test]
fn public_configuration_is_immutable_and_revalidates_typed_storage() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    let config = configuration();
    store.configure_auth(&config).unwrap();
    store.configure_auth(&config).unwrap();
    let mut different = config.clone();
    different.origin = "https://other.example".to_owned().try_into().unwrap();
    assert_eq!(
        store.configure_auth(&different),
        Err(StoreError::IdempotencyConflict)
    );
    let mut invalid = config.clone();
    invalid.protected_file_acknowledgement = None;
    assert_eq!(store.configure_auth(&invalid), Err(StoreError::Invalid));
    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute(
        "UPDATE metadata SET value=?1 WHERE key='auth_configuration'",
        [serde_json::to_string(&invalid).unwrap()],
    )
    .unwrap();
    drop(db);
    let store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.auth_configuration(), Err(StoreError::Storage));
}
#[test]
fn authority_rejection_removes_intent_without_restoring_consent() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    let first = store.begin_login(operation()).unwrap();
    store
        .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
        .unwrap();
    assert!(store.authorization_state().unwrap().locked);
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.complete_login(first), Err(StoreError::Fenced));
}

#[test]
fn passive_rejection_waits_for_a_new_explicit_login_and_ack_promotes_it() {
    let directory = Directory::new();
    let config = configuration();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&config).unwrap();
    let project = add_project(&mut store, &directory);
    store.enable_authorization(0).unwrap();
    store.share(project.state.context.workspace_id, 0).unwrap();
    assert!(
        store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
    store.mark_cloud_authorization_possible(0).unwrap();

    let rejected = store.fence_rejected_credentials(0, &config).unwrap();
    assert_eq!(rejected.generation, 1);
    assert!(rejected.locked);
    assert!(!rejected.pending_cloud_revoke);
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert_eq!(store.verified_authorization_generation().unwrap(), None);
    assert!(
        !store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
    assert!(
        store
            .pending_publications()
            .unwrap()
            .iter()
            .all(|publication| !publication.enabled)
    );
    drop(store);

    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.authorization_state().unwrap(), rejected);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert_eq!(store.login_intent().unwrap(), None);
    let intent = store.begin_login(operation()).unwrap();
    assert_eq!(intent.generation, rejected.generation);
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.deferred_login_intent().unwrap(), Some(intent));
    assert!(store.authorization_state().unwrap().pending_cloud_revoke);
    assert_eq!(store.begin_login(operation()).unwrap(), intent);
    assert_eq!(
        store.enable_authorization(intent.generation),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.complete_login(intent), Err(StoreError::Fenced));
    drop(store);

    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.deferred_login_intent().unwrap(), Some(intent));
    let acknowledged = store
        .acknowledge_authorization_revoke(intent.generation)
        .unwrap();
    assert!(acknowledged.locked);
    assert!(!acknowledged.pending_cloud_revoke);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert_eq!(store.login_intent().unwrap(), Some(intent));
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(false));
    let completed = store.complete_login(intent).unwrap();
    assert!(!completed.locked);
    assert!(
        !store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
    store
        .mark_cloud_authorization_possible(intent.generation)
        .unwrap();
    assert_eq!(
        store
            .acknowledge_authorization_revoke(intent.generation)
            .unwrap(),
        completed
    );
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(true));
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
}

#[test]
fn rejected_active_login_is_rebound_and_promoted_without_a_second_click() {
    let directory = Directory::new();
    let config = configuration();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&config).unwrap();
    let project = add_project(&mut store, &directory);
    store.enable_authorization(0).unwrap();
    store.share(project.state.context.workspace_id, 0).unwrap();
    let first = store.begin_login(operation()).unwrap();
    store
        .mark_cloud_authorization_possible(first.generation)
        .unwrap();

    let rejected = store
        .fence_rejected_credentials(first.generation, &config)
        .unwrap();
    assert_eq!(rejected.generation, first.generation + 1);
    assert!(rejected.locked && rejected.pending_cloud_revoke);
    let deferred = LoginIntent {
        operation_id: first.operation_id,
        generation: rejected.generation,
    };
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.deferred_login_intent().unwrap(), Some(deferred));
    assert_eq!(store.begin_login(operation()).unwrap(), deferred);
    assert!(
        !store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
    drop(store);

    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.authorization_state().unwrap(), rejected);
    assert_eq!(store.deferred_login_intent().unwrap(), Some(deferred));
    let acknowledged = store
        .acknowledge_authorization_revoke(rejected.generation)
        .unwrap();
    assert!(acknowledged.locked && !acknowledged.pending_cloud_revoke);
    assert_eq!(store.login_intent().unwrap(), Some(deferred));
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert!(
        !store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
    let completed = store.complete_login(deferred).unwrap();
    assert!(!completed.locked);
    assert!(
        !store
            .workspace(project.state.context.workspace_id)
            .unwrap()
            .consent
    );
}

#[test]
fn rejection_generation_configuration_and_metadata_are_strict() {
    let directory = Directory::new();
    let config = configuration();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&config).unwrap();
    let mut different = config.clone();
    different.origin = "https://other.example".to_owned().try_into().unwrap();
    assert_eq!(
        store.fence_rejected_credentials(0, &different),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.fence_rejected_credentials(1, &config),
        Err(StoreError::Fenced)
    );
    assert_eq!(store.authorization_state().unwrap().generation, 0);
    drop(store);

    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute(
        "INSERT INTO metadata(key,value) VALUES('authorization_rejection',?1)",
        [serde_json::json!({
            "version": 2,
            "generation": 1,
            "configuration": config,
        })
        .to_string()],
    )
    .unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.deferred_login_intent(), Err(StoreError::Storage));
    assert_eq!(store.begin_login(operation()), Err(StoreError::Storage));
    assert_eq!(store.enable_authorization(0), Err(StoreError::Storage));
    // Explicit logout remains the recovery path for malformed stale metadata.
    let fenced = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(fenced.generation, 1);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert_eq!(store.login_intent().unwrap(), None);
}

#[test]
fn generic_logout_cancels_deferred_relogin_and_ack_failure_rolls_back_promotion() {
    let directory = Directory::new();
    let config = configuration();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&config).unwrap();
    let first = store.begin_login(operation()).unwrap();
    store
        .mark_cloud_authorization_possible(first.generation)
        .unwrap();
    let rejected = store
        .fence_rejected_credentials(first.generation, &config)
        .unwrap();
    let deferred = store.deferred_login_intent().unwrap().unwrap();
    assert_eq!(deferred.operation_id, first.operation_id);
    assert_eq!(
        store.acknowledge_local_authorization_logout(rejected.generation),
        Err(StoreError::Fenced)
    );

    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute_batch(
        "CREATE TRIGGER fail_revoke_ack BEFORE UPDATE ON authorization_state
         BEGIN SELECT RAISE(ABORT,'synthetic ACK fault'); END;",
    )
    .unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(
        store.acknowledge_authorization_revoke(rejected.generation),
        Err(StoreError::Storage)
    );
    assert_eq!(store.authorization_state().unwrap(), rejected);
    assert_eq!(store.deferred_login_intent().unwrap(), Some(deferred));
    assert_eq!(store.login_intent().unwrap(), None);
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(true));
    drop(store);

    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute_batch("DROP TRIGGER fail_revoke_ack").unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    let logout = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert!(logout.pending_cloud_revoke);
    assert_eq!(store.deferred_login_intent().unwrap(), None);
    assert_eq!(store.login_intent().unwrap(), None);
    store
        .acknowledge_authorization_revoke(logout.generation)
        .unwrap();
    let replacement = store.begin_login(operation()).unwrap();
    assert_ne!(replacement.operation_id, deferred.operation_id);
    assert_eq!(replacement.generation, logout.generation);
}

#[test]
fn suspension_retains_verified_generation_across_restart_but_fence_clears_it() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    let intent = store.begin_login(operation()).unwrap();
    store.complete_login(intent).unwrap();
    assert_eq!(
        store.verified_authorization_generation().unwrap(),
        Some(intent.generation)
    );
    store.suspend_authorization(intent.generation).unwrap();
    drop(store);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert!(store.authorization_state().unwrap().locked);
    assert_eq!(
        store.verified_authorization_generation().unwrap(),
        Some(intent.generation)
    );
    store
        .fence_authorization(AuthorizationFenceReason::AuthorityRejected)
        .unwrap();
    assert_eq!(store.verified_authorization_generation().unwrap(), None);
    assert_eq!(
        store.enable_authorization(intent.generation),
        Err(StoreError::Fenced)
    );
}

#[test]
fn cloud_history_survives_fences_and_only_verified_ack_can_clear_it() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(false));
    store.configure_auth(&configuration()).unwrap();
    store.mark_cloud_authorization_possible(0).unwrap();
    let fence = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(true));
    assert_eq!(
        store.acknowledge_local_authorization_logout(fence.generation),
        Err(StoreError::Fenced)
    );
    assert!(store.authorization_state().unwrap().pending_cloud_revoke);
    store
        .acknowledge_authorization_revoke(fence.generation)
        .unwrap();
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), Some(false));
}

#[test]
fn legacy_missing_cloud_history_remains_unknown_after_configure() {
    let directory = Directory::new();
    let store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute(
        "DELETE FROM metadata WHERE key='cloud_authorization_history'",
        [],
    )
    .unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    assert_eq!(store.cloud_authorization_may_exist().unwrap(), None);
    let fence = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    assert_eq!(
        store.acknowledge_local_authorization_logout(fence.generation),
        Err(StoreError::Fenced)
    );
}
