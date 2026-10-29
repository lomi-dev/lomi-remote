use super::*;

fn store() -> HostStore {
    HostStore::open(Path::new(":memory:"), Limits::default()).unwrap()
}
fn auth() -> ipc::LocalAuthConfiguration {
    ipc::LocalAuthConfiguration {
        version: 1,
        origin: "https://identity.example".to_owned().try_into().unwrap(),
        remote_api_origin: None,
        relay_endpoint: None,
        client_id: "host-client".to_owned().try_into().unwrap(),
        provider: ipc::LocalAuthProvider::ProtectedFile,
        keychain_path: None,
        protected_file_acknowledgement: Some(ipc::LocalFileAcknowledgement::OsPermissionsOnly),
    }
}
fn document(revision: u64, authentication: Option<ipc::LocalAuthConfiguration>) -> PublicDocument {
    PublicDocument::encode(&Configuration {
        version: 1,
        revision,
        authentication,
    })
    .unwrap()
}
fn migrated(
    store: &mut HostStore,
    authentication: Option<ipc::LocalAuthConfiguration>,
) -> PublicDocument {
    if let Some(auth) = &authentication {
        store.configure_auth(auth).unwrap();
    }
    let first = document(1, authentication);
    let intent = store.public_prepare(None, &first).unwrap();
    store.public_finish(intent.operation_id, &first).unwrap();
    first
}
#[test]
fn prepared_record_fences_auth_and_requires_exact_operation_and_document() {
    let mut store = store();
    let desired = document(1, None);
    let intent = store.public_prepare(None, &desired).unwrap();
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Fenced)
    ));
    assert!(!store.public_configuration_ready().unwrap());
    let wrong = OperationId::from_bytes(Uuid::new_v4().into_bytes()).unwrap();
    assert_eq!(
        store.public_finish(wrong, &desired),
        Err(StoreError::Fenced)
    );
    assert_eq!(
        store.public_finish(intent.operation_id, &document(2, None)),
        Err(StoreError::Fenced)
    );
    assert!(
        store
            .public_configuration_state()
            .unwrap()
            .unwrap()
            .prepared
            .is_some()
    );
    store.public_finish(intent.operation_id, &desired).unwrap();
    assert!(store.public_configuration_ready().unwrap());
    assert!(store.auth_configuration().unwrap().is_none());
}
#[test]
fn independent_first_fills_are_allowed_and_every_binding_replacement_is_rejected() {
    let mut store = store();
    let mut config = auth();
    let mut current = migrated(&mut store, Some(config.clone()));
    for fill_api_first in [true, false] {
        if fill_api_first {
            config.remote_api_origin = Some("https://api.example".to_owned().try_into().unwrap());
        } else {
            config.relay_endpoint = Some(
                "wss://relay.example/v2/relay"
                    .to_owned()
                    .try_into()
                    .unwrap(),
            );
        }
        let next = document(
            current.configuration().unwrap().revision + 1,
            Some(config.clone()),
        );
        let intent = store.public_prepare(Some(&current), &next).unwrap();
        assert_eq!(
            HostStore::read_auth_configuration(&store.db).unwrap(),
            current.configuration().unwrap().authentication
        );
        store.public_finish(intent.operation_id, &next).unwrap();
        current = next;
    }
    let mut replacements = vec![];
    let mut changed = config.clone();
    changed.origin = "https://other.example".to_owned().try_into().unwrap();
    replacements.push(changed);
    let mut changed = config.clone();
    changed.client_id = "other-client".to_owned().try_into().unwrap();
    replacements.push(changed);
    let mut changed = config.clone();
    changed.remote_api_origin = None;
    replacements.push(changed);
    let mut changed = config.clone();
    changed.relay_endpoint = None;
    replacements.push(changed);
    let mut changed = config.clone();
    changed.provider = ipc::LocalAuthProvider::WindowsDpapi;
    changed.protected_file_acknowledgement = None;
    replacements.push(changed);
    for changed in replacements {
        let next = document(4, Some(changed));
        assert!(matches!(
            store.public_prepare(Some(&current), &next),
            Err(StoreError::IdempotencyConflict)
        ));
        assert!(store.public_configuration_ready().unwrap());
    }
    assert!(matches!(
        store.public_prepare(Some(&current), &document(4, None)),
        Err(StoreError::IdempotencyConflict)
    ));
    assert_eq!(store.configure_auth(&config), Err(StoreError::Fenced));
}
#[test]
fn logout_and_revoke_preserve_binding_and_prepared_document() {
    let mut store = store();
    let config = auth();
    let current = migrated(&mut store, Some(config.clone()));
    let mut next = config.clone();
    next.remote_api_origin = Some("https://api.example".to_owned().try_into().unwrap());
    let desired = document(2, Some(next));
    let intent = store.public_prepare(Some(&current), &desired).unwrap();
    let fence = store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    store
        .acknowledge_authorization_revoke(fence.generation)
        .unwrap();
    assert_eq!(
        HostStore::read_auth_configuration(&store.db).unwrap(),
        Some(config)
    );
    let state = store.public_configuration_state().unwrap().unwrap();
    assert!(
        state
            .prepared
            .as_ref()
            .is_some_and(|actual| actual == &intent)
    );
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Fenced)
    ));
}
#[test]
fn malformed_oversize_and_digest_tampering_never_fall_back_to_legacy_auth() {
    let mut store = store();
    let current = migrated(&mut store, Some(auth()));
    let saved: String = store
        .db
        .query_row("SELECT value FROM metadata WHERE key=?1", [KEY], |row| {
            row.get(0)
        })
        .unwrap();
    for text in [
        "{}".to_owned(),
        "{".to_owned(),
        " ".repeat(MAX_STATE_BYTES + 1),
        saved.replace("\"version\":1", "\"version\":2"),
    ] {
        store
            .db
            .execute(
                "UPDATE metadata SET value=?1 WHERE key=?2",
                params![text, KEY],
            )
            .unwrap();
        assert!(store.auth_configuration().is_err());
    }
    let mut state: PublicConfigurationState = serde_json::from_str(&saved).unwrap();
    state.current.as_mut().unwrap().sha256 = "0".repeat(64);
    store
        .db
        .execute(
            "UPDATE metadata SET value=?1 WHERE key=?2",
            params![serde_json::to_string(&state).unwrap(), KEY],
        )
        .unwrap();
    assert!(store.auth_configuration().is_err());
    store
        .db
        .execute(
            "UPDATE metadata SET value=?1 WHERE key=?2",
            params![saved, KEY],
        )
        .unwrap();
    store.public_block();
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Fenced)
    ));
    store.public_accept_current(&current).unwrap();
    assert_eq!(store.auth_configuration().unwrap(), Some(auth()));
}
#[test]
fn completed_migration_with_missing_state_or_missing_marker_is_corruption() {
    let mut store = store();
    migrated(&mut store, Some(auth()));
    let saved: String = store
        .db
        .query_row("SELECT value FROM metadata WHERE key=?1", [KEY], |row| {
            row.get(0)
        })
        .unwrap();
    store
        .db
        .execute("DELETE FROM metadata WHERE key=?1", [KEY])
        .unwrap();
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Storage)
    ));
    assert!(matches!(
        store.public_legacy_binding(),
        Err(StoreError::Storage)
    ));
    store
        .db
        .execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![KEY, saved],
        )
        .unwrap();
    store
        .db
        .execute("DELETE FROM metadata WHERE key=?1", [MARKER])
        .unwrap();
    assert!(matches!(
        store.auth_configuration(),
        Err(StoreError::Storage)
    ));
}
#[test]
fn relay_first_then_api_fill_preserves_the_independent_allowances() {
    let mut store = store();
    let mut configuration = auth();
    let first = migrated(&mut store, Some(configuration.clone()));
    configuration.relay_endpoint = Some(
        "wss://relay.example/v2/relay"
            .to_owned()
            .try_into()
            .unwrap(),
    );
    let second = document(2, Some(configuration.clone()));
    let intent = store.public_prepare(Some(&first), &second).unwrap();
    store.public_finish(intent.operation_id, &second).unwrap();
    configuration.remote_api_origin = Some("https://api.example".to_owned().try_into().unwrap());
    let third = document(3, Some(configuration.clone()));
    let intent = store.public_prepare(Some(&second), &third).unwrap();
    store.public_finish(intent.operation_id, &third).unwrap();
    assert_eq!(store.auth_configuration().unwrap(), Some(configuration));
}
#[test]
fn malformed_marker_projects_only_a_scalar_and_never_falls_back_to_binding() {
    let mut store = store();
    migrated(&mut store, Some(auth()));
    // TEXT length sees just the prefix before NUL. The production projection
    // must return an integer, never materialize the large suffix as a String.
    for malformed in [
        format!("1\0{}", "x".repeat(MAX_STATE_BYTES + 1)),
        "1\0".to_owned(),
        "é".repeat(4),
        "é".repeat(5),
        String::new(),
    ] {
        store
            .db
            .execute(
                "UPDATE metadata SET value=?1 WHERE key=?2",
                params![malformed, MARKER],
            )
            .unwrap();
        let projected: rusqlite::types::Value = store
            .db
            .query_row(MARKER_QUERY, [MARKER], |row| row.get(0))
            .unwrap();
        assert_eq!(projected, rusqlite::types::Value::Integer(0));
        assert!(matches!(
            store.public_configuration_state(),
            Err(StoreError::Storage)
        ));
        assert!(matches!(
            store.auth_configuration(),
            Err(StoreError::Storage)
        ));
        assert!(matches!(
            store.public_legacy_binding(),
            Err(StoreError::Storage)
        ));
    }
    store
        .db
        .execute("UPDATE metadata SET value='1' WHERE key=?1", [MARKER])
        .unwrap();
    let projected: rusqlite::types::Value = store
        .db
        .query_row(MARKER_QUERY, [MARKER], |row| row.get(0))
        .unwrap();
    assert_eq!(projected, rusqlite::types::Value::Integer(1));
    assert_eq!(store.auth_configuration().unwrap(), Some(auth()));
}
