//! Portable source coverage for the one-time trusted Remote API pin upgrade.
use lomi_host_store::*;
use lomi_remote_protocol::{OperationId, ipc::*};
use std::path::PathBuf;
use uuid::Uuid;

struct Directory(
    PathBuf,
    #[cfg(windows)] Option<lomi_platform::windows::OwnerLock>,
);
impl Directory {
    fn new() -> Self {
        #[cfg(not(windows))]
        let path = std::env::temp_dir().join(format!("lomi-auth-configuration-{}", Uuid::new_v4()));
        #[cfg(windows)]
        let path = PathBuf::from(std::env::var_os("USERPROFILE").unwrap())
            .join(format!("lomi-auth-configuration-{}", Uuid::new_v4()));
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
        {
            let owner = lomi_platform::windows::OwnerLock::acquire(&path).unwrap();
            owner.prepare_database().unwrap();
            Self(path, Some(owner))
        }
        #[cfg(not(windows))]
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
        #[cfg(windows)]
        drop(self.1.take());
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
fn pinned() -> LocalAuthConfiguration {
    let mut config = configuration();
    config.remote_api_origin = Some("https://remote.example".to_owned().try_into().unwrap());
    config
}
fn operation() -> OperationId {
    OperationId::from_bytes(*Uuid::new_v4().as_bytes()).unwrap()
}

#[test]
fn initial_pin_and_exact_retries_are_idempotent() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    assert_eq!(store.auth_configuration().unwrap(), Some(pinned()));
}

#[test]
fn legacy_missing_pin_can_be_installed_once_and_reopened() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    let mut legacy = serde_json::to_value(configuration()).unwrap();
    legacy.as_object_mut().unwrap().remove("remoteApiOrigin");
    db.execute(
        "UPDATE metadata SET value=?1 WHERE key='auth_configuration'",
        [serde_json::to_string(&legacy).unwrap()],
    )
    .unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.auth_configuration().unwrap(), Some(configuration()));
    store.configure_auth(&pinned()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    drop(store);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    assert_eq!(store.auth_configuration().unwrap(), Some(pinned()));
    store.configure_auth(&pinned()).unwrap();
    assert_eq!(
        store.configure_auth(&configuration()),
        Err(StoreError::IdempotencyConflict)
    );
}

#[test]
fn installed_pin_cannot_be_replaced_or_removed() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    let mut replacement = pinned();
    replacement.remote_api_origin = Some("https://other.example".to_owned().try_into().unwrap());
    for rejected in [replacement, configuration()] {
        assert_eq!(
            store.configure_auth(&rejected),
            Err(StoreError::IdempotencyConflict)
        );
        assert_eq!(store.auth_configuration().unwrap(), Some(pinned()));
    }
}

#[test]
fn pin_upgrade_cannot_change_identity_client_or_provider() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    let mut identity = pinned();
    identity.origin = "https://other-identity.example"
        .to_owned()
        .try_into()
        .unwrap();
    let mut client = pinned();
    client.client_id = "other-client".to_owned().try_into().unwrap();
    let mut provider = pinned();
    provider.provider = LocalAuthProvider::WindowsDpapi;
    provider.protected_file_acknowledgement = None;
    let mut keychain = pinned();
    keychain.provider = LocalAuthProvider::MacOsKeychain;
    keychain.protected_file_acknowledgement = None;
    keychain.keychain_path = Some("/private/operator.keychain".to_owned().try_into().unwrap());
    for rejected in [identity, client, provider, keychain] {
        assert_eq!(
            store.configure_auth(&rejected),
            Err(StoreError::IdempotencyConflict)
        );
        assert_eq!(store.auth_configuration().unwrap(), Some(configuration()));
    }
    store.configure_auth(&pinned()).unwrap();
}

#[test]
fn upgrade_preserves_pending_login_generation_clock_and_other_metadata() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&configuration()).unwrap();
    store.observe_authorization_clock(1234).unwrap();
    let intent = store.begin_login(operation()).unwrap();
    let state = store.authorization_state().unwrap();
    let identity = store.identity().clone();
    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    db.execute(
        "INSERT INTO metadata(key,value) VALUES('pin_test_sentinel','unchanged')",
        [],
    )
    .unwrap();
    let before: Vec<(String, String)> = db
        .prepare("SELECT key,value FROM metadata WHERE key NOT IN ('auth_configuration','owner_generation') ORDER BY key")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    drop(db);
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    store.configure_auth(&endpoints(true, true)).unwrap();
    assert_eq!(store.login_intent().unwrap(), Some(intent));
    assert_eq!(store.authorization_state().unwrap(), state);
    assert_eq!(store.identity(), &identity);
    drop(store);
    let db = rusqlite::Connection::open(directory.db()).unwrap();
    let after: Vec<(String, String)> = db
        .prepare("SELECT key,value FROM metadata WHERE key NOT IN ('auth_configuration','owner_generation') ORDER BY key")
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    assert_eq!(after, before);
}

#[test]
fn upgrade_preserves_verified_authorization_and_cloud_revoke_state() {
    for pending_revoke in [false, true] {
        let directory = Directory::new();
        let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
        store.configure_auth(&configuration()).unwrap();
        let intent = store.begin_login(operation()).unwrap();
        store.complete_login(intent).unwrap();
        store
            .mark_cloud_authorization_possible(intent.generation)
            .unwrap();
        if pending_revoke {
            store
                .fence_authorization(AuthorizationFenceReason::LocalLogout)
                .unwrap();
        }
        let state = store.authorization_state().unwrap();
        let verified = store.verified_authorization_generation().unwrap();
        let history = store.cloud_authorization_may_exist().unwrap();
        store.configure_auth(&pinned()).unwrap();
        store.configure_auth(&endpoints(true, true)).unwrap();
        assert_eq!(store.authorization_state().unwrap(), state);
        assert_eq!(store.verified_authorization_generation().unwrap(), verified);
        assert_eq!(store.cloud_authorization_may_exist().unwrap(), history);
        assert_eq!(store.login_intent().unwrap(), None);
    }
}

fn endpoints(api: bool, relay: bool) -> LocalAuthConfiguration {
    let mut config = configuration();
    if api {
        config.remote_api_origin = pinned().remote_api_origin;
    }
    if relay {
        config.relay_endpoint = Some(
            "wss://relay.example/v2/relay"
                .to_owned()
                .try_into()
                .unwrap(),
        );
    }
    config
}
#[test]
fn independent_pin_installation_orders_retry_and_reopen_preserve_configuration() {
    for sequence in [
        vec![(false, false), (true, false), (true, true)],
        vec![(false, false), (false, true), (true, true)],
        vec![(false, false), (true, true)],
        vec![(false, true)],
        vec![(true, true)],
    ] {
        let directory = Directory::new();
        for (api, relay) in sequence {
            let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
            let config = endpoints(api, relay);
            store.configure_auth(&config).unwrap();
            store.configure_auth(&config).unwrap();
            assert_eq!(store.auth_configuration().unwrap(), Some(config));
        }
    }
}
#[test]
fn installed_relay_and_api_pins_cannot_be_removed_or_replaced_after_logout() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    let installed = endpoints(true, true);
    store.configure_auth(&installed).unwrap();
    store.observe_authorization_clock(1234).unwrap();
    let login = store.begin_login(operation()).unwrap();
    store.complete_login(login).unwrap();
    store
        .mark_cloud_authorization_possible(login.generation)
        .unwrap();
    store
        .fence_authorization(AuthorizationFenceReason::LocalLogout)
        .unwrap();
    let before = store.authorization_state().unwrap();
    let mut replaced = installed.clone();
    replaced.relay_endpoint = Some(
        "wss://other.example/v2/relay"
            .to_owned()
            .try_into()
            .unwrap(),
    );
    let mut api = installed.clone();
    api.remote_api_origin = Some("https://other.example".to_owned().try_into().unwrap());
    for bad in [
        configuration(),
        endpoints(true, false),
        endpoints(false, true),
        replaced,
        api,
    ] {
        assert_eq!(
            store.configure_auth(&bad),
            Err(StoreError::IdempotencyConflict)
        );
        assert_eq!(store.authorization_state().unwrap(), before);
        assert_eq!(store.auth_configuration().unwrap(), Some(installed.clone()));
    }
    store.configure_auth(&installed).unwrap();
    assert_eq!(store.observe_authorization_clock(1).unwrap(), 1234);
}
#[test]
fn relay_upgrade_cannot_change_identity_client_provider_or_installed_api() {
    let directory = Directory::new();
    let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
    store.configure_auth(&pinned()).unwrap();
    let good = endpoints(true, true);
    let mut identity = good.clone();
    identity.origin = "https://other.example".to_owned().try_into().unwrap();
    let mut client = good.clone();
    client.client_id = "other".to_owned().try_into().unwrap();
    let mut provider = good.clone();
    provider.provider = LocalAuthProvider::WindowsDpapi;
    provider.protected_file_acknowledgement = None;
    let mut api = good.clone();
    api.remote_api_origin = Some("https://other.example".to_owned().try_into().unwrap());
    for bad in [identity, client, provider, api] {
        assert_eq!(
            store.configure_auth(&bad),
            Err(StoreError::IdempotencyConflict)
        );
        assert_eq!(store.auth_configuration().unwrap(), Some(pinned()));
    }
    store.configure_auth(&good).unwrap();
}
#[test]
fn missing_or_null_legacy_relay_can_fill_once_and_malformed_persisted_pin_fails_closed() {
    for endpoint in [
        None,
        Some(serde_json::Value::Null),
        Some(serde_json::json!("wss://RELAY.example/v2/relay")),
    ] {
        let directory = Directory::new();
        let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
        store.configure_auth(&configuration()).unwrap();
        drop(store);
        let db = rusqlite::Connection::open(directory.db()).unwrap();
        let mut value = serde_json::to_value(configuration()).unwrap();
        if let Some(endpoint) = &endpoint {
            value["relayEndpoint"] = endpoint.clone();
        }
        db.execute(
            "UPDATE metadata SET value=?1 WHERE key='auth_configuration'",
            [serde_json::to_string(&value).unwrap()],
        )
        .unwrap();
        drop(db);
        let mut store = HostStore::open(&directory.db(), Limits::default()).unwrap();
        if endpoint.as_ref().is_some_and(|v| v.is_string()) {
            assert_eq!(store.auth_configuration(), Err(StoreError::Storage));
            assert_eq!(
                store.configure_auth(&endpoints(false, true)),
                Err(StoreError::Storage)
            );
        } else {
            assert_eq!(store.auth_configuration().unwrap(), Some(configuration()));
            store.configure_auth(&endpoints(false, true)).unwrap();
            assert_eq!(
                store.auth_configuration().unwrap(),
                Some(endpoints(false, true))
            );
        }
    }
}
