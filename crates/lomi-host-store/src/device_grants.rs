//! Durable device grants for the tunnel: one row per device signed bundle
//! fingerprint. A grant is local consent evidence only; callers (reconciliation,
//! revocation, handshake) decide policy. Times are Unix milliseconds.
use super::*;
use lomi_remote_crypto::Permissions;

/// Schema applied by the device-grants migration.
pub(crate) const SCHEMA: &str = "CREATE TABLE IF NOT EXISTS device_grants(\
device_key BLOB PRIMARY KEY CHECK(length(device_key)=32),\
account_id BLOB NOT NULL CHECK(length(account_id)=16),\
device_id BLOB NOT NULL CHECK(length(device_id)=16),\
device_name TEXT NOT NULL CHECK(length(CAST(device_name AS BLOB))<=255),\
device_kind TEXT NOT NULL CHECK(length(CAST(device_kind AS BLOB))<=64),\
ceiling TEXT NOT NULL CHECK(ceiling IN('observe','control')),\
granted_at INTEGER NOT NULL,\
authorization_expires_at INTEGER NOT NULL,\
authorization_epoch INTEGER NOT NULL,\
server_confirmed_at INTEGER NOT NULL,\
control_confirmed_at INTEGER) WITHOUT ROWID;";
const COLUMNS: &str = "device_key,account_id,device_id,device_name,device_kind,ceiling,granted_at,authorization_expires_at,authorization_epoch,server_confirmed_at,control_confirmed_at";

pub const MAX_DEVICE_GRANTS: usize = 16;
/// A grant the server has not confirmed for longer than this is invalid.
pub const SERVER_CONFIRMATION_TTL_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceGrant {
    /// Fingerprint of the device signed bundle.
    pub device_key: [u8; 32],
    pub account_id: [u8; 16],
    pub device_id: [u8; 16],
    pub device_name: String,
    pub device_kind: String,
    /// Permission ceiling, stored as its canonical serde form (snake_case).
    pub ceiling: Permissions,
    pub granted_at: u64,
    /// Device authorization deadline from the account.
    pub authorization_expires_at: u64,
    pub authorization_epoch: u64,
    pub server_confirmed_at: u64,
    /// `None`: read-only until the first code confirmation on the Host.
    pub control_confirmed_at: Option<u64>,
}

impl DeviceGrant {
    /// Valid while the server confirmed it at most 24 h ago and the device
    /// authorization deadline (exclusive) is still ahead.
    pub fn is_valid(&self, now: u64) -> bool {
        now.saturating_sub(self.server_confirmed_at) <= SERVER_CONFIRMATION_TTL_MS
            && now < self.authorization_expires_at
    }
}

fn int(value: u64) -> Result<i64> {
    i64::try_from(value).map_err(|_| StoreError::Invalid)
}

fn uint(value: i64) -> Result<u64> {
    u64::try_from(value).map_err(|_| StoreError::Storage)
}

fn ceiling_text(ceiling: Permissions) -> &'static str {
    match ceiling {
        Permissions::Observe => "observe",
        Permissions::Control => "control",
    }
}

fn read_grant(row: &rusqlite::Row<'_>) -> Result<DeviceGrant> {
    let ceiling = match row.get::<_, String>(5)?.as_str() {
        "observe" => Permissions::Observe,
        "control" => Permissions::Control,
        _ => return Err(StoreError::Storage),
    };
    let control: Option<i64> = row.get(10)?;
    Ok(DeviceGrant {
        device_key: row.get(0)?,
        account_id: row.get(1)?,
        device_id: row.get(2)?,
        device_name: row.get(3)?,
        device_kind: row.get(4)?,
        ceiling,
        granted_at: uint(row.get(6)?)?,
        authorization_expires_at: uint(row.get(7)?)?,
        authorization_epoch: uint(row.get(8)?)?,
        server_confirmed_at: uint(row.get(9)?)?,
        control_confirmed_at: control.map(uint).transpose()?,
    })
}

impl HostStore {
    /// Insert a grant or refresh an existing one. A refresh keeps `granted_at`
    /// and, for the same account, `control_confirmed_at`. A new device beyond
    /// [`MAX_DEVICE_GRANTS`] fails with `DeviceGrantsFull`; nothing is evicted.
    pub fn upsert_grant(&mut self, grant: &DeviceGrant) -> Result<()> {
        if grant.device_name.len() > 255 || grant.device_kind.len() > 64 {
            return Err(StoreError::Invalid);
        }
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM device_grants WHERE device_key=?1)",
            [&grant.device_key[..]],
            |row| row.get(0),
        )?;
        let count: i64 = tx.query_row("SELECT count(*) FROM device_grants", [], |r| r.get(0))?;
        if !exists && count as usize >= MAX_DEVICE_GRANTS {
            return Err(StoreError::DeviceGrantsFull);
        }
        tx.execute(
            &format!(
                "INSERT INTO device_grants({COLUMNS}) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11) \
                 ON CONFLICT(device_key) DO UPDATE SET \
                 control_confirmed_at=CASE WHEN account_id=excluded.account_id \
                 THEN control_confirmed_at END, \
                 account_id=excluded.account_id,device_id=excluded.device_id,\
                 device_name=excluded.device_name,device_kind=excluded.device_kind,\
                 ceiling=excluded.ceiling,\
                 authorization_expires_at=excluded.authorization_expires_at,\
                 authorization_epoch=excluded.authorization_epoch,\
                 server_confirmed_at=excluded.server_confirmed_at"
            ),
            params![
                &grant.device_key[..],
                &grant.account_id[..],
                &grant.device_id[..],
                grant.device_name,
                grant.device_kind,
                ceiling_text(grant.ceiling),
                int(grant.granted_at)?,
                int(grant.authorization_expires_at)?,
                int(grant.authorization_epoch)?,
                int(grant.server_confirmed_at)?,
                grant.control_confirmed_at.map(int).transpose()?,
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_grant(&self, device_key: &[u8; 32]) -> Result<Option<DeviceGrant>> {
        self.db
            .query_row(
                &format!("SELECT {COLUMNS} FROM device_grants WHERE device_key=?1"),
                [&device_key[..]],
                |row| Ok(read_grant(row)),
            )
            .optional()?
            .transpose()
    }

    pub fn list_grants(&self) -> Result<Vec<DeviceGrant>> {
        let mut statement = self.db.prepare(&format!(
            "SELECT {COLUMNS} FROM device_grants ORDER BY granted_at,device_key"
        ))?;
        let rows = statement.query_map([], |row| Ok(read_grant(row)))?;
        rows.map(|row| row?).collect()
    }

    /// Record the one-time code confirmation that enables control.
    pub fn confirm_control(&mut self, device_key: &[u8; 32], now: u64) -> Result<()> {
        let changed = self.db.execute(
            "UPDATE device_grants SET control_confirmed_at=?2 WHERE device_key=?1",
            params![&device_key[..], int(now)?],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound);
        }
        Ok(())
    }

    /// Bulk server confirmation after a device-list reconciliation. Unknown
    /// fingerprints are ignored; returns the number of grants refreshed.
    pub fn mark_server_confirmed(&mut self, device_keys: &[[u8; 32]], now: u64) -> Result<usize> {
        let now = int(now)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut changed = 0;
        for key in device_keys {
            changed += tx.execute(
                "UPDATE device_grants SET server_confirmed_at=?2 WHERE device_key=?1",
                params![&key[..], now],
            )?;
        }
        tx.commit()?;
        Ok(changed)
    }

    /// Delete one grant; returns whether it existed.
    pub fn revoke(&mut self, device_key: &[u8; 32]) -> Result<bool> {
        let changed = self.db.execute(
            "DELETE FROM device_grants WHERE device_key=?1",
            [&device_key[..]],
        )?;
        Ok(changed > 0)
    }

    /// The owner's choice for new devices; `Auto` until one is saved.
    pub fn device_mode(&self) -> Result<lomi_remote_protocol::ipc::LocalDeviceMode> {
        let value: Option<String> = self
            .db
            .query_row(
                "SELECT value FROM metadata WHERE key='device_consent_mode'",
                [],
                |row| row.get(0),
            )
            .optional()?;
        value.map_or(Ok(lomi_remote_protocol::ipc::LocalDeviceMode::Auto), |v| {
            serde_json::from_str(&v).map_err(|_| StoreError::Storage)
        })
    }
    pub fn save_device_mode(
        &mut self,
        mode: lomi_remote_protocol::ipc::LocalDeviceMode,
    ) -> Result<()> {
        let value = serde_json::to_string(&mode).map_err(|_| StoreError::Invalid)?;
        self.db.execute(
            "INSERT INTO metadata(key,value) VALUES('device_consent_mode',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            [value],
        )?;
        Ok(())
    }

    /// Delete every grant of `account_id` whose key is not in `keep` (the
    /// server's current device list). Returns the number deleted.
    pub fn revoke_account_devices_not_in(
        &mut self,
        account_id: &[u8; 16],
        keep: &[[u8; 32]],
    ) -> Result<usize> {
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut statement =
            tx.prepare("SELECT device_key FROM device_grants WHERE account_id=?1")?;
        let stale = statement
            .query_map([&account_id[..]], |row| row.get::<_, [u8; 32]>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        drop(statement);
        let mut deleted = 0;
        for key in stale.iter().filter(|key| !keep.contains(key)) {
            deleted += tx.execute("DELETE FROM device_grants WHERE device_key=?1", [&key[..]])?;
        }
        tx.commit()?;
        Ok(deleted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = SERVER_CONFIRMATION_TTL_MS;

    struct Dir(PathBuf);
    impl Dir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("lomi-grants-{}", Uuid::new_v4()));
            fs::create_dir(&path).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
            }
            Self(fs::canonicalize(path).unwrap())
        }
        fn db(&self) -> PathBuf {
            self.0.join("host.sqlite3")
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn grant(n: u8) -> DeviceGrant {
        DeviceGrant {
            device_key: [n; 32],
            account_id: [1; 16],
            device_id: [n; 16],
            device_name: format!("device {n}"),
            device_kind: "phone".into(),
            ceiling: Permissions::Observe,
            granted_at: 1_000,
            authorization_expires_at: 10 * DAY,
            authorization_epoch: 7,
            server_confirmed_at: 1_000,
            control_confirmed_at: None,
        }
    }

    fn open(dir: &Dir) -> HostStore {
        HostStore::open(&dir.db(), Limits::default()).expect("open store")
    }

    #[test]
    fn device_mode_defaults_to_auto_and_persists() {
        use lomi_remote_protocol::ipc::LocalDeviceMode as M;
        let dir = Dir::new();
        let mut store = open(&dir);
        assert_eq!(store.device_mode().unwrap(), M::Auto);
        store.save_device_mode(M::Confirm).unwrap();
        drop(store);
        assert_eq!(open(&dir).device_mode().unwrap(), M::Confirm);
    }

    #[test]
    fn fresh_database_has_table_and_current_version() {
        let dir = Dir::new();
        let mut store = open(&dir);
        assert_eq!(store.list_grants().unwrap(), vec![]);
        store.upsert_grant(&grant(1)).unwrap();
        drop(store);
        let db = Connection::open(dir.db()).unwrap();
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, VERSION);
        assert_eq!(version, DEVICE_GRANTS_SCHEMA);
    }

    #[test]
    fn migration_adds_table_and_preserves_data() {
        let dir = Dir::new();
        let mut store = open(&dir);
        store.upsert_grant(&grant(1)).unwrap();
        drop(store);
        let db = Connection::open(dir.db()).unwrap();
        db.execute_batch(
            "INSERT INTO metadata(key,value) VALUES('grants_test_marker','keep'); DROP TABLE device_grants;",
        )
        .unwrap();
        db.pragma_update(None, "user_version", DEVICE_GRANTS_SCHEMA - 1)
            .unwrap();
        drop(db);
        let mut store = open(&dir);
        assert_eq!(store.list_grants().unwrap(), vec![]);
        store.upsert_grant(&grant(2)).unwrap();
        drop(store);
        let db = Connection::open(dir.db()).unwrap();
        let version: i64 = db
            .pragma_query_value(None, "user_version", |r| r.get(0))
            .unwrap();
        assert_eq!(version, DEVICE_GRANTS_SCHEMA);
        let marker: String = db
            .query_row(
                "SELECT value FROM metadata WHERE key='grants_test_marker'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(marker, "keep");
        assert!(
            dir.0
                .join(format!("host.before-v{DEVICE_GRANTS_SCHEMA}.sqlite"))
                .exists()
        );
    }

    #[test]
    fn crud_and_upsert_refresh() {
        let dir = Dir::new();
        let mut store = open(&dir);
        assert_eq!(store.get_grant(&[1; 32]).unwrap(), None);
        store.upsert_grant(&grant(1)).unwrap();
        assert_eq!(store.get_grant(&[1; 32]).unwrap(), Some(grant(1)));
        store.confirm_control(&[1; 32], 2_000).unwrap();
        assert_eq!(
            store.confirm_control(&[9; 32], 2_000),
            Err(StoreError::NotFound)
        );
        // Refresh keeps granted_at and control confirmation for the same account.
        let mut refreshed = grant(1);
        refreshed.granted_at = 5_000;
        refreshed.ceiling = Permissions::Control;
        refreshed.authorization_epoch = 8;
        refreshed.server_confirmed_at = 6_000;
        store.upsert_grant(&refreshed).unwrap();
        let stored = store.get_grant(&[1; 32]).unwrap().unwrap();
        assert_eq!(stored.granted_at, 1_000);
        assert_eq!(stored.control_confirmed_at, Some(2_000));
        assert_eq!(stored.ceiling, Permissions::Control);
        assert_eq!(stored.authorization_epoch, 8);
        assert_eq!(stored.server_confirmed_at, 6_000);
        // A different account loses the control confirmation.
        let mut moved = grant(1);
        moved.account_id = [2; 16];
        store.upsert_grant(&moved).unwrap();
        assert_eq!(
            store
                .get_grant(&[1; 32])
                .unwrap()
                .unwrap()
                .control_confirmed_at,
            None
        );
        assert!(store.revoke(&[1; 32]).unwrap());
        assert!(!store.revoke(&[1; 32]).unwrap());
        assert_eq!(store.list_grants().unwrap(), vec![]);
    }

    #[test]
    fn rejects_oversized_metadata() {
        let dir = Dir::new();
        let mut store = open(&dir);
        let mut g = grant(1);
        g.device_name = "x".repeat(256);
        assert_eq!(store.upsert_grant(&g), Err(StoreError::Invalid));
    }

    #[test]
    fn sixteen_grant_limit_without_eviction() {
        let dir = Dir::new();
        let mut store = open(&dir);
        for n in 0..16 {
            store.upsert_grant(&grant(n)).unwrap();
        }
        assert_eq!(
            store.upsert_grant(&grant(16)),
            Err(StoreError::DeviceGrantsFull)
        );
        assert_eq!(store.list_grants().unwrap().len(), 16);
        // Refreshing an existing device still works when full.
        store.upsert_grant(&grant(3)).unwrap();
        assert!(store.revoke(&[0; 32]).unwrap());
        store.upsert_grant(&grant(16)).unwrap();
    }

    #[test]
    fn validity_edges() {
        let g = grant(1); // confirmed at 1_000, authorization until 10 days
        assert!(g.is_valid(1_000 + DAY));
        assert!(!g.is_valid(1_000 + DAY + 1));
        let mut g = g;
        g.authorization_expires_at = 5_000;
        assert!(g.is_valid(4_999));
        assert!(!g.is_valid(5_000));
        assert!(!g.is_valid(5_001));
    }

    #[test]
    fn bulk_confirm_refreshes_only_listed() {
        let dir = Dir::new();
        let mut store = open(&dir);
        for n in 1..=3 {
            store.upsert_grant(&grant(n)).unwrap();
        }
        let changed = store
            .mark_server_confirmed(&[[1; 32], [3; 32], [9; 32]], 9_000)
            .unwrap();
        assert_eq!(changed, 2);
        let at = |n: u8| {
            store
                .get_grant(&[n; 32])
                .unwrap()
                .unwrap()
                .server_confirmed_at
        };
        assert_eq!((at(1), at(2), at(3)), (9_000, 1_000, 9_000));
    }

    #[test]
    fn revoke_not_in_list_is_scoped_to_the_account() {
        let dir = Dir::new();
        let mut store = open(&dir);
        for n in 1..=3 {
            store.upsert_grant(&grant(n)).unwrap();
        }
        let mut other = grant(4);
        other.account_id = [2; 16];
        store.upsert_grant(&other).unwrap();
        let deleted = store
            .revoke_account_devices_not_in(&[1; 16], &[[2; 32]])
            .unwrap();
        assert_eq!(deleted, 2);
        let keys: Vec<_> = store
            .list_grants()
            .unwrap()
            .iter()
            .map(|g| g.device_key[0])
            .collect();
        assert_eq!(keys, vec![2, 4]);
    }
}
