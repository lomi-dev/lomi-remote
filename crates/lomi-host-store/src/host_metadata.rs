//! Durable local Host display metadata. The label is kept in the existing
//! metadata table and is never included in remote RPC configuration.
use super::{HostStore, StoreError};
use lomi_remote_protocol::ipc::LocalHostName;
use rusqlite::{OptionalExtension, TransactionBehavior, params};

const KEY: &str = "host_display_name";
const MAX_HOST_NAME_BYTES: usize = 255;

fn read_name(connection: &rusqlite::Connection) -> Result<Option<LocalHostName>, StoreError> {
    let value: Option<String> = connection
        .query_row(
            "SELECT CASE WHEN length(CAST(value AS BLOB))<=?2 THEN value ELSE '' END \
             FROM metadata WHERE key=?1",
            params![KEY, MAX_HOST_NAME_BYTES as i64],
            |row| row.get(0),
        )
        .optional()?;
    value
        .map(|value| LocalHostName::try_from(value).map_err(|_| StoreError::Storage))
        .transpose()
}

impl HostStore {
    /// Read a previously initialized local display label. Legacy profiles have
    /// no value until startup initializes one under the actual owner lock.
    pub fn host_display_name(&self) -> Result<Option<LocalHostName>, StoreError> {
        read_name(&self.db)
    }

    /// Initialize a legacy profile once. Insert-if-absent runs in an immediate
    /// transaction, so startup can never replace an operator-selected value.
    pub fn initialize_host_display_name(
        &mut self,
        default: LocalHostName,
    ) -> Result<LocalHostName, StoreError> {
        let default =
            LocalHostName::try_from(String::from(default)).map_err(|_| StoreError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO NOTHING",
            params![KEY, default.as_str()],
        )?;
        let name = read_name(&tx)?.ok_or(StoreError::Storage)?;
        tx.commit()?;
        Ok(name)
    }

    /// Compare-and-set the display label. A stale expected value has no effect
    /// and is represented by the existing Store conflict error.
    pub fn set_host_display_name(
        &mut self,
        expected: Option<&LocalHostName>,
        desired: LocalHostName,
    ) -> Result<LocalHostName, StoreError> {
        let desired =
            LocalHostName::try_from(String::from(desired)).map_err(|_| StoreError::Invalid)?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current = read_name(&tx)?;
        if current.as_ref() != expected {
            return Err(StoreError::RevisionConflict);
        }
        if current.as_ref() != Some(&desired) {
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2) \
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![KEY, desired.as_str()],
            )?;
        }
        tx.commit()?;
        Ok(desired)
    }
}
