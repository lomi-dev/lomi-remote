//! Unix public-config coordination records; never a credential representation.
use super::*;
use lomi_platform::public_config::{self, Configuration, MAX_BYTES};

const KEY: &str = "public_configuration_v1";
const MARKER: &str = "public_configuration_migrated_v1";
// Return a fixed-size scalar. SQLite TEXT length stops at NUL; never return a
// stored marker String before verifying its exact byte representation.
const MARKER_QUERY: &str = "SELECT CASE WHEN length(CAST(value AS BLOB))=1 AND value='1' THEN 1 ELSE 0 END FROM metadata WHERE key=?1";
const MAX_STATE_BYTES: usize = 3 * MAX_BYTES * 6 + 8192;

/// Exact UTF-8 source plus digest; decoding always checks the canonical DTO.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicDocument {
    content: String,
    sha256: String,
}
impl PublicDocument {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        public_config::decode(bytes).map_err(|_| StoreError::Invalid)?;
        Ok(Self {
            content: std::str::from_utf8(bytes)
                .map_err(|_| StoreError::Invalid)?
                .to_owned(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
        })
    }
    pub fn encode(configuration: &Configuration) -> Result<Self> {
        Self::from_bytes(&public_config::encode(configuration).map_err(|_| StoreError::Invalid)?)
    }
    pub fn bytes(&self) -> &[u8] {
        self.content.as_bytes()
    }
    pub fn configuration(&self) -> Result<Configuration> {
        if self.content.len() > MAX_BYTES
            || self.sha256.len() != 64
            || self.sha256 != format!("{:x}", Sha256::digest(self.content.as_bytes()))
        {
            return Err(StoreError::Storage);
        }
        public_config::decode(self.bytes()).map_err(|_| StoreError::Storage)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PublicPreparationKind {
    Migrate,
    Configure,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPreparation {
    pub operation_id: OperationId,
    pub kind: PublicPreparationKind,
    pub expected: Option<PublicDocument>,
    pub desired: PublicDocument,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicConfigurationState {
    version: u32,
    pub current: Option<PublicDocument>,
    pub prepared: Option<PublicPreparation>,
}
impl PublicConfigurationState {
    fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(StoreError::Storage);
        }
        if let Some(current) = &self.current {
            current.configuration()?;
        }
        match (&self.current, &self.prepared) {
            (None, None) => return Err(StoreError::Storage),
            (current, Some(intent)) => {
                let desired = intent.desired.configuration()?;
                if let Some(expected) = &intent.expected {
                    expected.configuration()?;
                }
                match intent.kind {
                    PublicPreparationKind::Migrate => {
                        if current.is_some() {
                            return Err(StoreError::Storage);
                        }
                        match &intent.expected {
                            Some(expected) if expected != &intent.desired => {
                                return Err(StoreError::Storage);
                            }
                            None if desired.revision != 1 => return Err(StoreError::Storage),
                            _ => {}
                        }
                    }
                    PublicPreparationKind::Configure => {
                        if current.is_none() || current != &intent.expected {
                            return Err(StoreError::Storage);
                        }
                        let revision = intent
                            .expected
                            .as_ref()
                            .ok_or(StoreError::Storage)?
                            .configuration()?
                            .revision;
                        if revision.checked_add(1) != Some(desired.revision) {
                            return Err(StoreError::Storage);
                        }
                    }
                }
            }
            (Some(_), None) => {}
        }
        Ok(())
    }
}
fn state(db: &Connection) -> Result<Option<PublicConfigurationState>> {
    let marker: Option<i64> = db
        .query_row(MARKER_QUERY, [MARKER], |row| row.get(0))
        .optional()?;
    if marker.is_some_and(|value| value != 1) {
        return Err(StoreError::Storage);
    }
    let value: Option<String> = db.query_row(
        "SELECT CASE WHEN length(CAST(value AS BLOB))<=?2 THEN value ELSE '' END FROM metadata WHERE key=?1",
        params![KEY, MAX_STATE_BYTES as i64], |row| row.get(0)).optional()?;
    if value.is_none() && marker.is_some() {
        return Err(StoreError::Storage);
    }
    value
        .map(|text| {
            let value: PublicConfigurationState =
                serde_json::from_str(&text).map_err(|_| StoreError::Storage)?;
            value.validate()?;
            if value.current.is_some() != marker.is_some() {
                return Err(StoreError::Storage);
            }
            let binding = HostStore::read_auth_configuration(db)?;
            if let Some(current) = &value.current
                && current.configuration()?.authentication != binding
            {
                return Err(StoreError::Storage);
            }
            if let Some(intent) = &value.prepared {
                match intent.kind {
                    PublicPreparationKind::Migrate => {
                        if intent.desired.configuration()?.authentication != binding {
                            return Err(StoreError::Storage);
                        }
                    }
                    PublicPreparationKind::Configure => {
                        transition(&binding, &intent.desired.configuration()?.authentication)?
                    }
                }
            }
            Ok(value)
        })
        .transpose()
}
fn save(tx: &Transaction<'_>, value: &PublicConfigurationState) -> Result<()> {
    value.validate()?;
    let text = serde_json::to_string(value).map_err(|_| StoreError::Storage)?;
    if text.len() > MAX_STATE_BYTES {
        return Err(StoreError::Storage);
    }
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![KEY,text])?;
    Ok(())
}
/// Mirrors the legacy immutable binding and independent first-fill rules.
fn transition(
    existing: &Option<ipc::LocalAuthConfiguration>,
    next: &Option<ipc::LocalAuthConfiguration>,
) -> Result<()> {
    if let Some(next) = next {
        next.validate().map_err(|_| StoreError::Invalid)?;
    }
    if let Some(mut previous) = existing.clone() {
        let next = next.as_ref().ok_or(StoreError::IdempotencyConflict)?;
        if previous.remote_api_origin.is_none() {
            previous.remote_api_origin = next.remote_api_origin.clone();
        }
        if previous.relay_endpoint.is_none() {
            previous.relay_endpoint = next.relay_endpoint.clone();
        }
        if previous != *next {
            return Err(StoreError::IdempotencyConflict);
        }
    }
    Ok(())
}

impl HostStore {
    pub fn public_block(&mut self) {
        self.public_configuration = None;
        self.seal_authorization();
    }
    pub fn public_configuration_state(&self) -> Result<Option<PublicConfigurationState>> {
        state(&self.db)
    }
    pub fn public_configuration_ready(&self) -> Result<bool> {
        let Some(state) = state(&self.db)? else {
            return Ok(false);
        };
        Ok(state.prepared.is_none()
            && state.current.as_ref() == self.public_configuration.as_ref()
            && self.public_configuration.is_some())
    }
    pub fn public_legacy_binding(&self) -> Result<Option<ipc::LocalAuthConfiguration>> {
        if state(&self.db)?.is_some() {
            return Err(StoreError::Fenced);
        }
        Self::read_auth_configuration(&self.db)
    }
    pub fn public_current(&self) -> Result<PublicDocument> {
        if !self.public_configuration_ready()? {
            return Err(StoreError::Fenced);
        }
        self.public_configuration.clone().ok_or(StoreError::Fenced)
    }
    /// Must follow exact file validation and file+directory durability confirmation.
    pub fn public_accept_current(&mut self, observed: &PublicDocument) -> Result<()> {
        self.public_configuration = None;
        let state = state(&self.db)?.ok_or(StoreError::Fenced)?;
        if state.prepared.is_some() || state.current.as_ref() != Some(observed) {
            return Err(StoreError::Fenced);
        }
        observed.configuration()?;
        self.public_configuration = Some(observed.clone());
        Ok(())
    }
    /// Durable preparation is committed before callers may publish any file.
    pub fn public_prepare(
        &mut self,
        expected: Option<&PublicDocument>,
        desired: &PublicDocument,
    ) -> Result<PublicPreparation> {
        let next = desired.configuration()?;
        let ready = self.public_configuration_ready()?;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing = state(&tx)?;
        let binding = Self::read_auth_configuration(&tx)?;
        let (kind, current) = match existing {
            None => {
                if next.authentication != binding
                    || expected.is_some_and(|old| old != desired)
                    || (expected.is_none() && next.revision != 1)
                {
                    return Err(StoreError::IdempotencyConflict);
                }
                (PublicPreparationKind::Migrate, None)
            }
            Some(state) => {
                if !ready || state.prepared.is_some() || state.current.as_ref() != expected {
                    return Err(StoreError::Fenced);
                }
                transition(&binding, &next.authentication)?;
                (PublicPreparationKind::Configure, state.current)
            }
        };
        let intent = PublicPreparation {
            operation_id: OperationId::from_bytes(Uuid::new_v4().into_bytes())
                .map_err(|_| StoreError::Invalid)?,
            kind,
            expected: expected.cloned(),
            desired: desired.clone(),
        };
        save(
            &tx,
            &PublicConfigurationState {
                version: 1,
                current,
                prepared: Some(intent.clone()),
            },
        )?;
        // Clear before commit: a failed commit must never preserve a ready cache.
        self.public_configuration = None;
        tx.commit()?;
        Ok(intent)
    }
    /// Caller proves exact durable file publication; no generation is inferred.
    pub fn public_finish(
        &mut self,
        operation_id: OperationId,
        observed: &PublicDocument,
    ) -> Result<()> {
        self.public_configuration = None;
        let tx = self
            .db
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let state = state(&tx)?.ok_or(StoreError::Fenced)?;
        let intent = state.prepared.ok_or(StoreError::Fenced)?;
        if intent.operation_id != operation_id || &intent.desired != observed {
            return Err(StoreError::Fenced);
        }
        let desired = observed.configuration()?;
        if let Some(configuration) = &desired.authentication {
            tx.execute("INSERT INTO metadata(key,value) VALUES('auth_configuration',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value", [json(configuration)?])?;
        }
        save(
            &tx,
            &PublicConfigurationState {
                version: 1,
                current: Some(observed.clone()),
                prepared: None,
            },
        )?;
        tx.execute("INSERT INTO metadata(key,value) VALUES(?1,'1') ON CONFLICT(key) DO UPDATE SET value=excluded.value", [MARKER])?;
        tx.commit()?;
        self.public_configuration = Some(observed.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests;
