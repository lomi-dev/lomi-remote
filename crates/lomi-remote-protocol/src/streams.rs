//! Ordered application streams. These DTOs do not implement the atomic coordinator.
//! Workspace event, terminal, watch, input and resize sequences are distinct types.
//! Chunk bytes are opaque serialized experimental grid state, never a client-side
//! parser replay of raw PTY output. Binary transport carries bytes without base64;
//! JSON arrays here provide schema/fixture representation. Reassembly is capped at
//! 8 MiB, chunks at 16 KiB. A transport must enforce its assembly deadline and RAM
//! budget before allocation and delay live events until complete validation/apply.
use crate::rpc::dto;
use crate::rpc::*;
use crate::*;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Bounded absolute path reported by a Host shell through OSC 7. This is
/// advisory terminal metadata and never conveys workspace authority.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkingDirectory(String);
impl std::fmt::Debug for WorkingDirectory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WorkingDirectory([REDACTED])")
    }
}
impl WorkingDirectory {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl TryFrom<String> for WorkingDirectory {
    type Error = &'static str;
    fn try_from(path: String) -> Result<Self, Self::Error> {
        let units = path.encode_utf16().count();
        let absolute_posix = path.starts_with('/') && !path.starts_with("//");
        let bytes = path.as_bytes();
        let absolute_windows = bytes.len() >= 3
            && bytes[0].is_ascii_alphabetic()
            && bytes[1] == b':'
            && matches!(bytes[2], b'/' | b'\\');
        if path.is_empty()
            || units > 4096
            || path.chars().any(char::is_control)
            || (!absolute_posix && !absolute_windows)
            || path
                .split(['/', '\\'])
                .any(|part| part == "." || part == "..")
            || path.starts_with("\\\\")
        {
            return Err("invalid bounded absolute working directory");
        }
        Ok(Self(path))
    }
}
impl From<WorkingDirectory> for String {
    fn from(path: WorkingDirectory) -> Self {
        path.0
    }
}
impl JsonSchema for WorkingDirectory {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "WorkingDirectory".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "minLength": 1,
            "maxLength": 4096,
            "x-lomi-maxUtf16CodeUnits": 4096,
            "not": { "pattern": r"[\u0000-\u001F\u007F-\u009F]" }
        })
    }
}

/// Required JSON member whose value is either a bounded Host path or null.
/// Keeping the nullable value non-Option at the DTO field level makes generated
/// schemas require the member while preserving explicit null as a clear signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(into = "Option<String>")]
pub struct WorkingDirectoryValue(Option<WorkingDirectory>);
impl WorkingDirectoryValue {
    pub fn as_ref(&self) -> Option<&WorkingDirectory> {
        self.0.as_ref()
    }
}
impl TryFrom<Option<String>> for WorkingDirectoryValue {
    type Error = &'static str;
    fn try_from(value: Option<String>) -> Result<Self, Self::Error> {
        value.map(WorkingDirectory::try_from).transpose().map(Self)
    }
}
impl From<WorkingDirectoryValue> for Option<String> {
    fn from(value: WorkingDirectoryValue) -> Self {
        value.0.map(String::from)
    }
}
impl<'de> Deserialize<'de> for WorkingDirectoryValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct WorkingDirectoryVisitor;

        impl<'de> serde::de::Visitor<'de> for WorkingDirectoryVisitor {
            type Value = WorkingDirectoryValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an absolute Host path string or null")
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(WorkingDirectoryValue(None))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(WorkingDirectoryValue(None))
            }

            fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                String::deserialize(deserializer).and_then(Self::from_string)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::from_string(value.to_owned())
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Self::from_string(value)
            }
        }

        impl WorkingDirectoryVisitor {
            fn from_string<E>(value: String) -> Result<WorkingDirectoryValue, E>
            where
                E: serde::de::Error,
            {
                WorkingDirectory::try_from(value)
                    .map(|path| WorkingDirectoryValue(Some(path)))
                    .map_err(E::custom)
            }
        }

        // `missing_field`'s deserializer errors from `deserialize_any`, while
        // JSON null reaches `visit_unit`; this keeps required null distinct from
        // an omitted DTO member.
        deserializer.deserialize_any(WorkingDirectoryVisitor)
    }
}
impl From<Option<WorkingDirectory>> for WorkingDirectoryValue {
    fn from(value: Option<WorkingDirectory>) -> Self {
        Self(value)
    }
}
impl JsonSchema for WorkingDirectoryValue {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "WorkingDirectoryValue".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "An absolute Host path or null when unknown",
            "anyOf": [
                {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 4096,
                    "x-lomi-maxUtf16CodeUnits": 4096,
                    "not": { "pattern": r"[\u0000-\u001F\u007F-\u009F]" }
                },
                { "type": "null" }
            ]
        })
    }
}

macro_rules! sequence {($($name:ident),+)=>{$(
    #[derive(Debug,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,Serialize,Deserialize,JsonSchema)]
    #[serde(transparent)]
    pub struct $name(pub DecimalU64);
)+}}
sequence!(
    WorkspaceEventSeq,
    TerminalSeq,
    WatchSeq,
    InputSeq,
    ResizeSeq
);

dto!(WorkspaceSnapshotMetadata {
    context: WorkspaceContext,
    domain_revision: DecimalU64,
    subscription_id: SubscriptionId,
    through_seq: WorkspaceEventSeq,
    cursor: EventCursor,
    chunk_count: ChunkCount,
    total_bytes: DecimalU64
});
dto!(WorkspaceSnapshotChunk {
    subscription_id:SubscriptionId,index:ChunkIndex,bytes:BoundedList<u8,16384>
});
dto!(WorkspaceSnapshotComplete {
    subscription_id: SubscriptionId,
    through_seq: WorkspaceEventSeq,
    cursor: EventCursor
});
dto!(WorkspaceEvent {
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    event_seq: WorkspaceEventSeq,
    cursor: EventCursor,
    data: WorkspaceEventData
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "kind", content = "data", deny_unknown_fields)]
pub enum WorkspaceEventData {
    #[serde(rename = "workspace.changed")]
    WorkspaceChanged(WorkspaceChanged),
    #[serde(rename = "operation.changed")]
    OperationChanged(OperationReceipt),
    #[serde(rename = "files.invalidated")]
    FilesInvalidated(FilesInvalidated),
    #[serde(rename = "git.invalidated")]
    GitInvalidated(GitInvalidated),
    #[serde(rename = "terminal.controlChanged")]
    TerminalControlChanged(TerminalControlChanged),
    #[serde(rename = "cursor.advance")]
    CursorAdvance(CursorAdvance),
}
dto!(WorkspaceChanged {domain_revision:DecimalU64,operation_id:Option<OperationId>,state:WorkspaceState});
dto!(FilesInvalidated {entries:BoundedList<EntryId,200>,overflow:bool});
dto!(GitInvalidated {
    repository_id: RepositoryId
});
dto!(TerminalControlChanged {
    terminal: TerminalContext,
    lease_version: DecimalU64,
    controlled: bool
});
// Empty by design: capability filtering must not disclose hidden event payloads.
dto!(CursorAdvance {});
dto!(WorkspaceStreamAck {
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    through_seq: WorkspaceEventSeq,
    cursor: EventCursor
});
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResyncReason {
    Gap,
    StaleCursor,
    WorkspaceEpochChanged,
    RuntimeChanged,
    SessionEpochChanged,
    ProfileChanged,
    SubscriberOverflow,
    WatchOverflow,
    SnapshotInvalid,
    AssemblyTimeout,
}
dto!(WorkspaceResync {
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    reason: ResyncReason
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum WorkspaceStreamFrame {
    SnapshotMetadata(WorkspaceSnapshotMetadata),
    SnapshotChunk(WorkspaceSnapshotChunk),
    SnapshotComplete(WorkspaceSnapshotComplete),
    Event(WorkspaceEvent),
    Ack(WorkspaceStreamAck),
    ResyncRequired(WorkspaceResync),
}

dto!(TerminalSnapshotMetadata {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    through_seq: TerminalSeq,
    output_offset: DecimalU64,
    columns: TerminalDimension,
    rows: TerminalDimension,
    chunk_count: ChunkCount,
    total_bytes: DecimalU64,
    working_directory: WorkingDirectoryValue
});
dto!(TerminalSnapshotChunk {
    terminal:TerminalContext,subscription_id:SubscriptionId,index:ChunkIndex,bytes:BoundedList<u8,16384>
});
dto!(TerminalSnapshotComplete {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    through_seq: TerminalSeq,
    output_offset: DecimalU64
});
// A model delta may contain a full bounded checkpoint; split its serialized
// bytes into chunks rather than forcing a 16 KiB inline Grid representation.
dto!(TerminalDeltaMetadata {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    previous_seq: TerminalSeq,
    through_seq: TerminalSeq,
    chunk_count: ChunkCount,
    total_bytes: DecimalU64,
    working_directory: WorkingDirectoryValue
});
dto!(TerminalDeltaChunk {
    terminal:TerminalContext,subscription_id:SubscriptionId,
    index:ChunkIndex,bytes:BoundedList<u8,16384>
});
dto!(TerminalDeltaComplete {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    through_seq: TerminalSeq
});
dto!(TerminalDelta {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    seq: TerminalSeq,
    change: TerminalChange
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "kind",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum TerminalChange {
    /// Host-produced grid state delta in the named experimental profile.
    Grid(BoundedList<u8, 16384>),
    Resize(TerminalDimensions),
    Exit(TerminalExit),
    ControlChanged(TerminalControlChanged),
}
dto!(TerminalDimensions {
    columns: TerminalDimension,
    rows: TerminalDimension
});
dto!(TerminalExit {exit_code:Option<i32>});
dto!(TerminalResync {
    terminal: TerminalContext,
    subscription_id: SubscriptionId,
    reason: ResyncReason
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum TerminalStreamFrame {
    SnapshotMetadata(TerminalSnapshotMetadata),
    SnapshotChunk(TerminalSnapshotChunk),
    SnapshotComplete(TerminalSnapshotComplete),
    Delta(TerminalDelta),
    DeltaMetadata(TerminalDeltaMetadata),
    DeltaChunk(TerminalDeltaChunk),
    DeltaComplete(TerminalDeltaComplete),
    Ack(TerminalAckParams),
    ResyncRequired(TerminalResync),
}
dto!(FileWatchEvent {
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    watch_seq: WatchSeq,
    cursor: EventCursor,
    invalidation: FilesInvalidated
});
dto!(FileWatchAck {
    context: WorkspaceContext,
    subscription_id: SubscriptionId,
    through_seq: WatchSeq,
    cursor: EventCursor
});
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    content = "data",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum FileWatchFrame {
    Invalidated(FileWatchEvent),
    Ack(FileWatchAck),
    ResyncRequired(WorkspaceResync),
}

pub(crate) fn validate_snapshot_budget(
    count: ChunkCount,
    total: DecimalU64,
) -> Result<(), &'static str> {
    if count.0 == 0
        || count.0 > 1024
        || total.0 == 0
        || total.0 > 8388608
        || total.0 > u64::from(count.0) * 16384
        || total.0 < u64::from(count.0)
    {
        return Err("invalid snapshot chunk/total budget");
    }
    Ok(())
}
fn decode_frame<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, String> {
    if bytes.len() > 1048576 {
        return Err("control frame exceeds 1 MiB".into());
    }
    serde_json::from_slice(bytes).map_err(|e| e.to_string())
}
pub fn decode_workspace_frame(bytes: &[u8]) -> Result<WorkspaceStreamFrame, String> {
    let frame = decode_frame(bytes)?;
    match &frame {
        WorkspaceStreamFrame::SnapshotMetadata(m) => {
            validate_snapshot_budget(m.chunk_count, m.total_bytes)?
        }
        WorkspaceStreamFrame::SnapshotChunk(c) if c.bytes.0.is_empty() => {
            return Err("empty snapshot chunk".into());
        }
        WorkspaceStreamFrame::Event(e) => {
            if e.event_seq.0.0 == 0 {
                return Err("live event seq must be positive".into());
            }
            if let WorkspaceEventData::WorkspaceChanged(change) = &e.data {
                change.state.validate()?;
            }
            match &e.data {
                WorkspaceEventData::WorkspaceChanged(change)
                    if change.state.context != e.context
                        || change.domain_revision != change.state.domain_revision =>
                {
                    return Err("workspace event context/revision mismatch".into());
                }
                WorkspaceEventData::OperationChanged(receipt)
                    if receipt.stored_rights().workspace() != e.context.workspace_id =>
                {
                    return Err("operation event workspace mismatch".into());
                }
                WorkspaceEventData::TerminalControlChanged(control)
                    if control.terminal.workspace != e.context =>
                {
                    return Err("control event workspace mismatch".into());
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(frame)
}
pub fn decode_terminal_frame(bytes: &[u8]) -> Result<TerminalStreamFrame, String> {
    let frame = decode_frame(bytes)?;
    match &frame {
        TerminalStreamFrame::SnapshotMetadata(m) => {
            validate_snapshot_budget(m.chunk_count, m.total_bytes)?
        }
        TerminalStreamFrame::SnapshotChunk(c) if c.bytes.0.is_empty() => {
            return Err("empty terminal snapshot chunk".into());
        }
        TerminalStreamFrame::DeltaMetadata(metadata) => validate_delta_metadata(metadata)?,
        TerminalStreamFrame::DeltaChunk(chunk) if chunk.bytes.0.is_empty() => {
            return Err("empty terminal delta chunk".into());
        }
        TerminalStreamFrame::DeltaComplete(complete) if complete.through_seq.0.0 == 0 => {
            return Err("delta completion sequence must be positive".into());
        }
        TerminalStreamFrame::Delta(d) => {
            if d.seq.0.0 == 0 {
                return Err("live terminal seq must be positive".into());
            }
            match &d.change {
                TerminalChange::ControlChanged(c) if c.terminal != d.terminal => {
                    return Err("terminal delta context mismatch".into());
                }
                _ => {}
            }
        }
        _ => {}
    }
    Ok(frame)
}
pub fn decode_watch_frame(bytes: &[u8]) -> Result<FileWatchFrame, String> {
    let frame = decode_frame(bytes)?;
    if let FileWatchFrame::Invalidated(event) = &frame {
        if event.watch_seq.0.0 == 0 {
            return Err("watch seq must be positive".into());
        }
        if event.invalidation.overflow {
            return Err("watch overflow requires resync".into());
        }
    }
    Ok(frame)
}

/// Optional transport-side sequence guard; independent per subscription/session.
/// A gap is terminal for this guard; create a fresh guard after atomic resync.
#[derive(Debug, Clone)]
pub struct OrderedSequence {
    through: u64,
    resync_required: bool,
}
impl OrderedSequence {
    pub fn new(through: DecimalU64) -> Self {
        Self {
            through: through.0,
            resync_required: false,
        }
    }
    pub fn accept(&mut self, next: DecimalU64) -> Result<bool, ResyncReason> {
        if self.resync_required {
            return Err(ResyncReason::Gap);
        }
        if next.0 == self.through {
            return Ok(false);
        }
        if self.through.checked_add(1) != Some(next.0) {
            self.resync_required = true;
            return Err(ResyncReason::Gap);
        }
        self.through = next.0;
        Ok(true)
    }
}

/// Checked, bounded assembly metadata. Payload application and subscription
/// installation still require the host/client atomic coordinator.
#[derive(Debug)]
pub struct SnapshotAssembly {
    subscription_id: SubscriptionId,
    count: u32,
    next: u32,
    total: u64,
    received: u64,
}
impl SnapshotAssembly {
    pub fn new(
        subscription_id: SubscriptionId,
        count: ChunkCount,
        total: DecimalU64,
    ) -> Result<Self, String> {
        validate_snapshot_budget(count, total)?;
        Ok(Self {
            subscription_id,
            count: count.0,
            next: 0,
            total: total.0,
            received: 0,
        })
    }
    pub fn push(
        &mut self,
        subscription: &SubscriptionId,
        index: ChunkIndex,
        bytes: &[u8],
    ) -> Result<(), String> {
        if subscription != &self.subscription_id
            || index.0 != self.next
            || self.next >= self.count
            || bytes.is_empty()
            || bytes.len() > 16384
            || self.received + bytes.len() as u64 > self.total
        {
            return Err("invalid snapshot chunk ordering/budget".into());
        }
        self.received += bytes.len() as u64;
        self.next += 1;
        Ok(())
    }
    pub fn complete(&self, subscription: &SubscriptionId) -> Result<(), String> {
        if subscription != &self.subscription_id
            || self.next != self.count
            || self.received != self.total
        {
            Err("incomplete snapshot".into())
        } else {
            Ok(())
        }
    }
}

fn validate_delta_metadata(metadata: &TerminalDeltaMetadata) -> Result<(), &'static str> {
    validate_snapshot_budget(metadata.chunk_count, metadata.total_bytes)?;
    if metadata.previous_seq.0.0.checked_add(1) != Some(metadata.through_seq.0.0) {
        return Err("noncontiguous terminal delta metadata");
    }
    Ok(())
}

/// One bounded, in-order delta assembly. A failure poisons this assembly; resync
/// requires a fresh instance. The caller owns assembly deadlines and must abort
/// on expiry/disconnect. Completion verifies framing, not the opaque model's
/// semantics: validate/apply the decoded model before renderer ACK/state advance.
pub struct DeltaAssembly {
    metadata: TerminalDeltaMetadata,
    chunks: SnapshotAssembly,
    bytes: Vec<u8>,
    through: TerminalSeq,
    completed: bool,
    failed: bool,
}
impl std::fmt::Debug for DeltaAssembly {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeltaAssembly")
            .field("metadata", &self.metadata)
            .field("receivedBytes", &self.bytes.len())
            .field("completed", &self.completed)
            .field("failed", &self.failed)
            .finish()
    }
}
impl DeltaAssembly {
    pub fn new(
        metadata: TerminalDeltaMetadata,
        expected_through: TerminalSeq,
    ) -> Result<Self, String> {
        validate_delta_metadata(&metadata)?;
        if metadata.previous_seq != expected_through {
            return Err("delta previous sequence mismatch".into());
        }
        let chunks = SnapshotAssembly::new(
            metadata.subscription_id.clone(),
            metadata.chunk_count,
            metadata.total_bytes,
        )?;
        Ok(Self {
            metadata,
            chunks,
            bytes: Vec::new(),
            through: expected_through,
            completed: false,
            failed: false,
        })
    }
    /// The last completely assembled sequence; unchanged by metadata/chunks.
    pub fn through_seq(&self) -> TerminalSeq {
        self.through
    }
    pub fn abort(&mut self) {
        self.failed = true;
        self.bytes.clear();
    }
    pub fn push(&mut self, chunk: &TerminalDeltaChunk) -> Result<(), String> {
        if self.completed || self.failed || chunk.terminal != self.metadata.terminal {
            self.abort();
            return Err("invalid terminal delta assembly binding/state".into());
        }
        if let Err(error) = self
            .chunks
            .push(&chunk.subscription_id, chunk.index, &chunk.bytes.0)
        {
            self.abort();
            return Err(error);
        }
        self.bytes.extend_from_slice(&chunk.bytes.0);
        Ok(())
    }
    pub fn complete(&mut self, complete: &TerminalDeltaComplete) -> Result<Vec<u8>, String> {
        if self.completed
            || self.failed
            || complete.terminal != self.metadata.terminal
            || complete.subscription_id != self.metadata.subscription_id
            || complete.through_seq != self.metadata.through_seq
        {
            self.abort();
            return Err("invalid terminal delta completion binding/state".into());
        }
        if let Err(error) = self.chunks.complete(&complete.subscription_id) {
            self.abort();
            return Err(error);
        }
        self.completed = true;
        self.through = complete.through_seq;
        Ok(std::mem::take(&mut self.bytes))
    }
}
