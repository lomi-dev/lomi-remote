//! Proposed E0 budgets, not measured platform qualification or an S0.5 freeze.
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};
pub const CONTROL_MESSAGE_BYTES: u64 = 1024 * 1024;
pub const REASSEMBLY_BYTES: u64 = CONTROL_MESSAGE_BYTES;
pub const SNAPSHOT_BYTES: u64 = 8 * 1024 * 1024;
/// Matches crypto MAX_PLAINTEXT; ciphertext adds a 16-byte AEAD tag.
pub const FRAME_PLAINTEXT_BYTES: u64 = 16 * 1024;
pub const FRAME_CIPHERTEXT_BYTES: u64 = FRAME_PLAINTEXT_BYTES + 16;
pub const INPUT_BYTES: u64 = 16 * 1024;
pub const FILE_PREVIEW_BYTES: u64 = 1024 * 1024;
pub const LIST_PAGE_ENTRIES: u64 = 200;
pub const JOURNAL_EVENTS: u64 = 4096;
pub const JOURNAL_RETENTION_SECONDS: u64 = 600;
pub const SUBSCRIBER_QUEUE_BYTES: u64 = 1024 * 1024;
pub const RECEIPT_RETENTION_SECONDS: u64 = 24 * 60 * 60;
pub const REPLAY_BYTES: u64 = 2 * 1024 * 1024;
pub const MAX_FRAMES_PER_CHANNEL: u64 = 1_000_000;
pub const PLATFORM_QUALIFIED: bool = false;
macro_rules! bounded {
    ($name:ident, $min:expr, $max:expr) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "u64", into = "u64")]
        pub struct $name(u64);
        impl $name {
            pub fn new(value: u64) -> Result<Self, &'static str> {
                if ($min..=$max).contains(&value) { Ok(Self(value)) } else { Err("RESOURCE_EXHAUSTED") }
            }
            pub fn get(self) -> u64 { self.0 }
            pub fn checked_add(self, value: u64) -> Result<Self, &'static str> {
                Self::new(self.0.checked_add(value).ok_or("RESOURCE_EXHAUSTED")?)
            }
        }
        impl TryFrom<u64> for $name { type Error = &'static str; fn try_from(value: u64) -> Result<Self, Self::Error> { Self::new(value) } }
        impl From<$name> for u64 { fn from(value: $name) -> u64 { value.0 } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema { json_schema!({"type":"integer","minimum":$min,"maximum":$max}) }
        }
    };
}
bounded!(ControlMessageBytes, 0, CONTROL_MESSAGE_BYTES);
bounded!(ReassemblyBytes, 0, REASSEMBLY_BYTES);
bounded!(SnapshotBytes, 0, SNAPSHOT_BYTES);
bounded!(InputBytes, 0, INPUT_BYTES);
bounded!(FilePreviewBytes, 0, FILE_PREVIEW_BYTES);
bounded!(ListPageSize, 1, LIST_PAGE_ENTRIES);
bounded!(JournalEventCount, 0, JOURNAL_EVENTS);
bounded!(SubscriberQueueBytes, 0, SUBSCRIBER_QUEUE_BYTES);
// Routine draft choice: 1ms..120s request handling, separate from execution.
bounded!(TimeoutMs, 1, 120_000);
