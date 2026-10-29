//! Foundation identifiers. These types do not change cryptographic CBOR encoding.
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

const UUID_PATTERN: &str = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
fn parse_uuid(s: &str) -> Result<[u8; 16], &'static str> {
    if s.len() != 36 {
        return Err("expected canonical lowercase hyphenated UUID");
    }
    let mut bytes = [0u8; 16];
    let mut nibble = 0;
    for (i, b) in s.bytes().enumerate() {
        if [8, 13, 18, 23].contains(&i) {
            if b != b'-' {
                return Err("expected UUID separator");
            }
            continue;
        }
        let value = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => return Err("expected lowercase UUID hex"),
        };
        bytes[nibble / 2] |= value << if nibble % 2 == 0 { 4 } else { 0 };
        nibble += 1;
    }
    if bytes == [0; 16] {
        return Err("nil UUID is forbidden");
    }
    Ok(bytes)
}
fn uuid_text(bytes: [u8; 16]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    )
}
macro_rules! uuid_ids {
    ($($name:ident),+ $(,)?) => { $(
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; 16]);
        impl $name {
            pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, &'static str> {
                if bytes == [0; 16] { Err("nil UUID is forbidden") } else { Ok(Self(bytes)) }
            }
            pub fn to_bytes(self) -> [u8; 16] { self.0 }
        }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> { parse_uuid(&s).map(Self) }
        }
        impl From<$name> for String { fn from(id: $name) -> Self { uuid_text(id.0) } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({"type":"string", "pattern":UUID_PATTERN, "minLength":36, "maxLength":36, "not":{"const":"00000000-0000-0000-0000-000000000000"}})
            }
        }
    )+ };
}
uuid_ids!(
    AccountId,
    HostId,
    HostAuthorizationId,
    ConsumerAuthorizationId,
    WindowIdentityId,
    GrantId,
    WorkspaceId,
    WorkspaceEpoch,
    RuntimeId,
    OperationId,
    ChannelId,
    PaneId,
    TerminalSessionId,
    SessionEpoch,
    TabId,
    EntryId,
    RepositoryId,
    PairingId,
    EnrollmentId
);

macro_rules! opaque_tokens {
    ($($name:ident: $limit:literal),+ $(,)?) => { $(
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name { pub fn as_str(&self) -> &str { &self.0 } }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                if s.is_empty() || s.len() > $limit || !s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
                    Err("expected bounded ASCII alphanumeric/underscore/hyphen token")
                } else { Ok(Self(s)) }
            }
        }
        impl From<$name> for String { fn from(token: $name) -> Self { token.0 } }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({"type":"string", "pattern":"^[A-Za-z0-9_-]+$", "not":{"pattern":"[^A-Za-z0-9_-]"}, "minLength":1, "maxLength":$limit})
            }
        }
    )+ };
}
opaque_tokens!(RequestId:128, AccountSessionId:128, EventCursor:1024, FileRevision:256, RepoStateToken:256);
