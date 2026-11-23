//! Chat AI wire types (types only; Host behavior lives elsewhere).
//! Additive to application v2: methods are `chat.*`, the stream is message kind 6.
//! Threads never expose local paths. `u64` values use `DecimalU64` like the rest of
//! the protocol, so JavaScript clients never lose precision.
//! `chat.thread.get` results share the 1 MiB logical message cap with every other
//! response; the schema cannot bound the total, so the Host trims pages to fit.
use crate::message_framing::{MAX_FRAGMENT_PAYLOAD_LEN, MAX_MESSAGE_LEN};
use crate::rpc::{BoundedList, DisplayText, PageLimit, SubscriptionId, dto, text_type};
use crate::streams::ResyncReason;
use crate::{DecimalU64, Method, OperationId};
use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};
use serde::{Deserialize, Serialize};

/// Largest `text` of one snapshot/delta frame; leaves room for JSON framing and escaping.
pub const CHAT_STREAM_TEXT_BYTES: usize = 12 * 1024;
pub const CHAT_SEND_TEXT_BYTES: usize = 64 * 1024;
/// Remote copies of stored messages (up to 2 MiB) are truncated to this size so a
/// message frame or history page fits the 1 MiB logical message cap; `truncated` marks it.
pub const CHAT_MESSAGE_CONTENT_BYTES: usize = 512 * 1024;

macro_rules! hex_ids {
    ($($name:ident),+ $(,)?) => { $(
        /// 32 lowercase hex characters, the desktop chat store id format.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name([u8; 16]);
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                if s.len() != 32 { return Err("expected 32 lowercase hex characters"); }
                let mut bytes = [0u8; 16];
                for (i, b) in s.bytes().enumerate() {
                    let v = match b {
                        b'0'..=b'9' => b - b'0',
                        b'a'..=b'f' => b - b'a' + 10,
                        _ => return Err("expected lowercase hex"),
                    };
                    bytes[i / 2] |= v << if i % 2 == 0 { 4 } else { 0 };
                }
                Ok(Self(bytes))
            }
        }
        impl From<$name> for String {
            fn from(id: $name) -> Self { id.0.iter().map(|b| format!("{b:02x}")).collect() }
        }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> { stringify!($name).into() }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                json_schema!({"type":"string","pattern":"^[0-9a-f]{32}$","not":{"pattern":"[^0-9a-f]"},"minLength":32,"maxLength":32})
            }
        }
    )+ };
}
hex_ids!(ChatThreadId, ChatMessageId);

macro_rules! checked_string {
    ($name:ident, $check:expr, $schema:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);
        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
        impl TryFrom<String> for $name {
            type Error = &'static str;
            fn try_from(s: String) -> Result<Self, Self::Error> {
                let check: fn(&str) -> bool = $check;
                if check(&s) {
                    Ok(Self(s))
                } else {
                    Err("invalid bounded chat string")
                }
            }
        }
        impl From<$name> for String {
            fn from(s: $name) -> Self {
                s.0
            }
        }
        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut SchemaGenerator) -> Schema {
                $schema
            }
        }
    };
}
// Same rules as the desktop settings: valid_model_id, valid_effort and valid_title.
checked_string!(
    ChatModelId,
    |s| (1..=256).contains(&s.chars().count()) && !s.chars().any(char::is_control),
    json_schema!({"type":"string","minLength":1,"maxLength":256,"not":{"pattern":r"[\u0000-\u001F\u007F-\u009F]"}})
);
checked_string!(
    ChatEffort,
    |s| (1..=16).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_lowercase()),
    json_schema!({"type":"string","pattern":"^[a-z]{1,16}$","minLength":1,"maxLength":16})
);
checked_string!(
    ChatTitle,
    |s| (1..=200).contains(&s.chars().count()) && !s.chars().any(char::is_control),
    json_schema!({"type":"string","minLength":1,"maxLength":200,"not":{"pattern":r"[\u0000-\u001F\u007F-\u009F]"}})
);
// Prompt: any text except NUL (newlines and tabs are normal prompt content).
checked_string!(
    ChatText,
    |s| !s.is_empty() && s.len() <= CHAT_SEND_TEXT_BYTES && !s.contains('\0'),
    json_schema!({"type":"string","minLength":1,"maxLength":65536,"x-lomi-maxUtf8Bytes":65536,"not":{"pattern":r"\u0000"}})
);
checked_string!(
    ChatMessageContent,
    |s| s.len() <= CHAT_MESSAGE_CONTENT_BYTES,
    json_schema!({"type":"string","maxLength":524288,"x-lomi-maxUtf8Bytes":524288})
);
// May be empty (a keep-alive style snapshot of a message with no text yet).
checked_string!(
    ChatStreamText,
    |s| s.len() <= CHAT_STREAM_TEXT_BYTES,
    json_schema!({"type":"string","maxLength":12288,"x-lomi-maxUtf8Bytes":12288})
);
text_type!(ChatProviderId, 128, true);
text_type!(ChatName, 256, false);
text_type!(ChatCursor, 256, true);
text_type!(ChatStopReason, 64, true);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChatKind {
    Api,
    Cli,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub enum ChatPermissions {
    #[serde(rename = "read-only")]
    ReadOnly,
    #[serde(rename = "edit")]
    Edit,
    #[serde(rename = "full")]
    Full,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChatWorkspaceMode {
    Project,
    Private,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ChatRole {
    User,
    Assistant,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ChatMessageState {
    Committed,
    Dispatching,
    Streaming,
    Completed,
    Stopped,
    Failed,
    Interrupted,
}

dto!(ChatModel {
    model_id: ChatModelId,
    name: ChatName
});
dto!(ChatProvider {
    provider_id: ChatProviderId,
    kind: ChatKind,
    name: ChatName,
    cli: Option<ChatName>,
    models: BoundedList<ChatModel, 256>,
    efforts: BoundedList<ChatEffort, 16>,
    logged_in: Option<bool>,
    read_only_enforced: bool
});
dto!(ChatThread {
    thread_id: ChatThreadId,
    kind: ChatKind,
    provider_id: ChatProviderId,
    model: ChatModelId,
    title: ChatTitle,
    effort: Option<ChatEffort>,
    permissions: ChatPermissions,
    workspace_mode: ChatWorkspaceMode,
    revision: DecimalU64,
    created_ms: DecimalU64,
    updated_ms: DecimalU64,
    streaming: bool
});
dto!(ChatMessage {
    message_id: ChatMessageId,
    seq: DecimalU64,
    role: ChatRole,
    content: ChatMessageContent,
    truncated: bool,
    state: ChatMessageState,
    provider_id: ChatProviderId,
    model: ChatModelId,
    stream_seq: DecimalU64,
    stop_reason: Option<ChatStopReason>,
    error: Option<DisplayText>,
    created_ms: DecimalU64
});

crate::rpc::bounded_number!(ChatMessagePageLimit, 1, 50);
// 2 MiB of in-progress text in 12 KiB parts.
crate::rpc::bounded_number!(ChatSnapshotPart, 0, 170);

dto!(ChatProvidersParams {});
dto!(ChatProvidersResult {
    providers: BoundedList<ChatProvider, 32>
});
dto!(ChatThreadsListParams {
    cursor: Option<ChatCursor>,
    limit: PageLimit
});
dto!(ChatThreadsListResult {
    threads: BoundedList<ChatThread, 200>,
    next_cursor: Option<ChatCursor>
});
dto!(ChatThreadGetParams {
    thread_id: ChatThreadId,
    before_seq: Option<DecimalU64>,
    limit: ChatMessagePageLimit
});
dto!(ChatThreadGetResult {
    thread: ChatThread,
    messages: BoundedList<ChatMessage, 50>,
    has_more: bool
});
dto!(ChatStreamCursor {
    message_id: ChatMessageId,
    stream_seq: DecimalU64
});
// Replaces the connection's previous chat subscription.
dto!(ChatSubscribeParams {
    thread_id: Option<ChatThreadId>,
    after: Option<ChatStreamCursor>
});
dto!(ChatSubscribeResult {
    subscription_id: SubscriptionId
});
dto!(ChatThreadCreateParams {
    operation_id: OperationId,
    provider_id: ChatProviderId,
    model: ChatModelId,
    effort: Option<ChatEffort>,
    permissions: ChatPermissions,
    workspace_mode: ChatWorkspaceMode,
    title: Option<ChatTitle>
});
dto!(ChatThreadResult { thread: ChatThread });

/// Omitted fields stay unchanged; `effort: null` clears it back to the provider default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ChatThreadUpdateParams {
    pub operation_id: OperationId,
    pub thread_id: ChatThreadId,
    pub expected_revision: DecimalU64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<ChatTitle>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ChatModelId>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effort: Option<Option<ChatEffort>>,
}
impl<'de> Deserialize<'de> for ChatThreadUpdateParams {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase", deny_unknown_fields)]
        struct Wire {
            operation_id: OperationId,
            thread_id: ChatThreadId,
            expected_revision: DecimalU64,
            #[serde(default)]
            title: Option<ChatTitle>,
            #[serde(default)]
            model: Option<ChatModelId>,
            #[serde(default, deserialize_with = "set_or_clear")]
            effort: Option<Option<ChatEffort>>,
        }
        let w: Wire = crate::rpc::deserialize_object(deserializer)?;
        Ok(Self {
            operation_id: w.operation_id,
            thread_id: w.thread_id,
            expected_revision: w.expected_revision,
            title: w.title,
            model: w.model,
            effort: w.effort,
        })
    }
}
fn set_or_clear<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Option<ChatEffort>>, D::Error> {
    Option::<ChatEffort>::deserialize(d).map(Some)
}

dto!(ChatThreadDeleteParams {
    operation_id: OperationId,
    thread_id: ChatThreadId,
    expected_revision: DecimalU64
});
dto!(ChatThreadDeleteResult {});
dto!(ChatSendParams {
    operation_id: OperationId,
    thread_id: ChatThreadId,
    expected_revision: DecimalU64,
    text: ChatText
});
dto!(ChatSendResult {
    thread: ChatThread,
    user: ChatMessage,
    assistant: ChatMessage
});
dto!(ChatStopParams {
    thread_id: ChatThreadId
});

/// Chat mutations are idempotent by the `operationId` in their params. They have no
/// workspace-bound operation receipt, so effectful errors carry `operationId` only.
pub fn is_chat_mutation(method: Method) -> bool {
    matches!(
        method,
        Method::ChatThreadCreate
            | Method::ChatThreadUpdate
            | Method::ChatThreadDelete
            | Method::ChatSend
    )
}

/// Kind 6 stream frames. Snapshot and delta frames must fit one plaintext frame
/// (`MAX_FRAGMENT_PAYLOAD_LEN`); `message` and `thread` may span fragments up to the
/// 1 MiB logical message cap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(
    tag = "type",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ChatStreamFrame {
    Snapshot {
        message_id: ChatMessageId,
        state: ChatMessageState,
        stream_seq: DecimalU64,
        part: ChatSnapshotPart,
        last: bool,
        text: ChatStreamText,
    },
    Delta {
        message_id: ChatMessageId,
        seq: DecimalU64,
        text: ChatStreamText,
    },
    Message {
        message: ChatMessage,
    },
    Thread {
        thread: ChatThread,
    },
    ThreadDeleted {
        thread_id: ChatThreadId,
    },
    Resync {
        reason: ResyncReason,
    },
}

pub fn decode_chat_frame(bytes: &[u8]) -> Result<ChatStreamFrame, String> {
    if bytes.len() > MAX_MESSAGE_LEN {
        return Err("control frame exceeds 1 MiB".into());
    }
    let frame: ChatStreamFrame = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if let ChatStreamFrame::Delta { seq, text, .. } = &frame
        && (seq.0 == 0 || text.as_str().is_empty())
    {
        return Err("delta needs a positive seq and text".into());
    }
    // Escaping can expand text, so the encoded frame is checked as well as the text.
    if matches!(
        frame,
        ChatStreamFrame::Snapshot { .. }
            | ChatStreamFrame::Delta { .. }
            | ChatStreamFrame::Resync { .. }
            | ChatStreamFrame::ThreadDeleted { .. }
    ) && bytes.len() > MAX_FRAGMENT_PAYLOAD_LEN
    {
        return Err("chat frame exceeds one plaintext frame".into());
    }
    Ok(frame)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Capability, CapabilitySet, RpcCall, RpcResult, decode_request, http::PublishedWorkspace,
    };
    use serde_json::json;

    const OP: &str = "11111111-1111-4111-8111-111111111111";
    const TID: &str = "0123456789abcdef0123456789abcdef";

    fn request(method: &str, params: serde_json::Value) -> Result<crate::RpcRequest, String> {
        let body = json!({"v":2,"type":"request","requestId":"r1","timeoutMs":1000,
            "call":{"method":method,"params":params}});
        decode_request(body.to_string().as_bytes())
    }
    fn thread() -> serde_json::Value {
        json!({"threadId":TID,"kind":"cli","providerId":"claude","model":"m","title":"t",
            "effort":null,"permissions":"read-only","workspaceMode":"private",
            "revision":"1","createdMs":"1","updatedMs":"2","streaming":false})
    }
    fn message(content: &str) -> serde_json::Value {
        json!({"messageId":TID,"seq":"1","role":"assistant","content":content,"truncated":false,"state":"streaming",
            "providerId":"claude","model":"m","streamSeq":"0","stopReason":null,"error":null,"createdMs":"1"})
    }

    #[test]
    fn capability_names_and_dependencies() {
        let names = [
            (
                Capability::ChatRead,
                "chat.read",
                vec![Capability::WorkspaceRead],
            ),
            (
                Capability::ChatSend,
                "chat.send",
                vec![Capability::WorkspaceRead, Capability::ChatRead],
            ),
            (
                Capability::ChatPermissionsEdit,
                "chat.permissions.edit",
                vec![
                    Capability::WorkspaceRead,
                    Capability::ChatRead,
                    Capability::ChatSend,
                ],
            ),
            (
                Capability::ChatPermissionsFull,
                "chat.permissions.full",
                vec![
                    Capability::WorkspaceRead,
                    Capability::ChatRead,
                    Capability::ChatSend,
                    Capability::ChatPermissionsEdit,
                ],
            ),
        ];
        for (cap, name, deps) in names {
            assert_eq!(serde_json::to_value(cap).unwrap(), json!(name));
            assert_eq!(cap.dependencies(), deps.as_slice());
            assert!(Capability::ALL.contains(&cap));
        }
        let default = CapabilitySet::control_with_workspace_tools();
        assert!(
            Capability::ALL
                .iter()
                .filter(|c| c.is_chat())
                .all(|c| !default.contains(*c))
        );
        let chat = CapabilitySet::try_from(vec![
            Capability::WorkspaceRead,
            Capability::ChatRead,
            Capability::ChatSend,
        ])
        .unwrap();
        assert!(default.union(&chat).contains(Capability::ChatSend));
        assert!(CapabilitySet::try_from(vec![Capability::ChatSend]).is_err());
    }

    #[test]
    fn chat_method_rights() {
        let read = [Capability::WorkspaceRead, Capability::ChatRead];
        assert_eq!(
            crate::required_capabilities("chat.providers"),
            Some(&read[..])
        );
        assert_eq!(
            crate::required_capabilities("chat.stop"),
            Some(
                &[
                    Capability::WorkspaceRead,
                    Capability::ChatRead,
                    Capability::ChatSend
                ][..]
            )
        );
    }

    #[test]
    fn every_request_decodes_and_rejects_unknown_fields() {
        let cases = [
            ("chat.providers", json!({})),
            ("chat.threads.list", json!({"cursor":null,"limit":10})),
            (
                "chat.thread.get",
                json!({"threadId":TID,"beforeSeq":"5","limit":50}),
            ),
            (
                "chat.subscribe",
                json!({"threadId":TID,"after":{"messageId":TID,"streamSeq":"3"}}),
            ),
            (
                "chat.thread.create",
                json!({"operationId":OP,"providerId":"claude","model":"m","effort":"high",
                    "permissions":"edit","workspaceMode":"project","title":null}),
            ),
            (
                "chat.thread.update",
                json!({"operationId":OP,"threadId":TID,"expectedRevision":"1","effort":null}),
            ),
            (
                "chat.thread.delete",
                json!({"operationId":OP,"threadId":TID,"expectedRevision":"1"}),
            ),
            (
                "chat.send",
                json!({"operationId":OP,"threadId":TID,"expectedRevision":"1","text":"hi"}),
            ),
            ("chat.stop", json!({"threadId":TID})),
        ];
        for (method, params) in cases {
            let decoded =
                request(method, params.clone()).unwrap_or_else(|e| panic!("{method}: {e}"));
            assert_eq!(decoded.call.method().as_str(), method);
            let mut extra = params;
            extra["bogus"] = json!(1);
            assert!(
                request(method, extra).is_err(),
                "{method} accepted unknown field"
            );
        }
    }

    #[test]
    fn update_distinguishes_absent_and_null_effort() {
        let call = |p| match request("chat.thread.update", p).unwrap().call {
            RpcCall::ChatThreadUpdate(u) => u,
            _ => unreachable!(),
        };
        let base = json!({"operationId":OP,"threadId":TID,"expectedRevision":"1"});
        assert_eq!(call(base.clone()).effort, None);
        let mut cleared = base.clone();
        cleared["effort"] = json!(null);
        let cleared = call(cleared);
        assert_eq!(cleared.effort, Some(None));
        assert_eq!(
            serde_json::to_value(&cleared).unwrap()["effort"],
            json!(null)
        );
        assert!(
            serde_json::to_value(call(base))
                .unwrap()
                .get("effort")
                .is_none()
        );
    }

    #[test]
    fn input_bounds() {
        let send = |text: &str, tid: &str| {
            request(
                "chat.send",
                json!({"operationId":OP,"threadId":tid,"expectedRevision":"1","text":text}),
            )
        };
        assert!(send("", TID).is_err());
        assert!(send(&"a".repeat(CHAT_SEND_TEXT_BYTES), TID).is_ok());
        assert!(send(&"a".repeat(CHAT_SEND_TEXT_BYTES + 1), TID).is_err());
        assert!(send("hi", &TID.to_uppercase()).is_err());
        assert!(send("hi", "abc").is_err());
        let get = |limit| request("chat.thread.get", json!({"threadId":TID,"limit":limit}));
        assert!(get(0).is_err() && get(51).is_err() && get(1).is_ok());
    }

    #[test]
    fn results_round_trip() {
        let result = json!({"method":"chat.send","params":{"thread":thread(),"user":{
            "messageId":TID,"seq":"1","role":"user","content":"hi","truncated":false,"state":"committed",
            "providerId":"claude","model":"m","streamSeq":"0","stopReason":null,"error":null,"createdMs":"1"},
            "assistant":message("")}});
        let parsed: RpcResult = serde_json::from_value(result.clone()).unwrap();
        assert_eq!(parsed.method(), Method::ChatSend);
        assert_eq!(serde_json::to_value(&parsed).unwrap(), result);
    }

    #[test]
    fn published_workspace_capabilities_are_omitted_when_absent() {
        let base = json!({
            "workspaceId":"22222222-2222-4222-8222-222222222222",
            "workspaceEpoch":"33333333-3333-4333-8333-333333333333",
            "terminals":[]
        });
        let plain: PublishedWorkspace = serde_json::from_value(base.clone()).unwrap();
        assert_eq!(plain.capabilities, None);
        assert_eq!(serde_json::to_value(&plain).unwrap(), base);
        let mut with = base;
        with["capabilities"] = json!(["workspace.read", "chat.read"]);
        let parsed: PublishedWorkspace = serde_json::from_value(with.clone()).unwrap();
        assert_eq!(serde_json::to_value(&parsed).unwrap(), with);
        with["capabilities"] = json!(["chat.read"]);
        assert!(serde_json::from_value::<PublishedWorkspace>(with).is_err());
    }

    #[test]
    fn stream_frames_decode_and_enforce_frame_size() {
        let frame = |v: serde_json::Value| decode_chat_frame(v.to_string().as_bytes());
        let snapshot = |text: String| {
            json!({"type":"snapshot","messageId":TID,"state":"streaming","streamSeq":"4",
                "part":0,"last":true,"text":text})
        };
        assert!(frame(snapshot("x".repeat(CHAT_STREAM_TEXT_BYTES))).is_ok());
        assert!(frame(snapshot("x".repeat(CHAT_STREAM_TEXT_BYTES + 1))).is_err());
        // Escaping expands control characters past one plaintext frame.
        assert!(frame(snapshot("\u{1}".repeat(CHAT_STREAM_TEXT_BYTES))).is_err());
        assert!(frame(json!({"type":"delta","messageId":TID,"seq":"1","text":"a"})).is_ok());
        assert!(frame(json!({"type":"delta","messageId":TID,"seq":"0","text":"a"})).is_err());
        assert!(frame(json!({"type":"delta","messageId":TID,"seq":"1","text":""})).is_err());
        assert!(frame(json!({"type":"message","message":message("done")})).is_ok());
        assert!(frame(json!({"type":"thread","thread":thread()})).is_ok());
        assert!(frame(json!({"type":"threadDeleted","threadId":TID})).is_ok());
        assert!(frame(json!({"type":"resync","reason":"gap"})).is_ok());
        assert!(frame(json!({"type":"resync","reason":"gap","extra":1})).is_err());
        assert!(frame(json!({"type":"unknown"})).is_err());
    }

    #[test]
    fn chat_errors() {
        use crate::{Effect, ErrorCode, ErrorDetails, RemoteError};
        assert_eq!(ErrorCode::ChatBusy.http_status(), 409);
        let err = RemoteError::new(
            ErrorCode::ChatBusy,
            false,
            Effect::None,
            ErrorDetails::empty(),
            None,
        )
        .unwrap();
        assert!(err.validate_for_method(Method::ChatSend).is_ok());
    }
}
