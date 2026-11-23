// Generated from Rust JSON schema. Do not edit.

/**
 * Kind 6 stream frames. Snapshot and delta frames must fit one plaintext frame
 * (`MAX_FRAGMENT_PAYLOAD_LEN`); `message` and `thread` may span fragments up to the
 * 1 MiB logical message cap.
 */
export type ChatStreamFrame =
  | {
      last: boolean;
      messageId: ChatMessageId;
      part: ChatSnapshotPart;
      state: ChatMessageState;
      streamSeq: DecimalU64;
      text: ChatStreamText;
      type: "snapshot";
    }
  | {
      messageId: ChatMessageId;
      seq: DecimalU64;
      text: ChatStreamText;
      type: "delta";
    }
  | {
      message: ChatMessage;
      type: "message";
    }
  | {
      thread: ChatThread;
      type: "thread";
    }
  | {
      threadId: ChatThreadId;
      type: "threadDeleted";
    }
  | {
      reason: ResyncReason;
      type: "resync";
    };
export type ChatMessageId = string;
export type ChatSnapshotPart = number;
export type ChatMessageState =
  "committed" | "dispatching" | "streaming" | "completed" | "stopped" | "failed" | "interrupted";
export type DecimalU64 = string;
export type ChatStreamText = string;
export type ChatMessageContent = string;
export type DisplayText = string;
export type ChatModelId = string;
export type ChatProviderId = string;
export type ChatRole = "user" | "assistant";
export type ChatStopReason = string;
export type ChatEffort = string;
export type ChatKind = "api" | "cli";
export type ChatPermissions = "read-only" | "edit" | "full";
export type ChatThreadId = string;
export type ChatTitle = string;
export type ChatWorkspaceMode = "project" | "private";
export type ResyncReason =
  | "gap"
  | "stale_cursor"
  | "workspace_epoch_changed"
  | "runtime_changed"
  | "session_epoch_changed"
  | "profile_changed"
  | "subscriber_overflow"
  | "watch_overflow"
  | "snapshot_invalid"
  | "assembly_timeout";

export interface ChatMessage {
  content: ChatMessageContent;
  createdMs: DecimalU64;
  error?: DisplayText | null;
  messageId: ChatMessageId;
  model: ChatModelId;
  providerId: ChatProviderId;
  role: ChatRole;
  seq: DecimalU64;
  state: ChatMessageState;
  stopReason?: ChatStopReason | null;
  streamSeq: DecimalU64;
  truncated: boolean;
}
export interface ChatThread {
  createdMs: DecimalU64;
  effort?: ChatEffort | null;
  kind: ChatKind;
  model: ChatModelId;
  permissions: ChatPermissions;
  providerId: ChatProviderId;
  revision: DecimalU64;
  streaming: boolean;
  threadId: ChatThreadId;
  title: ChatTitle;
  updatedMs: DecimalU64;
  workspaceMode: ChatWorkspaceMode;
}
