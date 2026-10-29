// Generated from Rust JSON schema. Do not edit.

export type FileWatchFrame =
  | {
      data: FileWatchEvent;
      type: "invalidated";
    }
  | {
      data: FileWatchAck;
      type: "ack";
    }
  | {
      data: WorkspaceResync;
      type: "resyncRequired";
    };
export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type EventCursor = string;
export type EntryId = string;
/**
 * @maxItems 200
 */
export type BoundedList = EntryId[];
export type SubscriptionId = string;
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

export interface FileWatchEvent {
  context: WorkspaceContext;
  cursor: EventCursor;
  invalidation: FilesInvalidated;
  subscriptionId: SubscriptionId;
  watchSeq: DecimalU64;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface FilesInvalidated {
  entries: BoundedList;
  overflow: boolean;
}
export interface FileWatchAck {
  context: WorkspaceContext;
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface WorkspaceResync {
  context: WorkspaceContext;
  reason: ResyncReason;
  subscriptionId: SubscriptionId;
}
