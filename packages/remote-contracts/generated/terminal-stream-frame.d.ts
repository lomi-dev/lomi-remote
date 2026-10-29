// Generated from Rust JSON schema. Do not edit.

export type TerminalStreamFrame =
  | {
      data: TerminalSnapshotMetadata;
      type: "snapshotMetadata";
    }
  | {
      data: TerminalSnapshotChunk;
      type: "snapshotChunk";
    }
  | {
      data: TerminalSnapshotComplete;
      type: "snapshotComplete";
    }
  | {
      data: TerminalDelta;
      type: "delta";
    }
  | {
      data: TerminalDeltaMetadata;
      type: "deltaMetadata";
    }
  | {
      data: TerminalDeltaChunk;
      type: "deltaChunk";
    }
  | {
      data: TerminalDeltaComplete;
      type: "deltaComplete";
    }
  | {
      data: TerminalAckParams;
      type: "ack";
    }
  | {
      data: TerminalResync;
      type: "resyncRequired";
    };
export type ChunkCount = number;
export type TerminalDimension = number;
export type DecimalU64 = string;
export type SubscriptionId = string;
export type PaneId = string;
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
/**
 * An absolute Host path or null when unknown
 */
export type WorkingDirectoryValue = string | null;
/**
 * @maxItems 16384
 */
export type BoundedList = number[];
export type ChunkIndex = number;
export type TerminalChange =
  | {
      data: BoundedList;
      kind: "grid";
    }
  | {
      data: TerminalDimensions;
      kind: "resize";
    }
  | {
      data: TerminalExit;
      kind: "exit";
    }
  | {
      data: TerminalControlChanged;
      kind: "controlChanged";
    };
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

export interface TerminalSnapshotMetadata {
  chunkCount: ChunkCount;
  columns: TerminalDimension;
  outputOffset: DecimalU64;
  rows: TerminalDimension;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
  totalBytes: DecimalU64;
  workingDirectory: WorkingDirectoryValue;
}
export interface TerminalContext {
  paneId: PaneId;
  profile: TerminalProfile;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  workspace: WorkspaceContext;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface TerminalSnapshotChunk {
  bytes: BoundedList;
  index: ChunkIndex;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
}
export interface TerminalSnapshotComplete {
  outputOffset: DecimalU64;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
}
export interface TerminalDelta {
  change: TerminalChange;
  seq: DecimalU64;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
}
export interface TerminalDimensions {
  columns: TerminalDimension;
  rows: TerminalDimension;
}
export interface TerminalExit {
  exitCode?: number | null;
}
export interface TerminalControlChanged {
  controlled: boolean;
  leaseVersion: DecimalU64;
  terminal: TerminalContext;
}
export interface TerminalDeltaMetadata {
  chunkCount: ChunkCount;
  previousSeq: DecimalU64;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
  totalBytes: DecimalU64;
  workingDirectory: WorkingDirectoryValue;
}
export interface TerminalDeltaChunk {
  bytes: BoundedList;
  index: ChunkIndex;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
}
export interface TerminalDeltaComplete {
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
}
export interface TerminalAckParams {
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
}
export interface TerminalResync {
  reason: ResyncReason;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
}
