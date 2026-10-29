// Generated from Rust JSON schema. Do not edit.

/**
 * Data-plane frames are distinguishable from the existing versioned response
 * envelope, allowing bounded client demultiplexing without changing replies.
 */
export type LocalStreamEvent =
  | {
      frame: TerminalStreamFrame;
      stream: "terminal";
    }
  | {
      frame: WorkspaceStreamFrame;
      stream: "workspace";
    }
  | {
      frame: FileWatchFrame;
      stream: "files";
    };
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
export type WorkspaceStreamFrame =
  | {
      data: WorkspaceSnapshotMetadata;
      type: "snapshotMetadata";
    }
  | {
      data: WorkspaceSnapshotChunk;
      type: "snapshotChunk";
    }
  | {
      data: WorkspaceSnapshotComplete;
      type: "snapshotComplete";
    }
  | {
      data: WorkspaceEvent;
      type: "event";
    }
  | {
      data: WorkspaceStreamAck;
      type: "ack";
    }
  | {
      data: WorkspaceResync;
      type: "resyncRequired";
    };
export type EventCursor = string;
export type WorkspaceEventData =
  | {
      data: WorkspaceChanged;
      kind: "workspace.changed";
    }
  | {
      data: OperationReceipt;
      kind: "operation.changed";
    }
  | {
      data: FilesInvalidated;
      kind: "files.invalidated";
    }
  | {
      data: GitInvalidated;
      kind: "git.invalidated";
    }
  | {
      data: TerminalControlChanged;
      kind: "terminal.controlChanged";
    }
  | {
      data: CursorAdvance;
      kind: "cursor.advance";
    };
export type OperationId = string;
export type DisplayText = string;
/**
 * The shared terminal projection contains no private desktop view descriptors.
 */
export type TerminalLayout =
  | {
      kind: "pane";
      pane: TerminalPane;
    }
  | {
      axis: SplitAxis;
      first: TerminalLayout;
      kind: "split";
      second: TerminalLayout;
    };
export type PaneState = "starting" | "publishing" | "running" | "exited" | "stopped" | "lost";
export type SplitAxis = "horizontal" | "vertical";
export type TabId = string;
/**
 * @maxItems 32
 */
export type BoundedList2 = TerminalTab[];
export type ConsumerAuthorizationId = string;
export type Capability =
  | "workspace.read"
  | "terminal.observe"
  | "terminal.control"
  | "terminal.manage"
  | "files.read"
  | "files.write"
  | "git.read"
  | "git.write"
  | "git.network"
  | "git.execute";
export type CapabilitySet = Capability[];
export type Effect = "none" | "committed" | "partial" | "unknown";
export type Method =
  | "workspace.get"
  | "workspace.capabilities"
  | "workspace.subscribe"
  | "terminal.create"
  | "terminal.split"
  | "terminal.rename"
  | "terminal.move"
  | "terminal.close"
  | "terminal.restart"
  | "terminal.attach"
  | "terminal.snapshot"
  | "terminal.ack"
  | "terminal.claim"
  | "terminal.renew"
  | "terminal.release"
  | "terminal.input"
  | "terminal.resize"
  | "files.list"
  | "files.stat"
  | "files.read"
  | "files.searchNames"
  | "files.watch"
  | "files.create"
  | "files.mkdir"
  | "files.rename"
  | "files.remove"
  | "git.repositories"
  | "git.status"
  | "git.diff"
  | "git.log"
  | "git.show"
  | "git.stage"
  | "git.unstage"
  | "git.commit"
  | "git.fetch"
  | "git.push"
  | "git.pull"
  | "operation.status"
  | "operation.cancel";
export type OperationParameterHash = string;
/**
 * Only identifiers/revisions, no names, paths, commands or cached plaintext.
 */
export type OperationResult =
  | {
      domainRevision: DecimalU64;
      kind: "domain";
    }
  | {
      domainRevision: DecimalU64;
      kind: "terminal";
      paneId: PaneId;
      sessionEpoch: SessionEpoch;
      sessionId: TerminalSessionId;
    }
  | {
      entryId: EntryId;
      fileRevision: FileRevision;
      kind: "file";
    }
  | {
      kind: "git";
      repoStateToken: RepoStateToken;
    };
export type EntryId = string;
export type FileRevision = string;
export type RepoStateToken = string;
export type OperationState = "accepted" | "running" | "succeeded" | "failed" | "cancelled" | "outcome_unknown";
/**
 * @maxItems 200
 */
export type BoundedList3 = EntryId[];
export type RepositoryId = string;
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
export interface WorkspaceSnapshotMetadata {
  chunkCount: ChunkCount;
  context: WorkspaceContext;
  cursor: EventCursor;
  domainRevision: DecimalU64;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
  totalBytes: DecimalU64;
}
export interface WorkspaceSnapshotChunk {
  bytes: BoundedList;
  index: ChunkIndex;
  subscriptionId: SubscriptionId;
}
export interface WorkspaceSnapshotComplete {
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface WorkspaceEvent {
  context: WorkspaceContext;
  cursor: EventCursor;
  data: WorkspaceEventData;
  eventSeq: DecimalU64;
  subscriptionId: SubscriptionId;
}
export interface WorkspaceChanged {
  domainRevision: DecimalU64;
  operationId?: OperationId | null;
  state: WorkspaceState;
}
export interface WorkspaceState {
  context: WorkspaceContext;
  domainRevision: DecimalU64;
  name: DisplayText;
  tabs: BoundedList2;
}
export interface TerminalTab {
  layout: TerminalLayout;
  name: DisplayText;
  tabId: TabId;
}
export interface TerminalPane {
  paneId: PaneId;
  session?: TerminalContext | null;
  state: PaneState;
}
/**
 * Validated receipt DTO, not proof of persistence, admission, authority or fencing.
 * A consumer must authenticate current rights and row binding before disclosure.
 */
export interface OperationReceipt {
  actor: ConsumerAuthorizationId;
  actualRights: CapabilitySet;
  cancelRequested: boolean;
  effect: Effect;
  operationId: OperationId;
  originalMethod: Method;
  parameterHash: OperationParameterHash;
  repositoryExecution: boolean;
  result?: OperationResult | null;
  state: OperationState;
  workspaceId: WorkspaceId;
}
export interface FilesInvalidated {
  entries: BoundedList3;
  overflow: boolean;
}
export interface GitInvalidated {
  repositoryId: RepositoryId;
}
export interface CursorAdvance {}
export interface WorkspaceStreamAck {
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
export interface FileWatchEvent {
  context: WorkspaceContext;
  cursor: EventCursor;
  invalidation: FilesInvalidated;
  subscriptionId: SubscriptionId;
  watchSeq: DecimalU64;
}
export interface FileWatchAck {
  context: WorkspaceContext;
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
