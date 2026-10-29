// Generated from Rust JSON schema. Do not edit.

export type RpcCall =
  | {
      method: "workspace.get";
      params: WorkspaceReadParams;
    }
  | {
      method: "workspace.capabilities";
      params: WorkspaceReadParams;
    }
  | {
      method: "workspace.subscribe";
      params: WorkspaceSubscribeParams;
    }
  | {
      method: "terminal.create";
      params: TerminalCreateParams;
    }
  | {
      method: "terminal.split";
      params: TerminalSplitParams;
    }
  | {
      method: "terminal.rename";
      params: TerminalRenameParams;
    }
  | {
      method: "terminal.move";
      params: TerminalMoveParams;
    }
  | {
      method: "terminal.close";
      params: TerminalCloseParams;
    }
  | {
      method: "terminal.restart";
      params: TerminalRestartParams;
    }
  | {
      method: "terminal.attach";
      params: TerminalReadParams;
    }
  | {
      method: "terminal.snapshot";
      params: TerminalReadParams;
    }
  | {
      method: "terminal.ack";
      params: TerminalAckParams;
    }
  | {
      method: "terminal.claim";
      params: TerminalClaimParams;
    }
  | {
      method: "terminal.renew";
      params: TerminalLeaseParams;
    }
  | {
      method: "terminal.release";
      params: TerminalLeaseParams;
    }
  | {
      method: "terminal.input";
      params: TerminalInputParams;
    }
  | {
      method: "terminal.resize";
      params: TerminalResizeParams;
    }
  | {
      method: "files.list";
      params: FilesListParams;
    }
  | {
      method: "files.stat";
      params: FilesStatParams;
    }
  | {
      method: "files.read";
      params: FilesReadParams;
    }
  | {
      method: "files.searchNames";
      params: FilesSearchNamesParams;
    }
  | {
      method: "files.watch";
      params: FilesWatchParams;
    }
  | {
      method: "files.create";
      params: FilesCreateParams;
    }
  | {
      method: "files.mkdir";
      params: FilesCreateParams;
    }
  | {
      method: "files.rename";
      params: FilesRenameParams;
    }
  | {
      method: "files.remove";
      params: FilesRemoveParams;
    }
  | {
      method: "git.repositories";
      params: WorkspaceReadParams;
    }
  | {
      method: "git.status";
      params: GitStatusParams;
    }
  | {
      method: "git.diff";
      params: GitDiffParams;
    }
  | {
      method: "git.log";
      params: GitLogParams;
    }
  | {
      method: "git.show";
      params: GitShowParams;
    }
  | {
      method: "git.stage";
      params: GitStageParams;
    }
  | {
      method: "git.unstage";
      params: GitUnstageParams;
    }
  | {
      method: "git.commit";
      params: GitCommitParams;
    }
  | {
      method: "git.fetch";
      params: GitNetworkParams;
    }
  | {
      method: "git.push";
      params: GitNetworkParams;
    }
  | {
      method: "git.pull";
      params: GitPullParams;
    }
  | {
      method: "operation.status";
      params: OperationStatusParams;
    }
  | {
      method: "operation.cancel";
      params: OperationCancelParams;
    };
export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type EventCursor = string;
export type OperationId = string;
export type HostProfileId = string;
export type DisplayText = string;
export type SplitAxis = "horizontal" | "vertical";
export type PaneId = string;
export type TabId = string;
export type MovePlacement = "before" | "after";
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type SubscriptionId = string;
export type LeaseToken = string;
/**
 * @maxItems 16384
 */
export type BoundedList = number[];
export type TerminalDimension = number;
export type PageLimit = number;
export type EntryId = string;
export type FileRevision = string;
export type PreviewLimit = number;
export type SearchText = string;
export type DestinationState = "absent";
export type EntryName = string;
export type Confirmed = "confirmed";
export type RepositoryId = string;
export type RepoStateToken = string;
export type DiffView = "index" | "worktree";
export type ObjectId = string;
/**
 * @maxItems 200
 */
export type BoundedList2 = GitStagePath[];
/**
 * @maxItems 200
 */
export type BoundedList3 = EntryId[];
export type CommitMessage = string;
export type RefId = string;
export type RemoteId = string;
export type PullMode = "ff-only";
export type RequestId = string;
export type TimeoutMs = number;
export type RequestKind = "request";
export type ApplicationMajor = 2;

export interface RpcRequest {
  call: RpcCall;
  requestId: RequestId;
  timeoutMs: TimeoutMs;
  type: RequestKind;
  v: ApplicationMajor;
}
export interface WorkspaceReadParams {
  context: WorkspaceContext;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface WorkspaceSubscribeParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
}
export interface TerminalCreateParams {
  mutation: MutationContext;
  profileId: HostProfileId;
  tabName: DisplayText;
}
export interface MutationContext {
  context: WorkspaceContext;
  expectedRevision: DecimalU64;
  operationId: OperationId;
}
export interface TerminalSplitParams {
  axis: SplitAxis;
  mutation: MutationContext;
  paneId: PaneId;
  profileId: HostProfileId;
  tabId: TabId;
}
export interface TerminalRenameParams {
  mutation: MutationContext;
  name: DisplayText;
  tabId: TabId;
}
export interface TerminalMoveParams {
  mutation: MutationContext;
  paneId: PaneId;
  placement: MovePlacement;
  sourceTabId: TabId;
  targetPaneId: PaneId;
  targetTabId: TabId;
}
export interface TerminalCloseParams {
  expectedSession?: TerminalContext | null;
  mutation: MutationContext;
  paneId: PaneId;
}
export interface TerminalContext {
  paneId: PaneId;
  profile: TerminalProfile;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  workspace: WorkspaceContext;
}
export interface TerminalRestartParams {
  expectedSession?: TerminalContext | null;
  mutation: MutationContext;
  paneId: PaneId;
  profileId: HostProfileId;
}
export interface TerminalReadParams {
  terminal: TerminalContext;
}
export interface TerminalAckParams {
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
  throughSeq: DecimalU64;
}
export interface TerminalClaimParams {
  renderedThroughSeq: DecimalU64;
  subscriptionId: SubscriptionId;
  terminal: TerminalContext;
}
export interface TerminalLeaseParams {
  lease: LeaseBinding;
  terminal: TerminalContext;
}
export interface LeaseBinding {
  token: LeaseToken;
  version: DecimalU64;
}
export interface TerminalInputParams {
  bytes: BoundedList;
  inputId: DecimalU64;
  inputSeq: DecimalU64;
  lease: LeaseBinding;
  terminal: TerminalContext;
}
export interface TerminalResizeParams {
  columns: TerminalDimension;
  lease: LeaseBinding;
  resizeSeq: DecimalU64;
  rows: TerminalDimension;
  terminal: TerminalContext;
}
export interface FilesListParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  limit: PageLimit;
  parentEntryId: EntryId;
}
export interface FilesStatParams {
  context: WorkspaceContext;
  entryId: EntryId;
  fileRevision?: FileRevision | null;
}
export interface FilesReadParams {
  context: WorkspaceContext;
  entryId: EntryId;
  fileRevision?: FileRevision | null;
  maxBytes: PreviewLimit;
  offset: DecimalU64;
}
export interface FilesSearchNamesParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  limit: PageLimit;
  parentEntryId: EntryId;
  query: SearchText;
}
export interface FilesWatchParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  entryId: EntryId;
}
export interface FilesCreateParams {
  destination: DestinationState;
  mutation: FileMutationContext;
  name: EntryName;
  parentEntryId: EntryId;
  parentRevision: FileRevision;
}
export interface FileMutationContext {
  context: WorkspaceContext;
  operationId: OperationId;
}
export interface FilesRenameParams {
  destination: DestinationState;
  entryId: EntryId;
  fileRevision: FileRevision;
  mutation: FileMutationContext;
  name: EntryName;
  sourceParentId: EntryId;
  sourceParentRevision: FileRevision;
  targetParentId: EntryId;
  targetParentRevision: FileRevision;
}
export interface FilesRemoveParams {
  confirmation: Confirmed;
  entryId: EntryId;
  fileRevision: FileRevision;
  mutation: FileMutationContext;
  parentEntryId: EntryId;
  parentRevision: FileRevision;
}
export interface GitStatusParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  limit: PageLimit;
  repositoryId: RepositoryId;
  stateToken?: RepoStateToken | null;
}
export interface GitDiffParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  entryId?: EntryId | null;
  limit: PageLimit;
  repositoryId: RepositoryId;
  stateToken: RepoStateToken;
  view: DiffView;
}
export interface GitLogParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  limit: PageLimit;
  repositoryId: RepositoryId;
  stateToken: RepoStateToken;
}
export interface GitShowParams {
  context: WorkspaceContext;
  cursor?: EventCursor | null;
  limit: PageLimit;
  objectId: ObjectId;
  repositoryId: RepositoryId;
  stateToken: RepoStateToken;
}
export interface GitStageParams {
  expected: GitPreconditions;
  mutation: GitMutationContext;
  paths: BoundedList2;
  repositoryId: RepositoryId;
}
export interface GitPreconditions {
  head: RepoStateToken;
  index: RepoStateToken;
}
export interface GitMutationContext {
  context: WorkspaceContext;
  operationId: OperationId;
}
export interface GitStagePath {
  entryId: EntryId;
  fileRevision: FileRevision;
}
export interface GitUnstageParams {
  expected: GitPreconditions;
  mutation: GitMutationContext;
  paths: BoundedList3;
  repositoryId: RepositoryId;
}
export interface GitCommitParams {
  expected: GitPreconditions;
  message: CommitMessage;
  mutation: GitMutationContext;
  repositoryId: RepositoryId;
}
export interface GitNetworkParams {
  expectedRefs: RepoStateToken;
  mutation: GitMutationContext;
  refId: RefId;
  remoteId: RemoteId;
  repositoryId: RepositoryId;
}
export interface GitPullParams {
  expected: GitPreconditions;
  expectedRefs: RepoStateToken;
  expectedWorktree: RepoStateToken;
  mode: PullMode;
  mutation: GitMutationContext;
  refId: RefId;
  remoteId: RemoteId;
  repositoryId: RepositoryId;
}
export interface OperationStatusParams {
  context: WorkspaceContext;
  operationId: OperationId;
}
export interface OperationCancelParams {
  context: WorkspaceContext;
  operationId: OperationId;
}
