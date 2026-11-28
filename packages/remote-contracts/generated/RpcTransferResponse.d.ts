// Generated from Rust JSON schema. Do not edit.

export type RequestId = string;
export type RpcResult =
  | {
      method: "workspace.get";
      params: WorkspaceState;
    }
  | {
      method: "workspace.capabilities";
      params: WorkspaceCapabilitiesResult;
    }
  | {
      method: "workspace.subscribe";
      params: WorkspaceSnapshotMetadata;
    }
  | {
      method: "terminal.create";
      params: OperationReceipt;
    }
  | {
      method: "terminal.split";
      params: OperationReceipt;
    }
  | {
      method: "terminal.rename";
      params: OperationReceipt;
    }
  | {
      method: "terminal.move";
      params: OperationReceipt;
    }
  | {
      method: "terminal.close";
      params: OperationReceipt;
    }
  | {
      method: "terminal.restart";
      params: OperationReceipt;
    }
  | {
      method: "terminal.attach";
      params: TerminalSnapshotMetadata;
    }
  | {
      method: "terminal.snapshot";
      params: TerminalSnapshotMetadata;
    }
  | {
      method: "terminal.ack";
      params: TerminalAckResult;
    }
  | {
      method: "terminal.claim";
      params: TerminalLeaseResult;
    }
  | {
      method: "terminal.renew";
      params: TerminalLeaseResult;
    }
  | {
      method: "terminal.release";
      params: TerminalReleaseResult;
    }
  | {
      method: "terminal.input";
      params: InputReceipt;
    }
  | {
      method: "terminal.resize";
      params: TerminalResizeResult;
    }
  | {
      method: "files.list";
      params: FilesListResult;
    }
  | {
      method: "files.stat";
      params: FileMetadata;
    }
  | {
      method: "files.read";
      params: FilesReadResult;
    }
  | {
      method: "files.searchNames";
      params: FilesListResult;
    }
  | {
      method: "files.watch";
      params: FilesWatchResult;
    }
  | {
      method: "files.create";
      params: OperationReceipt;
    }
  | {
      method: "files.mkdir";
      params: OperationReceipt;
    }
  | {
      method: "files.rename";
      params: OperationReceipt;
    }
  | {
      method: "files.remove";
      params: OperationReceipt;
    }
  | {
      method: "git.repositories";
      params: GitRepositoriesResult;
    }
  | {
      method: "git.status";
      params: GitStatusResult;
    }
  | {
      method: "git.diff";
      params: GitDiffResult;
    }
  | {
      method: "git.log";
      params: GitLogResult;
    }
  | {
      method: "git.show";
      params: GitShowResult;
    }
  | {
      method: "git.stage";
      params: OperationReceipt;
    }
  | {
      method: "git.unstage";
      params: OperationReceipt;
    }
  | {
      method: "git.commit";
      params: OperationReceipt;
    }
  | {
      method: "git.fetch";
      params: OperationReceipt;
    }
  | {
      method: "git.push";
      params: OperationReceipt;
    }
  | {
      method: "git.pull";
      params: OperationReceipt;
    }
  | {
      method: "chat.providers";
      params: ChatProvidersResult;
    }
  | {
      method: "chat.threads.list";
      params: ChatThreadsListResult;
    }
  | {
      method: "chat.thread.get";
      params: ChatThreadGetResult;
    }
  | {
      method: "chat.subscribe";
      params: ChatSubscribeResult;
    }
  | {
      method: "chat.thread.create";
      params: ChatThreadResult;
    }
  | {
      method: "chat.thread.update";
      params: ChatThreadResult;
    }
  | {
      method: "chat.thread.delete";
      params: ChatThreadDeleteResult;
    }
  | {
      method: "chat.send";
      params: ChatSendResult;
    }
  | {
      method: "chat.stop";
      params: ChatThreadResult;
    }
  | {
      method: "operation.status";
      params: OperationReceipt;
    }
  | {
      method: "operation.cancel";
      params: OperationReceipt;
    };
export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
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
export type PaneId = string;
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type PaneState = "starting" | "publishing" | "running" | "exited" | "stopped" | "lost";
export type SplitAxis = "horizontal" | "vertical";
export type TabId = string;
/**
 * @maxItems 32
 */
export type BoundedList = TerminalTab[];
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
  | "git.execute"
  | "chat.read"
  | "chat.send"
  | "chat.permissions.edit"
  | "chat.permissions.full";
export type CapabilitySet = Capability[];
export type HostProfileId = string;
/**
 * @maxItems 32
 */
export type BoundedList2 = HostProfile[];
export type ChunkCount = number;
export type EventCursor = string;
export type SubscriptionId = string;
export type ConsumerAuthorizationId = string;
export type Effect = "none" | "committed" | "partial" | "unknown";
export type OperationId = string;
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
  | "chat.providers"
  | "chat.threads.list"
  | "chat.thread.get"
  | "chat.subscribe"
  | "chat.thread.create"
  | "chat.thread.update"
  | "chat.thread.delete"
  | "chat.send"
  | "chat.stop"
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
export type TerminalDimension = number;
/**
 * An absolute Host path or null when unknown
 */
export type WorkingDirectoryValue = string | null;
export type TimeoutMs = number;
export type LeaseToken = string;
export type InputBytes = number;
export type EntryKind = "file" | "directory" | "symlink" | "other";
export type EncodedPathId = string;
/**
 * @maxItems 200
 */
export type BoundedList3 = FileMetadata[];
/**
 * @maxItems 1048576
 */
export type BoundedList4 = number[];
export type FileEncoding = "utf8" | "utf16Le" | "utf16Be" | "binary" | "unknown";
export type LineEndings = "lf" | "crLf" | "cr" | "mixed" | "none";
export type RefId = string;
/**
 * @maxItems 200
 */
export type BoundedList7 = RefId[];
export type RemoteId = string;
export type GitRemoteSelectorKind = "head" | "fetch" | "push";
/**
 * @maxItems 200
 */
export type BoundedList8 = GitRemoteSelector[];
/**
 * @maxItems 32
 */
export type BoundedList6 = GitRemote[];
export type RepositoryId = string;
/**
 * @maxItems 32
 */
export type BoundedList5 = GitRepository[];
export type GitChange =
  "unchanged" | "added" | "modified" | "deleted" | "renamed" | "copied" | "unmerged" | "untracked";
/**
 * @maxItems 200
 */
export type BoundedList9 = GitStatusEntry[];
export type DiffLineKind = "context" | "added" | "removed";
export type DiffLineText = string;
/**
 * @maxItems 200
 */
export type BoundedList12 = GitDiffLine[];
/**
 * @maxItems 200
 */
export type BoundedList11 = GitDiffHunk[];
/**
 * @maxItems 200
 */
export type BoundedList10 = GitDiffFile[];
export type ObjectId = string;
/**
 * @maxItems 200
 */
export type BoundedList13 = GitCommitSummary[];
export type ChatName = string;
export type ChatEffort = string;
/**
 * @maxItems 16
 */
export type BoundedList16 = ChatEffort[];
export type ChatKind = "api" | "cli";
export type ChatModelId = string;
/**
 * @maxItems 256
 */
export type BoundedList15 = ChatModel[];
export type ChatProviderId = string;
/**
 * @maxItems 32
 */
export type BoundedList14 = ChatProvider[];
export type ChatCursor = string;
export type ChatPermissions = "read-only" | "edit" | "full";
export type ChatThreadId = string;
export type ChatTitle = string;
export type ChatWorkspaceMode = "project" | "private";
/**
 * @maxItems 200
 */
export type BoundedList17 = ChatThread[];
export type ChatMessageContent = string;
export type ChatMessageId = string;
export type ChatRole = "user" | "assistant";
export type ChatMessageState =
  "committed" | "dispatching" | "streaming" | "completed" | "stopped" | "failed" | "interrupted";
export type ChatStopReason = string;
/**
 * @maxItems 50
 */
export type BoundedList18 = ChatMessage[];
/**
 * Fixed `type` of [`RpcTransferResponse`] (the other stream 0 answers are `result` and `error`).
 */
export type TransferTag = "transfer";
export type ApplicationMajor = 2;

export interface RpcTransferResponse {
  requestId: RequestId;
  result: RpcResult;
  transferBytes: DecimalU64;
  transferStream: number;
  type: TransferTag;
  v: ApplicationMajor;
}
export interface WorkspaceState {
  context: WorkspaceContext;
  domainRevision: DecimalU64;
  name: DisplayText;
  tabs: BoundedList;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
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
export interface TerminalContext {
  paneId: PaneId;
  profile: TerminalProfile;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  workspace: WorkspaceContext;
}
export interface WorkspaceCapabilitiesResult {
  capabilities: CapabilitySet;
  profiles: BoundedList2;
}
export interface HostProfile {
  name: DisplayText;
  profileId: HostProfileId;
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
export interface TerminalAckResult {
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface TerminalLeaseResult {
  expiresInMs: TimeoutMs;
  lease: LeaseBinding;
  nextInputId: DecimalU64;
  nextInputSeq: DecimalU64;
  nextResizeSeq: DecimalU64;
  terminal: TerminalContext;
}
export interface LeaseBinding {
  token: LeaseToken;
  version: DecimalU64;
}
export interface TerminalReleaseResult {
  released: boolean;
  terminal: TerminalContext;
}
/**
 * Ephemeral receipt in session-epoch RAM only. No input bytes or keystroke hash.
 * Acceptance counts PTY bytes; it does not mean shell execution or permit replay.
 */
export interface InputReceipt {
  acceptedBytes: InputBytes;
  inputId: DecimalU64;
  inputSeq: DecimalU64;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  submittedBytes: InputBytes;
}
export interface TerminalResizeResult {
  columns: TerminalDimension;
  resizeSeq: DecimalU64;
  rows: TerminalDimension;
  terminal: TerminalContext;
}
export interface FilesListResult {
  entries: BoundedList3;
  nextCursor?: EventCursor | null;
  truncated: boolean;
}
export interface FileMetadata {
  displayName: DisplayText;
  entryId: EntryId;
  fileRevision: FileRevision;
  kind: EntryKind;
  pathId: EncodedPathId;
  size: DecimalU64;
}
export interface FilesReadResult {
  bytes: BoundedList4;
  encoding: FileEncoding;
  lineEndings: LineEndings;
  metadata: FileMetadata;
  offset: DecimalU64;
  truncated: boolean;
}
export interface FilesWatchResult {
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface GitRepositoriesResult {
  repositories: BoundedList5;
}
export interface GitRepository {
  displayName: DisplayText;
  remotes: BoundedList6;
  repositoryId: RepositoryId;
}
export interface GitRemote {
  displayName: DisplayText;
  refs: BoundedList7;
  refsStateToken: RepoStateToken;
  remoteId: RemoteId;
  selectors?: BoundedList8;
}
export interface GitRemoteSelector {
  displayName: DisplayText;
  fetch: boolean;
  kind: GitRemoteSelectorKind;
  pull: boolean;
  push: boolean;
  refId: RefId;
}
export interface GitStatusResult {
  entries: BoundedList9;
  head: RepoStateToken;
  index: RepoStateToken;
  nextCursor?: EventCursor | null;
  stateToken: RepoStateToken;
  truncated: boolean;
}
export interface GitStatusEntry {
  displayName: DisplayText;
  entryId: EntryId;
  fileRevision: FileRevision;
  index: GitChange;
  pathId: EncodedPathId;
  worktree: GitChange;
}
export interface GitDiffResult {
  files: BoundedList10;
  nextCursor?: EventCursor | null;
  stateToken: RepoStateToken;
  truncated: boolean;
}
export interface GitDiffFile {
  binary: boolean;
  displayName: DisplayText;
  entryId: EntryId;
  hunks: BoundedList11;
  truncated: boolean;
}
export interface GitDiffHunk {
  lines: BoundedList12;
  newStart: DecimalU64;
  oldStart: DecimalU64;
}
export interface GitDiffLine {
  kind: DiffLineKind;
  text: DiffLineText;
}
export interface GitLogResult {
  commits: BoundedList13;
  nextCursor?: EventCursor | null;
  stateToken: RepoStateToken;
  truncated: boolean;
}
export interface GitCommitSummary {
  author: DisplayText;
  objectId: ObjectId;
  subject: DisplayText;
  timestampSeconds: DecimalU64;
}
export interface GitShowResult {
  commit: GitCommitSummary;
  diff: GitDiffResult;
}
export interface ChatProvidersResult {
  providers: BoundedList14;
}
export interface ChatProvider {
  cli?: ChatName | null;
  efforts: BoundedList16;
  kind: ChatKind;
  loggedIn?: boolean | null;
  models: BoundedList15;
  name: ChatName;
  providerId: ChatProviderId;
  readOnlyEnforced: boolean;
}
export interface ChatModel {
  modelId: ChatModelId;
  name: ChatName;
}
export interface ChatThreadsListResult {
  nextCursor?: ChatCursor | null;
  threads: BoundedList17;
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
export interface ChatThreadGetResult {
  hasMore: boolean;
  messages: BoundedList18;
  thread: ChatThread;
}
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
export interface ChatSubscribeResult {
  subscriptionId: SubscriptionId;
}
export interface ChatThreadResult {
  thread: ChatThread;
}
export interface ChatThreadDeleteResult {}
export interface ChatSendResult {
  assistant: ChatMessage;
  thread: ChatThread;
  user: ChatMessage;
}
