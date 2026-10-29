// Generated from Rust JSON schema. Do not edit.

export type RequestId = string;
export type ResultOf_LocalResultOr_LocalError =
  | {
      Ok: LocalResult;
    }
  | {
      Err: LocalError;
    };
export type LocalResult =
  | {
      type: "nativeFileStage";
      value: LocalNativeFileStage;
    }
  | {
      type: "nativeEditor";
      value: LocalNativeEditorResult;
    }
  | {
      type: "nativeEditorDisposition";
      value: NativeEditorDisposition;
    }
  | {
      type: "nativeGit";
      value: LocalNativeGitResult;
    }
  | {
      type: "nativeEffectChallenge";
      value: LocalNativeEffectChallenge;
    }
  | {
      type: "authConfigured";
      value: {};
    }
  | {
      type: "loginAccepted";
      value: LocalLoginAccepted;
    }
  | {
      type: "loginStatus";
      value: LocalLoginStatus;
    }
  | {
      type: "loginPresentation";
      value: LocalLoginPresentation;
    }
  | {
      type: "stopping";
      value: {};
    }
  | {
      type: "status";
      value: LocalStatus;
    }
  | {
      type: "hostNameSet";
      value: LocalHostName;
    }
  | {
      type: "maintenanceStatus";
      value: LocalMaintenanceStatus;
    }
  | {
      type: "setupStartMode";
      value: LocalStartModePreference;
    }
  | {
      type: "doctor";
      value: BoundedList;
    }
  | {
      type: "doctorReport";
      value: LocalDoctorReport;
    }
  | {
      type: "operatorSnapshot";
      value: LocalOperatorSnapshot;
    }
  | {
      type: "diagnosticLogs";
      value: DiagnosticLogSnapshot;
    }
  | {
      type: "workspaceDetails";
      value: LocalWorkspaceDetails;
    }
  | {
      type: "workspaceRemovalStatus";
      value: LocalWorkspaceRemovalStatus;
    }
  | {
      type: "workspacePublication";
      value: LocalWorkspacePublication;
    }
  | {
      type: "workspaces";
      value: BoundedList3;
    }
  | {
      type: "profiles";
      value: BoundedList4;
    }
  | {
      type: "workspace";
      value: LocalWorkspaceSummary;
    }
  | {
      type: "workspaceImported";
      value: LocalWorkspaceImportReceipt;
    }
  | {
      type: "workspaceBindings";
      value: WorkspaceBindingsSnapshot;
    }
  | {
      type: "shellProfileRegistered";
      value: {
        profileId: HostProfileId;
      };
    }
  | {
      type: "workspaceState";
      value: WorkspaceState;
    }
  | {
      type: "removed";
      value: WorkspaceId;
    }
  | {
      type: "rpc";
      value: RpcResponse;
    }
  | {
      type: "streamAcknowledged";
      value: SubscriptionId;
    }
  | {
      type: "nativeLease";
      value: NativeLease;
    }
  | {
      type: "nativeIntent";
      value: HostId;
    }
  | {
      type: "nativeEditorAcknowledged";
      value: HostId;
    }
  | {
      type: "nativeAcknowledged";
      value: HostId;
    };
export type HostId = string;
export type LocalRootPath = string;
export type LocalNativeResultJson = string;
export type LocalNativeEffectState = "running" | "succeeded" | "failed" | "outcomeUnknown";
export type NativeEditorRetirement = "unresolved" | "joined" | "notStarted" | "recovered";
export type HostKeyCommitmentHex = string;
export type LocalNativeGitState = "preparing" | "prepared" | "running" | "succeeded" | "failed" | "outcomeUnknown";
export type DecimalU64 = string;
export type OperationId = string;
export type LocalAuthNetwork = "idle" | "working" | "available" | "unavailable";
export type LocalAuthPhase =
  | "unconfigured"
  | "idle"
  | "initializing"
  | "awaitingApproval"
  | "exchanging"
  | "registering"
  | "ready"
  | "refreshing"
  | "locked"
  | "pendingRevoke"
  | "unavailable";
export type LocalAuthStorage = "unconfigured" | "available" | "locked" | "unavailable";
export type UserCode = string;
export type LocalHostName = string;
export type RuntimeId = string;
export type LocalSharing = "disabled" | "enabled";
/**
 * Saved local preference only. It does not install or start an OS service.
 */
export type LocalStartMode = "manual" | "login" | "boot";
/**
 * Closed diagnostics vocabulary: no arbitrary error text, env, paths, terminal
 * transcripts, account credentials or file payloads can enter this export.
 */
export type DoctorCheck =
  | "ipcVersion"
  | "profileOwner"
  | "service"
  | "autostart"
  | "clock"
  | "network"
  | "dns"
  | "tls"
  | "proxy"
  | "authorization"
  | "storage"
  | "shell"
  | "git"
  | "rootPermissions"
  | "limits";
export type DoctorHealth =
  | "healthy"
  | "unavailable"
  | "permissionDenied"
  | "incompatible"
  | "unknown"
  | "configurationInvalid"
  | "transportUnavailable"
  | "authorizationRejected"
  | "disabledByPolicy";
/**
 * @maxItems 32
 */
export type BoundedList = DoctorDiagnostic[];
export type DiagnosticCode =
  | "hostStarted"
  | "hostStartRejected"
  | "ipcRequestRejected"
  | "ipcVersionMismatch"
  | "profileInvalid"
  | "serviceUnavailable"
  | "serviceRegistrationMissing"
  | "authenticationConfigurationMissing"
  | "authenticationRejected"
  | "networkUnavailable"
  | "networkConfigurationInvalid"
  | "dnsUnavailable"
  | "tlsUnavailable"
  | "networkTimeout"
  | "storageUnavailable"
  | "shellConfigurationMissing"
  | "shellExecutableUnavailable"
  | "builtInGitUnavailable"
  | "nativeGitUnavailable"
  | "activationPending"
  | "resourceLimitReached";
export type DiagnosticComponent =
  | "host"
  | "ipc"
  | "profile"
  | "service"
  | "authentication"
  | "network"
  | "storage"
  | "shell"
  | "git"
  | "updater"
  | "terminal";
export type DiagnosticSeverity = "info" | "warning" | "error";
/**
 * @maxItems 128
 */
export type BoundedList2 = DiagnosticLogEntry[];
export type LocalWorkspaceWebUrl = string;
export type LocalProjectName = string;
export type WorkspaceId = string;
export type LocalWorkspaceRemovalPhase = "not_started" | "stopping" | "uncertain" | "complete";
export type LocalPublicationState = "pending" | "acknowledged" | "unknown";
/**
 * @maxItems 200
 */
export type BoundedList3 = LocalWorkspaceSummary[];
/**
 * @maxItems 200
 */
export type BoundedList4 = LocalProfileSummary[];
/**
 * Owner-local resolution of stable import IDs. `Missing` is distinct from
 * `Retired`: an import may not have been committed yet.
 */
export type WorkspaceBinding =
  | {
      import_id: WorkspaceId;
      state: "missing";
    }
  | {
      import_id: WorkspaceId;
      root_path: LocalRootPath;
      state: "active";
      workspace_id: WorkspaceId;
    }
  | {
      import_id: WorkspaceId;
      state: "pending";
      workspace_id: WorkspaceId;
    }
  | {
      import_id: WorkspaceId;
      state: "retired";
      workspace_id: WorkspaceId;
    };
/**
 * @maxItems 256
 */
export type BoundedList5 = WorkspaceBinding[];
export type HostProfileId = string;
export type WorkspaceEpoch = string;
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
export type BoundedList6 = TerminalTab[];
export type RpcResponse =
  | {
      requestId: RequestId;
      result: RpcResult;
      type: "result";
      v: ApplicationMajor;
    }
  | {
      error: RemoteError;
      operationId?: OperationId | null;
      requestId: RequestId;
      type: "error";
      v: ApplicationMajor;
    };
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
      method: "operation.status";
      params: OperationReceipt;
    }
  | {
      method: "operation.cancel";
      params: OperationReceipt;
    };
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
/**
 * @maxItems 32
 */
export type BoundedList7 = HostProfile[];
export type ChunkCount = number;
export type EventCursor = string;
export type SubscriptionId = string;
export type ConsumerAuthorizationId = string;
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
export type BoundedList8 = FileMetadata[];
/**
 * @maxItems 1048576
 */
export type BoundedList9 = number[];
export type FileEncoding = "utf8" | "utf16Le" | "utf16Be" | "binary" | "unknown";
export type LineEndings = "lf" | "crLf" | "cr" | "mixed" | "none";
export type RefId = string;
/**
 * @maxItems 200
 */
export type BoundedList12 = RefId[];
export type RemoteId = string;
export type GitRemoteSelectorKind = "head" | "fetch" | "push";
/**
 * @maxItems 200
 */
export type BoundedList13 = GitRemoteSelector[];
/**
 * @maxItems 32
 */
export type BoundedList11 = GitRemote[];
export type RepositoryId = string;
/**
 * @maxItems 32
 */
export type BoundedList10 = GitRepository[];
export type GitChange =
  "unchanged" | "added" | "modified" | "deleted" | "renamed" | "copied" | "unmerged" | "untracked";
/**
 * @maxItems 200
 */
export type BoundedList14 = GitStatusEntry[];
export type DiffLineKind = "context" | "added" | "removed";
export type DiffLineText = string;
/**
 * @maxItems 200
 */
export type BoundedList17 = GitDiffLine[];
/**
 * @maxItems 200
 */
export type BoundedList16 = GitDiffHunk[];
/**
 * @maxItems 200
 */
export type BoundedList15 = GitDiffFile[];
export type ObjectId = string;
/**
 * @maxItems 200
 */
export type BoundedList18 = GitCommitSummary[];
export type ApplicationMajor = 2;
export type ErrorCode =
  | "INVALID_ARGUMENT"
  | "AUTH_REQUIRED"
  | "SCOPE_DENIED"
  | "WORKSPACE_UNSHARED"
  | "REPOSITORY_EXECUTION_REQUIRED"
  | "PROTECTED_PATH"
  | "RESOURCE_NOT_FOUND"
  | "OPERATION_NOT_FOUND"
  | "STALE_EPOCH"
  | "REVISION_CONFLICT"
  | "FILE_CHANGED"
  | "IDEMPOTENCY_CONFLICT"
  | "HOST_BUSY"
  | "CONTROL_REQUIRED"
  | "CONTROL_REVOKED"
  | "SESSION_EXITED"
  | "RESYNC_REQUIRED"
  | "DIRECTORY_NOT_EMPTY"
  | "CREDENTIALS_REQUIRED"
  | "GIT_IDENTITY_REQUIRED"
  | "UNSUPPORTED_CAPABILITY"
  | "OUTCOME_UNKNOWN"
  | "OPERATION_EXPIRED"
  | "UPDATE_REQUIRED"
  | "RESOURCE_EXHAUSTED"
  | "FRESHNESS_REQUIRED"
  | "SERVICE_UNAVAILABLE"
  | "DEADLINE_EXCEEDED";
export type ErrorDetails = RevisionErrorDetails | EmptyErrorDetails;
export type NativeWriterState = "registered" | "active" | "quarantine" | "finished";
export type LocalError =
  | ("INVALID_ARGUMENT" | "PERMISSION_DENIED" | "VERSION_MISMATCH" | "CONFLICT" | "QUARANTINE" | "UNAVAILABLE")
  | "NATIVE_BIND_REJECTED";
export type LocalIpcMajor = 1;

export interface LocalResponse {
  requestId: RequestId;
  result: ResultOf_LocalResultOr_LocalError;
  version: LocalIpcVersion;
}
export interface LocalNativeFileStage {
  operationId: HostId;
  path: LocalRootPath;
}
export interface LocalNativeEditorResult {
  operationId: HostId;
  resultJson?: LocalNativeResultJson | null;
  state: LocalNativeEffectState;
}
export interface NativeEditorDisposition {
  operationId: HostId;
  retirement: NativeEditorRetirement;
  state: LocalNativeEffectState;
}
export interface LocalNativeGitResult {
  custodySettled: boolean;
  operationId: HostId;
  planHash?: HostKeyCommitmentHex | null;
  previewJson?: LocalNativeResultJson | null;
  requestHash: HostKeyCommitmentHex;
  resultJson?: LocalNativeResultJson | null;
  state: LocalNativeGitState;
}
export interface LocalNativeEffectChallenge {
  challenge: HostId;
  operationId: HostId;
}
export interface LocalLoginAccepted {
  generation: DecimalU64;
  operationId: OperationId;
}
export interface LocalLoginStatus {
  accessExpiresAt?: DecimalU64 | null;
  generation: DecimalU64;
  locked: boolean;
  network: LocalAuthNetwork;
  operationId?: OperationId | null;
  pendingCloudRevoke: boolean;
  phase: LocalAuthPhase;
  refreshAt?: DecimalU64 | null;
  storage: LocalAuthStorage;
}
export interface LocalLoginPresentation {
  expiresAt: DecimalU64;
  nextPollAt: DecimalU64;
  userCode: UserCode;
  verificationUrl: LocalRootPath;
}
export interface LocalStatus {
  hostId: HostId;
  hostName: LocalHostName;
  runtimeId: RuntimeId;
  sharing: LocalSharing;
}
export interface LocalMaintenanceStatus {
  activeTerminals: DecimalU64;
  hostId: HostId;
  profileSchema: DecimalU64;
  runtimeId: RuntimeId;
}
export interface LocalStartModePreference {
  startMode: LocalStartMode;
}
export interface DoctorDiagnostic {
  check: DoctorCheck;
  health: DoctorHealth;
}
export interface LocalDoctorReport {
  checks: BoundedList;
  lastError?: DiagnosticCode | null;
  logsAvailable: boolean;
}
export interface LocalOperatorSnapshot {
  activeTerminals: DecimalU64;
  connectedClients?: number | null;
  login: LocalLoginStatus;
  status: LocalStatus;
  uptimeSeconds: DecimalU64;
}
export interface DiagnosticLogSnapshot {
  available: boolean;
  entries: BoundedList2;
  nextCursor: DecimalU64;
  truncated: boolean;
}
export interface DiagnosticLogEntry {
  code: DiagnosticCode;
  component: DiagnosticComponent;
  sequence: DecimalU64;
  severity: DiagnosticSeverity;
  unixTimeMs?: DecimalU64 | null;
}
export interface LocalWorkspaceDetails {
  remoteWebUrl?: LocalWorkspaceWebUrl | null;
  rootPath: LocalRootPath;
  workspace: LocalWorkspaceSummary;
}
export interface LocalWorkspaceSummary {
  name: LocalProjectName;
  sharing: LocalSharing;
  workspaceId: WorkspaceId;
}
export interface LocalWorkspaceRemovalStatus {
  attemptId?: OperationId | null;
  confirmedSessions: DecimalU64;
  phase: LocalWorkspaceRemovalPhase;
  totalSessions: DecimalU64;
  workspaceId: WorkspaceId;
}
export interface LocalWorkspacePublication {
  authGeneration: DecimalU64;
  consent: LocalSharing;
  hostId: HostId;
  publication: LocalPublicationState;
  workspaceId: WorkspaceId;
}
export interface LocalProfileSummary {
  name: LocalProjectName;
  profileId: HostId;
}
export interface LocalWorkspaceImportReceipt {
  importId: WorkspaceId;
  workspace: LocalWorkspaceSummary;
}
export interface WorkspaceBindingsSnapshot {
  bindings: BoundedList5;
  hostId: HostId;
  runtimeId: RuntimeId;
}
export interface WorkspaceState {
  context: WorkspaceContext;
  domainRevision: DecimalU64;
  name: DisplayText;
  tabs: BoundedList6;
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
  profiles: BoundedList7;
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
  entries: BoundedList8;
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
  bytes: BoundedList9;
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
  repositories: BoundedList10;
}
export interface GitRepository {
  displayName: DisplayText;
  remotes: BoundedList11;
  repositoryId: RepositoryId;
}
export interface GitRemote {
  displayName: DisplayText;
  refs: BoundedList12;
  refsStateToken: RepoStateToken;
  remoteId: RemoteId;
  selectors?: BoundedList13;
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
  entries: BoundedList14;
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
  files: BoundedList15;
  nextCursor?: EventCursor | null;
  stateToken: RepoStateToken;
  truncated: boolean;
}
export interface GitDiffFile {
  binary: boolean;
  displayName: DisplayText;
  entryId: EntryId;
  hunks: BoundedList16;
  truncated: boolean;
}
export interface GitDiffHunk {
  lines: BoundedList17;
  newStart: DecimalU64;
  oldStart: DecimalU64;
}
export interface GitDiffLine {
  kind: DiffLineKind;
  text: DiffLineText;
}
export interface GitLogResult {
  commits: BoundedList18;
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
export interface RemoteError {
  code: ErrorCode;
  details: ErrorDetails;
  effect: Effect;
  message: string;
  operation?: OperationLookup | null;
  retryable: boolean;
}
export interface RevisionErrorDetails {
  actualRevision: DecimalU64;
  expectedRevision: DecimalU64;
}
export interface EmptyErrorDetails {}
/**
 * Status lookup route within the authenticated workspace channel. Never a URL.
 */
export interface OperationLookup {
  operationId: OperationId;
  workspaceId: WorkspaceId;
}
export interface NativeLease {
  expiresAtMs: DecimalU64;
  fence: DecimalU64;
  intentId: HostId;
  state: NativeWriterState;
}
export interface LocalIpcVersion {
  major: LocalIpcMajor;
  minor: number;
}
