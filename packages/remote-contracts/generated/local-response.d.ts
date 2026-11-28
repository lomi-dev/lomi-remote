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
      type: "chatLevel";
      value: LocalChatLevelState;
    }
  | {
      type: "chatThreads";
      value: BoundedList7;
    }
  | {
      type: "chatThread";
      value: LocalChatThread;
    }
  | {
      type: "chatDeleted";
      value: {};
    }
  | {
      type: "chatAudit";
      value: BoundedList8;
    }
  | {
      type: "devices";
      value: LocalDevices;
    }
  | {
      type: "deviceMode";
      value: LocalDeviceModeState;
    }
  | {
      type: "deviceNotices";
      value: BoundedList11;
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
/**
 * Owner-granted Chat AI level of one workspace. `Off` is the default: nothing
 * chat-related enters the ceiling or the publication.
 */
export type ChatLevel = "off" | "send" | "edit" | "full";
export type ChatPermissions = "read-only" | "edit" | "full";
export type ChatProviderId = string;
export type ChatThreadId = string;
export type ChatTitle = string;
/**
 * @maxItems 200
 */
export type BoundedList7 = LocalChatThread[];
export type LocalChatAuditLine = string;
/**
 * @maxItems 200
 */
export type BoundedList8 = LocalChatAuditLine[];
export type LocalDeviceText = string;
export type LocalDeviceLevel = "read" | "control";
/**
 * @maxItems 16
 */
export type BoundedList9 = LocalDeviceGrant[];
export type LocalDeviceMode = "auto" | "confirm";
export type LocalDeviceReason = "newDevice" | "control";
/**
 * @maxItems 16
 */
export type BoundedList10 = LocalDeviceApproval[];
export type LocalDeviceNoticeKind = "newDevice" | "controlRequested" | "grantsFull" | "rateLimited";
/**
 * @maxItems 32
 */
export type BoundedList11 = LocalDeviceNotice[];
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
/**
 * @maxItems 32
 */
export type BoundedList12 = HostProfile[];
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
export type BoundedList13 = FileMetadata[];
/**
 * @maxItems 1048576
 */
export type BoundedList14 = number[];
export type FileEncoding = "utf8" | "utf16Le" | "utf16Be" | "binary" | "unknown";
export type LineEndings = "lf" | "crLf" | "cr" | "mixed" | "none";
export type RefId = string;
/**
 * @maxItems 200
 */
export type BoundedList17 = RefId[];
export type RemoteId = string;
export type GitRemoteSelectorKind = "head" | "fetch" | "push";
/**
 * @maxItems 200
 */
export type BoundedList18 = GitRemoteSelector[];
/**
 * @maxItems 32
 */
export type BoundedList16 = GitRemote[];
export type RepositoryId = string;
/**
 * @maxItems 32
 */
export type BoundedList15 = GitRepository[];
export type GitChange =
  "unchanged" | "added" | "modified" | "deleted" | "renamed" | "copied" | "unmerged" | "untracked";
/**
 * @maxItems 200
 */
export type BoundedList19 = GitStatusEntry[];
export type DiffLineKind = "context" | "added" | "removed";
export type DiffLineText = string;
/**
 * @maxItems 200
 */
export type BoundedList22 = GitDiffLine[];
/**
 * @maxItems 200
 */
export type BoundedList21 = GitDiffHunk[];
/**
 * @maxItems 200
 */
export type BoundedList20 = GitDiffFile[];
export type ObjectId = string;
/**
 * @maxItems 200
 */
export type BoundedList23 = GitCommitSummary[];
export type ChatName = string;
export type ChatEffort = string;
/**
 * @maxItems 16
 */
export type BoundedList26 = ChatEffort[];
export type ChatKind = "api" | "cli";
export type ChatModelId = string;
/**
 * @maxItems 256
 */
export type BoundedList25 = ChatModel[];
/**
 * @maxItems 32
 */
export type BoundedList24 = ChatProvider[];
export type ChatCursor = string;
export type ChatWorkspaceMode = "project" | "private";
/**
 * @maxItems 200
 */
export type BoundedList27 = ChatThread[];
export type ChatMessageContent = string;
export type ChatMessageId = string;
export type ChatRole = "user" | "assistant";
export type ChatMessageState =
  "committed" | "dispatching" | "streaming" | "completed" | "stopped" | "failed" | "interrupted";
export type ChatStopReason = string;
/**
 * @maxItems 50
 */
export type BoundedList28 = ChatMessage[];
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
  | "CHAT_BUSY"
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
export interface LocalChatLevelState {
  level: ChatLevel;
  workspaceId: WorkspaceId;
}
export interface LocalChatThread {
  permissions: ChatPermissions;
  providerId: ChatProviderId;
  streaming: boolean;
  threadId: ChatThreadId;
  title: ChatTitle;
  updatedMs: DecimalU64;
  workspaceId: WorkspaceId;
}
export interface LocalDevices {
  grants: BoundedList9;
  mode: LocalDeviceMode;
  pending: BoundedList10;
}
export interface LocalDeviceGrant {
  fingerprint: LocalDeviceText;
  grantedAt: DecimalU64;
  kind: LocalDeviceText;
  level: LocalDeviceLevel;
  name: LocalDeviceText;
  serverConfirmedAt: DecimalU64;
  valid: boolean;
}
export interface LocalDeviceApproval {
  at: DecimalU64;
  circuit: LocalDeviceText;
  code: LocalDeviceText;
  deviceName: LocalDeviceText;
  fingerprint: LocalDeviceText;
  reason: LocalDeviceReason;
}
export interface LocalDeviceModeState {
  mode: LocalDeviceMode;
}
export interface LocalDeviceNotice {
  code?: LocalDeviceText | null;
  deviceName: LocalDeviceText;
  kind: LocalDeviceNoticeKind;
}
export interface WorkspaceCapabilitiesResult {
  capabilities: CapabilitySet;
  profiles: BoundedList12;
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
  entries: BoundedList13;
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
  bytes: BoundedList14;
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
  repositories: BoundedList15;
}
export interface GitRepository {
  displayName: DisplayText;
  remotes: BoundedList16;
  repositoryId: RepositoryId;
}
export interface GitRemote {
  displayName: DisplayText;
  refs: BoundedList17;
  refsStateToken: RepoStateToken;
  remoteId: RemoteId;
  selectors?: BoundedList18;
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
  entries: BoundedList19;
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
  files: BoundedList20;
  nextCursor?: EventCursor | null;
  stateToken: RepoStateToken;
  truncated: boolean;
}
export interface GitDiffFile {
  binary: boolean;
  displayName: DisplayText;
  entryId: EntryId;
  hunks: BoundedList21;
  truncated: boolean;
}
export interface GitDiffHunk {
  lines: BoundedList22;
  newStart: DecimalU64;
  oldStart: DecimalU64;
}
export interface GitDiffLine {
  kind: DiffLineKind;
  text: DiffLineText;
}
export interface GitLogResult {
  commits: BoundedList23;
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
  providers: BoundedList24;
}
export interface ChatProvider {
  cli?: ChatName | null;
  efforts: BoundedList26;
  kind: ChatKind;
  loggedIn?: boolean | null;
  models: BoundedList25;
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
  threads: BoundedList27;
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
  messages: BoundedList28;
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
