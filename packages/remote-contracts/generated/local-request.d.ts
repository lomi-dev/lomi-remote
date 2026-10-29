// Generated from Rust JSON schema. Do not edit.

export type LocalCall =
  | {
      method: "native.files.stage";
      params: LocalNativeFileBlob;
    }
  | {
      method: "native.files.execute";
      params: LocalNativeEditorExecute;
    }
  | {
      method: "native.files.executeGuarded";
      params: LocalNativeEditorExecute;
    }
  | {
      method: "native.effect.decision";
      params: LocalNativeEffectDecision;
    }
  | {
      method: "native.files.status";
      params: NativeIntentTarget;
    }
  | {
      method: "native.files.disposition";
      params: NativeIntentTarget;
    }
  | {
      method: "native.files.acknowledge";
      params: NativeIntentTarget;
    }
  | {
      method: "native.acknowledge";
      params: NativeIntentTarget;
    }
  | {
      method: "native.git.prepareGuarded";
      params: LocalNativeGitPrepare;
    }
  | {
      method: "native.git.executeGuarded";
      params: LocalNativeGitExecute;
    }
  | {
      method: "native.git.status";
      params: NativeIntentTarget;
    }
  | {
      method: "native.git.cancelPrepared";
      params: NativeIntentTarget;
    }
  | {
      method: "native.git.acknowledge";
      params: NativeIntentTarget;
    }
  | {
      method: "auth.configure";
      params: LocalAuthConfigure;
    }
  | {
      method: "login.start";
      params: LocalLoginStart;
    }
  | {
      method: "login.status";
      params: {};
    }
  | {
      method: "login.presentation";
      params: {};
    }
  | {
      method: "logout";
      params: LocalOperatorIntent;
    }
  | {
      method: "daemon.stop";
      params: LocalOperatorIntent;
    }
  | {
      method: "status";
      params: {};
    }
  | {
      method: "host.name.set";
      params: LocalHostNameSet;
    }
  | {
      method: "maintenance.prepare";
      params: LocalOperatorIntent;
    }
  | {
      method: "setup.startMode.read";
      params: {};
    }
  | {
      method: "setup.startMode.save";
      params: LocalStartModePreference;
    }
  | {
      method: "doctor";
      params: {};
    }
  | {
      method: "doctor.report";
      params: {};
    }
  | {
      method: "operator.snapshot";
      params: {};
    }
  | {
      method: "diagnostics.logs";
      params: LocalDiagnosticLogsRead;
    }
  | {
      method: "workspaces";
      params: {};
    }
  | {
      method: "workspace.inspect";
      params: LocalWorkspaceRead;
    }
  | {
      method: "workspace.details";
      params: LocalWorkspaceRead;
    }
  | {
      method: "workspace.removal.status";
      params: LocalWorkspaceRead;
    }
  | {
      method: "workspace.publication";
      params: LocalWorkspaceRead;
    }
  | {
      method: "workspace.rename";
      params: LocalWorkspaceRename;
    }
  | {
      method: "profiles";
      params: {};
    }
  | {
      method: "localWorkspaceAdd";
      params: LocalWorkspaceAdd;
    }
  | {
      method: "workspace.import";
      params: LocalWorkspaceImport;
    }
  | {
      method: "workspace.bindings.read";
      params: WorkspaceBindingsRead;
    }
  | {
      method: "shellProfile.register";
      params: LocalShellProfileRegister;
    }
  | {
      method: "localWorkspaceRemove";
      params: LocalWorkspaceTarget;
    }
  | {
      method: "share";
      params: LocalWorkspaceTarget;
    }
  | {
      method: "share.authorized";
      params: LocalWorkspaceConsentAuthorized;
    }
  | {
      method: "unshare.authorized";
      params: LocalWorkspaceConsentAuthorized;
    }
  | {
      method: "unshare";
      params: LocalWorkspaceTarget;
    }
  | {
      method: "rpc";
      params: RpcRequest;
    }
  | {
      method: "stream.ack";
      params: LocalStreamAck;
    }
  | {
      method: "native.intent";
      params: NativeIntentRequest;
    }
  | {
      method: "native.bindJob";
      params: NativeBindJobRequest;
    }
  | {
      method: "native.acquire";
      params: NativeIntentTarget;
    }
  | {
      method: "native.check";
      params: NativeIntentTarget;
    }
  | {
      method: "native.renew";
      params: NativeIntentTarget;
    }
  | {
      method: "native.requestFinish";
      params: NativeIntentTarget;
    }
  | {
      method: "native.reconcile";
      params: NativeIntentTarget;
    };
export type DecimalU64 = string;
export type HostKeyCommitmentHex = string;
export type HostId = string;
export type LocalNativeEditorEffect =
  | {
      effect: "save";
      expectedRevision: HostKeyCommitmentHex;
      relative: LocalNativeRelativePath;
      root: LocalRootPath;
    }
  | {
      absolutePath: LocalRootPath;
      effect: "saveNew";
      openFiles: BoundedList;
    }
  | {
      absolutePath: LocalRootPath;
      effect: "saveNewChecked";
      expectedRevision?: HostKeyCommitmentHex | null;
      openFiles: BoundedList;
    }
  | {
      effect: "projectFiles";
      root: LocalRootPath;
    }
  | {
      effect: "desktopFiles";
      root: LocalRootPath;
      timeoutMs: TimeoutMs;
    }
  | {
      effect: "artifactCreate";
      expectedParentRevision: HostKeyCommitmentHex;
      relative: LocalNativeRelativePath;
      root: LocalRootPath;
    };
export type LocalNativeRelativePath = string;
export type LocalRootPath = string;
/**
 * @maxItems 256
 */
export type BoundedList = LocalNativeFileLocation[];
export type TimeoutMs = number;
/**
 * @maxItems 8
 */
export type BoundedList2 = LocalRootPath[];
export type LocalNativeResultJson = string;
export type WorkspaceId = string;
export type LocalAuthClientId = string;
export type LocalAuthOrigin = string;
export type LocalFileAcknowledgement = "osPermissionsOnly";
export type LocalAuthProvider = "protectedFile" | "macOsKeychain" | "windowsDpapi" | "linuxSecretService";
export type LocalRelayEndpoint = string;
export type Confirmed = "confirmed";
export type OperationId = string;
export type LocalHostName = string;
/**
 * Saved local preference only. It does not install or start an OS service.
 */
export type LocalStartMode = "manual" | "login" | "boot";
export type LocalProjectName = string;
/**
 * @maxItems 256
 */
export type BoundedList3 = WorkspaceId[];
export type LocalProcessArgument = string;
/**
 * @maxItems 32
 */
export type BoundedList4 = LocalProcessArgument[];
export type LocalShellEnvironmentName = string;
/**
 * @maxItems 8
 */
export type BoundedList5 = LocalShellEnvironment[];
/**
 * Typed description of an ordinary discovered shell. Its fields are local
 * configuration only; remote RPC still selects a registered profile ID.
 */
export type LocalShellIntegration =
  | {
      home: LocalRootPath;
      original_zdotdir?: LocalRootPath | null;
      platform: "nativeV1";
      shell: LocalShellKind;
    }
  | {
      distro: LocalProjectName;
      home: LocalRootPath;
      platform: "wslV1";
      shell: LocalShellKind;
      shell_executable: LocalRootPath;
    };
export type LocalShellKind = ("bash" | "zsh" | "fish" | "sh" | "powershell" | "cmd") | "other";
export type HostProfileId = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
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
export type EventCursor = string;
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
export type BoundedList6 = number[];
export type TerminalDimension = number;
export type PageLimit = number;
export type EntryId = string;
export type FileRevision = string;
export type PreviewLimit = number;
export type SearchText = string;
export type DestinationState = "absent";
export type EntryName = string;
export type RepositoryId = string;
export type RepoStateToken = string;
export type DiffView = "index" | "worktree";
export type ObjectId = string;
/**
 * @maxItems 200
 */
export type BoundedList7 = GitStagePath[];
/**
 * @maxItems 200
 */
export type BoundedList8 = EntryId[];
export type CommitMessage = string;
export type RefId = string;
export type RemoteId = string;
export type PullMode = "ff-only";
export type RequestId = string;
export type RequestKind = "request";
export type ApplicationMajor = 2;
export type LocalStreamAck =
  | {
      frame: WorkspaceStreamAck;
      stream: "workspace";
    }
  | {
      frame: FileWatchAck;
      stream: "files";
    };
export type NativeIntentScope =
  | {
      scope: "workspace";
      workspaceId: WorkspaceId;
    }
  | {
      scope: "unscoped";
    };
export type LocalNativeParentOperationId = string;
export type LocalIpcMajor = 1;

export interface LocalRequest {
  call: LocalCall;
  requestId: RequestId;
  version: LocalIpcVersion;
}
export interface LocalNativeFileBlob {
  byteLength: DecimalU64;
  contentSha256: HostKeyCommitmentHex;
  operationId: HostId;
}
export interface LocalNativeEditorExecute {
  blob: LocalNativeFileBlob;
  effect: LocalNativeEditorEffect;
}
export interface LocalNativeFileLocation {
  relative: LocalNativeRelativePath;
  root: LocalRootPath;
}
export interface LocalNativeEffectDecision {
  allowed: boolean;
  challenge: HostId;
  operationId: HostId;
}
export interface NativeIntentTarget {
  intentId: HostId;
}
export interface LocalNativeGitPrepare {
  input: LocalNativeGitInput;
  operationId: HostId;
  timeoutMs: TimeoutMs;
}
export interface LocalNativeGitInput {
  controlRoots: BoundedList2;
  requestJson: LocalNativeResultJson;
  root: LocalRootPath;
  workspaceId: WorkspaceId;
}
export interface LocalNativeGitExecute {
  operationId: HostId;
  planHash: HostKeyCommitmentHex;
  requestHash: HostKeyCommitmentHex;
  timeoutMs: TimeoutMs;
}
export interface LocalAuthConfigure {
  configuration: LocalAuthConfiguration;
  operatorIntent: Confirmed;
}
export interface LocalAuthConfiguration {
  clientId: LocalAuthClientId;
  keychainPath?: LocalRootPath | null;
  origin: LocalAuthOrigin;
  protectedFileAcknowledgement?: LocalFileAcknowledgement | null;
  provider: LocalAuthProvider;
  relayEndpoint?: LocalRelayEndpoint | null;
  remoteApiOrigin?: LocalAuthOrigin | null;
  version: number;
}
export interface LocalLoginStart {
  operationId: OperationId;
}
export interface LocalOperatorIntent {
  operatorIntent: Confirmed;
}
export interface LocalHostNameSet {
  expectedName?: LocalHostName | null;
  name: LocalHostName;
}
export interface LocalStartModePreference {
  startMode: LocalStartMode;
}
export interface LocalDiagnosticLogsRead {
  afterSequence?: DecimalU64 | null;
  limit: number;
}
export interface LocalWorkspaceRead {
  workspaceId: WorkspaceId;
}
export interface LocalWorkspaceRename {
  expectedName: LocalProjectName;
  name: LocalProjectName;
  operatorIntent: Confirmed;
  workspaceId: WorkspaceId;
}
export interface LocalWorkspaceAdd {
  name: LocalProjectName;
  operatorIntent: Confirmed;
  rootPath: LocalRootPath;
}
export interface LocalWorkspaceImport {
  name: LocalProjectName;
  operatorIntent: Confirmed;
  rootPath: LocalRootPath;
  workspaceId: WorkspaceId;
}
export interface WorkspaceBindingsRead {
  importIds: BoundedList3;
}
export interface LocalShellProfileRegister {
  args: BoundedList4;
  cwd: LocalRootPath;
  environment: BoundedList5;
  executable: LocalRootPath;
  integration?: LocalShellIntegration | null;
  name: LocalProjectName;
  operatorIntent: Confirmed;
  profileId: HostProfileId;
  workspaceId: WorkspaceId;
}
export interface LocalShellEnvironment {
  name: LocalShellEnvironmentName;
  value: LocalProcessArgument;
}
export interface LocalWorkspaceTarget {
  operatorIntent: Confirmed;
  workspaceId: WorkspaceId;
}
export interface LocalWorkspaceConsentAuthorized {
  expectedAuthorizationGeneration: DecimalU64;
  expectedContext: WorkspaceContext;
  expectedHostId: HostId;
  expectedImportId: WorkspaceId;
  expectedRootPath: LocalRootPath;
  operatorIntent: Confirmed;
  workspaceId: WorkspaceId;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
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
  bytes: BoundedList6;
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
  paths: BoundedList7;
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
  paths: BoundedList8;
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
export interface WorkspaceStreamAck {
  context: WorkspaceContext;
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface FileWatchAck {
  context: WorkspaceContext;
  cursor: EventCursor;
  subscriptionId: SubscriptionId;
  throughSeq: DecimalU64;
}
export interface NativeIntentRequest {
  intentId: HostId;
  scope: NativeIntentScope;
}
export interface NativeBindJobRequest {
  intentId: HostId;
  parentOperationId: LocalNativeParentOperationId;
  storeRoot: LocalRootPath;
}
export interface LocalIpcVersion {
  major: LocalIpcMajor;
  minor: number;
}
