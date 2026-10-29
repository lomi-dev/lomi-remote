// Generated from Rust JSON schema. Do not edit.

export type AccountId = string;
export type AccountSessionId = string;
export type ChannelId = string;
export type ConsumerAuthorizationId = string;
export type DecimalU64 = string;
export type EnrollmentId = string;
export type EntryId = string;
export type EventCursor = string;
export type FileRevision = string;
export type GrantId = string;
export type HostAuthorizationId = string;
export type HostId = string;
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
export type OperationId = string;
export type PairingId = string;
export type PaneId = string;
export type RepoStateToken = string;
export type RepositoryId = string;
export type RequestId = string;
export type RuntimeId = string;
export type SessionEpoch = string;
export type TabId = string;
export type TerminalSessionId = string;
export type ApplicationMajor = 2;
export type GrantContextVersion = 3;
export type LocalIpcMajor = 1;
export type RemoteApiMajor = 2;
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type WindowIdentityId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;

export interface FoundationTypes {
  account_id: AccountId;
  account_session_id: AccountSessionId;
  channel_id: ChannelId;
  consumer_authorization_id: ConsumerAuthorizationId;
  decimal_u64: DecimalU64;
  enrollment_id: EnrollmentId;
  entry_id: EntryId;
  event_cursor: EventCursor;
  file_revision: FileRevision;
  grant_id: GrantId;
  host_authorization_id: HostAuthorizationId;
  host_id: HostId;
  method: Method;
  operation_id: OperationId;
  pairing_id: PairingId;
  pane_id: PaneId;
  repo_state_token: RepoStateToken;
  repository_id: RepositoryId;
  request_id: RequestId;
  runtime_id: RuntimeId;
  session_epoch: SessionEpoch;
  tab_id: TabId;
  terminal_session_id: TerminalSessionId;
  versions: VersionAxes;
  window_identity_id: WindowIdentityId;
  workspace_epoch: WorkspaceEpoch;
  workspace_id: WorkspaceId;
}
export interface VersionAxes {
  applicationMajor: ApplicationMajor;
  grantContextVersion: GrantContextVersion;
  localIpc: LocalIpcVersion;
  remoteApiMajor: RemoteApiMajor;
  terminalProfile: TerminalProfile;
}
export interface LocalIpcVersion {
  major: LocalIpcMajor;
  minor: number;
}
