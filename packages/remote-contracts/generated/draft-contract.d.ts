// Generated from Rust JSON schema. Do not edit.

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
export type DraftCommand =
  | {
      method: "files.create";
      params: FileCreate;
    }
  | {
      method: "files.remove";
      params: FileRemove;
    }
  | {
      method: "terminal.create";
      params: TerminalCreate;
    };
export type EntryId = string;
export type FileRevision = string;
export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type OperationId = string;
export type ChannelPurpose = "workspace" | "terminal";
export type PaneId = string;
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type ApplicationMajor = 2;
export type GrantContextVersion = 3;
export type LocalIpcMajor = 1;
export type RemoteApiMajor = 2;

export interface DraftContract {
  capabilities: CapabilitySet;
  command: DraftCommand;
  mutation: MutationContext;
  purpose: ChannelPurpose;
  terminal?: TerminalContext | null;
  versions: VersionAxes;
}
export interface FileCreate {
  name: string;
  parentEntryId: EntryId;
  parentRevision: FileRevision;
}
export interface FileRemove {
  confirmed: boolean;
  entryId: EntryId;
  fileRevision: FileRevision;
  parentRevision: FileRevision;
}
export interface TerminalCreate {
  profileId: string;
  tabName: string;
}
export interface MutationContext {
  context: WorkspaceContext;
  expectedRevision: DecimalU64;
  operationId: OperationId;
}
export interface WorkspaceContext {
  grantRevision: DecimalU64;
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface TerminalContext {
  paneId: PaneId;
  profile: TerminalProfile;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  workspace: WorkspaceContext;
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
