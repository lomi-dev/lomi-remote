// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type RuntimeId = string;
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
export type PaneId = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;
/**
 * @maxItems 4096
 */
export type PublicationTerminals = PublishedTerminal[];
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
/**
 * @maxItems 256
 */
export type PublicationWorkspaces = PublishedWorkspace[];

export interface PublicationParams {
  expectedPublicationSeq: DecimalU64;
  publicationSeq: DecimalU64;
  runtime: RuntimeBinding;
  workspaces: PublicationWorkspaces;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
/**
 * `capabilities` is the published ceiling; omitted (not null) when the Host
 * publishes none, so Hosts without it keep byte-identical JSON.
 */
export interface PublishedWorkspace {
  capabilities?: CapabilitySet | null;
  terminals: PublicationTerminals;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface PublishedTerminal {
  paneId: PaneId;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
}
