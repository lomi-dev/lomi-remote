// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type RuntimeId = string;
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
export interface PublishedWorkspace {
  terminals: PublicationTerminals;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface PublishedTerminal {
  paneId: PaneId;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
}
