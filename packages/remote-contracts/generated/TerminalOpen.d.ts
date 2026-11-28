// Generated from Rust JSON schema. Do not edit.

export type TerminalDimension = number;
export type PaneId = string;
export type SessionEpoch = string;
export type WorkspaceId = string;

export interface TerminalOpen {
  afterSeq?: number | null;
  cols: TerminalDimension;
  paneId: PaneId;
  rows: TerminalDimension;
  sessionEpoch: SessionEpoch;
  workspaceId: WorkspaceId;
}
