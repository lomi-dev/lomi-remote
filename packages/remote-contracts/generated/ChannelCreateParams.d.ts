// Generated from Rust JSON schema. Do not edit.

export type GrantId = string;
export type DecimalU64 = string;
export type OperationId = string;
export type RuntimeId = string;
export type ChannelTarget =
  | {
      purpose: "workspace";
      workspaceEpoch: WorkspaceEpoch;
      workspaceId: WorkspaceId;
    }
  | {
      paneId: PaneId;
      purpose: "terminal";
      sessionEpoch: SessionEpoch;
      sessionId: TerminalSessionId;
      workspaceEpoch: WorkspaceEpoch;
      workspaceId: WorkspaceId;
    };
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type PaneId = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type WindowIdentityId = string;

export interface ChannelCreateParams {
  grantId: GrantId;
  grantRevision: DecimalU64;
  operationId: OperationId;
  runtime: RuntimeBinding;
  target: ChannelTarget;
  windowIdentityId?: WindowIdentityId | null;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
