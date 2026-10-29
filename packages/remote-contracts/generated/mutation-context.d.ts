// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type RuntimeId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
export type OperationId = string;

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
