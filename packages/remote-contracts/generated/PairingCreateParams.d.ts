// Generated from Rust JSON schema. Do not edit.

export type HostId = string;
export type OperationId = string;
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
export type DecimalU64 = string;
export type RuntimeId = string;
export type WindowIdentityId = string;
export type WorkspaceEpoch = string;
export type WorkspaceId = string;

export interface PairingCreateParams {
  hostId: HostId;
  operationId: OperationId;
  requestedCapabilities: CapabilitySet;
  runtime: RuntimeBinding;
  windowIdentityId: WindowIdentityId;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
