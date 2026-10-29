// Generated from Rust JSON schema. Do not edit.

export type HostAccessCredential = string;
export type AccountId = string;
export type DecimalU64 = string;
export type HostAuthorizationId = string;
export type HostId = string;
export type HostRefreshCredential = string;
export type OperationId = string;

export interface HostAuthorizationResult {
  access: HostAccessCredential;
  accountId: AccountId;
  expiresInSeconds: DecimalU64;
  hostAuthorizationId: HostAuthorizationId;
  hostId: HostId;
  refresh: HostRefreshCredential;
  rotationId: OperationId;
}
