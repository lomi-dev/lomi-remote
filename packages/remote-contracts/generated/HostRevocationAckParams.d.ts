// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type HostAuthorizationId = string;

export interface HostRevocationAckParams {
  expectedHostAccessEpoch: DecimalU64;
  hostAuthorizationId: HostAuthorizationId;
  /**
   * Retained proof for an already-revoked family; grants no host access.
   */
  refresh: string;
}
