// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type RuntimeId = string;

export interface RuntimeClaimResult {
  leaseMs: DecimalU64;
  runtime: RuntimeBinding;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
