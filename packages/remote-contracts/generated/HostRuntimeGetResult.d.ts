// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type HostId = string;
export type RuntimeId = string;

export interface HostRuntimeGetResult {
  freshnessMs: DecimalU64;
  hostAccessEpoch: DecimalU64;
  hostId: HostId;
  leaseMs: DecimalU64;
  publicationSeq: DecimalU64;
  runtime?: RuntimeBinding | null;
  runtimeGeneration: DecimalU64;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
