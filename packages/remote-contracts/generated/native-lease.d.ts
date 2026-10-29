// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type HostId = string;
export type NativeWriterState = "registered" | "active" | "quarantine" | "finished";

export interface NativeLease {
  expiresAtMs: DecimalU64;
  fence: DecimalU64;
  intentId: HostId;
  state: NativeWriterState;
}
