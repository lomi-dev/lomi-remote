// Generated from Rust JSON schema. Do not edit.

export type DecimalU64 = string;
export type RuntimeId = string;
export type WindowIdentityId = string;

export interface ChannelTicketParams {
  runtime: RuntimeBinding;
  windowIdentityId?: WindowIdentityId | null;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
