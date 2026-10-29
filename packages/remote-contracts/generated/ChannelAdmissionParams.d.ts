// Generated from Rust JSON schema. Do not edit.

export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type DecimalU64 = string;
export type RuntimeId = string;

export interface ChannelAdmissionParams {
  admission: SignedChannelAdmissionWire;
  runtime: RuntimeBinding;
}
export interface SignedChannelAdmissionWire {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
