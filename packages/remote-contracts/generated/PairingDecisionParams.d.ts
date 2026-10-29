// Generated from Rust JSON schema. Do not edit.

export type PairingDecisionParams =
  | {
      decision: "approve";
      grant: SignedGrantWire;
      runtime: RuntimeBinding;
    }
  | {
      decision: "deny";
      runtime: RuntimeBinding;
    };
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type DecimalU64 = string;
export type RuntimeId = string;

export interface SignedGrantWire {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
