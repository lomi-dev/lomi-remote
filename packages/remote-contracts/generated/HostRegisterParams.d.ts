// Generated from Rust JSON schema. Do not edit.

export type HostId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;

export interface HostRegisterParams {
  hostId: HostId;
  identity: EnrollmentProof;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
