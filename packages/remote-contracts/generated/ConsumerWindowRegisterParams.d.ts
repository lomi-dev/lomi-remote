// Generated from Rust JSON schema. Do not edit.

export type OperationId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type WindowIdentityId = string;

export interface ConsumerWindowRegisterParams {
  operationId: OperationId;
  proof: EnrollmentProof;
  windowIdentityId: WindowIdentityId;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
