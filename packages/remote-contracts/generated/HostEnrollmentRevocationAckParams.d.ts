// Generated from Rust JSON schema. Do not edit.

export type EnrollmentId = string;
export type OperationId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;

export interface HostEnrollmentRevocationAckParams {
  enrollmentId: EnrollmentId;
  operationId: OperationId;
  proof: EnrollmentProof;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
