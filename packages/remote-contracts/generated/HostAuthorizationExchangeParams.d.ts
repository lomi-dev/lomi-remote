// Generated from Rust JSON schema. Do not edit.

export type EnrollmentBootstrapCredential = string;
export type EnrollmentId = string;
export type HostId = string;
export type OperationId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;

export interface HostAuthorizationExchangeParams {
  bootstrap: EnrollmentBootstrapCredential;
  enrollmentId: EnrollmentId;
  hostId: HostId;
  operationId: OperationId;
  proof: EnrollmentProof;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
