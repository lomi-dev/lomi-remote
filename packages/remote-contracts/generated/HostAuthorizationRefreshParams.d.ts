// Generated from Rust JSON schema. Do not edit.

export type HostAuthorizationId = string;
export type HostId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type HostRefreshCredential = string;
export type OperationId = string;

export interface HostAuthorizationRefreshParams {
  hostAuthorizationId: HostAuthorizationId;
  hostId: HostId;
  proof: EnrollmentProof;
  refresh: HostRefreshCredential;
  rotationId: OperationId;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
