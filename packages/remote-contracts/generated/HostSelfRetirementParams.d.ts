// Generated from Rust JSON schema. Do not edit.

export type HostAuthorizationId = string;
export type OperationId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type HostRefreshCredential = string;

export interface HostSelfRetirementParams {
  expectedHostAccessEpoch: string;
  expiresAt: string;
  hostAuthorizationId: HostAuthorizationId;
  operationId: OperationId;
  preparedAt: string;
  proof: EnrollmentProof;
  refresh: HostRefreshCredential;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
