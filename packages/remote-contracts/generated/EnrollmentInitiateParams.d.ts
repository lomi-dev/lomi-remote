// Generated from Rust JSON schema. Do not edit.

export type PublicClientId = string;
export type HostKeyCommitmentHex = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;

export interface EnrollmentInitiateParams {
  clientId: PublicClientId;
  keyCommitment: HostKeyCommitmentHex;
  proof: EnrollmentProof;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
