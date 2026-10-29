// Generated from Rust JSON schema. Do not edit.

export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type WindowIdentityId = string;

export interface ConsumerWindowChallengeParams {
  identity: EnrollmentProof;
  windowIdentityId: WindowIdentityId;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
