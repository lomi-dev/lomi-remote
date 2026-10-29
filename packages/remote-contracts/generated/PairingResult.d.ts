// Generated from Rust JSON schema. Do not edit.

export type PairingResult =
  | {
      pairingId: PairingId;
      proposal: PairingProposal;
      status: "pending";
    }
  | {
      authority: CurrentAuthorityBinding;
      grant: SignedGrantWire;
      identities: PeerIdentities;
      pairingId: PairingId;
      proposal: PairingProposal;
      status: "approved";
    }
  | {
      pairingId: PairingId;
      status: "denied";
    }
  | {
      pairingId: PairingId;
      status: "expired";
    };
export type PairingId = string;
export type DecimalU64 = string;
export type AccountSessionId = string;
export type ConsumerAuthorizationId = string;
export type HostAuthorizationId = string;
export type RuntimeId = string;
export type PaneId = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;
export type TerminalProfile = "lomi-rust-grid-v1-experimental";
export type WorkspaceEpoch = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type IdentityFingerprintHex = string;

export interface PairingProposal {
  authority: CurrentAuthorityBinding;
  identities: PeerIdentities;
  maximumGrant: CanonicalCryptoCborHex;
}
export interface CurrentAuthorityBinding {
  accessEpoch: DecimalU64;
  accountSessionId: AccountSessionId;
  consumerAuthorizationId: ConsumerAuthorizationId;
  grantRevision: DecimalU64;
  hostAuthorizationId: HostAuthorizationId;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
  terminalMembership?: ChannelTerminalMembership | null;
  workspaceEpoch: WorkspaceEpoch;
}
export interface ChannelTerminalMembership {
  paneId: PaneId;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  terminalProfile: TerminalProfile;
}
export interface PeerIdentities {
  consumer: EnrollmentProof;
  consumerFingerprint: IdentityFingerprintHex;
  host: EnrollmentProof;
  hostFingerprint: IdentityFingerprintHex;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
export interface SignedGrantWire {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
