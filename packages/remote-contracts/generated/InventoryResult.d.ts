// Generated from Rust JSON schema. Do not edit.

export type AccountId = string;
export type AccountSessionId = string;
export type ConsumerClass = "web" | "desktop" | "mobile";
export type ConsumerAuthorizationId = string;
export type DecimalU64 = string;
export type HostId = string;
export type CanonicalCryptoCborHex = string;
export type SignatureHex = string;
export type IdentityFingerprintHex = string;
export type HostKeyCommitmentHex = string;
export type RuntimeId = string;
export type CommitmentHostRole = "host";
/**
 * @minItems 64
 * @maxItems 64
 */
export type CommitmentSignature = [
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number,
  number
];
export type InventoryStatus = "online" | "offline" | "publishing";
export type PaneId = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;
/**
 * @maxItems 4096
 */
export type PublicationTerminals = PublishedTerminal[];
export type WorkspaceEpoch = string;
export type WorkspaceId = string;
/**
 * @maxItems 256
 */
export type PublicationWorkspaces = PublishedWorkspace[];
/**
 * @maxItems 256
 */
export type InventoryHosts = InventoryHost[];

export interface InventoryResult {
  authorization: ConsumerAuthorizationContext;
  hosts: InventoryHosts;
}
export interface ConsumerAuthorizationContext {
  accountId: AccountId;
  accountSessionId: AccountSessionId;
  canManageAccount: boolean;
  class: ConsumerClass;
  consumerAuthorizationId: ConsumerAuthorizationId;
  expiresAt: DecimalU64;
}
export interface InventoryHost {
  hostId: HostId;
  identity: EnrollmentProof;
  identityFingerprint: IdentityFingerprintHex;
  initialCommitment: HostKeyCommitmentHex;
  runtime: RuntimeBinding;
  signedCommitment: SignedHostKeyCommitmentWire;
  status: InventoryStatus;
  workspaces: PublicationWorkspaces;
}
export interface EnrollmentProof {
  canonicalCbor: CanonicalCryptoCborHex;
  signature: SignatureHex;
}
export interface RuntimeBinding {
  hostAccessEpoch: DecimalU64;
  runtimeGeneration: DecimalU64;
  runtimeId: RuntimeId;
}
export interface SignedHostKeyCommitmentWire {
  descriptor: HostKeyCommitmentDescriptor;
  signature: CommitmentSignature;
}
export interface HostKeyCommitmentDescriptor {
  /**
   * @minItems 32
   * @maxItems 32
   */
  channelKey: [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  /**
   * @minItems 16
   * @maxItems 16
   */
  hostId: [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  /**
   * @minItems 32
   * @maxItems 32
   */
  identityKey: [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  keyVersion: number;
  /**
   * @minItems 32
   * @maxItems 32
   */
  mailboxKey: [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number
  ];
  role: CommitmentHostRole;
  version: number;
}
export interface PublishedWorkspace {
  terminals: PublicationTerminals;
  workspaceEpoch: WorkspaceEpoch;
  workspaceId: WorkspaceId;
}
export interface PublishedTerminal {
  paneId: PaneId;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
}
