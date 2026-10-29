// Generated from Rust JSON schema. Do not edit.

/**
 * Closed, proof-only acknowledgement result. The no-family case deliberately
 * has no family ID or epoch fields.
 */
export type HostEnrollmentRevocationAckResult =
  | {
      accountId: AccountId;
      enrollmentId: EnrollmentId;
      familyHostAccessEpoch: string;
      hostAccessEpoch: string;
      hostAuthorizationId: HostAuthorizationId;
      hostId: HostId;
      operationId: OperationId;
      outcome: "revokedFamily";
    }
  | {
      accountId: AccountId;
      enrollmentId: EnrollmentId;
      hostId: HostId;
      operationId: OperationId;
      outcome: "noFamily";
    };
export type AccountId = string;
export type EnrollmentId = string;
export type HostAuthorizationId = string;
export type HostId = string;
export type OperationId = string;
