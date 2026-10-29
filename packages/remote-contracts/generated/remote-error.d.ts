// Generated from Rust JSON schema. Do not edit.

export type ErrorCode =
  | "INVALID_ARGUMENT"
  | "AUTH_REQUIRED"
  | "SCOPE_DENIED"
  | "WORKSPACE_UNSHARED"
  | "REPOSITORY_EXECUTION_REQUIRED"
  | "PROTECTED_PATH"
  | "RESOURCE_NOT_FOUND"
  | "OPERATION_NOT_FOUND"
  | "STALE_EPOCH"
  | "REVISION_CONFLICT"
  | "FILE_CHANGED"
  | "IDEMPOTENCY_CONFLICT"
  | "HOST_BUSY"
  | "CONTROL_REQUIRED"
  | "CONTROL_REVOKED"
  | "SESSION_EXITED"
  | "RESYNC_REQUIRED"
  | "DIRECTORY_NOT_EMPTY"
  | "CREDENTIALS_REQUIRED"
  | "GIT_IDENTITY_REQUIRED"
  | "UNSUPPORTED_CAPABILITY"
  | "OUTCOME_UNKNOWN"
  | "OPERATION_EXPIRED"
  | "UPDATE_REQUIRED"
  | "RESOURCE_EXHAUSTED"
  | "FRESHNESS_REQUIRED"
  | "SERVICE_UNAVAILABLE"
  | "DEADLINE_EXCEEDED";
export type ErrorDetails = RevisionErrorDetails | EmptyErrorDetails;
export type DecimalU64 = string;
export type Effect = "none" | "committed" | "partial" | "unknown";
export type OperationId = string;
export type WorkspaceId = string;

export interface RemoteError {
  code: ErrorCode;
  details: ErrorDetails;
  effect: Effect;
  message: string;
  operation?: OperationLookup | null;
  retryable: boolean;
}
export interface RevisionErrorDetails {
  actualRevision: DecimalU64;
  expectedRevision: DecimalU64;
}
export interface EmptyErrorDetails {}
/**
 * Status lookup route within the authenticated workspace channel. Never a URL.
 */
export interface OperationLookup {
  operationId: OperationId;
  workspaceId: WorkspaceId;
}
