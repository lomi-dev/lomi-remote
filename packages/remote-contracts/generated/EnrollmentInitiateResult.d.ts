// Generated from Rust JSON schema. Do not edit.

export type DeviceCode = string;
export type EnrollmentId = string;
export type DecimalU64 = string;
export type UserCode = string;

export interface EnrollmentInitiateResult {
  deviceCode: DeviceCode;
  enrollmentId: EnrollmentId;
  expiresInSeconds: DecimalU64;
  pollIntervalSeconds: DecimalU64;
  userCode: UserCode;
}
