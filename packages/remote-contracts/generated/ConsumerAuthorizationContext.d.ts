// Generated from Rust JSON schema. Do not edit.

export type AccountId = string;
export type AccountSessionId = string;
export type ConsumerClass = "web" | "desktop" | "mobile";
export type ConsumerAuthorizationId = string;
export type DecimalU64 = string;

export interface ConsumerAuthorizationContext {
  accountId: AccountId;
  accountSessionId: AccountSessionId;
  canManageAccount: boolean;
  class: ConsumerClass;
  consumerAuthorizationId: ConsumerAuthorizationId;
  expiresAt: DecimalU64;
}
