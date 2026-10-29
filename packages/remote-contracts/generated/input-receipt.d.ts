// Generated from Rust JSON schema. Do not edit.

export type InputBytes = number;
export type DecimalU64 = string;
export type SessionEpoch = string;
export type TerminalSessionId = string;

/**
 * Ephemeral receipt in session-epoch RAM only. No input bytes or keystroke hash.
 * Acceptance counts PTY bytes; it does not mean shell execution or permit replay.
 */
export interface InputReceipt {
  acceptedBytes: InputBytes;
  inputId: DecimalU64;
  inputSeq: DecimalU64;
  sessionEpoch: SessionEpoch;
  sessionId: TerminalSessionId;
  submittedBytes: InputBytes;
}
