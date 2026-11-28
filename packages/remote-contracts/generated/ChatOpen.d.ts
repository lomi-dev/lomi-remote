// Generated from Rust JSON schema. Do not edit.

export type ChatMessageId = string;
export type ChatThreadId = string;
export type WorkspaceId = string;

export interface ChatOpen {
  after?: ChatAfter | null;
  threadId: ChatThreadId;
  workspaceId: WorkspaceId;
}
export interface ChatAfter {
  messageId: ChatMessageId;
  streamSeq: number;
}
