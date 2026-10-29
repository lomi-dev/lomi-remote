// Generated from Rust JSON schema. Do not edit.

export type ChannelId = string;
export type DecimalU64 = string;
export type RelayTicket = string;

export interface ChannelTicketResult {
  channelId: ChannelId;
  expiresInMs: DecimalU64;
  ticket: RelayTicket;
}
