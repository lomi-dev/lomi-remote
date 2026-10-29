// Generated from Rust JSON schema. Do not edit.

export type ChannelId = string;
export type RelayTicket = string;

export interface WssAdmissionFrame {
  channelId: ChannelId;
  ticket: RelayTicket;
}
