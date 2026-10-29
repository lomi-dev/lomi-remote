// Generated from Rust JSON schema. Do not edit.

export type HostId = string;
export type RuntimeId = string;
export type LocalIpcMajor = 1;

export interface LocalServerHello {
  hostId: HostId;
  nonce: HostId;
  profileId: HostId;
  runtimeId: RuntimeId;
  version: LocalIpcVersion;
}
export interface LocalIpcVersion {
  major: LocalIpcMajor;
  minor: number;
}
