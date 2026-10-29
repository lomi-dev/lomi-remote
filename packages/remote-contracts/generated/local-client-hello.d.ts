// Generated from Rust JSON schema. Do not edit.

export type HostId = string;
export type LocalIpcMajor = 1;

export interface LocalClientHello {
  nonce: HostId;
  profileId: HostId;
  version: LocalIpcVersion;
}
export interface LocalIpcVersion {
  major: LocalIpcMajor;
  minor: number;
}
