// Generated from Rust JSON schema. Do not edit.

/**
 * Opaque signed device bundle; verified elsewhere.
 *
 * @maxItems 4096
 */
export type BoundedList2 = number[];
export type DeviceKind = "web" | "mobile" | "desktop";
export type DeviceName = string;
/**
 * Declaration order equals the OPEN kind code and the postcard variant index.
 */
export type StreamKind = "rpc" | "directory" | "terminal" | "chat" | "files.watch" | "transfer" | "media";
/**
 * @maxItems 64
 */
export type BoundedList = ResumeEntry[];

export interface Hello {
  authEpoch: number;
  deviceBundle: BoundedList2;
  deviceKind: DeviceKind;
  deviceName: DeviceName;
  hostAccessEpoch: number;
  resume: BoundedList;
  runtimeGeneration: number;
  sendDirectory: boolean;
}
export interface ResumeEntry {
  cursor: number;
  kind: StreamKind;
}
