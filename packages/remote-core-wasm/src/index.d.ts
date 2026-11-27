export type CoreErrorDetail = { code: string; [key: string]: unknown };
export class CoreError extends Error { detail: CoreErrorDetail; }
export type LinkRecord =
  | { type: 'connect' | 'close' }
  | { type: 'send'; bytes: Uint8Array }
  | { type: 'event'; event: { type: string; [key: string]: unknown } };
export function initializeRemoteCore(moduleOrBytes: BufferSource | WebAssembly.Module): void;
/** Throws Error('CORE_BROKEN') after a WebAssembly trap; recreate the worker. `directory.seal`/`directory.open` wipe `payload`.
 * `handle` 0 for stateless and creating operations. Throws CoreError. */
export function coreCall(handle: number, op: string, args?: object, payload?: Uint8Array): Uint8Array;
export function coreJson<T = unknown>(handle: number, op: string, args?: object, payload?: Uint8Array): T;
export function coreFree(handle: number): void;
export function decodeRecords(data: Uint8Array): LinkRecord[];
