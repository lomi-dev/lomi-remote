import { initSync, call, free } from '../generated/remote_core.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let initialized = false;

export class CoreError extends Error {
  constructor(detail) { super(detail.code); this.name = 'CoreError'; this.detail = detail; }
}
/** Initialize with fetched bytes or a compiled WebAssembly.Module. */
export function initializeRemoteCore(moduleOrBytes) {
  initSync({ module: moduleOrBytes });
  initialized = true;
}
/** One bridge operation (see README). Returns the data bytes or throws CoreError. */
export function coreCall(handle, op, args, payload = new Uint8Array(0)) {
  if (!initialized) throw new Error('CORE_NOT_INITIALIZED');
  const out = call(handle, op, args === undefined ? new Uint8Array(0) : encoder.encode(JSON.stringify(args)), payload);
  const data = out.subarray(1);
  if (out[0] === 0) return data;
  throw new CoreError(JSON.parse(decoder.decode(data)));
}
export function coreFree(handle) { free(handle); }
export function coreJson(handle, op, args, payload) { return JSON.parse(decoder.decode(coreCall(handle, op, args, payload))); }
/** Splits a link result into { type: 'connect' | 'send' | 'close' | 'event', bytes?, event? }. */
export function decodeRecords(data) {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  const out = [];
  for (let i = 0; i < data.length;) {
    const tag = data[i], len = view.getUint32(i + 1), body = data.subarray(i + 5, i + 5 + len);
    i += 5 + len;
    if (tag === 1) out.push({ type: 'connect' });
    else if (tag === 2) out.push({ type: 'send', bytes: body });
    else if (tag === 3) out.push({ type: 'close' });
    else if (tag === 4) out.push({ type: 'event', event: JSON.parse(decoder.decode(body)) });
    else throw new Error('BAD_RECORD');
  }
  return out;
}
