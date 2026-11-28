import { initSync, call, free } from '../generated/remote_core.js';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
let initialized = false;
let broken = false;
// Payloads of these operations carry key bytes; the wrapper wipes them after the call.
const SECRET_PAYLOAD_OPS = new Set(['directory.seal', 'directory.open', 'tunnel.new']);

export class CoreError extends Error {
  constructor(detail) { super(detail.code); this.name = 'CoreError'; this.detail = detail; }
}
/** Initialize with fetched bytes or a compiled WebAssembly.Module. */
export function initializeRemoteCore(moduleOrBytes) {
  // wasm-bindgen's web glue keeps one instance per module load, so a trapped instance cannot be
  // replaced in place: recreate the worker (or reload the page) and initialize again there.
  if (broken) throw new Error('CORE_BROKEN');
  initSync({ module: moduleOrBytes });
  initialized = true;
}
/** Runs `fn` against the instance; a WebAssembly trap leaves it unusable (locks, registry), so it is retired. */
export function _guard(fn) {
  if (!initialized) throw new Error('CORE_NOT_INITIALIZED');
  if (broken) throw new Error('CORE_BROKEN');
  try { return fn(); } catch (error) {
    if (error instanceof WebAssembly.RuntimeError) { broken = true; throw new Error('CORE_BROKEN', { cause: error }); }
    throw error;
  }
}
/** One bridge operation (see README). Returns the data bytes or throws CoreError / CORE_BROKEN. */
export function coreCall(handle, op, args, payload = new Uint8Array(0)) {
  try {
    const out = _guard(() => call(handle, op, args === undefined ? new Uint8Array(0) : encoder.encode(JSON.stringify(args)), payload));
    const data = out.subarray(1);
    if (out[0] === 0) return data;
    throw new CoreError(JSON.parse(decoder.decode(data)));
  } finally { if (SECRET_PAYLOAD_OPS.has(op)) payload.fill(0); }
}
export function coreFree(handle) { if (!broken) _guard(() => free(handle)); }
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
