import {
  initSync, protocol_validate_wire, protocol_validate_response_for,
  BrowserMessageEncoder, BrowserMessageAssembler,
} from '../generated/protocol_codec.js';
let initialized = false;
function fail(code) { throw new Error(code); }
const CONTROL_MESSAGE_BYTES = 1024 * 1024;
// Registry names are short ASCII identifiers; keep hostile kind strings bounded
// before wasm-bindgen allocates them too. Rust remains the registry authority.
const KIND_BYTES = 64;
function text(value, limit = CONTROL_MESSAGE_BYTES, limitCode = 'RESOURCE_EXHAUSTED') {
  if (typeof value !== 'string') fail('INVALID_ARGUMENT');
  // UTF-8 always needs at least as many bytes as valid UTF-16 code units.
  // This O(1) check avoids scanning or copying arbitrarily large strings.
  if (value.length > limit) fail(limitCode);
  let bytes = 0;
  // Count UTF-8 without allocating an encoded copy. Also reject lone surrogates
  // before wasm-bindgen's TextEncoder could replace them with U+FFFD.
  for (let i = 0; i < value.length; i++) {
    const unit = value.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(++i);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail('INVALID_ARGUMENT');
      bytes += 4;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) fail('INVALID_ARGUMENT');
    else bytes += unit <= 0x7f ? 1 : unit <= 0x7ff ? 2 : 3;
    if (bytes > limit) fail(limitCode);
  }
  return value;
}
function ready() { if (!initialized) fail('CODEC_NOT_INITIALIZED'); }
function validate(call) {
  try { call(); } catch (error) {
    fail(error === 'RESOURCE_EXHAUSTED' ? 'RESOURCE_EXHAUSTED' : 'INVALID_ARGUMENT');
  }
}
/** Initialize with browser-fetched bytes or a compiled WebAssembly.Module. */
export function initializeProtocolCodec(moduleOrBytes) {
  initSync({ module: moduleOrBytes });
  initialized = true;
}
export function isProtocolCodecInitialized() { return initialized; }
export function protocolValidateWire(kind, rawJson) {
  ready();
  text(kind, KIND_BYTES, 'INVALID_ARGUMENT'); text(rawJson);
  validate(() => protocol_validate_wire(kind, rawJson));
}
export function protocolValidateResponseFor(rawRequestJson, rawResponseJson) {
  ready();
  text(rawRequestJson); text(rawResponseJson);
  validate(() => protocol_validate_response_for(rawRequestJson, rawResponseJson));
}

// Preflight uses intrinsic getters, never hostile object/subclass accessors.
// Return a plain view so wasm-bindgen also reads trusted .length/.buffer fields.
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedGetter = name => Object.getOwnPropertyDescriptor(typedArrayPrototype, name).get;
const typedTag = Object.getOwnPropertyDescriptor(typedArrayPrototype, Symbol.toStringTag).get;
const typedByteLength = typedGetter('byteLength');
const typedByteOffset = typedGetter('byteOffset');
const typedBuffer = typedGetter('buffer');
const arrayBufferByteLength = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const arrayBufferResizable = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'resizable')?.get;
const framingResource = Symbol('framing resource limit');
function framingBytes(value, limit) {
  if (typedTag.call(value) !== 'Uint8Array') fail('INVALID_ARGUMENT');
  const length = typedByteLength.call(value);
  if (length > limit) throw framingResource;
  const buffer = typedBuffer.call(value);
  arrayBufferByteLength.call(buffer); // Reject SharedArrayBuffer before copying.
  if (arrayBufferResizable?.call(buffer)) fail('INVALID_ARGUMENT');
  return new Uint8Array(buffer, typedByteOffset.call(value), length);
}
function framingClock(value) {
  // Rust checks canonical digits and u64 overflow; no lossy Number conversion.
  if (typeof value !== 'string' || value.length === 0 || value.length > 20) fail('INVALID_ARGUMENT');
  return value;
}
const framingInstances = new WeakMap();
function disposeFraming(instance) {
  const inner = framingInstances.get(instance);
  if (!inner) return;
  framingInstances.delete(instance);
  try { inner.dispose(); } finally { inner.free(); }
}
function withFraming(instance, call) {
  const inner = framingInstances.get(instance);
  if (!inner) fail('INVALID_ARGUMENT');
  try { return call(inner); } catch (error) {
    disposeFraming(instance);
    fail(error === framingResource ? 'RESOURCE_EXHAUSTED' : 'INVALID_ARGUMENT');
  }
}

/** One ordered direction/channel; dispose on authority change/disconnect/rekey. */
export class ProtocolMessageEncoder {
  constructor() {
    ready();
    framingInstances.set(this, new BrowserMessageEncoder());
  }
  begin(kind, bytes) {
    return withFraming(this, inner => {
      if (!Number.isInteger(kind) || kind < 1 || kind > 5) fail('INVALID_ARGUMENT');
      return inner.begin(kind, framingBytes(bytes, CONTROL_MESSAGE_BYTES));
    });
  }
  nextFrame() { return withFraming(this, inner => inner.nextFrame() ?? null); }
  dispose() { disposeFraming(this); }
}

/** Opaque logical bytes only: completion makes no effect or authority decision. */
export class ProtocolMessageAssembler {
  constructor() {
    ready();
    framingInstances.set(this, new BrowserMessageAssembler());
  }
  push(frame, nowMs) {
    return withFraming(this, inner => {
      // Both arguments pass O(1) bounds/type checks before either enters WASM.
      const bytes = framingBytes(frame, 16_384);
      const time = framingClock(nowMs);
      const completed = inner.push(bytes, time);
      if (completed == null) return null;
      try {
        return { kind: completed.kind(), id: completed.id(), bytes: completed.takeBytes() };
      } finally { completed.free(); }
    });
  }
  expire(nowMs) { return withFraming(this, inner => inner.expire(framingClock(nowMs))); }
  dispose() { disposeFraming(this); }
}
