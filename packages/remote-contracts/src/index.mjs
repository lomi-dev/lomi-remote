import { validators } from '../generated/registry.mjs';

// Only static failure messages leave this boundary. Ajv errors and payloads are
// deliberately not exposed: paths, titles, terminal bytes and secrets are private.
const failure = () => new Error('Invalid remote contract.');
// Count without allocating an encoded copy. UTF-16 length is a lower bound on
// UTF-8 bytes, so oversized strings fail before scanning their contents.
function utf8Fits(value, maximum) {
  if (value.length > maximum) return false;
  let bytes=0;
  for (let i=0; i<value.length; i++) {
    const unit=value.charCodeAt(i);
    if (unit<=0x7f) bytes++;
    else if (unit<=0x7ff) bytes+=2;
    else if (unit>=0xd800 && unit<=0xdbff) {
      const next=value.charCodeAt(++i);
      if (!(next>=0xdc00 && next<=0xdfff)) return false;
      bytes+=4;
    } else if (unit>=0xdc00 && unit<=0xdfff) return false;
    else bytes+=3;
    if (bytes>maximum) return false;
  }
  return true;
}
// Object predicates describe the original value. Reject serialization hooks,
// accessors and non-JSON values before any schema reads or JSON.stringify call.
function plainJsonData(value, depth=0, seen=new WeakSet()) {
  if (depth>128) return false;
  if (value===null || typeof value==='boolean') return true;
  if (typeof value==='number') return Number.isFinite(value);
  if (typeof value==='string') return utf8Fits(value,1024*1024);
  if (typeof value!=='object' || seen.has(value)) return false;
  const array=Array.isArray(value), prototype=Object.getPrototypeOf(value);
  if (prototype!==(array ? Array.prototype : Object.prototype) && !(prototype===null && !array)) return false;
  for (let parent=prototype; parent; parent=Object.getPrototypeOf(parent)) {
    if (Object.getOwnPropertyDescriptor(parent,'toJSON')) return false;
  }
  if (Object.getOwnPropertySymbols(value).length) return false;
  const names=Object.getOwnPropertyNames(value);
  if (array && names.length!==value.length+1) return false; // holes/extra props
  seen.add(value);
  for (const key of names) {
    const descriptor=Object.getOwnPropertyDescriptor(value,key);
    if (!descriptor || !Object.hasOwn(descriptor,'value') || key==='toJSON') return false;
    if (array && key==='length') continue;
    if ((!array && !descriptor.enumerable) || !utf8Fits(key,1024*1024) || !plainJsonData(descriptor.value,depth+1,seen)) return false;
  }
  seen.delete(value);
  return true;
}
export function validateShape(name, value) {
  const validator = Object.hasOwn(validators, name) && validators[name];
  try { return !!validator && plainJsonData(value) && validator(value); }
  catch { return false; }
}
// JSON.parse silently accepts duplicate fields. Reject them before parsing so a
// consumer never sees a different message from serde's deny_unknown_fields DTOs.
function uniqueKeys(json) {
  const stack = [];
  for (let i=0; i<json.length; i++) {
    const c=json[i];
    if (c === '"') {
      const begin=i++;
      while(i<json.length && json[i] !== '"') { if(json[i]==='\\') i++; i++; }
      let next=i+1; while (/\s/.test(json[next] ?? '') && next<json.length) next++;
      if(json[next] === ':') {
        const keys=stack.at(-1);
        if(!(keys instanceof Set)) throw failure();
        const key=JSON.parse(json.slice(begin,i+1));
        if(keys.has(key)) throw failure();
        keys.add(key);
      }
    } else if(c === '{' || c === '[') {
      stack.push(c==='{' ? new Set() : null);
      if(stack.length>128) throw failure();
    } else if(c === '}' || c === ']') stack.pop();
  }
}
export function decodeShape(name, json) {
  try {
    if(typeof json !== 'string') throw failure();
    const max = name === 'wss-admission-frame' ? 16*1024 : 1024*1024;
    if(!utf8Fits(json,max)) throw failure();
    uniqueKeys(json);
    const value = JSON.parse(json);
    if(!validateShape(name,value)) throw failure();
    return value;
  } catch { throw failure(); }
}
// Supply the browser/native Rust WASM adapter after initializeProtocolCodec.
// This setter is trusted application configuration, never a wire/data input.
let canonicalCodec = null;
export function initializeCanonicalCodec(adapter) {
  if (!adapter || typeof adapter.validateWire !== 'function' || typeof adapter.validateResponseFor !== 'function') throw failure();
  canonicalCodec = Object.freeze({ validateWire: adapter.validateWire, validateResponseFor: adapter.validateResponseFor });
}
export function decode(name, json) {
  if (!canonicalCodec) throw new Error('Canonical protocol codec is not initialized.');
  try {
    // Check size before calling WASM; Rust owns duplicate-field, canonical and
    // cross-field checks on the original JSON, rather than a reserialized value.
    const value = decodeShape(name,json);
    canonicalCodec.validateWire(name,json);
    return value;
  } catch { throw failure(); }
}
export function validate(name,value) {
  try { if (!validateShape(name,value)) return false; decode(name,JSON.stringify(value)); return true; }
  catch { return false; }
}
// Canonical Rust request/response correlation is mandatory before dispatch/apply.
// This never retries or replays an operation or terminal input.
export function decodeResponse(request,json) {
  if (!canonicalCodec) throw new Error('Canonical protocol codec is not initialized.');
  try {
    if (!validateShape('rpc-request',request)) throw failure();
    const response=decodeShape('rpc-response',json);
    canonicalCodec.validateResponseFor(JSON.stringify(request),json);
    return response;
  } catch { throw failure(); }
}
export function checkResponse(request,response) {
  if (!canonicalCodec) return false;
  try { if (!validateShape('rpc-response',response)) return false; decodeResponse(request,JSON.stringify(response)); return true; }
  catch { return false; }
}
export class OrderedSequence {
  #next = null;
  #blocked = false;
  accept(sequence) {
    if(this.#blocked) return false;
    if(typeof sequence !== 'string' || !/^(0|[1-9][0-9]*)$/.test(sequence)) return false;
    const value=BigInt(sequence);
    if(this.#next !== null && value===this.#next-1n) return false;
    if(value>18446744073709551615n || (this.#next !== null && value!==this.#next)) { this.#blocked=true; return false; }
    this.#next=value+1n;
    return true;
  }
  reset() { this.#next=null; this.#blocked=false; }
}
