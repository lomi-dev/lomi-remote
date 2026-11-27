// Shared vectors against the built WASM package (same files as crates/lomi-remote-core/tests/shared_vectors.rs).
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { initializeRemoteCore, coreCall, coreJson, coreFree, decodeRecords, CoreError } from '../src/index.mjs';

const dir = new URL('../../../crates/lomi-remote-core/test-vectors/', import.meta.url);
const relay = JSON.parse(readFileSync(new URL('relay-frames.v1.json', dir), 'utf8'));
const scenarios = JSON.parse(readFileSync(new URL('core-scenarios.v1.json', dir), 'utf8'));
initializeRemoteCore(readFileSync(fileURLToPath(new URL('../generated/remote_core_bg.wasm', import.meta.url))));

const hex = s => Uint8Array.from(s.match(/../g) ?? [], b => parseInt(b, 16));
const toHex = b => Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
const errorOf = fn => { try { fn(); } catch (e) { assert.ok(e instanceof CoreError); return e.detail; } assert.fail('expected an error'); };
const json = data => JSON.parse(new TextDecoder().decode(data));

test('relay vectors', () => {
  const args = v => ({ fromRelay: v.direction === 'relay' });
  for (const v of relay.valid) {
    const bytes = hex(v.hex), a = args(v);
    assert.deepEqual(coreJson(0, 'frame.decode', a, bytes), v.frame, v.name);
    const canon = coreCall(0, 'frame.canonical', a, bytes);
    if (v.canonical) assert.equal(toHex(canon), v.hex, v.name);
    assert.equal(toHex(coreCall(0, 'frame.canonical', a, canon)), toHex(canon), v.name);
    assert.deepEqual(coreJson(0, 'frame.decode', a, canon), v.frame, v.name);
  }
  const classes = { EMPTY_FRAME: 'framing', FRAME_TOO_LARGE: 'framing', UNKNOWN_TYPE: 'framing', WRONG_DIRECTION: 'framing', BAD_UTF8: 'encoding', BAD_JSON: 'encoding', BAD_SHAPE: 'shape' };
  for (const v of relay.invalid) assert.equal(errorOf(() => coreCall(0, 'frame.decode', args(v), hex(v.hex))).code, classes[v.error], v.name);
});

function payload(spec, lastSeal) {
  if (spec === undefined) return new Uint8Array(0);
  if (spec.startsWith('hex:')) {
    const h = spec.slice(4), tail = h.endsWith('@last');
    const head = hex(tail ? h.slice(0, -5) : h);
    return tail ? Uint8Array.from([...head, ...lastSeal]) : head;
  }
  if (spec.startsWith('utf8:')) return new TextEncoder().encode(spec.slice(5));
  if (spec.startsWith('vector:')) return hex(relay.valid.find(v => v.name === spec.slice(7)).hex);
  throw new Error(`payload ${spec}`);
}
function records(data) {
  return decodeRecords(data).map(r => r.type === 'send'
    ? { t: 'send', frame: coreJson(0, 'frame.decode', { fromRelay: false }, r.bytes) }
    : r.type === 'event' ? { t: 'event', event: r.event } : { t: r.type });
}

for (const sc of scenarios.scenarios) {
  test(`scenario ${sc.name}`, () => {
    const handles = {};
    let lastSeal = new Uint8Array(0);
    try {
      sc.steps.forEach((step, n) => {
        const at = `${sc.name} step ${n} (${step.op})`;
        const run = () => coreCall(step.on ? handles[step.on] : 0, step.op, step.args, payload(step.payload, lastSeal));
        const want = step.expect ?? {};
        if (want.error) return assert.deepEqual(errorOf(run), want.error, at);
        const data = run();
        if (step.as) handles[step.as] = json(data).handle;
        if (step.op === 'directory.seal') lastSeal = data.slice();
        if (want.json) assert.deepEqual(json(data), want.json, at);
        else if (want.records) assert.deepEqual(records(data), want.records, at);
        else if (want.hex) assert.equal(toHex(data), want.hex, at);
      });
    } finally {
      for (const h of Object.values(handles)) { coreFree(h); coreFree(h); }
    }
  });
}
