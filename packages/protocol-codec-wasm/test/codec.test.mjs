import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import test from 'node:test';
import { inspect } from 'node:util';
import { initSync, BrowserMessageEncoder, BrowserMessageAssembler } from '../generated/protocol_codec.js';
import {
  initializeProtocolCodec, isProtocolCodecInitialized, protocolValidateWire, protocolValidateResponseFor,
  ProtocolMessageEncoder, ProtocolMessageAssembler,
} from '../src/index.mjs';
const fixturePath = new URL('../../remote-contracts/fixtures/rust-codec.json', import.meta.url);
const fixtures = [
  ...JSON.parse(readFileSync(fixturePath, 'utf8')),
  ...JSON.parse(readFileSync(new URL('../../../contracts/fixtures/rpc-streams/text-parity.json', import.meta.url), 'utf8')),
];
test('initialization is explicit and required', () => {
  assert.equal(isProtocolCodecInitialized(), false);
  assert.throws(() => protocolValidateWire('rpc-request', '{}'), /^Error: CODEC_NOT_INITIALIZED$/);
  assert.throws(() => new ProtocolMessageEncoder(), /^Error: CODEC_NOT_INITIALIZED$/);
  assert.throws(() => new ProtocolMessageAssembler(), /^Error: CODEC_NOT_INITIALIZED$/);
  initializeProtocolCodec(readFileSync(new URL('../generated/protocol_codec_bg.wasm', import.meta.url)));
  assert.equal(isProtocolCodecInitialized(), true);
});
test('oversized strings reject before WASM copies or memory growth', () => {
  // Generated bindings expose their initialized exports to development tests;
  // the public runtime API does not expose WASM memory.
  const { memory } = initSync();
  const before = memory.buffer.byteLength;
  const ascii = ' '.repeat(8 * 1024 * 1024);
  const multibyte = '€'.repeat(400000); // Below the UTF-16 limit, above UTF-8.
  const surrogatePairs = '😀'.repeat(300000);
  const request = JSON.stringify(fixtures.find(f => f.schema === 'rpc-request' && f.accepted).value);
  for (const oversized of [ascii, multibyte, surrogatePairs]) {
    assert.throws(() => protocolValidateWire('rpc-request', oversized), /^Error: RESOURCE_EXHAUSTED$/);
    assert.throws(() => protocolValidateResponseFor(request, oversized), /^Error: RESOURCE_EXHAUSTED$/);
    assert.throws(() => protocolValidateResponseFor(oversized, request), /^Error: RESOURCE_EXHAUSTED$/);
  }
  assert.throws(() => protocolValidateWire(ascii, '{}'), /^Error: INVALID_ARGUMENT$/);
  assert.throws(() => protocolValidateWire('rpc-request', '"\ud800"'), /^Error: INVALID_ARGUMENT$/);
  assert.equal(memory.buffer.byteLength, before);
});
test('UTF-8 preflight distinguishes exact byte bounds', () => {
  // Whitespace is invalid JSON, but reaches Rust exactly at the byte budget.
  assert.throws(() => protocolValidateWire('rpc-request', ' '.repeat(1048576)), /^Error: INVALID_ARGUMENT$/);
  assert.throws(() => protocolValidateWire('rpc-request', 'é'.repeat(524288)), /^Error: INVALID_ARGUMENT$/);
  assert.throws(() => protocolValidateWire('rpc-request', 'é'.repeat(524289)), /^Error: RESOURCE_EXHAUSTED$/);
});
for (const fixture of fixtures) {
  test(`actual Rust WASM parity: ${fixture.name}`, () => {
    const validate = () => fixture.request
      ? protocolValidateResponseFor(JSON.stringify(fixture.request), JSON.stringify(fixture.value))
      : protocolValidateWire(fixture.schema, JSON.stringify(fixture.value));
    if (fixture.accepted) assert.doesNotThrow(validate);
    else assert.throws(validate, /^Error: (INVALID_ARGUMENT|RESOURCE_EXHAUSTED)$/);
  });
}
const valid = fixtures.find(f => f.schema === 'rpc-request' && f.accepted).value;
const raw = JSON.stringify(valid);
test('RPC request objects reject positional arrays at every shared boundary', () => {
  const requestFor = method => structuredClone(fixtures.find(f =>
    f.schema === 'rpc-request' && f.accepted && f.value.call.method === method).value);
  const workspace = requestFor('workspace.get');
  const creation = requestFor('terminal.create');
  const input = requestFor('terminal.input');
  for (const request of [workspace, creation, input]) {
    assert.doesNotThrow(() => protocolValidateWire('rpc-request', JSON.stringify(request)));
  }
  const context = workspace.call.params.context;
  const positionalContext = [context.workspaceId, context.workspaceEpoch, context.runtimeId,
    context.runtimeGeneration, context.hostAccessEpoch, context.grantRevision];
  const mutation = creation.call.params.mutation;
  const terminal = input.call.params.terminal;
  const cases = [
    [workspace.v, workspace.type, workspace.requestId, workspace.timeoutMs, workspace.call],
    { ...workspace, call: [workspace.call.method, workspace.call.params] },
    { ...workspace, call: { ...workspace.call, params: [context] } },
    { ...workspace, call: { ...workspace.call, params: { context: positionalContext } } },
    { ...creation, call: { ...creation.call, params: { ...creation.call.params,
      mutation: [mutation.operationId, mutation.context, mutation.expectedRevision] } } },
    { ...input, call: { ...input.call, params: { ...input.call.params,
      terminal: [terminal.workspace, terminal.paneId, terminal.sessionId, terminal.sessionEpoch, terminal.profile] } } },
  ];
  for (const [index, request] of cases.entries()) {
    assert.throws(() => protocolValidateWire('rpc-request', JSON.stringify(request)),
      /^Error: INVALID_ARGUMENT$/, `positional request case ${index}`);
  }
});
test('duplicate keys rejected before typed enum buffering', () => {
  for (const json of [raw.replace('"v":2', '"v":2,"v":2'), raw.replace('"workspaceId":', '"runtimeGeneration":"1","workspaceId":')]) {
    assert.throws(() => protocolValidateWire('rpc-request',json), /^Error: INVALID_ARGUMENT$/);
  }
});
test('JSON escaped surrogates and actual unpaired UTF16 fail safely', () => {
  for (const invalid of ['"\\ud800"', '"\\udfff"', '"\ud800"', '"\udfff"', '"\ud800x"', '"\\uZZZZ"']) {
    assert.throws(() => protocolValidateWire('rpc-request', invalid), /^Error: INVALID_ARGUMENT$/);
  }
});
test('all raw roots are bounded before deserialization', () => {
  assert.throws(() => protocolValidateWire('rpc-request', ' '.repeat(1048577)), /^Error: RESOURCE_EXHAUSTED$/);
  assert.throws(() => protocolValidateResponseFor(raw, ' '.repeat(1048577)), /^Error: RESOURCE_EXHAUSTED$/);
});
test('unknown kinds and standalone responses reject with closed safe errors', () => {
  for (const kind of ['private-token-value', 'rpc-response', 'foundation-types']) {
    assert.throws(() => protocolValidateWire(kind, '{}'), /^Error: INVALID_ARGUMENT$/);
  }
});
const id = '11111111-1111-4111-8111-111111111111';
test('canonical error message, details, retry and effect semantics', () => {
  const safe = {code:'INVALID_ARGUMENT',message:'Invalid request.',retryable:false,effect:'none',details:{}};
  assert.doesNotThrow(() => protocolValidateWire('remote-error',JSON.stringify(safe)));
  for (const patch of [{message:'never-echo-me'},{retryable:true},{effect:'committed'},{details:{expectedRevision:'1',actualRevision:'2'}}]) {
    assert.throws(() => protocolValidateWire('remote-error',JSON.stringify({...safe,...patch})), /^Error: INVALID_ARGUMENT$/);
  }
});
test('capability closure and receipt state semantics use Rust checked serde', () => {
  const receipt = {operationId:id,actor:id,workspaceId:id,originalMethod:'files.create',
    actualRights:['workspace.read','files.read','files.write'],repositoryExecution:false,
    parameterHash:'0'.repeat(64),state:'accepted',cancelRequested:false,effect:'none'};
  assert.doesNotThrow(() => protocolValidateWire('operation-receipt',JSON.stringify(receipt)));
  for (const patch of [{actualRights:['files.write']},{actualRights:['workspace.read','files.read','files.write','files.write']},{state:'succeeded'},{effect:'committed'},{originalMethod:'workspace.get'}]) {
    assert.throws(() => protocolValidateWire('operation-receipt',JSON.stringify({...receipt,...patch})), /^Error: INVALID_ARGUMENT$/);
  }
});
test('unknown fields and secret-looking values never escape errors', () => {
  assert.throws(() => protocolValidateWire('rpc-request',JSON.stringify({...valid, privateToken:'never-echo-me'})), /^Error: INVALID_ARGUMENT$/);
});
test('HTTP and IPC roots use canonical typed DTOs', () => {
  const hello = {version:{major:1,minor:0},profileId:id,nonce:id};
  protocolValidateWire('local-client-hello',JSON.stringify(hello));
  assert.throws(() => protocolValidateWire('local-client-hello',JSON.stringify({...hello,version:{major:2,minor:0}})), /^Error: INVALID_ARGUMENT$/);
  protocolValidateWire('HostRevokeParams',JSON.stringify({expectedHostAccessEpoch:'1'}));
  assert.throws(() => protocolValidateWire('HostRevokeParams',JSON.stringify({expectedHostAccessEpoch:'1',privateToken:'never-echo-me'})), /^Error: INVALID_ARGUMENT$/);
});

test('runtime lookup rejects raw duplicate fields and GET request DTO kinds', () => {
  const lookup = fixtures.find(f => f.name === 'authority-v2/runtime-get/unclaimed-generation-zero').value;
  const json = JSON.stringify(lookup);
  for (const raw of [
    json.replace('"runtime":null', '"runtime":null,"runtime":null'),
    json.replace('"leaseMs":"0"', '"leaseMs":"0","leaseMs":"0"'),
  ]) assert.throws(() => protocolValidateWire('HostRuntimeGetResult', raw), /^Error: INVALID_ARGUMENT$/);
  for (const kind of ['RuntimeGetParams', 'HostRuntimeGetParams']) {
    assert.throws(() => protocolValidateWire(kind, '{}'), /^Error: INVALID_ARGUMENT$/);
  }
});

// Keep framing cases in this initialized file: separate files can race module
// initialization under Node/Bun. These fixtures duplicate wire bytes only in tests.
const fragmentPayload = 16_352;
const invalidFraming = /^Error: INVALID_ARGUMENT$/;
const resourceFraming = /^Error: RESOURCE_EXHAUSTED$/;
function framingRoundtrip(bytes, kind = 1) {
  const encoder = new ProtocolMessageEncoder();
  const assembler = new ProtocolMessageAssembler();
  try {
    assert.equal(encoder.begin(kind, bytes), '1');
    let completed = null;
    let frames = 0;
    for (let frame; (frame = encoder.nextFrame()) !== null;) {
      assert.ok(frame instanceof Uint8Array);
      assert.ok(frame.byteLength <= 16_384);
      assert.ok(frame.byteLength + 24 + 24 + 16 <= 16_448);
      assert.equal(completed, null);
      completed = assembler.push(frame, String(frames++));
    }
    assert.ok(completed);
    assert.equal(completed.id, '1');
    assert.equal(completed.kind, kind);
    assert.deepEqual(completed.bytes, bytes);
    assert.equal(frames, Math.ceil(bytes.length / fragmentPayload));
    return frames;
  } finally { encoder.dispose(); assembler.dispose(); }
}
function canonicalFixture() {
  const encoder = new ProtocolMessageEncoder();
  try {
    encoder.begin(1, new Uint8Array(2 * fragmentPayload + 1).fill(42));
    return [encoder.nextFrame(), encoder.nextFrame(), encoder.nextFrame()];
  } finally { encoder.dispose(); }
}
function editFrame(frame, edit) {
  const copy = frame.slice();
  edit(copy, new DataView(copy.buffer));
  return copy;
}
function assertPoisoned(assembler) {
  assert.throws(() => assembler.expire('0'), invalidFraming);
  assert.throws(() => assembler.push(new Uint8Array(), '0'), invalidFraming);
  assembler.dispose(); assembler.dispose();
}

test('canonical Rust framing: 1 MiB uses exactly 65 bounded frames', () => {
  assert.equal(framingRoundtrip(new Uint8Array(1_048_576).fill(165)), 65);
});
test('canonical Rust framing: 16 KiB integer-array JSON and opaque UTF-8 boundaries', () => {
  const json = new TextEncoder().encode(JSON.stringify(Array(16_384).fill(255)));
  assert.equal(json.length, 65_537);
  framingRoundtrip(json, 3);
  const utf8 = new TextEncoder().encode('a'.repeat(fragmentPayload - 1) + '🙂');
  const encoder = new ProtocolMessageEncoder();
  const assembler = new ProtocolMessageAssembler();
  try {
    encoder.begin(4, utf8);
    const first = encoder.nextFrame();
    assert.throws(() => new TextDecoder('utf-8', { fatal: true }).decode(first.subarray(32)));
    assert.equal(assembler.push(first, '0'), null);
    assert.deepEqual(assembler.push(encoder.nextFrame(), '1').bytes, utf8);
  } finally { encoder.dispose(); assembler.dispose(); }
  framingRoundtrip(Uint8Array.of(255, 254), 5);
});
test('canonical Rust framing: exact native-reference header and sequential kinds/IDs', () => {
  const encoder = new ProtocolMessageEncoder();
  const assembler = new ProtocolMessageAssembler();
  try {
    for (let kind = 1; kind <= 5; kind++) {
      assert.equal(encoder.begin(kind, Uint8Array.of(66, 67)), String(kind));
      const frame = encoder.nextFrame();
      // Same independent reference as native exact_wire_header_* unit test.
      assert.deepEqual([...frame], [76, 77, 70, 50, 1, kind, 0, 0,
        0, 0, 0, 0, 0, 0, 0, kind, 0, 0, 0, 2,
        0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 66, 67]);
      const done = assembler.push(frame, String(kind));
      assert.equal(done.kind, kind);
      assert.equal(done.id, String(kind));
      assert.equal(encoder.nextFrame(), null);
    }
  } finally { encoder.dispose(); assembler.dispose(); }
});
test('canonical Rust framing: malformed identity, sequence, headers and drip feeds poison', () => {
  const [first, middle, final] = canonicalFixture();
  const mutations = [
    editFrame(middle, (_, view) => view.setUint32(20, fragmentPayload + 1)), // Gap.
    first, // Duplicate offset zero.
    editFrame(middle, (_, view) => view.setUint32(16, 2 * fragmentPayload + 2)),
    editFrame(middle, bytes => { bytes[5] = 2; }),
    editFrame(middle, (_, view) => view.setBigUint64(8, 2n)), // Interleaving ID.
    editFrame(middle, bytes => { bytes[6] = 1; }),
    editFrame(middle, bytes => { bytes[28] = 1; }),
    editFrame(middle, bytes => { bytes[4] = 2; }),
    editFrame(middle, bytes => { bytes[5] = 6; }),
    editFrame(middle, bytes => { bytes[0] = 0; }),
    editFrame(middle, (_, view) => view.setUint32(24, fragmentPayload - 1)),
    editFrame(middle.subarray(0, 33), (_, view) => view.setUint32(24, 1)), // Short middle.
  ];
  for (const bad of mutations) {
    const assembler = new ProtocolMessageAssembler();
    assert.equal(assembler.push(first, '0'), null);
    assert.throws(() => assembler.push(bad, '1'), invalidFraming);
    assertPoisoned(assembler);
  }
  for (const bad of [
    new Uint8Array(31),
    editFrame(first, (_, view) => view.setBigUint64(8, 0n)),
    editFrame(first, (_, view) => view.setBigUint64(8, 18_446_744_073_709_551_615n)),
    editFrame(first, (_, view) => view.setUint32(16, 1_048_577)),
    editFrame(first, (_, view) => view.setUint32(16, 0)),
    editFrame(first.subarray(0, 32), (_, view) => view.setUint32(24, 0)),
    editFrame(first.subarray(0, 33), (_, view) => view.setUint32(24, 1)), // One-byte drip.
    editFrame(final, (_, view) => view.setUint32(20, 0xffff_ffff)), // Checked overflow.
  ]) {
    const assembler = new ProtocolMessageAssembler();
    assert.throws(() => assembler.push(bad, '0'), invalidFraming);
    assertPoisoned(assembler);
  }
  const assembler = new ProtocolMessageAssembler();
  assembler.push(first, '0'); assembler.push(middle, '1');
  const trailing = new Uint8Array(final.length + 1);
  trailing.set(final); trailing[trailing.length - 1] = 42;
  new DataView(trailing.buffer).setUint32(24, 2);
  assert.throws(() => assembler.push(trailing, '2'), invalidFraming);
  assertPoisoned(assembler);
});
test('canonical Rust framing: deadline is nonsliding and clocks preserve full u64 precision', () => {
  const [first, middle, final] = canonicalFixture();
  const assembler = new ProtocolMessageAssembler();
  assembler.push(first, '10'); assembler.push(middle, '5009');
  assert.throws(() => assembler.push(final, '5010'), invalidFraming);
  assertPoisoned(assembler);
  const precise = new ProtocolMessageAssembler();
  precise.push(first, '9007199254740993');
  assert.throws(() => precise.expire('9007199254740992'), invalidFraming);
  assertPoisoned(precise);
  const maximum = new ProtocolMessageAssembler();
  maximum.push(first, '18446744073709546615'); // u64::MAX - 5000.
  maximum.expire('18446744073709551614');
  assert.throws(() => maximum.expire('18446744073709551615'), invalidFraming);
  assertPoisoned(maximum);
  const overflow = new ProtocolMessageAssembler();
  assert.throws(() => overflow.push(first, '18446744073709546616'), invalidFraming);
  assertPoisoned(overflow);
  const idle = new ProtocolMessageAssembler();
  idle.expire('18446744073709551615');
  assert.throws(() => idle.expire('18446744073709551614'), invalidFraming);
  assertPoisoned(idle);
});
test('canonical Rust framing: bad clock syntax and types permanently dispose', () => {
  const [first] = canonicalFixture();
  for (const bad of ['', '00', '01', '+1', '-1', ' 1', '1.0', '1e3', 'é',
    '18446744073709551616', '9'.repeat(1_000_000), 1, 1n, null, {}]) {
    for (const method of ['push', 'expire']) {
      const assembler = new ProtocolMessageAssembler();
      assembler.push(first, '0');
      assert.throws(() => method === 'push' ? assembler.push(first, bad) : assembler.expire(bad), invalidFraming);
      assertPoisoned(assembler);
    }
  }
});
test('canonical Rust framing: input preflight prevents WASM growth and hostile accessors', () => {
  let touched = false;
  const fake = { get length() { touched = true; throw Error('never-echo-me'); },
    get byteLength() { touched = true; throw Error('never-echo-me'); } };
  const big = new Uint8Array(8 * 1024 * 1024);
  const inputs = [fake, {}, [], new DataView(new ArrayBuffer(1)), new Uint16Array(1), 'secret', null];
  if (typeof SharedArrayBuffer !== 'undefined') inputs.push(new Uint8Array(new SharedArrayBuffer(1)));
  if (typeof ArrayBuffer.prototype.resize === 'function') inputs.push(new Uint8Array(new ArrayBuffer(1, { maxByteLength: 2 })));
  for (const [input, error] of [...inputs.map(input => [input, invalidFraming]), [big, resourceFraming]]) {
    const encoder = new ProtocolMessageEncoder();
    const assembler = new ProtocolMessageAssembler();
    const before = initSync().memory.buffer.byteLength;
    assert.throws(() => encoder.begin(1, input), error);
    assert.throws(() => assembler.push(input, '0'), error);
    assert.equal(initSync().memory.buffer.byteLength, before);
    assert.throws(() => encoder.nextFrame(), invalidFraming);
    assertPoisoned(assembler);
  }
  assert.equal(touched, false);
  const clockFrame = canonicalFixture()[0];
  const clockAssembler = new ProtocolMessageAssembler();
  const beforeClock = initSync().memory.buffer.byteLength;
  assert.throws(() => clockAssembler.push(clockFrame, '9'.repeat(1_000_000)), invalidFraming);
  assert.equal(initSync().memory.buffer.byteLength, beforeClock);
  assertPoisoned(clockAssembler);
  class HostileBytes extends Uint8Array {
    get length() { throw Error('never-echo-me'); }
    get byteLength() { throw Error('never-echo-me'); }
    get buffer() { throw Error('never-echo-me'); }
    get byteOffset() { throw Error('never-echo-me'); }
  }
  const encoder = new ProtocolMessageEncoder();
  try {
    assert.equal(encoder.begin(1, new HostileBytes([42])), '1');
    assert.equal(encoder.nextFrame()[32], 42);
  } finally { encoder.dispose(); }
});
test('canonical Rust framing: encoder errors, abort disposal and bounded preflight poison', () => {
  for (const kind of [0, 6, 257, NaN, 1.5, '1', {}, null]) {
    const encoder = new ProtocolMessageEncoder();
    assert.throws(() => encoder.begin(kind, Uint8Array.of(42)), invalidFraming);
    assert.throws(() => encoder.begin(1, Uint8Array.of(42)), invalidFraming);
  }
  const empty = new ProtocolMessageEncoder();
  assert.throws(() => empty.begin(1, new Uint8Array()), invalidFraming);
  assert.throws(() => empty.nextFrame(), invalidFraming);
  const busy = new ProtocolMessageEncoder();
  busy.begin(1, Uint8Array.of(42));
  assert.throws(() => busy.begin(1, Uint8Array.of(42)), invalidFraming);
  assert.throws(() => busy.nextFrame(), invalidFraming);
  const encoder = new ProtocolMessageEncoder();
  encoder.begin(1, new Uint8Array(1_048_576));
  encoder.dispose(); encoder.dispose();
  assert.throws(() => encoder.nextFrame(), invalidFraming);
});
test('WASM ownership bridge transfers completed payload only once and poisons invalid clock', () => {
  const encoder = new BrowserMessageEncoder();
  const assembler = new BrowserMessageAssembler();
  try {
    assert.equal(encoder.begin(1, Uint8Array.of(255, 254)), '1');
    const completed = assembler.push(encoder.nextFrame(), '0');
    try {
      assert.equal(completed.id(), '1');
      assert.equal(completed.kind(), 1);
      assert.deepEqual(completed.takeBytes(), Uint8Array.of(255, 254));
      assert.throws(() => completed.takeBytes(), error => error === 'INVALID_ARGUMENT');
    } finally { completed.free(); }
    assert.throws(() => assembler.expire('01'), error => error === 'INVALID_ARGUMENT');
    assert.throws(() => assembler.expire('1'), error => error === 'INVALID_ARGUMENT');
  } finally { encoder.dispose(); encoder.free(); assembler.dispose(); assembler.free(); }
});
test('framing wrapper inspection and errors never expose buffered payload', () => {
  const secret = 'DO_NOT_LOG_THIS_PAYLOAD';
  const bytes = new Uint8Array(fragmentPayload + 1);
  bytes.set(new TextEncoder().encode(secret));
  const encoder = new ProtocolMessageEncoder();
  const assembler = new ProtocolMessageAssembler();
  try {
    encoder.begin(1, bytes);
    assert.equal(assembler.push(encoder.nextFrame(), '0'), null);
    assert.ok(!inspect({ encoder, assembler }).includes(secret));
    assert.deepEqual(Object.keys(encoder), []);
    assert.deepEqual(Object.keys(assembler), []);
    assert.throws(() => assembler.expire(secret), invalidFraming);
    assertPoisoned(assembler);
  } finally { encoder.dispose(); assembler.dispose(); }
});
