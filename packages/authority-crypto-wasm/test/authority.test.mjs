import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import * as api from '../src/index.mjs';
import * as raw from '../generated/authority_crypto.js';

const fixture = JSON.parse(readFileSync(new URL('../../../crates/lomi-remote-crypto/tests/fixtures/enrollment-wire-v1.json', import.meta.url)));
const wire = JSON.parse(readFileSync(new URL('../../../contracts/fixtures/enrollment/wire.json', import.meta.url)));
const wasm = readFileSync(new URL('../generated/authority_crypto_bg.wasm', import.meta.url));
const encode = JSON.stringify;
const pin = () => Uint8Array.from(fixture.initialCommitment);
const account = () => Uint8Array.from(fixture.approvedAccountId);
const verifyFinal = (changes = {}) => api.verifyHostEnrollmentProof(
  encode(changes.proof ?? fixture.finalProof), encode(changes.expected ?? fixture.expected),
  encode(changes.committed ?? fixture.committed), changes.pin ?? pin(),
  changes.account ?? account(), changes.now ?? BigInt(fixture.now));
const invalid = call => assert.throws(call, { message: 'INVALID_ARGUMENT' });
const context = () => Object.fromEntries(['enrollmentId', 'bootstrapSessionId', 'operationId', 'nonce', 'audience', 'expiresAt']
  .map(key => [key, structuredClone(fixture.expected[key])]));
const prepare = (changes = {}) => JSON.parse(api.prepareHostEnrollmentChallenge(
  encode(changes.committed ?? fixture.committed), changes.pin ?? pin(),
  changes.account ?? account(), encode(changes.context ?? context())));

test('trusted startup requires initialization and refuses replacement', () => {
  assert.throws(() => api.verifyHostKeyInitiation(encode(fixture.init)), { message: 'CRYPTO_NOT_INITIALIZED' });
  api.initializeAuthorityCrypto(wasm);
  assert.throws(() => api.initializeAuthorityCrypto(wasm), { message: 'CRYPTO_ALREADY_INITIALIZED' });
});

test('release WASM verifies actual native public commitment vector', () => {
  assert.deepEqual(JSON.parse(api.verifyHostKeyInitiation(encode(fixture.init))), fixture.committed);
});

test('shared Rust transport fixtures also pass cryptographic initiation validation', () => {
  for (const row of wire) {
    if (row.accepted) assert.equal(JSON.parse(api.verifyHostKeyInitiation(encode(row.value))).descriptor.role, 'host');
    else invalid(() => api.verifyHostKeyInitiation(encode(row.value)));
  }
});

test('valid-shaped forged signature and inconsistent outer pin are rejected', () => {
  for (const mutate of [value => { value.proof.signature = '00'.repeat(64); },
    value => { value.keyCommitment = '00'.repeat(32); }]) {
    const value = structuredClone(fixture.init); mutate(value);
    invalid(() => api.verifyHostKeyInitiation(encode(value)));
  }
});

test('each of the three keys is bound by signature even after recomputing the outer hash', () => {
  for (const field of ['identityKey', 'channelKey', 'mailboxKey']) {
    const value = structuredClone(fixture.init);
    const key = Buffer.from(fixture.committed.descriptor[field]).toString('hex');
    assert(value.proof.canonicalCbor.includes(key));
    const changed = (key.startsWith('00') ? '01' : '00') + key.slice(2);
    value.proof.canonicalCbor = value.proof.canonicalCbor.replace(key, changed);
    value.keyCommitment = createHash('sha256').update(Buffer.from(value.proof.canonicalCbor, 'hex')).digest('hex');
    invalid(() => api.verifyHostKeyInitiation(encode(value)));
  }
});

test('non-shortest and trailing CBOR fail with internally consistent hashes', () => {
  for (const bytes of ['9808' + fixture.init.proof.canonicalCbor.slice(2), fixture.init.proof.canonicalCbor + '00']) {
    const value = structuredClone(fixture.init);
    value.proof.canonicalCbor = bytes;
    value.keyCommitment = createHash('sha256').update(Buffer.from(bytes, 'hex')).digest('hex');
    invalid(() => api.verifyHostKeyInitiation(encode(value)));
  }
});

test('actual final enrollment proof verifies with independently supplied trusted state', () => {
  assert.equal(verifyFinal(), undefined);
});

test('trusted preparation reproduces the native challenge and exact signed canonical bytes', () => {
  const prepared = prepare();
  assert.deepEqual(prepared.challenge, fixture.expected);
  assert.equal(prepared.canonicalCbor, fixture.finalProof.canonicalCbor);
  const other = account(); other[0] ^= 1;
  const changed = prepare({ account: other });
  assert.deepEqual(changed.challenge.hostId, fixture.committed.descriptor.hostId);
  assert.notDeepEqual(changed.challenge.hostKeyFingerprint, prepared.challenge.hostKeyFingerprint);
});

test('preparation rejects forged stored keys, inconsistent pins and zero approved accounts', () => {
  invalid(() => prepare({ pin: new Uint8Array(32) }));
  invalid(() => prepare({ account: new Uint8Array(16) }));
  const committed = structuredClone(fixture.committed); committed.signature.fill(0);
  invalid(() => prepare({ committed }));
});

test('trusted context cannot supply replacement host, fingerprint, account or version', () => {
  for (const key of ['hostId', 'hostKeyFingerprint', 'accountId', 'version']) {
    invalid(() => prepare({ context: { ...context(), [key]: 1 } }));
  }
  for (const key of ['enrollmentId', 'bootstrapSessionId', 'operationId', 'nonce']) {
    const value = context(); value[key].fill(0);
    invalid(() => prepare({ context: value }));
  }
});

test('preparation enforces bounded ASCII audience and canonical unsigned expiry', () => {
  assert.equal(prepare({ context: { ...context(), audience: 'a'.repeat(256) } }).challenge.audience.length, 256);
  for (const audience of ['', 'a'.repeat(257), 'contains space', 'é', '\ud800']) {
    invalid(() => prepare({ context: { ...context(), audience } }));
  }
  for (const expiresAt of ['0', '01', '18446744073709551616', 1000, '-1']) {
    invalid(() => prepare({ context: { ...context(), expiresAt } }));
  }
});

test('commitment signature cannot be replayed as final enrollment proof', () => {
  const proof = structuredClone(fixture.finalProof);
  proof.signature = fixture.init.proof.signature;
  invalid(() => verifyFinal({ proof }));
});

test('final signature and canonical request must match the retained challenge', () => {
  for (const proof of [{ ...fixture.finalProof, signature: '00'.repeat(64) },
    { ...fixture.finalProof, canonicalCbor: fixture.finalProof.canonicalCbor + '00' }]) {
    invalid(() => verifyFinal({ proof }));
  }
  for (const field of ['enrollmentId', 'hostId', 'hostKeyFingerprint', 'bootstrapSessionId', 'nonce', 'operationId']) {
    const expected = structuredClone(fixture.expected);
    expected[field][0] ^= 1;
    invalid(() => verifyFinal({ expected }));
  }
  invalid(() => verifyFinal({ expected: { ...fixture.expected, audience: 'different-authority' } }));
});

test('stored key, original pin and approved account cannot be substituted', () => {
  invalid(() => verifyFinal({ pin: new Uint8Array(32) }));
  const other = account(); other[0] ^= 1;
  invalid(() => verifyFinal({ account: other }));
  invalid(() => verifyFinal({ account: new Uint8Array(16) }));
  const committed = structuredClone(fixture.committed);
  committed.descriptor.mailboxKey[0] ^= 1;
  invalid(() => verifyFinal({ committed }));
});

test('expiry is exclusive and time requires an exact unsigned u64 BigInt', () => {
  invalid(() => verifyFinal({ now: BigInt(fixture.expected.expiresAt) }));
  for (const now of [Number(fixture.now), fixture.now, -1n, 1n << 64n, 1.5, Object(1n)]) {
    invalid(() => verifyFinal({ now }));
  }
});

test('runtime bounds and malformed UTF-16 fail before copying into WASM', () => {
  for (const value of [null, {}, 'x'.repeat(32769), '\ud800', '\udc00', 'é'.repeat(20000)]) {
    invalid(() => api.verifyHostKeyInitiation(value));
  }
  invalid(() => api.verifyHostKeyInitiation(encode({ ...fixture.init, approved: true })));
  invalid(() => verifyFinal({ pin: new Uint8Array(31) }));
  invalid(() => verifyFinal({ account: new Uint8Array(17) }));
});

test('Rust bindings independently enforce time and pin lengths', () => {
  for (const now of [Number(fixture.now), -1n, 1n << 64n]) assert.throws(() => raw.verify_host_enrollment_proof(
    encode(fixture.finalProof), encode(fixture.expected), encode(fixture.committed), pin(), account(), now));
  assert.throws(() => raw.verify_host_enrollment_proof(encode(fixture.finalProof), encode(fixture.expected),
    encode(fixture.committed), new Uint8Array(31), account(), BigInt(fixture.now)));
});

test('public wrapper exports guarded APIs and release artifact excludes fixture APIs', () => {
  assert.deepEqual(Object.keys(api).sort(), ['BrowserChannel', 'BrowserHandshakeV3', 'BrowserIdentity', 'initializeAuthorityCrypto', 'prepareChannelContextV3', 'prepareConsumerWindowChallenge', 'prepareGrantProposalV3', 'prepareHostEnrollmentChallenge', 'verifyChannelAdmissionV3', 'verifyConsumerWindowIdentity', 'verifyConsumerWindowProof', 'verifyGrantProposalV3', 'verifyHostEnrollmentProof', 'verifyHostKeyInitiation', 'verifyHostRefreshProof', 'verifyRegisteredHostIdentity']);
  assert(!WebAssembly.Module.exports(new WebAssembly.Module(wasm)).some(entry => /fixture/i.test(entry.name)));
  const provenance = JSON.parse(readFileSync(new URL('../generated/provenance.json', import.meta.url)));
  assert.equal(provenance.testFixtures, false);
  assert.deepEqual(provenance.features, ['browser']);
  assert.equal(provenance.profile, 'release');
});

const refresh = JSON.parse(readFileSync(new URL('../../../crates/lomi-remote-crypto/tests/fixtures/host-refresh-v1.json', import.meta.url)));
const verifyRefresh = (changes = {}) => api.verifyHostRefreshProof(
  encode(changes.proof ?? refresh.proof), encode(changes.committed ?? refresh.committed),
  changes.pin ?? Uint8Array.from(refresh.initialCommitment),
  changes.account ?? Uint8Array.from(refresh.approvedAccountId),
  encode(changes.context ?? refresh.context));

test('release WASM verifies the native refresh golden vector using derived host claims', () => {
  assert.equal(verifyRefresh(), undefined);
});

test('refresh rejects each substituted trusted context field and account binding', () => {
  for (const field of ['hostAuthorizationId', 'rotationId', 'refreshHash']) {
    const context = structuredClone(refresh.context); context[field][0] ^= 1;
    invalid(() => verifyRefresh({ context }));
    context[field].fill(0);
    invalid(() => verifyRefresh({ context }));
  }
  invalid(() => verifyRefresh({ context: { ...refresh.context, audience: 'https://staging.example/v2/remote/host-authorizations/refresh' } }));
  invalid(() => verifyRefresh({ account: new Uint8Array(16).fill(9) }));
  invalid(() => verifyRefresh({ pin: new Uint8Array(32) }));
  for (const field of ['identityKey', 'channelKey', 'mailboxKey']) {
    const committed = structuredClone(refresh.committed); committed.descriptor[field][0] ^= 1;
    invalid(() => verifyRefresh({ committed }));
  }
});

test('refresh context rejects replacement claims, invalid audience and request-domain replay', () => {
  for (const field of ['accountId', 'approvedAccountId', 'hostId', 'hostKeyFingerprint', 'role', 'version']) {
    invalid(() => verifyRefresh({ context: { ...refresh.context, [field]: 1 } }));
  }
  for (const audience of ['', 'a'.repeat(257), 'contains space', 'é', '\ud800']) {
    invalid(() => verifyRefresh({ context: { ...refresh.context, audience } }));
  }
  invalid(() => verifyRefresh({ proof: fixture.finalProof }));
  invalid(() => verifyFinal({ proof: refresh.proof }));
  for (const canonicalCbor of ['9809' + refresh.proof.canonicalCbor.slice(2), refresh.proof.canonicalCbor + '00']) {
    invalid(() => verifyRefresh({ proof: { ...refresh.proof, canonicalCbor } }));
  }
  invalid(() => verifyRefresh({ proof: { ...refresh.proof, signature: '00'.repeat(64) } }));
});

test('refresh wrapper guards all JSON inputs and fixed typed-array arguments', () => {
  const args = [encode(refresh.proof), encode(refresh.committed), Uint8Array.from(refresh.initialCommitment),
    Uint8Array.from(refresh.approvedAccountId), encode(refresh.context)];
  for (const index of [0, 1, 4]) {
    for (const value of [null, {}, 'x'.repeat(32769), '\ud800', '\udc00', 'é'.repeat(20000)]) {
      const changed = args.slice(); changed[index] = value;
      invalid(() => api.verifyHostRefreshProof(...changed));
    }
  }
  for (const [index, value] of [[2, new Uint8Array(31)], [2, Array(32).fill(0)],
    [3, new Uint8Array(17)], [3, Array(16).fill(0)]]) {
    const changed = args.slice(); changed[index] = value;
    invalid(() => api.verifyHostRefreshProof(...changed));
  }
  assert.throws(() => raw.verify_host_refresh_proof(args[0], args[1], new Uint8Array(31), args[3], args[4]));
});
