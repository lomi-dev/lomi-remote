import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTempModule } from './helpers/temp-module.mjs';

// A fresh isolated release build can exercise the exact wrapper source without
// replacing packaged artifacts or claiming their provenance has been refreshed.
const artifact = process.env.AUTHORITY_CRYPTO_TEST_ARTIFACTS;
const generated = artifact ? pathToFileURL(resolve(artifact, 'authority_crypto.js'))
  : new URL('../generated/authority_crypto.js', import.meta.url);
const wasm = readFileSync(artifact ? resolve(artifact, 'authority_crypto_bg.wasm')
  : new URL('../generated/authority_crypto_bg.wasm', import.meta.url));
const source = readFileSync(new URL('../src/index.mjs', import.meta.url), 'utf8')
  .replace("'../generated/authority_crypto.js'", JSON.stringify(generated.href));
// Bun caches data modules across files; each suite owns its wrapper startup.
const apiModule = createTempModule(source + '\n// window-identity test module\n');
const api = await import(apiModule.url);
apiModule.cleanup();
const raw = await import(generated.href);
api.initializeAuthorityCrypto(wasm);
const json = JSON.stringify;
const bytes = (n, value) => new Uint8Array(n).fill(value);
const array = (n, value) => Array(n).fill(value);
const account = bytes(16, 1), windowId = bytes(16, 2);
const context = () => ({ consumerAuthorizationId: array(16, 3), accountSessionId: 'opaque_Parent-Session42',
  windowIdentityId: array(16, 2), operationId: array(16, 4), nonce: array(32, 5),
  audience: 'https://example.test/consumer/windows', expiresAt: '100' });
const invalid = fn => assert.throws(fn, { message: 'INVALID_ARGUMENT' });
function setup(ctx = context()) {
  const identity = new raw.BrowserIdentity(account, windowId, false, 1);
  const wire = identity.public_identity_wire();
  const prepared = JSON.parse(api.prepareConsumerWindowChallenge(wire, account, json(ctx)));
  const proof = identity.sign_consumer_window_proof(Buffer.from(prepared.canonicalCbor, 'hex'));
  return { identity, wire, ...prepared, proof };
}
function verify(s, changes = {}) {
  return api.verifyConsumerWindowProof(changes.proof ?? s.proof, json(changes.challenge ?? s.challenge),
    changes.wire ?? s.wire, changes.account ?? account, Object.hasOwn(changes, 'now') ? changes.now : 99n);
}

test('release WASM returns verified complete identity and signs the canonical prepared challenge', () => {
  const s = setup();
  try {
    const verified = JSON.parse(api.verifyConsumerWindowIdentity(s.wire, account, windowId));
    assert.deepEqual(verified.identity, JSON.parse(s.identity.public_bundle()));
    assert.deepEqual(verified.fingerprint, Array.from(s.identity.fingerprint()));
    assert.equal(JSON.parse(s.proof).canonicalCbor, s.canonicalCbor);
    assert.equal(verify(s), undefined);
    assert.deepEqual(Object.keys(JSON.parse(s.wire)).sort(), ['canonicalCbor', 'signature']);
  } finally { s.identity.free(); }
});

test('registered host verification returns native finalized full identity and rejects substituted retained state', () => {
  // Public outputs from a native random PendingHostIdentity generation and
  // finalization; the generator emits no seed, private key or fixture API.
  const f = JSON.parse(readFileSync(new URL('./fixtures/registered-host-public.json', import.meta.url)));
  const call = (changes = {}) => api.verifyRegisteredHostIdentity(json(changes.proof ?? f.proof),
    json(changes.committed ?? f.committed), changes.pin ?? Uint8Array.from(f.pin),
    changes.account ?? Uint8Array.from(f.approvedAccountId));
  assert.deepEqual(JSON.parse(call()), { identity: f.identity, fingerprint: f.fingerprint });
  invalid(() => call({ pin: bytes(32, 9) }));
  invalid(() => call({ account: bytes(16, 9) }));
  invalid(() => call({ account: bytes(16, 0) }));
  for (const field of ['identityKey', 'channelKey', 'mailboxKey', 'hostId']) {
    const committed = structuredClone(f.committed); committed.descriptor[field][0] ^= 1;
    invalid(() => call({ committed }));
  }
  const committed = structuredClone(f.committed); committed.signature[0] ^= 1;
  invalid(() => call({ committed }));
  for (const proof of [{ ...f.proof, signature: '00'.repeat(64) },
    { ...f.proof, canonicalCbor: f.proof.canonicalCbor + '00' },
    { ...f.proof, approved: true }, { ...f.proof, signature: Buffer.from(f.committed.signature).toString('hex') }]) {
    invalid(() => call({ proof }));
  }
  const s = setup();
  try { invalid(() => call({ proof: JSON.parse(s.wire) })); }
  finally { s.identity.free(); }
  assert.throws(() => raw.verify_registered_host_identity(json(f.proof), json(f.committed), bytes(31, 1), account));
});

test('proof verification binds every independently retained context field and expires exclusively', () => {
  const s = setup();
  try {
    for (const field of Object.keys(s.challenge)) {
      const challenge = structuredClone(s.challenge);
      if (Array.isArray(challenge[field])) challenge[field][0] ^= 1;
      else if (field === 'version') challenge[field]++;
      else challenge[field] += '1';
      invalid(() => verify(s, { challenge }));
    }
    invalid(() => verify(s, { account: bytes(16, 9) }));
    invalid(() => verify(s, { now: 100n }));
    invalid(() => verify(s, { now: (1n << 64n) - 1n }));
    const other = setup();
    try { invalid(() => verify(s, { wire: other.wire })); }
    finally { other.identity.free(); }
  } finally { s.identity.free(); }
});

test('malformed, noncanonical, trailing and forged public wire or challenge proofs fail', () => {
  const s = setup();
  try {
    for (const input of [s.wire, s.proof]) {
      for (const value of [
        { ...JSON.parse(input), signature: '00'.repeat(64) },
        { ...JSON.parse(input), canonicalCbor: JSON.parse(input).canonicalCbor + '00' },
        { ...JSON.parse(input), canonicalCbor: '98' + JSON.parse(input).canonicalCbor },
        { ...JSON.parse(input), canonicalCbor: 'AA' },
        { ...JSON.parse(input), extra: true },
      ]) {
        if (input === s.wire) invalid(() => api.verifyConsumerWindowIdentity(json(value), account, windowId));
        else invalid(() => verify(s, { proof: json(value) }));
      }
    }
    for (const canonical of [Buffer.from(s.canonicalCbor + '00', 'hex'),
      Buffer.from('980b' + s.canonicalCbor.slice(2), 'hex'), bytes(1025, 0)]) {
      assert.throws(() => s.identity.sign_consumer_window_proof(canonical));
    }
    invalid(() => verify(s, { proof: s.wire }));
    invalid(() => api.verifyConsumerWindowIdentity(s.wire, bytes(16, 9), windowId));
    invalid(() => api.verifyConsumerWindowIdentity(s.wire, account, bytes(16, 9)));
    invalid(() => api.prepareConsumerWindowChallenge(s.wire, account, json({ ...context(), accountId: array(16, 1) })));
    invalid(() => verify(s, { challenge: { ...s.challenge, extra: true } }));
  } finally { s.identity.free(); }
});

test('signer enforces native identity bindings and rejects disposal and unsigned JSON', () => {
  const s = setup();
  const other = new raw.BrowserIdentity(account, bytes(16, 9), false, 1);
  const host = new raw.BrowserIdentity(account, windowId, true, 1);
  try {
    const canonical = Buffer.from(s.canonicalCbor, 'hex');
    assert.throws(() => other.sign_consumer_window_proof(canonical));
    assert.throws(() => host.sign_consumer_window_proof(canonical));
    assert.throws(() => s.identity.sign_consumer_window_proof(Buffer.from(json(s.challenge))));
    invalid(() => api.verifyConsumerWindowIdentity(host.public_identity_wire(), account, windowId));
    s.identity.dispose();
    assert.throws(() => s.identity.sign_consumer_window_proof(canonical));
  } finally { s.identity.free(); other.free(); host.free(); }
});

test('BigInt time is checked by both wrapper and raw Rust binding, including u64 maximum', () => {
  const s = setup({ ...context(), expiresAt: ((1n << 64n) - 1n).toString() });
  try {
    assert.equal(verify(s, { now: (1n << 64n) - 2n }), undefined);
    for (const now of [1, '1', -1n, 1n << 64n, Object(1n), null]) {
      invalid(() => verify(s, { now }));
      assert.throws(() => raw.verify_consumer_window_proof(s.proof, json(s.challenge), s.wire, account, now));
    }
    invalid(() => verify(s, { now: (1n << 64n) - 1n }));
  } finally { s.identity.free(); }
});

test('new wrappers reject invalid JSON, UTF-16, argument lengths and untrusted fields', () => {
  const s = setup();
  try {
    for (const bad of [null, {}, '\ud800', '\udc00', 'é'.repeat(20000), 'x'.repeat(32769), '{} trailing']) {
      invalid(() => api.verifyConsumerWindowIdentity(bad, account, windowId));
      invalid(() => api.prepareConsumerWindowChallenge(s.wire, account, bad));
      invalid(() => api.verifyConsumerWindowProof(bad, json(s.challenge), s.wire, account, 1n));
      invalid(() => api.verifyRegisteredHostIdentity(bad, '{}', bytes(32, 1), account));
    }
    invalid(() => api.verifyConsumerWindowIdentity(s.wire, bytes(15, 1), windowId));
    invalid(() => api.verifyConsumerWindowIdentity(s.wire, account, array(16, 2)));
    assert.throws(() => raw.verify_consumer_window_identity(s.wire, bytes(15, 1), windowId));
    invalid(() => api.prepareConsumerWindowChallenge(s.wire, account,
      json({ ...context(), accountSessionId: 'a'.repeat(129) })));
    invalid(() => api.prepareConsumerWindowChallenge(s.wire, account, json({ ...context(), expiresAt: '01' })));
  } finally { s.identity.free(); }
});

test('release exports exclude test fixtures and public wrapper exposes only guarded authority functions', () => {
  assert(!Object.keys(raw).some(name => /fixture/i.test(name)));
  assert(!('fixture' in raw.BrowserIdentity));
  assert(!WebAssembly.Module.exports(new WebAssembly.Module(wasm)).some(entry => /fixture/i.test(entry.name)));
  assert.deepEqual(Object.keys(api).sort(), [
    'BrowserChannel', 'BrowserHandshakeV3', 'BrowserIdentity', 'initializeAuthorityCrypto',
    'prepareChannelContextV3', 'prepareConsumerWindowChallenge', 'prepareGrantProposalV3',
    'prepareHostEnrollmentChallenge', 'verifyChannelAdmissionV3', 'verifyConsumerWindowIdentity',
    'verifyConsumerWindowProof', 'verifyGrantProposalV3', 'verifyHostEnrollmentProof',
    'verifyHostKeyInitiation', 'verifyHostRefreshProof', 'verifyRegisteredHostIdentity',
  ].sort());
  assert(!Object.keys(api).some(name => /sign|fixture/i.test(name)));
  assert.equal(typeof api.BrowserIdentity.prototype.signConsumerWindowProof, 'function');
});
