import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { createTempModule } from './helpers/temp-module.mjs';

const artifact = process.env.AUTHORITY_CRYPTO_TEST_ARTIFACTS;
const generated = artifact ? pathToFileURL(resolve(artifact, 'authority_crypto.js'))
  : new URL('../generated/authority_crypto.js', import.meta.url);
const wasm = readFileSync(artifact ? resolve(artifact, 'authority_crypto_bg.wasm')
  : new URL('../generated/authority_crypto_bg.wasm', import.meta.url));
const source = readFileSync(new URL('../src/index.mjs', import.meta.url), 'utf8')
  .replace("'../generated/authority_crypto.js'", JSON.stringify(generated.href));
// Keep this suite's initialization guard independent in Bun's shared process.
const apiModule = createTempModule(source + '\n// authority-v3 test module\n');
const api = await import(apiModule.url);
apiModule.cleanup();
const raw = await import(generated.href);
api.initializeAuthorityCrypto(wasm);
// Native normal-feature, random-key public outputs. No private keys or signing APIs.
const f = JSON.parse(readFileSync(new URL('./fixtures/authority-v3-public.json', import.meta.url)));
const json = JSON.stringify;
const hp = Uint8Array.from(f.hostPin), cp = Uint8Array.from(f.consumerPin);
const account = new Uint8Array(16).fill(1);
const invalid = fn => assert.throws(fn, { message: 'INVALID_ARGUMENT' });
const change = (value, field, replacement) => ({ ...structuredClone(value), [field]: replacement });
function prepare(c = {}) {
  return JSON.parse(api.prepareGrantProposalV3(json(c.grant ?? f.maximum), json(c.host ?? f.hostWire),
    json(c.consumer ?? f.consumerWire), c.account ?? account, c.hp ?? hp, c.cp ?? cp));
}
function verify(c = {}) {
  return JSON.parse(api.verifyGrantProposalV3(json(c.wire ?? f.grantWire), c.maximum ?? f.maximumCbor,
    json(c.host ?? f.hostWire), json(c.consumer ?? f.consumerWire), c.hp ?? hp, c.cp ?? cp,
    json(c.authority ?? f.authority), Object.hasOwn(c, 'now') ? c.now : 100n));
}
function context(c = {}) {
  return JSON.parse(api.prepareChannelContextV3(json(c.context ?? f.context), json(c.grant ?? f.grantWire),
    json(c.host ?? f.hostWire), json(c.consumer ?? f.consumerWire), c.hp ?? hp, c.cp ?? cp,
    json(c.authority ?? f.authority), Object.hasOwn(c, 'now') ? c.now : 100n));
}
function admission(c = {}) {
  return JSON.parse(api.verifyChannelAdmissionV3(json(c.wire ?? f.admissionWire), c.expected ?? f.contextCbor,
    json(c.grant ?? f.grantWire), json(c.host ?? f.hostWire), json(c.consumer ?? f.consumerWire),
    c.hp ?? hp, c.cp ?? cp, json(c.authority ?? f.authority), Object.hasOwn(c, 'now') ? c.now : 100n));
}

test('prepare native canonical proposal and verify a signed capability and expiry narrowing', () => {
  assert.deepEqual(prepare(), { grant: f.maximum, canonicalCbor: f.maximumCbor });
  assert.deepEqual(verify(), { ...f.grant, canonicalCbor: f.grantWire.canonicalCbor });
  assert.deepEqual(verify({ wire: f.maximumWire }).grant, f.maximum);
  assert.deepEqual(context(), { context: f.context, canonicalCbor: f.contextCbor });
  assert.deepEqual(admission(), { admission: f.admission, grant: f.grant, host: f.host, consumer: f.consumer });
});

test('preparation binds approved account, endpoint roles, subjects and all-key fingerprints', () => {
  invalid(() => prepare({ account: new Uint8Array(16).fill(9) }));
  invalid(() => prepare({ account: new Uint8Array(16) }));
  invalid(() => prepare({ host: f.consumerWire, consumer: f.hostWire }));
  for (const field of ['hostId', 'consumerId', 'hostFingerprint', 'consumerFingerprint', 'accountId']) {
    const grant = structuredClone(f.maximum); grant[field][0] ^= 1;
    invalid(() => prepare({ grant }));
  }
  for (const wire of ['host', 'consumer']) {
    const value = structuredClone(f[`${wire}Wire`]);
    // Final three canonical bstr keys are 34 bytes each; mutate each public key.
    for (const fromEnd of [1, 35, 69]) {
      const bytes = Buffer.from(value.canonicalCbor, 'hex'); bytes[bytes.length - fromEnd] ^= 1;
      invalid(() => prepare({ [wire]: { ...value, canonicalCbor: bytes.toString('hex') } }));
    }
  }
});

test('independent retained maximum forbids immutable changes and capability or expiry expansion', () => {
  invalid(() => verify({ wire: f.changedWire }));
  invalid(() => verify({ wire: f.widenedWire, maximum: f.grantWire.canonicalCbor }));
  invalid(() => verify({ wire: f.maximumWire, maximum: f.grantWire.canonicalCbor }));
  invalid(() => context({ context: { ...f.context, grant: f.maximum } }));
  invalid(() => admission({ grant: f.maximumWire }));
});

test('every current authority field, endpoint pin, and identity signature is checked', () => {
  for (const field of Object.keys(f.authority).filter(k => k !== 'terminalMembership')) {
    const authority = structuredClone(f.authority);
    if (Array.isArray(authority[field])) authority[field][0] ^= 1;
    else authority[field] += '1';
    for (const call of [verify, context, admission]) invalid(() => call({ authority }));
  }
  for (const call of [prepare, verify, context, admission]) {
    invalid(() => call({ hp: new Uint8Array(32).fill(9) }));
    invalid(() => call({ cp: new Uint8Array(32).fill(9) }));
    for (const field of ['host', 'consumer']) invalid(() => call({ [field]: {
      ...f[`${field}Wire`], signature: '00'.repeat(64) } }));
  }
});

test('channel admission requires exact retained context, signature and terminal membership', () => {
  const c = { context: f.terminalContext, grant: f.maximumWire, authority: f.terminalAuthority };
  assert.equal(context(c).canonicalCbor, f.terminalCbor);
  assert.equal(admission({ ...c, wire: f.terminalAdmissionWire, expected: f.terminalCbor }).admission.context.purpose, 'terminal');
  invalid(() => context({ ...c, authority: f.authority }));
  invalid(() => admission({ ...c, wire: f.terminalAdmissionWire, expected: f.terminalCbor, authority: f.authority }));
  const authority = structuredClone(f.terminalAuthority); authority.terminalMembership.sessionEpoch[0] ^= 1;
  invalid(() => context({ ...c, authority }));
  invalid(() => admission({ ...c, wire: f.terminalAdmissionWire, expected: f.terminalCbor, authority }));
  invalid(() => admission({ expected: f.terminalCbor }));
  invalid(() => admission({ wire: { ...f.admissionWire, signature: '00'.repeat(64) } }));
  const changed = context({ context: change(f.context, 'channelId', Array(16).fill(88)) });
  invalid(() => admission({ expected: changed.canonicalCbor }));
});

test('expiry is exclusive, issued-at inclusive, and u64 BigInt time is mandatory at both boundaries', () => {
  assert.equal(context({ now: 100n }).canonicalCbor, f.contextCbor);
  assert.equal(admission({ now: 124n }).admission.context.expiresAt, '125');
  for (const now of [99n, 125n, (1n << 64n) - 1n]) {
    invalid(() => context({ now })); invalid(() => admission({ now }));
  }
  invalid(() => verify({ now: 1000n }));
  assert.deepEqual(verify({ wire: f.maximumWire, now: (1n << 64n) - 2n }).grant, f.maximum);
  invalid(() => verify({ wire: f.maximumWire, now: (1n << 64n) - 1n }));
  for (const now of [1, '100', -1n, 1n << 64n, Object(100n), null]) {
    for (const call of [verify, context, admission]) invalid(() => call({ now }));
    assert.throws(() => raw.verify_grant_proposal_v3(json(f.grantWire), f.maximumCbor,
      json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), now));
    assert.throws(() => raw.prepare_channel_context_v3(json(f.context), json(f.grantWire),
      json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), now));
    assert.throws(() => raw.verify_channel_admission_v3(json(f.admissionWire), f.contextCbor,
      json(f.grantWire), json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), now));
  }
});

test('strict carriers reject unknown fields, forged signatures, trailing and nonminimal CBOR', () => {
  for (const wire of [{ ...f.grantWire, extra: true }, { ...f.grantWire, signature: '00'.repeat(64) },
    { ...f.grantWire, canonicalCbor: f.grantWire.canonicalCbor + '00' },
    { ...f.grantWire, canonicalCbor: '9817' + f.grantWire.canonicalCbor.slice(2) }]) {
    invalid(() => verify({ wire })); invalid(() => context({ grant: wire })); invalid(() => admission({ grant: wire }));
  }
  for (const wire of [{ ...f.admissionWire, extra: true },
    { ...f.admissionWire, canonicalCbor: f.contextCbor + '00' },
    { ...f.admissionWire, canonicalCbor: '980a' + f.contextCbor.slice(2) }]) invalid(() => admission({ wire }));
  for (const hex of [f.maximumCbor + '00', '9817' + f.maximumCbor.slice(2), 'AA', '00'.repeat(8193)]) invalid(() => verify({ maximum: hex }));
  for (const hex of [f.contextCbor + '00', '980a' + f.contextCbor.slice(2), 'AA', '00'.repeat(8193)]) invalid(() => admission({ expected: hex }));
  invalid(() => prepare({ grant: { ...f.maximum, unknown: true } }));
  invalid(() => context({ context: { ...f.context, unknown: true } }));
  for (const call of [verify, context, admission]) invalid(() => call({ authority: { ...f.authority, unknown: true } }));
});

test('wrappers reject non-string, oversized, malformed UTF-16 and invalid fixed arguments', () => {
  for (const bad of [null, {}, '\ud800', '\udc00', 'é'.repeat(20000), 'x'.repeat(32769), '{} trailing']) {
    invalid(() => api.prepareGrantProposalV3(bad, json(f.hostWire), json(f.consumerWire), account, hp, cp));
    invalid(() => api.verifyGrantProposalV3(json(f.grantWire), bad, json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), 100n));
    invalid(() => api.prepareChannelContextV3(bad, json(f.grantWire), json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), 100n));
    invalid(() => api.verifyChannelAdmissionV3(json(f.admissionWire), bad, json(f.grantWire), json(f.hostWire), json(f.consumerWire), hp, cp, json(f.authority), 100n));
  }
  for (const call of [prepare, verify, context, admission]) {
    invalid(() => call({ hp: Array(32).fill(1) }));
    invalid(() => call({ cp: new Uint8Array(31) }));
  }
  invalid(() => prepare({ account: new Uint8Array(15) }));
  assert(!Object.keys(raw).some(name => /fixture/i.test(name)));
  assert(!WebAssembly.Module.exports(new WebAssembly.Module(wasm)).some(entry => /fixture/i.test(entry.name)));
});
