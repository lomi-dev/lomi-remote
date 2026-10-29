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
const apiModule = createTempModule(source + '\n// browser-api test module\n');
const api = await import(apiModule.url);
apiModule.cleanup();
const json = JSON.stringify;
const bytes = (length, value) => new Uint8Array(length).fill(value);
const array = (length, value) => Array(length).fill(value);
const context = (windowId) => ({
  consumerAuthorizationId: array(16, 3),
  accountSessionId: 'opaque_Parent-Session42',
  windowIdentityId: windowId,
  operationId: array(16, 4),
  nonce: array(32, 5),
  audience: 'https://example.test/consumer/windows',
  expiresAt: '100',
});

test('browser identity exports require initialization and sign only through Rust', () => {
  assert.deepEqual(Object.keys(api).sort(), [
    'BrowserChannel', 'BrowserHandshakeV3', 'BrowserIdentity', 'initializeAuthorityCrypto',
    'prepareChannelContextV3', 'prepareConsumerWindowChallenge', 'prepareGrantProposalV3',
    'prepareHostEnrollmentChallenge', 'verifyChannelAdmissionV3', 'verifyConsumerWindowIdentity',
    'verifyConsumerWindowProof', 'verifyGrantProposalV3', 'verifyHostEnrollmentProof',
    'verifyHostKeyInitiation', 'verifyHostRefreshProof', 'verifyRegisteredHostIdentity',
  ].sort());
  assert.throws(() => new api.BrowserIdentity(), { message: 'CRYPTO_NOT_INITIALIZED' });
  assert.throws(() => new api.BrowserHandshakeV3(), { message: 'CRYPTO_NOT_INITIALIZED' });
  assert.throws(() => new api.BrowserChannel(), { message: 'CRYPTO_NOT_INITIALIZED' });

  api.initializeAuthorityCrypto(wasm);
  assert.throws(() => new api.BrowserChannel(), { message: 'INVALID_ARGUMENT' });
  const accountId = bytes(16, 1), windowId = bytes(16, 2);
  const identity = new api.BrowserIdentity({ accountId, subjectId: windowId, host: false, keyVersion: 1 });
  try {
    assert.equal(Object.keys(identity).length, 0);
    assert.equal(identity.secretKey, undefined);
    assert.equal(identity.exportSecretSeedBlob, undefined);
    assert.equal(typeof identity.seedBlobForEncryption, 'function');
    assert.equal(JSON.parse(identity.publicBundle()).bundle.role, 'device');
    assert.equal(JSON.parse(identity.publicIdentityWire()).canonicalCbor.length > 0, true);
    assert.equal(identity.fingerprint().length, 32);

    const expectedBundle = identity.publicBundle();
    const seedBlob = identity.seedBlobForEncryption();
    assert.equal(seedBlob.length, 97);
    assert.equal(seedBlob[0], 1);
    assert.throws(() => identity.seedBlobForEncryption(), { message: 'SEED_BLOB_ALREADY_EXPORTED' });
    const restored = api.BrowserIdentity.restore({
      accountId, subjectId: windowId, seedBlob, expectedBundleJson: expectedBundle,
    });
    seedBlob.fill(0);
    try {
      assert.equal(restored.publicBundle(), expectedBundle);
      assert.deepEqual(restored.fingerprint(), identity.fingerprint());
      assert.throws(() => api.BrowserIdentity.restore({
        accountId: bytes(16, 9), subjectId: windowId,
        seedBlob: bytes(97, 0), expectedBundleJson: expectedBundle,
      }), { message: 'INVALID_ARGUMENT' });
    } finally { restored.free(); }

    const prepared = JSON.parse(api.prepareConsumerWindowChallenge(
      identity.publicIdentityWire(), accountId, json(context(Array.from(windowId))),
    ));
    const canonicalCbor = Uint8Array.from(Buffer.from(prepared.canonicalCbor, 'hex'));
    const proof = identity.signConsumerWindowProof(canonicalCbor);
    assert.equal(JSON.parse(proof).canonicalCbor, prepared.canonicalCbor);
    assert.equal(api.verifyConsumerWindowProof(
      proof, json(prepared.challenge), identity.publicIdentityWire(), accountId, 99n,
    ), undefined);
    assert.throws(() => identity.signConsumerWindowProof(bytes(1025, 0)), { message: 'INVALID_ARGUMENT' });
    assert.throws(() => identity.signConsumerWindowProof([1, 2, 3]), { message: 'INVALID_ARGUMENT' });

    identity.dispose();
    assert.throws(() => identity.signConsumerWindowProof(canonicalCbor), { message: 'CRYPTO_OBJECT_DISPOSED' });
  } finally {
    identity.free();
    identity.free();
  }
  assert.throws(() => identity.publicBundle(), { message: 'CRYPTO_OBJECT_DISPOSED' });
});
