import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { pathToFileURL } from 'node:url';

// The checked-in Rust/WASM interop artifact is fixture-enabled for tests only.
// Production package code is unchanged and contains no fixture constructor.
const packageRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const fixtureArtifact = resolve(packageRoot, '../../artifacts/crypto-v3-browser/wasm');
const generatedSource = readFileSync(resolve(fixtureArtifact, 'lomi_remote_crypto.js'), 'utf8');
const tempDirectory = mkdtempSync(join(tmpdir(), 'lomi-browser-v3-test-'));
const generatedPath = join(tempDirectory, 'fixture-generated.mjs');
writeFileSync(generatedPath, generatedSource);
const generated = pathToFileURL(generatedPath).href;
const wasm = readFileSync(resolve(fixtureArtifact, 'lomi_remote_crypto_bg.wasm'));
const fixturePath = resolve(packageRoot, '../../tests/crypto-v3-browser/native-vectors.json');
const cases = JSON.parse(readFileSync(fixturePath, 'utf8'));
let source = readFileSync(resolve(packageRoot, 'src/index.mjs'), 'utf8');
source = source.replace(/^import \{[^\n]+\} from '\.\.\/generated\/authority_crypto\.js';$/m,
  `import { initSync, BrowserIdentity as RustBrowserIdentity, BrowserHandshakeV3 as RustBrowserHandshakeV3 } from ${JSON.stringify(generated)};`);
source = source.replace(
  'return new RustBrowserIdentity(accountId, subjectId, host, keyVersion);',
  'return RustBrowserIdentity.fixture(host, host ? 7 : 17);',
);
if (source.includes("'../generated/authority_crypto.js'") || source.includes('return new RustBrowserIdentity(')) {
  throw new Error('failed to isolate the Rust fixture constructor in the test module');
}
const apiPath = join(tempDirectory, 'browser-api.mjs');
writeFileSync(apiPath, source + '\n// browser-v3-api test module\n');
const api = await import(pathToFileURL(apiPath).href);
rmSync(tempDirectory, { recursive: true, force: true });

function identity(host) {
  return new api.BrowserIdentity({
    accountId: new Uint8Array(16).fill(1),
    subjectId: new Uint8Array(16).fill(host ? 2 : 3),
    host,
    keyVersion: 1,
  });
}
function handshakeOptions(fixture, initiator, endpoint) {
  return {
    initiator,
    identity: endpoint,
    signedJson: JSON.stringify(fixture.signed),
    expectedJson: JSON.stringify(fixture.expected),
    authorityJson: JSON.stringify(fixture.authority),
    hostPin: Uint8Array.from(fixture.hostPin),
    consumerPin: Uint8Array.from(fixture.consumerPin),
    now: 100n,
  };
}
const equalBytes = (left, right) => Buffer.from(left).equals(Buffer.from(right));

test('V3 handshake creates disposable channels and rejects oversized JSON before WASM', () => {
  api.initializeAuthorityCrypto(wasm);
  const fixture = cases['a-workspace'];
  const consumerIdentity = identity(false);
  const hostIdentity = identity(true);
  let consumerHandshake, hostHandshake, consumerChannel, hostChannel, abandoned;
  try {
    const consumerOptions = handshakeOptions(fixture, true, consumerIdentity);
    assert.throws(() => new api.BrowserHandshakeV3({
      ...consumerOptions,
      signedJson: 'x'.repeat(32 * 1024 + 1),
    }), { message: 'INVALID_ARGUMENT' });

    consumerHandshake = new api.BrowserHandshakeV3(consumerOptions);
    hostHandshake = new api.BrowserHandshakeV3(handshakeOptions(fixture, false, hostIdentity));
    const first = consumerHandshake.write();
    hostHandshake.read(first);
    consumerHandshake.read(hostHandshake.write());
    hostHandshake.read(consumerHandshake.write());

    consumerChannel = consumerHandshake.finish();
    hostChannel = hostHandshake.finish();
    assert.equal(consumerChannel instanceof api.BrowserChannel, true);
    assert.equal(equalBytes(consumerChannel.transcriptHash(), hostChannel.transcriptHash()), true);

    const route = Uint8Array.from(fixture.expected.channelId);
    const payload = new TextEncoder().encode('native/WASM v3 channel payload');
    const frame = consumerChannel.sealBinary(route, payload);
    assert.equal(equalBytes(hostChannel.openBinary(route, frame), payload), true);

    hostChannel.dispose();
    assert.throws(() => hostChannel.sealBinary(route, payload), { message: 'CRYPTO_OBJECT_DISPOSED' });
    hostChannel.free();
    hostChannel.free();
    hostChannel = undefined;

    abandoned = new api.BrowserHandshakeV3(consumerOptions);
    abandoned.dispose();
    assert.throws(() => abandoned.write(), { message: 'CRYPTO_OBJECT_DISPOSED' });
  } finally {
    abandoned?.free();
    consumerHandshake?.free();
    hostHandshake?.free();
    consumerChannel?.free();
    hostChannel?.free();
    consumerIdentity.free();
    hostIdentity.free();
  }
});
