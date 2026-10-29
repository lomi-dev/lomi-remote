import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { assertAdapted } from '../scripts/cross-target-provenance-utils.mjs';

test('adaptation validation rejects missing and added files', () => {
  assert.throws(() => assertAdapted('fixture', { a: '1', b: '2' }, { a: '1' }, []), /inventory mismatch.*missing=b/);
  assert.throws(() => assertAdapted('fixture', { a: '1' }, { a: '1', b: '2' }, []), /inventory mismatch.*added=b/);
});

test('adaptation validation rejects undocumented content drift', () => {
  assert.throws(() => assertAdapted('fixture', { a: '1' }, { a: '2' }, []), /differs outside its pinned adaptations: a/);
  assert.doesNotThrow(() => assertAdapted('fixture', { a: '1' }, { a: '2' }, ['a']));
});

test('cross-target provenance check passes and pins only documented mobile adaptations', async () => {
  const result = spawnSync(process.execPath, ['scripts/check-cross-target-provenance.mjs'], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  const manifest = JSON.parse(await readFile('CROSS-TARGET-PROVENANCE.json', 'utf8'));
  assert.deepEqual(manifest.adaptations.mobileCryptoVendor.paths, ['Cargo.toml', 'tests/grant_v3_wire.rs']);
  assert.deepEqual(manifest.adaptations.mobileCryptoVendor.mobileOnlyPaths, ['Cargo.lock', 'pkg/lomi_remote_crypto.d.ts', 'pkg/lomi_remote_crypto.js', 'pkg/lomi_remote_crypto_bg.wasm', 'pkg/lomi_remote_crypto_bg.wasm.d.ts', 'tests/grant-v3/proof.rs']);
  assert.deepEqual(manifest.adaptations.mobileProtocolVendor.paths, ['Cargo.toml', 'src/http.rs', 'tests/http_identity.rs']);
  assert.ok(Object.keys(manifest.consumers.mobileHandwrittenRemoteSources).length > 0);
  assert.match(manifest.description, /handwritten contract sources/);
  assert.equal(typeof manifest.consumers.mobileModuleProvenanceSha256, 'string');
  assert.ok(Object.keys(manifest.consumers.mobileProductInputs).length > 0);
  assert.ok(Object.keys(manifest.consumers.mobileBuildInputs).length > 0);
});
