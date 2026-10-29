#!/usr/bin/env node
// Hash-pinned inventory of the remote product's canonical sources and consumer snapshots.
import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { assertAdapted } from './cross-target-provenance-utils.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const web = resolve(root, '../remote-web');
const mobile = resolve(root, '../mobile-app');
const manifestPath = join(root, 'CROSS-TARGET-PROVENANCE.json');
const write = process.argv.includes('--write');
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
async function files(dir, prefix = '') {
  const out = [];
  for (const e of await readdir(dir, { withFileTypes: true })) {
    if (e.isSymbolicLink()) throw new Error(`Symlink is not allowed in provenance input: ${join(dir, e.name)}`);
    if (e.name === 'target' || e.name === 'node_modules' || e.name === '.git') continue;
    const p = prefix ? `${prefix}/${e.name}` : e.name;
    if (e.isDirectory()) out.push(...await files(join(dir, e.name), p));
    else if (e.isFile()) out.push(p);
  }
  return out.sort();
}
async function hashFiles(base, paths) {
  return Object.fromEntries(await Promise.all(paths.map(async p => [p, sha(await readFile(join(base, p)))])));
}
async function tree(base, subdir) {
  const full = join(base, subdir);
  return hashFiles(full, await files(full));
}

const cryptoDiffs = ['Cargo.toml', 'tests/grant_v3_wire.rs'];
const protocolDiffs = ['Cargo.toml'];
const cryptoMobileOnly = ['Cargo.lock', 'pkg/lomi_remote_crypto.d.ts', 'pkg/lomi_remote_crypto.js', 'pkg/lomi_remote_crypto_bg.wasm', 'pkg/lomi_remote_crypto_bg.wasm.d.ts', 'tests/grant-v3/proof.rs'];
const cryptoSource = await tree(root, 'crates/lomi-remote-crypto');
const protocolSource = await tree(root, 'crates/lomi-remote-protocol');
const cryptoMobile = await tree(mobile, 'modules/lomi-remote-crypto/vendor/core');
const protocolMobile = await tree(mobile, 'modules/lomi-remote-crypto/vendor/lomi-remote-protocol');
assertAdapted('mobile crypto vendor', cryptoSource, cryptoMobile, cryptoDiffs, cryptoMobileOnly);
assertAdapted('mobile protocol vendor', protocolSource, protocolMobile, protocolDiffs);

const webPackages = {};
for (const name of ['remote-contracts', 'protocol-codec-wasm', 'authority-crypto-wasm', 'terminal-renderer']) {
  const path = `packages/${name}`;
  const canonical = await tree(root, path);
  const snapshot = await tree(web, path);
  // remote-web packages are intentionally runtime-only; the existing sync check
  // validates the allowed file set and generated package manifest.
  webPackages[name] = { canonical, snapshot };
}
const mobileManual = await tree(mobile, 'src/remote');
const mobileModuleManifest = JSON.parse(await readFile(join(mobile, 'modules/lomi-remote-crypto/PROVENANCE.json'), 'utf8'));
const manifest = {
  format: 1,
  description: 'Source-provenance and release-preflight gate. It does not establish production or device acceptance. Web, desktop and mobile share packages/remote-contracts/src/rpc-client.ts and generated wire types; hash-tracked mobile src/remote files implement application state and native adapters. Rust protocol validation is shared through WASM or the pinned native vendor.',
  adaptations: {
    mobileCryptoVendor: { paths: cryptoDiffs, mobileOnlyPaths: cryptoMobileOnly, hashes: Object.fromEntries(cryptoDiffs.map(p => [p, { canonical: cryptoSource[p], mobile: cryptoMobile[p] }])) },
    mobileProtocolVendor: { paths: protocolDiffs, hashes: Object.fromEntries(protocolDiffs.map(p => [p, { canonical: protocolSource[p], mobile: protocolMobile[p] }])) },
  },
  canonical: {
    rustCrypto: cryptoSource,
    rustProtocol: protocolSource,
    schemas: await tree(root, 'contracts'),
    wasmPackages: {
      protocolCodec: await tree(root, 'packages/protocol-codec-wasm'),
      authorityCrypto: await tree(root, 'packages/authority-crypto-wasm'),
    },
  },
  consumers: {
    remoteWebPackages: webPackages,
    mobileCryptoVendor: cryptoMobile,
    mobileProtocolVendor: protocolMobile,
    mobileHandwrittenRemoteSources: mobileManual,
    mobileModuleProvenanceSha256: sha(await readFile(join(mobile, 'modules/lomi-remote-crypto/PROVENANCE.json'))),
    mobileProductInputs: mobileModuleManifest.mobileProductSha256,
    mobileBuildInputs: mobileModuleManifest.mobileBuildSha256,
    mobileRendererPackage: await tree(mobile, 'packages/terminal-renderer'),
    mobileContractPackage: await tree(mobile, 'packages/remote-contracts'),
    mobileRendererInputs: await hashFiles(mobile, [
      'renderer/index.ts', 'scripts/build-renderer.mjs', 'src/terminal/generated.ts',
    ]),
  },
};
const rendered = `${JSON.stringify(manifest, null, 2)}\n`;
if (!write) {
  const checks = [
    ['remote contracts', process.execPath, [join(root, 'packages/remote-contracts/scripts/generate.mjs'), '--check'], root],
    ['protocol codec WASM', process.execPath, [join(root, 'packages/protocol-codec-wasm/scripts/build.mjs'), '--check'], root],
    ['authority crypto WASM', process.execPath, [join(root, 'packages/authority-crypto-wasm/scripts/build.mjs'), '--check'], root],
    ['remote-web package snapshots', process.execPath, [join(root, 'scripts/sync-remote-web-packages.mjs'), '--check'], root],
    ['mobile crypto provenance', 'python3', [join(mobile, 'scripts/check-crypto.py')], mobile],
  ];
  for (const [label, command, args, cwd] of checks) {
    const result = spawnSync(command, args, { cwd, encoding: 'utf8' });
    if (result.stdout) process.stdout.write(result.stdout);
    if (result.stderr) process.stderr.write(result.stderr);
    if (result.status !== 0) {
      console.error(`${label} check failed (status ${result.status ?? 'unknown'})`);
      process.exitCode = 1;
    }
  }
}
if (write) {
  await writeFile(manifestPath, rendered);
  console.log('cross-target provenance manifest written');
} else {
  const actual = await readFile(manifestPath, 'utf8');
  if (actual !== rendered) {
    console.error('CROSS-TARGET-PROVENANCE.json is stale; run node scripts/check-cross-target-provenance.mjs --write');
    process.exitCode = 1;
  } else {
    console.log('cross-target provenance is current');
  }
}
