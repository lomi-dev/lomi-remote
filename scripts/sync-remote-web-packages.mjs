#!/usr/bin/env node
// Generate consumer snapshots from canonical packages and the native protocol.
// Rust remains the protocol and crypto source; no consumer owns a wire copy.
import { createHash } from 'node:crypto';
import { lstat, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const web = resolve(root, '../remote-web');
const mobile = resolve(root, '../mobile-app');
const check = process.argv.includes('--check');
const contractSource = join(root, 'packages/remote-contracts');
const codecSource = join(root, 'packages/protocol-codec-wasm');
const authoritySource = join(root, 'packages/authority-crypto-wasm');
const rendererSource = join(root, 'packages/terminal-renderer');
async function contractRuntimeFiles() {
  const generated = join(contractSource, 'generated');
  const index = await readFile(join(generated, 'index.d.ts'), 'utf8');
  const referenced = new Set(['index.d.ts']);
  for (const [, moduleName] of index.matchAll(/\bfrom\s+['"]\.\/([^'"]+)['"]/g)) {
    if (!moduleName.endsWith('.js')) {
      throw new Error(`Unexpected generated declaration import: ./${moduleName}`);
    }
    referenced.add(moduleName.slice(0, -'.js'.length) + '.d.ts');
  }
  for (const declaration of referenced) {
    try {
      await readFile(join(generated, declaration));
    } catch {
      throw new Error(`generated/index.d.ts references missing declaration: generated/${declaration}`);
    }
  }
  return [
    'src/index.mjs', 'src/rpc-client.ts', 'fixtures/rust-codec.json',
    'generated/registry.mjs', 'generated/validators.mjs',
    ...[...referenced].sort().map(name => `generated/${name}`),
  ];
}
const snapshots = [
  {
    source: rendererSource,
    destination: join(mobile, 'packages/terminal-renderer'),
    mobileManifestKey: 'mobileRendererSha256',
    files: async () => ['src/index.mjs', 'src/schema.mjs', 'src/stream-assembler.ts', 'src/workspace-stream.ts'],
  },
  {
    source: contractSource,
    destination: join(mobile, 'packages/remote-contracts'),
    mobileManifestKey: 'mobileContractPackageSha256',
    files: contractRuntimeFiles,
  },
  {
    source: rendererSource,
    destination: join(web, 'packages/terminal-renderer'),
    files: async () => ['src/index.mjs', 'src/schema.mjs', 'src/stream-assembler.ts', 'src/workspace-stream.ts'],
  },
  {
    source: contractSource,
    destination: join(web, 'packages/remote-contracts'),
    files: contractRuntimeFiles,
  },
  {
    source: codecSource,
    destination: join(web, 'packages/protocol-codec-wasm'),
    files: async () => [
      'src/index.mjs', 'src/index.d.ts', 'generated/protocol_codec.js',
      'generated/protocol_codec.d.ts', 'generated/protocol_codec_bg.wasm',
      'generated/protocol_codec_bg.wasm.d.ts',
    ],
  },
  {
    source: authoritySource,
    destination: join(web, 'packages/authority-crypto-wasm'),
    files: async () => [
      'src/index.mjs', 'src/index.d.ts',
      'generated/authority_crypto.js', 'generated/authority_crypto_bg.wasm',
      'generated/authority_crypto_bg.wasm.d.ts',
    ],
  },
];

const digest = bytes => createHash('sha256').update(bytes).digest('hex');
async function runtimePackageJson(source) {
  const pkg = JSON.parse(await readFile(join(source, 'package.json'), 'utf8'));
  // The web snapshot ships runtime code only, so package development tooling
  // must not become part of remote-web's install graph.
  delete pkg.scripts;
  delete pkg.devDependencies;
  delete pkg.files;
  return Buffer.from(`${JSON.stringify(pkg, null, 2)}\n`);
}
const errors = [];
await syncMobileProtocol();
const manifestDigests = {};
for (const snapshot of snapshots) {
  const files = (await snapshot.files()).sort();
  const expected = new Map();
  for (const path of files) expected.set(path, await readFile(join(snapshot.source, path)));
  expected.set('package.json', await runtimePackageJson(snapshot.source));
  const manifestPath = 'snapshot-manifest.json';
  const manifest = {
    generated: true,
    source: relative(root, snapshot.source).split('\\').join('/'),
    files: Object.fromEntries([...expected].sort(([a], [b]) => a.localeCompare(b))
      .map(([path, bytes]) => [path, digest(bytes)])),
  };
  expected.set(manifestPath, Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`));
  if (snapshot.destination.startsWith(mobile + '/')) {
    const provenancePath = join(mobile, 'modules/lomi-remote-crypto/PROVENANCE.json');
    const provenance = JSON.parse(await readFile(provenancePath, 'utf8'));
    const hashes = Object.fromEntries([...expected].map(([path, bytes]) => [path, digest(bytes)]));
    if (check) {
      if (JSON.stringify(provenance[snapshot.mobileManifestKey]) !== JSON.stringify(hashes)) {
        errors.push(`mobile ${relative(mobile, snapshot.destination)} provenance differs from canonical package output`);
      }
    } else {
      provenance[snapshot.mobileManifestKey] = hashes;
      await writeFile(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);
    }
  }
  const packageName = JSON.parse(expected.get('package.json').toString('utf8')).name;
  manifestDigests[packageName] = digest(expected.get(manifestPath));

  if (!check) {
    await rm(snapshot.destination, { recursive: true, force: true });
    for (const [path, bytes] of expected) {
      const target = join(snapshot.destination, path);
      await mkdir(dirname(target), { recursive: true });
      await writeFile(target, bytes);
    }
    continue;
  }

  for (const [path, bytes] of expected) {
    const target = join(snapshot.destination, path);
    try {
      const actual = await readFile(target);
      if (!actual.equals(bytes)) errors.push(`${relative(web, target)} differs from canonical package output`);
    } catch {
      errors.push(`${relative(web, target)} is missing; run node ../lomi-remote/scripts/sync-remote-web-packages.mjs`);
    }
  }
  try {
    const actualFiles = await listFiles(snapshot.destination);
    for (const path of actualFiles) if (!expected.has(path)) errors.push(`${relative(web, join(snapshot.destination, path))} is not an allowed snapshot file`);
  } catch {
    errors.push(`${relative(web, snapshot.destination)} is missing; run node ../lomi-remote/scripts/sync-remote-web-packages.mjs`);
  }
}
// The runtime resolver retains exact manifest/wasm pins. Generate them in the
// same operation as the snapshots so a build never needs manual hash edits.
const protocolWasm = await readFile(join(codecSource, 'generated/protocol_codec_bg.wasm'));
const pins = `// Generated by lomi-remote/scripts/sync-remote-web-packages.mjs. Do not edit.\n`
  + `export const PACKAGE_SNAPSHOT_PINS = Object.freeze({\n`
  + `  protocolWasm: Object.freeze(${JSON.stringify({ sha256: digest(protocolWasm), bytes: protocolWasm.length })}),\n`
  + `  manifests: Object.freeze(${JSON.stringify(manifestDigests, null, 2)}),\n});\n`;
const pinsPath = join(web, 'scripts/package-snapshot-pins.mjs');
if (check) {
  if (await readFile(pinsPath, 'utf8').catch(() => null) !== pins) {
    errors.push('scripts/package-snapshot-pins.mjs differs from canonical package output');
  }
} else {
  await writeFile(pinsPath, pins);
}
if (errors.length) {
  console.error(errors.join('\n'));
  process.exitCode = 1;
} else {
  console.log(check ? 'remote-web package snapshots are current' : 'remote-web package snapshots generated');
}

async function listFiles(directory, prefix = '') {
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw new Error(`Snapshot root must be a real directory: ${directory}`);
  }
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink()) throw new Error(`Snapshot input cannot be a symlink: ${join(directory, entry.name)}`);
    if (entry.isDirectory()) output.push(...await listFiles(join(directory, entry.name), path));
    else output.push(path);
  }
  return output;
}

async function syncMobileProtocol() {
  const source = join(root, 'crates/lomi-remote-protocol');
  const destination = join(mobile, 'modules/lomi-remote-crypto/vendor/lomi-remote-protocol');
  const provenancePath = join(mobile, 'modules/lomi-remote-crypto/PROVENANCE.json');
  const provenance = JSON.parse(await readFile(provenancePath, 'utf8'));
  const recorded = provenance.protocolSha256;
  if (!recorded || typeof recorded !== 'object' || Array.isArray(recorded)) {
    throw new Error('Mobile protocol snapshot has no trusted source inventory');
  }
  const current = (await listFiles(destination)).sort();
  const recordedPaths = Object.keys(recorded).sort();
  const paths = (await listFiles(source)).sort();
  if (!paths.includes('Cargo.toml') || !recordedPaths.includes('Cargo.toml') || !current.includes('Cargo.toml')) {
    throw new Error('Mobile protocol Cargo adaptation is missing');
  }
  const expected = new Map();
  for (const path of paths) {
    const bytes = await readFile(join(source, path));
    expected.set(path, path === 'Cargo.toml' ? await nativeProtocolCargo(bytes) : bytes);
  }
  // Preserve the sole Cargo adaptation and reject consumer edits. Bytes already
  // identical to the canonical source also permit a safe rerun if generation
  // was interrupted before its final provenance write.
  for (const path of current) {
    const actual = digest(await readFile(join(destination, path)));
    const canonical = expected.has(path) ? digest(expected.get(path)) : undefined;
    if (actual !== recorded[path] && actual !== canonical) {
      throw new Error(`Mobile protocol snapshot was edited: ${path}`);
    }
  }
  for (const path of recordedPaths) {
    if (!current.includes(path) && expected.has(path)) {
      if (check) errors.push(`mobile native protocol snapshot is missing: ${path}`);
    }
  }
  if (check) {
    for (const [path, bytes] of expected) {
      if (recorded[path] !== digest(bytes)) errors.push(`mobile native protocol snapshot differs: ${path}`);
    }
    for (const path of recordedPaths) {
      if (!expected.has(path)) errors.push(`mobile native protocol snapshot retains removed source: ${path}`);
    }
    return;
  }
  for (const [path, bytes] of expected) {
    await mkdir(dirname(join(destination, path)), { recursive: true });
    await writeFile(join(destination, path), bytes);
  }
  for (const path of recordedPaths) {
    if (!expected.has(path)) await rm(join(destination, path), { force: true });
  }
  provenance.protocolSha256 = Object.fromEntries([...expected].map(([path, bytes]) => [path, digest(bytes)]));
  await writeFile(provenancePath, `${JSON.stringify(provenance, null, 2)}\n`);
}

async function nativeProtocolCargo(bytes) {
  const workspace = await readFile(join(root, 'Cargo.toml'), 'utf8');
  const packageTable = workspace.match(/^\[workspace\.package\]\r?\n([\s\S]*?)(?=^\[|(?![\s\S]))/m)?.[1];
  if (!packageTable) throw new Error('Canonical workspace package settings are missing');
  let manifest = bytes.toString('utf8');
  for (const [key, pattern] of [['edition', '[0-9]{4}'], ['rust-version', '[0-9]+\\.[0-9]+(?:\\.[0-9]+)?']]) {
    const workspaceLine = new RegExp(`^${key}\\s*=\\s*"(${pattern})"\\s*$`, 'gm');
    const inheritedLine = new RegExp(`^${key}\\.workspace\\s*=\\s*true\\s*$`, 'gm');
    const values = [...packageTable.matchAll(workspaceLine)];
    if (values.length !== 1 || [...manifest.matchAll(inheritedLine)].length !== 1) {
      throw new Error(`Canonical native protocol ${key} adaptation needs review`);
    }
    manifest = manifest.replace(inheritedLine, `${key} = ${JSON.stringify(values[0][1])}`);
  }
  return Buffer.from(manifest);
}
