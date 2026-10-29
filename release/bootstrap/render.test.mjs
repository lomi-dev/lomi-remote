import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import { parseCatalog, renderInstallers } from './render.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const renderPath = path.join(here, 'render.mjs');
const version = '1.2.3';
const origin = `https://updates.example.invalid/lomi/v${version}/`;
const sha256 = (value) => createHash('sha256').update(value).digest('hex');

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])]));
  }
  return value;
}

function canonicalText(value) {
  return JSON.stringify(canonical(value));
}

function artifact(filename, hash, size) {
  return { url: origin + filename, sha256: hash, size };
}

function makeCatalog() {
  const baseLinux = `lomi-remote-linux-x86_64-${version}`;
  const baseWindows = `lomi-remote-windows-x86_64-${version}`;
  const preflight = artifact(`${baseLinux}.install.sh`, 'c'.repeat(64), 512);
  const command = `/bin/sh -c 'curl ${preflight.url}; # ${preflight.sha256}' lomi-linux-bootstrap\n`;
  return {
    format: 1,
    version,
    releaseOrigin: origin,
    sourceRevision: 'a'.repeat(40),
    publicRoot: artifact(`release-root-${'d'.repeat(64)}.json`, 'd'.repeat(64), 2048),
    targets: [
      {
        platform: 'linux-x86_64',
        archive: artifact(`${baseLinux}.zip`, 'b'.repeat(64), 8192),
        linuxBootstrap: {
          preflight,
          manifest: artifact(`${baseLinux}.bootstrap-manifest`, 'e'.repeat(64), 128),
          signature: artifact(`${baseLinux}.sig`, 'f'.repeat(64), 64),
          publicKey: artifact(`${baseLinux}.der`, '1'.repeat(64), 44),
          command,
          commandSha256: sha256(command),
        },
      },
      {
        platform: 'windows-x86_64',
        archive: artifact(`${baseWindows}.zip`, '2'.repeat(64), 16384),
      },
    ],
  };
}

test('parseCatalog accepts canonical pinned Linux and Windows targets', () => {
  const catalog = makeCatalog();
  const raw = canonicalText(catalog);
  assert.deepEqual(parseCatalog(raw, sha256(raw)), canonical(catalog));
});

test('parseCatalog rejects a wrong digest and noncanonical JSON bytes', () => {
  const catalog = makeCatalog();
  const raw = canonicalText(catalog);
  assert.throws(() => parseCatalog(raw, '0'.repeat(64)), /catalog rejected/);
  assert.throws(() => parseCatalog(`${raw}\n`, sha256(`${raw}\n`)), /catalog rejected/);
  assert.throws(() => parseCatalog(JSON.stringify(catalog), sha256(JSON.stringify(catalog))), /catalog rejected/);
});

test('parseCatalog rejects an artifact outside the version-pinned origin', () => {
  const catalog = makeCatalog();
  catalog.targets[0].archive.url = catalog.targets[0].archive.url.replace('/v1.2.3/', '/');
  const raw = canonicalText(catalog);
  assert.throws(() => parseCatalog(raw, sha256(raw)), /catalog rejected/);
});

test('parseCatalog rejects duplicate platforms and bootstrap command pin drift', () => {
  const duplicate = makeCatalog();
  duplicate.targets.push({ ...duplicate.targets[0] });
  let raw = canonicalText(duplicate);
  assert.throws(() => parseCatalog(raw, sha256(raw)), /catalog rejected/);

  const changedCommand = makeCatalog();
  changedCommand.targets[0].linuxBootstrap.command += 'changed';
  raw = canonicalText(changedCommand);
  assert.throws(() => parseCatalog(raw, sha256(raw)), /catalog rejected/);
});

test('renderInstallers pins approved assets and supports a valid partial target set', async () => {
  const catalog = makeCatalog();
  const scripts = await renderInstallers({
    LOMI_REMOTE_INSTALLATION_CATALOG_JSON: canonicalText(catalog),
    LOMI_REMOTE_INSTALLATION_CATALOG_SHA256: sha256(canonicalText(catalog)),
  });

  assert.match(scripts['install.sh'], /1\.2\.3/);
  assert.match(scripts['install.sh'], new RegExp(catalog.targets[0].linuxBootstrap.preflight.url.replaceAll('/', '\\/')));
  assert.match(scripts['install.sh'], new RegExp(catalog.targets[0].linuxBootstrap.preflight.sha256));
  assert.doesNotMatch(scripts['install.sh'], /windows-x86_64/);
  assert.doesNotMatch(scripts['install.sh'], /^\s*eval(?:\s|$)/m);

  assert.match(scripts['install.ps1'], /1\.2\.3/);
  assert.match(scripts['install.ps1'], /x86_64/);
  assert.match(scripts['install.ps1'], new RegExp(catalog.targets[1].archive.sha256));
  assert.doesNotMatch(scripts['install.ps1'], /@@[A-Z_]+@@/);
});

test('renderer CLI writes both generated installers from a pinned catalog file', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'lomi-render-test-'));
  try {
    const catalogPath = path.join(directory, 'installation-catalog.json');
    const outputPath = path.join(directory, 'output');
    const raw = canonicalText(makeCatalog());
    await writeFile(catalogPath, raw, 'utf8');
    execFileSync(process.execPath, [renderPath, catalogPath, outputPath], { stdio: 'pipe' });
    const shell = await readFile(path.join(outputPath, 'install.sh'), 'utf8');
    const powershell = await readFile(path.join(outputPath, 'install.ps1'), 'utf8');
    assert.match(shell, /lomi-remote-linux-x86_64-1\.2\.3\.install\.sh/);
    assert.match(powershell, /lomi-remote-windows-x86_64-1\.2\.3\.zip/);
    assert.doesNotMatch(`${shell}\n${powershell}`, /@@[A-Z_]+@@/);
    assert.doesNotMatch(shell, /^\s*eval(?:\s|$)/m);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('empty catalog environment emits the not-yet-published message', async () => {
  assert.equal(parseCatalog(undefined, undefined), null);
  const scripts = await renderInstallers({});
  assert.match(scripts['install.sh'], /no signed release is published/);
  assert.match(scripts['install.ps1'], /no signed release is published/);
});
