// Development tooling only; the verification runtime imports no Node built-ins.
import { readFileSync, readdirSync, mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { resolve, dirname, relative, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const root = resolve(pkg, '../..');
const check = process.argv.includes('--check');
if (process.argv.slice(2).some(arg => arg !== '--check')) throw Error('usage: build.mjs [--check]');
const run = (binary, args) => execFileSync(binary, args, {
  cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'], timeout: 300000,
}).trim();
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function sourceSnapshot() {
  const sourceFiles = ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'];
  function collect(directory) {
    for (const entry of readdirSync(resolve(root, directory), { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const path = `${directory}/${entry.name}`;
      if (['node_modules', 'generated', '__pycache__', 'target', '.git'].includes(entry.name)) continue;
      if (entry.isSymbolicLink()) throw Error(`source symlink: ${path}`);
      if (entry.isDirectory()) collect(path);
      else if (entry.isFile()) sourceFiles.push(path);
    }
  }
  for (const directory of ['crates/lomi-remote-crypto', 'crates/lomi-remote-protocol', 'packages/authority-crypto-wasm']) collect(directory);
  return Object.fromEntries(sourceFiles.sort().map(name => [name, sha(readFileSync(resolve(root, name)))]));
}
// Bind normal concurrent source edits to failure, rather than recording only
// post-build source bytes against a possibly older cached/build output.
const sources = sourceSnapshot();
const bindgen = run('wasm-bindgen', ['--version']);
if (bindgen !== 'wasm-bindgen 0.2.126') throw Error('wasm-bindgen CLI must be 0.2.126');
run('cargo', ['build', '--locked', '-p', 'lomi-remote-crypto', '--lib', '--release',
  '--target', 'wasm32-unknown-unknown', '--no-default-features', '--features', 'browser']);
const target = process.env.CARGO_TARGET_DIR ? resolve(root, process.env.CARGO_TARGET_DIR) : resolve(root, 'target');
const binary = resolve(target, 'wasm32-unknown-unknown/release/lomi_remote_crypto.wasm');
const temporary = mkdtempSync(join(tmpdir(), 'lomi-authority-crypto-'));
try {
  // Shared Cargo targets can be replaced by another build. Bind the exact
  // bytes used by bindgen and the input digest to one private snapshot.
  const inputBytes = readFileSync(binary);
  const inputSnapshot = join(temporary, 'input.wasm');
  writeFileSync(inputSnapshot, inputBytes, { flag: 'wx', mode: 0o600 });
  run('wasm-bindgen', [inputSnapshot, '--target', 'web', '--out-dir', temporary, '--out-name', 'authority_crypto']);
  rmSync(inputSnapshot);
  const generated = readFileSync(join(temporary, 'authority_crypto.js'), 'utf8');
  if (/\bfixture\s*\(/.test(generated)) throw Error('fixture API entered authority release');
  for (const name of ['verify_host_key_initiation', 'verify_host_enrollment_proof', 'prepare_host_enrollment_challenge', 'verify_host_refresh_proof', 'verify_registered_host_identity', 'verify_consumer_window_identity', 'prepare_consumer_window_challenge', 'verify_consumer_window_proof', 'prepare_grant_proposal_v3', 'verify_grant_proposal_v3', 'prepare_channel_context_v3', 'verify_channel_admission_v3']) {
    if (!generated.includes(`export function ${name}(`)) throw Error(`missing canonical verifier: ${name}`);
  }
  const module = new WebAssembly.Module(readFileSync(join(temporary, 'authority_crypto_bg.wasm')));
  if (WebAssembly.Module.exports(module).some(entry => /fixture/i.test(entry.name))) {
    throw Error('fixture WASM export entered authority release');
  }
  if (JSON.stringify(sourceSnapshot()) !== JSON.stringify(sources)) throw Error('authority source changed during build');
  const artifacts = Object.fromEntries(readdirSync(temporary).sort().map(name => [name, sha(readFileSync(join(temporary, name)))]));
  writeFileSync(join(temporary, 'provenance.json'), `${JSON.stringify({
    format: 1, package: '@lomi/authority-crypto-wasm', target: 'wasm32-unknown-unknown',
    profile: 'release', features: ['browser'], testFixtures: false,
    sourceInputMode: 'live workspace guarded by equal pre-build and post-bindgen source digests',
    tools: { rustc: run('rustc', ['--version']), cargo: run('cargo', ['--version']), wasmBindgen: bindgen },
    sourceSha256: sources, inputWasmSha256: sha(inputBytes), generatedSha256: artifacts,
    scope: 'Public canonical identity, enrollment, refresh, window-proof and v3 grant/channel verification; no class, approval, replay or transaction authority.',
    provenanceSelfHash: false,
  }, null, 2)}\n`);
  const output = join(pkg, 'generated');
  mkdirSync(output, { recursive: true });
  const expected = readdirSync(temporary).sort();
  for (const name of expected) {
    const bytes = readFileSync(join(temporary, name));
    if (check) {
      if (!bytes.equals(readFileSync(join(output, name)))) throw Error(`authority WASM drift: ${relative(root, join(output, name))}`);
    } else writeFileSync(join(output, name), bytes);
  }
  if (readdirSync(output).some(name => !expected.includes(name))) throw Error('unexpected authority generated artifact');
} finally { rmSync(temporary, { recursive: true, force: true }); }
console.log(check ? 'Authority crypto WASM verified' : 'Authority crypto WASM generated');
