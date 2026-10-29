// Development tooling only. The browser runtime imports no Node built-ins.
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
const run = (bin, args) => execFileSync(bin, args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] }).trim();
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
function sourceSnapshot() {
  const sourceFiles = [];
  function collect(dir) {
    for (const name of readdirSync(resolve(root, dir), { withFileTypes: true }).sort((a,b) => a.name.localeCompare(b.name))) {
      const path = `${dir}/${name.name}`;
      if (name.isSymbolicLink()) throw Error(`source symlink: ${path}`);
      if (name.isDirectory()) collect(path);
      else if (path.endsWith('.rs')) sourceFiles.push(path);
    }
  }
  collect('crates/lomi-remote-protocol/src');
  sourceFiles.push('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'crates/lomi-remote-protocol/Cargo.toml', 'packages/protocol-codec-wasm/scripts/build.mjs', 'packages/protocol-codec-wasm/src/index.mjs', 'packages/protocol-codec-wasm/src/index.d.ts', 'packages/protocol-codec-wasm/package.json', 'packages/protocol-codec-wasm/test/codec.test.mjs', 'packages/protocol-codec-wasm/README.md');
  return Object.fromEntries(sourceFiles.sort().map(name => [name, sha(readFileSync(resolve(root,name)))]));
}
const sources = sourceSnapshot();
const cli = run('wasm-bindgen', ['--version']);
if (cli !== 'wasm-bindgen 0.2.126') throw Error('wasm-bindgen CLI must be 0.2.126');
run('cargo', ['rustc', '--locked', '-p', 'lomi-remote-protocol', '--lib', '--release', '--target', 'wasm32-unknown-unknown', '--features', 'browser', '--crate-type', 'cdylib']);
const target = process.env.CARGO_TARGET_DIR ? resolve(root, process.env.CARGO_TARGET_DIR) : resolve(root, 'target');
const binary = resolve(target, 'wasm32-unknown-unknown/release/lomi_remote_protocol.wasm');
const temporary = mkdtempSync(join(tmpdir(), 'lomi-protocol-codec-'));
try {
  const inputBytes = readFileSync(binary);
  const inputSnapshot = join(temporary, 'input.wasm');
  writeFileSync(inputSnapshot, inputBytes, { flag: 'wx', mode: 0o600 });
  run('wasm-bindgen', [inputSnapshot, '--target', 'web', '--out-dir', temporary, '--out-name', 'protocol_codec']);
  rmSync(inputSnapshot);
  if (JSON.stringify(sourceSnapshot()) !== JSON.stringify(sources)) throw Error('protocol source changed during build');
  const artifacts = Object.fromEntries(readdirSync(temporary).sort().map(name => [name, sha(readFileSync(join(temporary,name)))]));
  const provenance = {
    format: 1, package: '@lomi/protocol-codec-wasm', target: 'wasm32-unknown-unknown', profile: 'release',
    features: ['browser'], tools: { rustc: run('rustc', ['--version']), cargo: run('cargo', ['--version']), wasmBindgen: cli },
    sourceInputMode: 'live workspace guarded by equal pre-build and post-bindgen source digests',
    sourceSha256: sources, inputWasmSha256: sha(inputBytes), generatedSha256: artifacts,
    scope: 'Pure wire validation and generic logical-message framing; no authentication, cryptography, database state, authority, freshness or semantic domain stream application.',
    provenanceSelfHash: false
  };
  writeFileSync(join(temporary, 'provenance.json'), `${JSON.stringify(provenance, null, 2)}\n`);
  const output = join(pkg, 'generated');
  mkdirSync(output, {recursive:true});
  const expected = readdirSync(temporary).sort();
  for (const name of expected) {
    const data = readFileSync(join(temporary,name));
    if (check) {
      if (!data.equals(readFileSync(join(output,name)))) throw Error(`WASM artifact drift: ${relative(root,join(output,name))}`);
    } else writeFileSync(join(output,name),data);
  }
  if (readdirSync(output).some(name => !expected.includes(name))) throw Error('unexpected protocol generated artifact');
} finally { rmSync(temporary, {recursive:true,force:true}); }
console.log(check ? 'Protocol WASM artifacts verified' : 'Protocol WASM artifacts generated');
