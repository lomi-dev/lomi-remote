import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { readFile } from 'node:fs/promises';
import { existsSync, mkdirSync, renameSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { createHash } from 'node:crypto';
import { platform, release, arch } from 'node:os';


const root = new URL('../../', import.meta.url);
const output = process.env.LOMI_PROTOCOL_BROWSER_EVIDENCE ? pathToFileURL(process.env.LOMI_PROTOCOL_BROWSER_EVIDENCE) : new URL('artifacts/protocol-browser/evidence.json', root);
const files = new Map([
  ['/contracts/src/index.mjs', 'packages/remote-contracts/src/index.mjs'],
  ['/contracts/generated/registry.mjs', 'packages/remote-contracts/generated/registry.mjs'],
  ['/contracts/generated/validators.mjs', 'packages/remote-contracts/generated/validators.mjs'],
  ['/codec/src/index.mjs', 'packages/protocol-codec-wasm/src/index.mjs'],
  ['/codec/generated/protocol_codec.js', 'packages/protocol-codec-wasm/generated/protocol_codec.js'],
  ['/codec/generated/protocol_codec_bg.wasm', 'packages/protocol-codec-wasm/generated/protocol_codec_bg.wasm'],
  ['/fixtures/rust.json', 'packages/remote-contracts/fixtures/rust-codec.json'],
  ['/fixtures/text.json', 'contracts/fixtures/rpc-streams/text-parity.json'],
]);
const report = { attemptId: process.env.LOMI_PROTOCOL_BROWSER_ATTEMPT ?? randomUUID(), startedAt: new Date().toISOString(), phase: 'starting', kind: 'canonical-protocol-actual-browser', qualified: false,
  complete: false, passed: false, sourceSha256: {}, cleanup: {},
  environment: { node: process.versions.node, os: platform(), release: release(), arch: arch() } };
const sha = value => createHash('sha256').update(value).digest('hex');
function persist() {
  mkdirSync(new URL('./',output), { recursive:true, mode:0o700 });
  const temporary=new URL(`evidence.${report.attemptId}.tmp`,output);
  writeFileSync(temporary,JSON.stringify(report,null,2)+'\n',{mode:0o600});
  renameSync(temporary,output);
}
// Invalidate any previous pass before dynamic Playwright import or setup.
persist();
const cancellation=new AbortController();
const interrupt=()=>{ report.interrupted=true; cancellation.abort(); };
process.on('SIGINT',interrupt);
process.on('SIGTERM',interrupt);
const poll=setInterval(()=>{
  if(process.env.LOMI_PROTOCOL_BROWSER_CANCEL && existsSync(process.env.LOMI_PROTOCOL_BROWSER_CANCEL)) interrupt();
},50);
const interrupted=()=>new Error('Interrupted');
function checkCancellation() { if(cancellation.signal.aborted) throw interrupted(); }
async function bounded(promise,milliseconds,{cancel=true}={}) {
  let timer, onAbort;
  try {
    const races=[promise,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('Deadline')),milliseconds);})];
    if(cancel) races.push(new Promise((_,reject)=>{
      onAbort=()=>reject(interrupted());
      cancellation.signal.addEventListener('abort',onAbort,{once:true});
      if(cancellation.signal.aborted) onAbort();
    }));
    return await Promise.race(races);
  } finally {
    clearTimeout(timer);
    if(onAbort) cancellation.signal.removeEventListener('abort',onAbort);
  }
}
let browser;
let browserServer;
let server;
let failed = true;
try {
  const { chromium } = await import('../../packages/terminal-renderer/node_modules/@playwright/test/index.mjs');
  checkCancellation();
  const content = new Map();
  for (const [route, path] of files) {
    checkCancellation();
    const bytes = await readFile(new URL(path, root));
    content.set(route, bytes);
    report.sourceSha256[path] = sha(bytes);
  }
  report.sourceSha256['tests/protocol-browser/browser.mjs'] = sha(await readFile(new URL(import.meta.url)));
  server = createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('Content-Type', 'text/html; charset=utf-8');
      response.end('<!doctype html><title>Protocol fixture</title>');
      return;
    }
    const bytes = content.get(request.url);
    if (!bytes) { response.writeHead(404); response.end(); return; }
    response.setHeader('Content-Type', request.url.endsWith('.wasm') ? 'application/wasm' :
      request.url.endsWith('.json') ? 'application/json' : 'text/javascript');
    response.setHeader('Cache-Control', 'no-store');
    response.end(bytes);
  });
  await bounded(new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  }), 5_000, {cancel:false});
  report.phase='server-ready';
  report.owned={ nodePid:process.pid, serverPort:server.address().port };
  persist();
  checkCancellation();
  // Keep acquisition owned until Playwright finishes, then unwind on cancellation.
  browserServer = await bounded(chromium.launchServer({ headless:true, timeout:20_000 }),25_000,{cancel:false});
  report.owned.browserPid=browserServer.process().pid;
  report.owned.browserServerPort=Number(new URL(browserServer.wsEndpoint()).port);
  persist();
  checkCancellation();
  browser = await bounded(chromium.connect(browserServer.wsEndpoint()),10_000,{cancel:false});
  report.phase='browser-ready';
  persist();
  if(process.env.LOMI_PROTOCOL_BROWSER_HOLD==='1') await bounded(new Promise(()=>{}),60_000);
  checkCancellation();
  report.environment.browser = browser.version();
  const context = await browser.newContext({ serviceWorkers: 'block' });
  const page = await context.newPage();
  page.setDefaultTimeout(20_000);
  let pageErrors = 0;
  page.on('pageerror', () => { pageErrors++; });
  await page.goto('http://127.0.0.1:' + server.address().port, { waitUntil: 'load' });
  report.observation = await bounded(page.evaluate(async () => {
    const sdk = await import('/contracts/src/index.mjs');
    const codec = await import('/codec/src/index.mjs');
    let beforeInitializationRejected = false;
    try { sdk.decode('rpc-request', '{}'); } catch { beforeInitializationRejected = true; }
    if (!beforeInitializationRejected) throw new Error('Initialization');
    const bytes = await (await fetch('/codec/generated/protocol_codec_bg.wasm')).arrayBuffer();
    codec.initializeProtocolCodec(bytes);
    sdk.initializeCanonicalCodec({
      validateWire: codec.protocolValidateWire,
      validateResponseFor: codec.protocolValidateResponseFor,
    });
    let cases = 0, accepted = 0, rejected = 0, skippedUnboundResponses = 0, textCases = 0, e1Cases = 0;
    for (const url of ['/fixtures/rust.json', '/fixtures/text.json']) {
      for (const fixture of await (await fetch(url)).json()) {
        if (fixture.schema === 'rpc-response' && !fixture.request) {
          if (url === '/fixtures/text.json') throw new Error('Missing text request');
          skippedUnboundResponses++;
          continue;
        }
        const actual = fixture.request ? sdk.checkResponse(fixture.request, fixture.value) :
          sdk.validate(fixture.schema, fixture.value);
        if (actual !== fixture.accepted) throw new Error('Parity');
        if (fixture.accepted) accepted++; else rejected++;
        if (url === '/fixtures/text.json') textCases++;
        if (fixture.name.startsWith('e1/')) e1Cases++;
        cases++;
      }
    }
    const invalid = [
      ['rpc-request', '{"v":2,"v":2}'],
      ['rpc-request', '{"v":2,"private":"\\ud800"}'],
      ['rpc-request', '{"v":2,"private":"' + String.fromCharCode(0xd800) + '"}'],
      ['rpc-request', ' '.repeat(1024 * 1024 + 1)],
      ['not-a-wire-type', '{}'],
    ];
    for (const [kind, raw] of invalid) {
      let denied = false;
      try { sdk.decode(kind, raw); }
      catch (error) { denied = error.message === 'Invalid remote contract.'; }
      if (!denied) throw new Error('Unsafe wire');
    }
    return { beforeInitializationRejected, codecInitialized: codec.isProtocolCodecInitialized(),
      cases, accepted, rejected, textCases, e1Cases, skippedUnboundResponses, rawNegativeCases: invalid.length };
  }), 30_000);
  assert.equal(pageErrors, 0);
  assert(report.observation.cases >= 100);
  assert(report.observation.accepted > 0 && report.observation.rejected > 0);
  assert.equal(report.observation.textCases, 20);
  // Unbound legacy shape responses are counted explicitly, never called parity.
  for (const [path, expected] of Object.entries(report.sourceSha256)) {
    assert.equal(sha(await readFile(new URL(path, root))), expected);
  }
  report.inputsUnchanged = true;
  checkCancellation();
  failed = false;
} catch (error) {
  // Never copy wire values, field names or browser exception text into evidence.
  report.errorClass = error?.constructor?.name ?? 'Error';
} finally {
  const cleanupErrors = [];
  const stop = async (label, action) => {
    try { await action(); report.cleanup[label] = true; }
    catch { report.cleanup[label] = false; cleanupErrors.push(label); }
  };
  await Promise.all([
    stop('browserClosed', async () => {
      if(browserServer) {
        try { await bounded(browserServer.close(),10_000,{cancel:false}); }
        catch {
          // BrowserServer owns the exact child; never signal a discovered PID.
          await bounded(browserServer.kill(),3_000,{cancel:false});
          report.cleanup.browserKilled=true;
          throw new Error('Browser cleanup required force');
        }
      }
      if(browser) await bounded(browser.close(),2_000,{cancel:false});
    }),
    stop('serverClosed', async () => {
      if (!server) return;
      server.closeAllConnections();
      if (server.listening) await bounded(new Promise((resolve, reject) =>
        server.close(error => error ? reject(error) : resolve())), 5_000,{cancel:false});
    }),
  ]);
  report.cleanup.errors = cleanupErrors;
  clearInterval(poll);
  report.phase=report.interrupted ? 'interrupted' : failed ? 'failed' : 'finished';
  report.complete = !failed && !report.interrupted && cleanupErrors.length === 0;
  report.passed = report.complete;
  report.exitCode = report.passed ? 0 : 1;
  persist();
  process.removeListener('SIGINT',interrupt);
  process.removeListener('SIGTERM',interrupt);
}
console.log(report.passed ? 'passed: actual Chromium canonical Rust/WASM contract parity' :
  'failed: actual Chromium protocol evidence is incomplete');
process.exitCode = report.exitCode;
