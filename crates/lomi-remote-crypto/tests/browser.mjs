// Explicit test-fixtures feature is required; these seeds never enter default builds.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { chromium } from '@playwright/test';
const crate = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const manifest = resolve(crate, 'Cargo.toml');
const fixture = JSON.parse(execFileSync('cargo', ['run', '--quiet', '--locked', '--manifest-path', manifest, '--features', 'test-fixtures', '--example', 'interoperability'], {encoding:'utf8'}));
const server = createServer((req,res) => {
  if(req.url==='/fixture') {res.setHeader('Content-Type','application/json');res.end(JSON.stringify(fixture));return;}
  if(req.url==='/') {res.setHeader('Content-Type','text/html');res.end('<!doctype html><title>Unqualified crypto test</title>');return;}
  const files = {'/crypto.js':['lomi_remote_crypto.js','text/javascript'],'/lomi_remote_crypto_bg.wasm':['lomi_remote_crypto_bg.wasm','application/wasm']};
  const entry=files[req.url];if(!entry){res.writeHead(404);res.end();return;}
  res.setHeader('Content-Type',entry[1]);res.end(readFileSync(resolve(crate,'pkg',entry[0])));
});
await new Promise(resolve => server.listen(0,'127.0.0.1',resolve));
let browser;
try {
  browser=await chromium.launch({headless:true});
  const page=await browser.newPage();await page.goto(`http://127.0.0.1:${server.address().port}`);
  const native=spawn(resolve(crate,'target/debug/examples/live_interoperability'),[],{stdio:['pipe','pipe','inherit']});
  const lines=createInterface({input:native.stdout}); const replies=[];lines.on('line',line=>replies.shift()(JSON.parse(line)));
  await page.exposeFunction('nativeCrypto',command=>new Promise(resolve=>{replies.push(resolve);native.stdin.write(JSON.stringify(command)+'\n');}));
  const result=await page.evaluate(async()=>{
    const crypto=await import('/crypto.js');await crypto.default();const f=await(await fetch('/fixture')).json();
    const fail=(condition,message)=>{if(!condition)throw Error(message);};
    const equal=(a,b)=>JSON.stringify(Array.from(a))===JSON.stringify(Array.from(b));
    const rejects=(fn)=>{try{fn();return false;}catch{return true;}};
    fail(crypto.production_qualified()===false,'production gate');
    fail(crypto.live_production_qualified()===true,'live production gate');
    const host=crypto.BrowserIdentity.fixture(true,11),device=crypto.BrowserIdentity.fixture(false,21);
    fail(equal(host.fingerprint(),f.host_pin),'native/WASM host fingerprint');fail(equal(device.fingerprint(),f.device_pin),'native/WASM device fingerprint');
    fail(crypto.pairing_fingerprint(new Uint8Array(16).fill(1),new Uint8Array(16).fill(2),new Uint8Array(16).fill(3),new Uint8Array(f.host_pin),new Uint8Array(f.device_pin),new Uint8Array(32).fill(8))===f.pairing_fingerprint_hex,'pairing digest cross-language');
    crypto.verify_peer_approval(JSON.stringify(f.approval),JSON.stringify(f.host_bundle),new Uint8Array(f.host_pin),JSON.stringify(f.approval.approval),1000n,1n);
    const approvalExpected=structuredClone(f.approval.approval);approvalExpected.session_ids[0][0]^=1;
    fail(rejects(()=>crypto.verify_peer_approval(JSON.stringify(f.approval),JSON.stringify(f.host_bundle),new Uint8Array(f.host_pin),JSON.stringify(approvalExpected),1000n,1n)),'WASM approval scoped sessions');
    fail(rejects(()=>crypto.verify_peer_approval(JSON.stringify(f.approval),JSON.stringify(f.host_bundle),new Uint8Array(f.host_pin),JSON.stringify(f.approval.approval),2000n,1n)),'WASM approval deadline');
    crypto.verify_public_bundle(JSON.stringify(f.host_bundle),new Uint8Array(f.host_pin));
    const changed=structuredClone(f.host_bundle);changed.bundle.mailbox_key[0]^=1;fail(rejects(()=>crypto.verify_public_bundle(JSON.stringify(changed),new Uint8Array(f.host_pin))),'substituted mailbox key');
    const context=JSON.stringify(f.context),hb=host.public_bundle(),db=device.public_bundle();
    const client=new crypto.BrowserHandshake(true,device,context,hb,host.fingerprint());const server=new crypto.BrowserHandshake(false,host,context,db,device.fingerprint());
    server.read(client.write());client.read(server.write());server.read(client.write());
    const c=client.finish(),s=server.finish();fail(equal(c.transcript_hash(),s.transcript_hash()),'Noise transcript');
    const routing=new Uint8Array(16).fill(9),payload=new TextEncoder().encode('界e\u0301');const frame=c.seal(routing,payload);fail(equal(s.open(routing,frame),payload),'WASM Noise roundtrip');fail(rejects(()=>s.open(routing,frame)),'Noise replay');
    const native=async(op,bytes=[])=>window.nativeCrypto({op,bytes:Array.from(bytes)});
    const ok=async(op,bytes)=>{const r=await native(op,bytes);fail(!r.Err,`native ${op}: ${r.Err}`);return new Uint8Array(r.Ok);};
    const mixed=new crypto.BrowserHandshake(true,device,context,hb,host.fingerprint());
    await ok('read',mixed.write()); mixed.read(await ok('write')); await ok('read',mixed.write());
    const mc=mixed.finish();fail(equal(mc.transcript_hash(),await ok('finish')),'mixed transcript');
    const mf=mc.seal_binary(routing,payload); fail(equal(await ok('open',mf),payload),'WASM to native Noise');
    const nr=await ok('seal',payload);fail(equal(mc.open_binary(routing,nr),payload),'native to WASM Noise');
    fail(Boolean((await native('open',mf)).Err),'mixed replay');
    fail(Boolean((await native('seal',payload)).Err),'mixed fail closed');
    mc.dispose();fail(rejects(()=>mc.seal_binary(routing,payload)),'explicit disposal');mc.free();
    const aborted=new crypto.BrowserHandshake(true,device,context,hb,host.fingerprint());aborted.dispose();fail(rejects(()=>aborted.write()),'abort');aborted.free();
    const badClient=new crypto.BrowserHandshake(true,device,context,hb,host.fingerprint());
    const badServer=new crypto.BrowserHandshake(false,host,context,db,device.fingerprint());
    badServer.read(badClient.write());badClient.read(badServer.write());badServer.read(badClient.write());
    const bc=badClient.finish(),bs=badServer.finish();const corrupt=bc.seal_binary(routing,payload);corrupt[corrupt.length-1]^=1;
    fail(rejects(()=>bs.open_binary(routing,corrupt)),'binary tamper');fail(rejects(()=>bs.seal_binary(routing,payload)),'tamper closes');bc.free();bs.free();
    const policy=JSON.stringify(f.policy),envelope=JSON.stringify(f.envelope),hostPin=new Uint8Array(f.host_pin);
    fail(new TextDecoder().decode(device.open_mailbox(envelope,hb,hostPin,policy,1100n))==='native-to-browser','native HPKE to browser');
    fail(rejects(()=>device.open_mailbox(envelope,hb,hostPin,policy,1100n)),'HPKE replay');
    const tampered=structuredClone(f.envelope);tampered.enc[0]^=1;fail(rejects(()=>device.open_mailbox(JSON.stringify(tampered),hb,hostPin,policy,1100n)),'HPKE enc tamper');
    fail(rejects(()=>device.open_mailbox(envelope,hb,hostPin,policy,1500n)),'HPKE expiry');
    const ephemeral=new crypto.BrowserIdentity(new Uint8Array(16).fill(1),new Uint8Array(16).fill(3),false,1);fail(ephemeral.fingerprint().length===32,'browser entropy generation');ephemeral.free();
    const outgoing=host.seal_mailbox(db,device.fingerprint(),policy,1000n,1500n,new TextEncoder().encode('browser-to-native'));
    host.free();device.free();c.free();s.free();return {outgoing,checks:23};
  });
  const verification=execFileSync('cargo',['run','--quiet','--locked','--manifest-path',manifest,'--features','test-fixtures','--example','interoperability','--','verify'],{input:result.outgoing,encoding:'utf8'});
  native.stdin.end();
  assert.match(verification,/browser-to-native verified/);console.log(`Chromium WASM: ${result.checks} checks; full bidirectional native/WASM Noise and experimental HPKE verified`);
} finally {await browser?.close();await new Promise(resolve=>server.close(resolve));}
