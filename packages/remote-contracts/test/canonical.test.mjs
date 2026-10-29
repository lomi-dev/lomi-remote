import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { initializeProtocolCodec, protocolValidateWire, protocolValidateResponseFor } from '../../protocol-codec-wasm/src/index.mjs';
import { initializeCanonicalCodec, validate, validateShape, decode, decodeShape, checkResponse, decodeResponse } from '../src/index.mjs';
await initializeProtocolCodec(await readFile(new URL('../../protocol-codec-wasm/generated/protocol_codec_bg.wasm',import.meta.url)));
initializeCanonicalCodec({validateWire:protocolValidateWire,validateResponseFor:protocolValidateResponseFor});
test('local auth configuration agrees across generated and canonical codecs for the optional Remote API pin',()=>{
  const legacy={version:{major:1,minor:0},requestId:'11111111-1111-1111-1111-111111111111',call:{method:'auth.configure',params:{configuration:{version:1,origin:'https://identity.example',clientId:'host',provider:'protectedFile',keychainPath:null,protectedFileAcknowledgement:'osPermissionsOnly'},operatorIntent:'confirmed'}}};
  for(const pin of [undefined,null,'https://remote.example']) {
    const request=structuredClone(legacy);
    if(pin!==undefined) request.call.params.configuration.remoteApiOrigin=pin;
    assert.equal(validateShape('local-request',request),true);
    assert.equal(validate('local-request',request),true);
    assert.deepEqual(decode('local-request',JSON.stringify(request)),request);
  }
  for(const pin of ['', 'x'.repeat(181),42,[],{}]) {
    const request=structuredClone(legacy);
    request.call.params.configuration.remoteApiOrigin=pin;
    assert.equal(validateShape('local-request',request),false);
    assert.equal(validate('local-request',request),false);
  }
  const unknown=structuredClone(legacy);
  unknown.call.params.configuration.remote_api_origin='https://remote.example';
  assert.equal(validateShape('local-request',unknown),false);
  assert.equal(validate('local-request',unknown),false);
});
for (const file of ['../fixtures/rust-codec.json','../../../contracts/fixtures/rpc-streams/text-parity.json']) {
  const cases=JSON.parse(await readFile(new URL(file,import.meta.url),'utf8'));
  for (const fixture of cases) {
    if(fixture.schema==='rpc-response' && !fixture.request) throw new Error('Response parity fixture requires its original request.');
    test(`canonical Rust WASM parity: ${fixture.name}`,()=>{
      if(fixture.request) {
        assert.equal(checkResponse(fixture.request,fixture.value),fixture.accepted);
        if(fixture.accepted) assert.deepEqual(decodeResponse(fixture.request,JSON.stringify(fixture.value)),fixture.value);
        else assert.throws(()=>decodeResponse(fixture.request,JSON.stringify(fixture.value)),/^Error: Invalid remote contract\.$/);
      } else {
        assert.equal(validate(fixture.schema,fixture.value),fixture.accepted);
        if(fixture.accepted) assert.deepEqual(decode(fixture.schema,JSON.stringify(fixture.value)),fixture.value);
        else assert.throws(()=>decode(fixture.schema,JSON.stringify(fixture.value)),/^Error: Invalid remote contract\.$/);
      }
    });
  }
}
test('canonical decoding rejects raw duplicates and lone surrogates safely',()=>{
  assert.throws(()=>decode('rpc-request','{"v":2,"v":2}'),/^Error: Invalid remote contract\.$/);
  assert.throws(()=>decode('rpc-request','{"private":"\\ud800"}'),/^Error: Invalid remote contract\.$/);
});

const corpus=JSON.parse(await readFile(new URL('../fixtures/rust-codec.json',import.meta.url),'utf8'));
const plainRequest=corpus.find(f=>f.schema==='rpc-request' && f.accepted).value;
const plainResponse=corpus.find(f=>f.schema==='rpc-response' && f.request && f.accepted);
test('object predicates reject direct, nested and hidden serialization hooks',()=>{
  let hooks=0;
  const hook=()=>{ hooks++; return plainRequest; };
  const direct={toJSON:hook};
  assert.equal(validate('rpc-request',direct),false);
  const hidden=structuredClone(plainRequest);
  Object.defineProperty(hidden,'toJSON',{value:hook,enumerable:false});
  assert.equal(validate('rpc-request',hidden),false);
  const nested=structuredClone(plainRequest);
  Object.defineProperty(nested.call.params.context,'toJSON',{value:()=>{hooks++;return plainRequest.call.params.context;},enumerable:false});
  assert.equal(validate('rpc-request',nested),false);
  assert.equal(validateShape('rpc-request',nested),false);
  const response={toJSON(){ hooks++; return plainResponse.value; }};
  assert.equal(checkResponse(plainResponse.request,response),false);
  const hiddenResponse=structuredClone(plainResponse.value);
  Object.defineProperty(hiddenResponse,'toJSON',{value(){hooks++;return plainResponse.value;},enumerable:false});
  assert.equal(checkResponse(plainResponse.request,hiddenResponse),false);
  assert.equal(hooks,0);
});
test('object predicates reject accessors, custom prototypes and non-JSON values',()=>{
  let reads=0;
  const accessor=structuredClone(plainRequest);
  Object.defineProperty(accessor,'requestId',{get(){reads++;return plainRequest.requestId;},enumerable:true});
  assert.equal(validate('rpc-request',accessor),false);
  assert.equal(validateShape('rpc-request',accessor),false);
  const nested=structuredClone(plainRequest);
  Object.defineProperty(nested.call.params.context,'runtimeGeneration',{get(){reads++;return '1';},enumerable:true});
  assert.equal(validate('rpc-request',nested),false);
  assert.equal(reads,0);
  assert.equal(validate('rpc-request',Object.create(plainRequest)),false);
  const custom=structuredClone(plainRequest); Object.setPrototypeOf(custom,{untrusted:true});
  assert.equal(validate('rpc-request',custom),false);
  const callable=structuredClone(plainRequest); callable.call.params.extra=()=>{};
  assert.equal(validate('rpc-request',callable),false);
  const symbol=structuredClone(plainRequest); symbol[Symbol('hidden')]=true;
  assert.equal(validate('rpc-request',symbol),false);
  assert.equal(validate('rpc-request',plainRequest),true);
  assert.equal(checkResponse(plainResponse.request,plainResponse.value),true);
});
test('oversized raw JSON fails before an encoded copy is allocated',()=>{
  const previous=globalThis.TextEncoder; let encodes=0;
  globalThis.TextEncoder=class { encode(){encodes++;throw new Error('Unexpected encoding allocation.');} };
  try {
    for(const input of [' '.repeat(1024*1024+1),'é'.repeat(524289)]) {
      assert.throws(()=>decodeShape('rpc-request',input),/^Error: Invalid remote contract\.$/);
      assert.throws(()=>decode('rpc-request',input),/^Error: Invalid remote contract\.$/);
    }
    assert.equal(encodes,0);
  } finally { globalThis.TextEncoder=previous; }
});
