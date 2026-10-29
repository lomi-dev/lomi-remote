import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { validateShape as validate, decodeShape as decode, validate as validateCanonical, decode as decodeCanonical, OrderedSequence } from '../src/index.mjs';
for (const file of ['../fixtures/rust-codec.json','../../../contracts/fixtures/rpc-streams/text-parity.json']) {
  const cases=JSON.parse(await readFile(new URL(file,import.meta.url),'utf8'));
  for (const fixture of cases) test(`Rust codec parity: ${fixture.name}`,()=>{
    assert.equal(validate(fixture.schema,fixture.value),fixture.schemaAccepted ?? fixture.accepted);
    if(fixture.request) return; // Canonical correlation is tested against Rust WASM separately.
    if(fixture.schemaAccepted ?? fixture.accepted) assert.deepEqual(decode(fixture.schema,JSON.stringify(fixture.value)),fixture.value);
    else assert.throws(()=>decode(fixture.schema,JSON.stringify(fixture.value)),/^Error: Invalid remote contract\.$/);
  });
}
test('duplicate JSON fields and lone UTF16 surrogates fail with safe errors',()=>{
  assert.throws(()=>decode('rpc-request','{"secret":"private","secret":"private"}'),/^Error: Invalid remote contract\.$/);
  assert.equal(validate('HostRegisterParams',{hostId:'11111111-1111-4111-8111-111111111111',hostPublicKey:'\ud800'}),false);
});
test('revocation acknowledgement has an exact body schema and generated validator',()=>{
  const valid={
    hostAuthorizationId:'11111111-1111-4111-8111-111111111111',
    expectedHostAccessEpoch:'7',
    refresh:'retained_refresh_proof',
  };
  assert.equal(validate('HostRevocationAckParams',valid),true);
  assert.deepEqual(decode('HostRevocationAckParams',JSON.stringify(valid)),valid);
  assert.equal(validate('HostRevocationAckParams',{...valid,authorization:'Bearer ordinary'}),false);
  assert.equal(validate('HostRevocationAckParams',{...valid,expectedHostAccessEpoch:7}),false);
  assert.equal(validate('HostRevocationAckParams',{...valid,refresh:'bad proof'}),false);
});
test('checked API fails closed before canonical Rust codec initialization',()=>{
  assert.equal(validateCanonical('rpc-request',{}),false);
  assert.throws(()=>decodeCanonical('rpc-request','{}'),/^Error: Canonical protocol codec is not initialized\.$/);
});
test('ordered streams reject duplicate/gap and require explicit reset',()=>{
  const sequence=new OrderedSequence();
  assert.equal(sequence.accept('1'),true);
  assert.equal(sequence.accept('1'),false);
  assert.equal(sequence.accept('3'),false);
  assert.equal(sequence.accept('2'),false);
  assert.equal(sequence.accept('18446744073709551616'),false);
  sequence.reset();
  assert.equal(sequence.accept('9'),true);
});
