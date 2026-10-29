import test from 'node:test';
import assert from 'node:assert/strict';
import { applySnapshot, applyPatch, setInputEnabled, ProjectionError } from '../../packages/terminal-renderer/src/index.mjs';
import { terminal } from './fixtures.mjs';
import { fixture, negativeCases, expansionCase, epochCases } from './patch-fixtures.mjs';
import { assertBuffer } from './assertions.mjs';
test('production sparse patch projects cells and metadata with zero raw parser calls', () => {
  const { old, patch } = fixture(), t = terminal();
  applySnapshot(t, old);
  let parsed = 0;
  t._core._inputHandler.parse = () => { parsed++; };
  applyPatch(t, patch);
  const next = structuredClone(old);
  next.normal.lines[0].cells.splice(0, 4, patch.update.normal.rows[0].cells[0].cell, patch.update.normal.rows[0].cells[1].cell, ...Array(2).fill(patch.update.normal.rows[0].cells[2].cell));
  assertBuffer(t, next.normal, 'normal');
  assertBuffer(t, next.alternate, 'alt');
  assert.equal(parsed, 0);
  setInputEnabled(t, true);
  assert.equal(t.options.disableStdin, false);
  t.dispose();
});
test('malformed patches invalidate input until an explicit new snapshot', () => {
  for (const patch of negativeCases().patches) {
    const { old } = fixture(), t = terminal();
    applySnapshot(t, old);
    setInputEnabled(t, true);
    assert.throws(() => applyPatch(t, patch), ProjectionError);
    assert.equal(t.options.disableStdin, true);
    assert.throws(() => setInputEnabled(t, true), ProjectionError);
    applySnapshot(t, old);
    setInputEnabled(t, true);
    t.dispose();
  }
  const { patch } = fixture(), t = terminal();
  assert.throws(() => applyPatch(t, patch), ProjectionError);
  t.dispose();
});
test('compact run expansion is rejected before structuredClone allocates a replacement grid', () => {
  const { old, patch } = expansionCase(), t = terminal(old.cols, old.rows);
  assert(new TextEncoder().encode(JSON.stringify(patch)).byteLength < 512 * 1024);
  applySnapshot(t, old);
  setInputEnabled(t, true);
  const clone = globalThis.structuredClone;
  let clones = 0;
  globalThis.structuredClone = (value) => { clones++; return clone(value); };
  try {
    assert.throws(() => applyPatch(t, patch), /expanded snapshot exceeds 8 MiB/);
    assert.equal(clones, 0);
    assert.equal(t.options.disableStdin, true);
  }
  finally {
    globalThis.structuredClone = clone;
    t.dispose();
  }
});

test('production epoch syntax rejects matching noncanonical legacy baselines', () => {
  for(const {old,patch} of epochCases()) {
    const t=terminal();applySnapshot(t,old);setInputEnabled(t,true);
    assert.throws(()=>applyPatch(t,patch),/invalid patch epoch/);
    assert.equal(t.options.disableStdin,true);
    assert.throws(()=>setInputEnabled(t,true),ProjectionError);t.dispose();
  }
});
