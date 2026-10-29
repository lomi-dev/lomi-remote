import { readFile } from "node:fs/promises";
import assert from "node:assert/strict";
import {
  applySnapshot,
  applyDelta,
  applyPatch,
  PROFILE,
} from "../../packages/terminal-renderer/src/index.mjs";
import { terminal } from "./fixtures.mjs";
import { assertBuffer } from "./assertions.mjs";
const path = process.argv[2];
if (!path)
  throw new Error(
    "usage: node tests/terminal-state/rust-oracle.mjs /absolute/synthetic-state-fixtures.json",
  );
const fixture = JSON.parse(await readFile(path, "utf8"));
assert.equal(fixture.profile, PROFILE);
assert.equal(fixture.qualified, false);
assert(Array.isArray(fixture.cases) && fixture.cases.length > 0);
let projections = 0,
  attachBoundaries = 0;
function verify(t, s) {
  assert.equal(t.rows, s.rows);
  assert.equal(t.cols, s.cols);
  assert.equal(t.buffer.active.type, s.active);
  assertBuffer(t, s.normal, "normal");
  assertBuffer(t, s.alternate, "alt");
  const c = t._core,
    m = s.modes,
    d = c.coreService.decPrivateModes;
  for (const key of [
    "applicationCursorKeys",
    "applicationKeypad",
    "origin",
    "wraparound",
    "sendFocus",
  ])
    assert.equal(d[key], m[key]);
  assert.equal(d.bracketedPasteMode, m.bracketedPaste);
  assert.equal(c.coreService.modes.insertMode, m.insert);
  assert.equal(c.coreService.isCursorHidden, !m.cursorVisible);
  assert.equal(d.cursorStyle, s.cursorStyle.shape);
  assert.equal(d.cursorBlink, s.cursorStyle.blinking);
  assert.equal(
    c.coreMouseService.activeProtocol,
    { none: "NONE", x10: "X10", vt200: "VT200", drag: "DRAG", any: "ANY" }[
      m.mouseTracking
    ],
  );
  assert.equal(
    c.coreMouseService.activeEncoding,
    { default: "DEFAULT", utf8: "LOMI_UTF8", sgr: "SGR" }[m.mouseEncoding],
  );
  assert.equal(c._inputHandler._windowTitle, s.title ?? "");
  projections++;
}
for (const entry of fixture.cases) {
  try {
    const t = terminal(entry.snapshot.cols, entry.snapshot.rows);
    applySnapshot(t, entry.snapshot);
    verify(t, entry.snapshot);
    for (const event of entry.deltas) {
      applyDelta(t, event);
      verify(t, event.state);
    }
    verify(t, entry.final);
    if (fixture.patchFormat === "grid-patch-v1") {
      assert.equal(entry.patches.length, entry.deltas.length);
      applySnapshot(t, entry.snapshot);
      for (let i=0;i<entry.patches.length;i++) { applyPatch(t,entry.patches[i]); verify(t,entry.deltas[i].state); }
    }
    t.dispose();
    // Attach at every emitted host state, then continue with the next event.
    // Partial UTF8/CSI/OSC/DCS are retained by Rust; xterm parses no bytes.
    const states = [
      entry.snapshot,
      ...entry.deltas.map((event) => event.state),
    ];
    for (let i = 0; i < states.length; i++) {
      const target = terminal(states[i].cols, states[i].rows);
      applySnapshot(target, states[i]);
      verify(target, states[i]);
      attachBoundaries++;
      if (i < entry.deltas.length) {
        applyDelta(target, entry.deltas[i]);
        verify(target, entry.deltas[i].state);
      }
      if (fixture.patchFormat === "grid-patch-v1" && i < entry.patches.length) {
        applySnapshot(target, states[i]); applyPatch(target,entry.patches[i]); verify(target,entry.deltas[i].state);
      }
      target.dispose();
    }
  } catch (error) {
    throw new Error(`Rust projection case ${entry.id}: ${error.message}`, {
      cause: error,
    });
  }
}
console.log(
  `passed: ${fixture.cases.length} Rust fixture cases, ${projections} full-grid/mode projections, ${attachBoundaries} attachment boundaries; profile remains experimental`,
);
