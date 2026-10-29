import { createServer } from "node:http";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import { chromium } from "../../packages/terminal-renderer/node_modules/@playwright/test/index.mjs";
import { snapshot, line } from "./fixtures.mjs";
import {negativeCases,expansionCase,epochCases} from "./patch-fixtures.mjs";
const root = new URL("../../packages/terminal-renderer/", import.meta.url);
const pageHtml = `<!doctype html><html><head><link rel="stylesheet" href="/xterm.css"></head><body><div id="terminal" style="width:800px;height:500px"></div><button id="outside">Outside</button><script src="/xterm.js"></script><script type="module">
import * as adapter from '/src/index.mjs';
import {assertBuffer} from '/projection.mjs'; window.compareBuffer=assertBuffer;
window.adapter=adapter;window.term=new Terminal({cols:8,rows:3,scrollback:100,allowProposedApi:true});window.term.open(document.querySelector('#terminal'));window.ready=true;
</script></body></html>`;
const files = {
  "/xterm.js": "node_modules/@xterm/xterm/lib/xterm.js",
  "/xterm.css": "node_modules/@xterm/xterm/css/xterm.css",
  "/src/index.mjs": "src/index.mjs",
  "/src/schema.mjs": "src/schema.mjs",
};
const server = createServer(async (req, res) => {
  try {
    if (req.url === "/") {
      res.setHeader("Content-Type", "text/html");
      res.end(pageHtml);
      return;
    }
    if (req.url === "/projection.mjs") {
      res.setHeader("Content-Type", "text/javascript");
      res.end(await readFile(new URL("./projection.mjs", import.meta.url))); return;
    }
    const file = files[req.url];
    if (!file) {
      res.statusCode = 404;
      res.end();
      return;
    }
    res.setHeader(
      "Content-Type",
      file.endsWith(".css") ? "text/css" : "text/javascript",
    );
    res.end(await readFile(new URL(file, root)));
  } catch {
    res.statusCode = 500;
    res.end();
  }
});
const evidencePath = new URL("../../artifacts/terminal-state/browser-patch-evidence.json", import.meta.url);
const sourcePaths = ["packages/terminal-renderer/src/index.mjs", "packages/terminal-renderer/src/schema.mjs", "tests/terminal-state/browser.mjs", "tests/terminal-state/projection.mjs", "tests/terminal-state/patch-fixtures.mjs", "crates/lomi-terminal-state/src/bin/state-fixtures.rs", "crates/lomi-terminal-state/src/lib.rs", "crates/lomi-terminal-state/src/patch.rs", "Cargo.lock"];
async function provenance() {
  return Object.fromEntries(await Promise.all(sourcePaths.map(async path => [path, createHash("sha256").update(await readFile(new URL("../../" + path, import.meta.url))).digest("hex")])));
}
await mkdir(new URL("../../artifacts/terminal-state/", import.meta.url), {recursive:true});
const sourceHashes = await provenance();
const evidence = {kind:"production-grid-patch-browser", complete:false, qualified:false, sourceHashes};
await writeFile(evidencePath, JSON.stringify(evidence,null,2) + "\n");
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(`http://127.0.0.1:${server.address().port}`);
  await page.waitForFunction(() => window.ready === true);
  const s = snapshot();
  s.normal.baseY = 2;
  s.normal.lines = [
    line(8, "zero"),
    line(8, "one"),
    line(8, "two"),
    line(8, "three"),
    line(8, "four"),
  ];
  s.title = "browser fixture";
  s.colors[42] = { r: 12, g: 34, b: 56 };
  s.colors[256] = { r: 45, g: 67, b: 89 };
  const attached = await page.evaluate((s) => {
    window.input = [];
    window.titles = [];
    window.parseCalls = 0;
    term.onData((d) => input.push(d));
    term.onTitleChange((d) => titles.push(d));
    const original = term._core._inputHandler.parse.bind(
      term._core._inputHandler,
    );
    term._core._inputHandler.parse = (...args) => {
      parseCalls++;
      return original(...args);
    };
    adapter.applySnapshot(term, s);
    term.scrollLines(-1);
    term.select(0, 1, 3);
    return {
      selection: term.getSelection(),
      scroll: term.buffer.active.viewportY,
      title: titles.at(-1),
      fg: term._core._themeService.colors.foreground.css,
      ansi: term._core._themeService.colors.ansi[42].css,
    };
  }, s);
  assert.equal(attached.selection, "one");
  assert.equal(attached.scroll, 1);
  assert.equal(attached.title, "browser fixture");
  assert.equal(attached.fg, "#2d4359");
  assert.equal(attached.ansi, "#0c2238");
  const next = structuredClone(s);
  next.sequence = "1";
  next.outputOffset = "10";
  next.modes.applicationCursorKeys = true;
  next.modes.applicationKeypad = true;
  next.modes.bracketedPaste = true;
  next.modes.sendFocus = true;
  next.cursorStyle = { shape: "underline", blinking: true };
  next.colors[42] = null;
  next.normal.lines[4] = line(8, "delta");
  const applied = await page.evaluate((next) => {
    let resets = 0;
    const reset = term.reset.bind(term);
    term.reset = () => {
      resets++;
      reset();
    };
    adapter.applyDelta(term, {
      profile: next.profile,
      version: 1,
      sessionEpoch: next.sessionEpoch,
      previousSequence: "0",
      state: next,
    });
    adapter.setInputEnabled(term, true);
    return {
      selection: term.getSelection(),
      scroll: term.buffer.active.viewportY,
      resets,
      ansi: term._core._themeService.colors.ansi[42].css,
    };
  }, next);
  assert.equal(applied.selection, "one");
  assert.equal(applied.scroll, 1);
  assert.equal(applied.resets, 0);
  assert.notEqual(applied.ansi, "#0c2238");
  await page.locator(".xterm-helper-textarea").focus();
  await page.keyboard.press("ArrowUp");
  await page.evaluate(() => term.paste("paste-fixture"));
  await page.locator("#outside").focus();
  const input = await page.evaluate(() => ({
    input,
    parseCalls,
    privateModes: term._core.coreService.decPrivateModes,
    selection: term.getSelection(),
  }));
  assert(input.input.includes("\x1bOA"));
  assert(input.input.includes("\x1b[200~paste-fixture\x1b[201~"));
  assert(input.input.includes("\x1b[I"));
  assert(input.input.includes("\x1b[O"));
  assert.equal(input.parseCalls, 0);
  assert.equal(input.privateModes.applicationKeypad, true);
  assert.equal(input.privateModes.cursorStyle, "underline");
  assert.equal(input.privateModes.cursorBlink, true);
  assert.deepEqual(errors, []);
  const keypad = await page.evaluate((next) => {
    window.intents = [];
    const priorHandler = () => true;
    term.attachCustomKeyEventHandler(priorHandler);
    const handle = adapter.installApplicationKeypadHook(term, (intent) =>
      intents.push(intent),
    );
    const keys = [
      "Numpad0",
      "Numpad1",
      "Numpad2",
      "Numpad3",
      "Numpad4",
      "Numpad5",
      "Numpad6",
      "Numpad7",
      "Numpad8",
      "Numpad9",
      "NumpadDecimal",
      "NumpadDivide",
      "NumpadMultiply",
      "NumpadSubtract",
      "NumpadAdd",
      "NumpadEnter",
      "NumpadEqual",
    ];
    const dispatch = (code, extra = {}) =>
      term.textarea.dispatchEvent(
        new KeyboardEvent("keydown", {
          code,
          key: "Unidentified",
          location: 3,
          bubbles: true,
          cancelable: true,
          ...extra,
        }),
      );
    keys.forEach((code) => dispatch(code));
    const count = intents.length;
    dispatch("Numpad1", { ctrlKey: true });
    dispatch("Numpad1", { shiftKey: true });
    dispatch("Numpad1", { altKey: true });
    dispatch("Numpad1", { metaKey: true });
    adapter.setInputEnabled(term, false);
    dispatch("Numpad1");
    adapter.setInputEnabled(term, true);
    const off = structuredClone(next);
    off.sequence = "2";
    off.modes.applicationKeypad = false;
    adapter.applyDelta(term, {
      profile: off.profile,
      version: 1,
      sessionEpoch: off.sessionEpoch,
      previousSequence: "1",
      state: off,
    });
    adapter.setInputEnabled(term, true);
    dispatch("Numpad1");
    handle.dispose();
    handle.dispose();
    dispatch("Numpad1");
    return {
      intents,
      count,
      afterDispose: intents.length,
      rawParseCalls: parseCalls,
      priorHandlerRestored: term._core._customKeyEventHandler === priorHandler,
    };
  }, next);
  assert.deepEqual(
    keypad.intents.map((i) => i.data),
    [..."pqrstuvwxynojmkMX"].map((c) => "\x1bO" + c),
  );
  assert(
    keypad.intents.every(
      (i) =>
        i.kind === "human-input" &&
        i.inputType === "application-keypad" &&
        i.sessionEpoch === s.sessionEpoch,
    ),
  );
  assert.equal(keypad.count, 17);
  assert.equal(keypad.afterDispose, 17);
  assert.equal(keypad.rawParseCalls, 0);
  assert.equal(keypad.priorHandlerRestored, true);
  const fixtureBytes = await readFile(new URL("../../artifacts/terminal-state/synthetic-fixtures.json", import.meta.url));
  const rust = JSON.parse(fixtureBytes);
  assert.equal(rust.patchFormat, "grid-patch-v1");
  assert.equal(rust.qualified, false);
  const patchProof = await page.evaluate(({ fixture, negatives, expansion, epochs }) => {
    const assert = { equal: (a, b) => { if (a !== b)
        throw new Error("projection value mismatch"); }, deepEqual: (a, b) => { if (JSON.stringify(a) !== JSON.stringify(b))
        throw new Error("projection structure mismatch"); } };
    let projections = 0, boundaries = 0, patches = 0;
    function verify(s) {
      assert.equal(term.rows, s.rows);
      assert.equal(term.cols, s.cols);
      assert.equal(term.buffer.active.type, s.active);
      compareBuffer(term, s.normal, "normal", assert);
      compareBuffer(term, s.alternate, "alt", assert);
      const c = term._core, d = c.coreService.decPrivateModes, m = s.modes;
      for (const k of ["applicationCursorKeys", "applicationKeypad", "origin", "wraparound", "sendFocus"])
        assert.equal(d[k], m[k]);
      assert.equal(d.bracketedPasteMode, m.bracketedPaste);
      assert.equal(c.coreService.modes.insertMode, m.insert);
      assert.equal(c.coreService.isCursorHidden, !m.cursorVisible);
      assert.equal(d.cursorStyle, s.cursorStyle.shape);
      assert.equal(d.cursorBlink, s.cursorStyle.blinking);
      assert.equal(c.coreMouseService.activeProtocol, { none: "NONE", x10: "X10", vt200: "VT200", drag: "DRAG", any: "ANY" }[m.mouseTracking]);
      assert.equal(c.coreMouseService.activeEncoding, { default: "DEFAULT", utf8: "LOMI_UTF8", sgr: "SGR" }[m.mouseEncoding]);
      assert.equal(c._inputHandler._windowTitle, s.title ?? "");
      projections++;
    }
    for (const entry of fixture.cases) {
      assert.equal(entry.patches.length, entry.deltas.length);
      adapter.applySnapshot(term, entry.snapshot);
      verify(entry.snapshot);
      for (let i = 0; i < entry.patches.length; i++) {
        adapter.applyPatch(term, entry.patches[i]);
        verify(entry.deltas[i].state);
        patches++;
      }
      verify(entry.final);
      const states = [entry.snapshot, ...entry.deltas.map(d => d.state)];
      for (let i = 0; i < states.length; i++) {
        adapter.applySnapshot(term, states[i]);
        verify(states[i]);
        boundaries++;
        if (i < entry.patches.length) {
          adapter.applyPatch(term, entry.patches[i]);
          verify(states[i + 1]);
          patches++;
        }
      }
    }
    // The same malformed corpus runs in Node and actual Chromium.
    let malformedRejected = 0;
    for (const bad of negatives.patches) {
      adapter.applySnapshot(term, negatives.old);
      adapter.setInputEnabled(term, true);
      let rejected = false;
      try {
        adapter.applyPatch(term, bad);
      }
      catch {
        rejected = true;
      }
      assert.equal(rejected, true);
      assert.equal(term.options.disableStdin, true);
      let blocked = false;
      try {
        adapter.setInputEnabled(term, true);
      }
      catch {
        blocked = true;
      }
      assert.equal(blocked, true);
      malformedRejected++;
    }
    let canonicalEpochRejected=0;
    for(const {old,patch} of epochs) {
      adapter.applySnapshot(term,old);adapter.setInputEnabled(term,true);
      let rejected=false;try{adapter.applyPatch(term,patch)}catch(error){rejected=error.message.includes("invalid patch epoch")}
      assert.equal(rejected,true);assert.equal(term.options.disableStdin,true);
      let blocked=false;try{adapter.setInputEnabled(term,true)}catch{blocked=true}assert.equal(blocked,true);
      canonicalEpochRejected++;
    }
    adapter.applySnapshot(term, expansion.old);
    adapter.setInputEnabled(term, true);
    const clone = globalThis.structuredClone;
    let expansionClones = 0, expansionRejected = false;
    globalThis.structuredClone = value => { expansionClones++; return clone(value); };
    try {
      adapter.applyPatch(term, expansion.patch);
    }
    catch (error) {
      expansionRejected = error.message.includes("expanded snapshot exceeds 8 MiB");
    }
    finally {
      globalThis.structuredClone = clone;
    }
    assert.equal(expansionRejected, true);
    assert.equal(expansionClones, 0);
    assert.equal(term.options.disableStdin, true);
    return { cases: fixture.cases.length, projections, boundaries, patches, rawParseCalls: parseCalls, malformedRejected, canonicalEpochRejected, expansionRejected, expansionClones };
  }, { fixture: rust, negatives: negativeCases(), expansion: expansionCase(), epochs: epochCases() });
  assert.equal(patchProof.rawParseCalls, 0);
  assert(patchProof.patches > 0);
  assert.equal(errors.length, 0);
  console.log("production patch proof:", JSON.stringify({ ...patchProof, fixtureSha256: createHash("sha256").update(fixtureBytes).digest("hex"), qualified: false }));
  assert.deepEqual(await provenance(),sourceHashes,"source changed during browser proof");
  Object.assign(evidence,{browser:await browser.version(),...patchProof,fixtureSha256:createHash("sha256").update(fixtureBytes).digest("hex")});
  console.log("browser:", await browser.version());
  console.log(
    "passed: actual Chromium xterm6 DOM renderer, palette set/restore, title, live selection/scroll, application cursor, paste, focus, cursor style; zero PTY parser calls",
  );
} finally {
  const cleanup=await Promise.allSettled([browser?.close(),new Promise((resolve,reject)=>server.close(error=>error?reject(error):resolve()))]);
  if(cleanup.some(result=>result.status==="rejected")) throw new Error("browser fixture cleanup failed");
}
evidence.complete=true;
await writeFile(evidencePath,JSON.stringify(evidence,null,2)+"\n");
