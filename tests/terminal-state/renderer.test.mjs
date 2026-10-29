import test from "node:test";
import { assertBuffer } from "./assertions.mjs";
import assert from "node:assert/strict";
import {
  applySnapshot,
  applyDelta,
  setInputEnabled,
  ProjectionError,
} from "../../packages/terminal-renderer/src/index.mjs";
import {
  terminal,
  snapshot,
  blank,
  line,
  delta,
  inspect,
} from "./fixtures.mjs";

test("projects both grids, wide/combining cells, delayed-wrap cursor, attributes, links and palette effects", () => {
  const t = terminal();
  const s = snapshot();
  s.normal.cursor = { x: 8, y: 1 };
  s.normal.savedCursor = { x: 3, y: 2 };
  s.normal.lines[1].wrapped = true;
  s.normal.lines[0].cells[0] = blank({
    text: "界",
    width: 2,
    fg: { kind: "rgb", r: 1, g: 2, b: 3 },
    bg: { kind: "indexed", index: 22 },
    flags: ["bold", "dim", "italic", "inverse", "hidden", "strike", "blink"],
    underlineStyle: 3,
    underlineColor: { kind: "rgb", r: 3, g: 4, b: 5 },
    hyperlink: { id: "same", uri: "https://example.invalid/grid" },
  });
  s.normal.lines[0].cells[1] = blank({ width: 0 });
  s.normal.lines[0].cells[2] = blank({ text: "e\u0301" });
  s.alternate.lines[0] = line(8, "ALT");
  s.alternate.lines[0].cells[3] = blank({
    text: "L",
    hyperlink: { id: "same", uri: "https://example.invalid/grid" },
  });
  s.colors[42] = { r: 10, g: 20, b: 30 };
  s.colors[256] = { r: 100, g: 90, b: 80 };
  s.title = "Synthetic terminal";
  const titles = [],
    colors = [],
    data = [];
  t.onTitleChange((v) => titles.push(v));
  t.onData((v) => data.push(v));
  t._core._inputHandler.onColor((v) => colors.push(v));
  applySnapshot(t, s);
  assertBuffer(t, s.normal, "normal");
  assertBuffer(t, s.alternate, "alt");
  assert.deepEqual(titles, ["Synthetic terminal"]);
  assert(colors.flat().some((v) => v.index === 42 && v.type === 1));
  assert.deepEqual(data, []);
  assert.equal(t._core.optionsService.options.disableStdin, true);
  assert.throws(() => t.write("\x1b]52;c;secret\x07"), ProjectionError);
  t.dispose();
});
test("full-state live deltas preserve local scroll/selection and synchronize input modes before enabling input", () => {
  const t = terminal();
  const s = snapshot();
  s.normal.baseY = 2;
  s.normal.lines.push(line(8, "four"), line(8, "five"));
  applySnapshot(t, s);
  t.scrollLines(-1);
  const before = t._core._bufferService.buffer.ydisp;
  let resets = 0;
  const original = t.reset.bind(t);
  t.reset = () => {
    resets++;
    original();
  };
  const next = structuredClone(s);
  next.sequence = "1";
  next.outputOffset = "19";
  next.title = "next";
  next.modes = {
    applicationCursorKeys: true,
    applicationKeypad: true,
    bracketedPaste: true,
    insert: true,
    origin: true,
    wraparound: false,
    sendFocus: true,
    cursorVisible: false,
    mouseTracking: "drag",
    mouseEncoding: "sgr",
  };
  next.cursorStyle = { shape: "bar", blinking: true };
  const result = applyDelta(t, delta(next, "0"));
  assert.equal(resets, 0);
  assert.equal(result.selectionPreserved, true);
  assert.equal(t._core._bufferService.buffer.ydisp, before);
  const c = t._core;
  assert.equal(c.coreService.decPrivateModes.applicationCursorKeys, true);
  assert.equal(c.coreService.decPrivateModes.applicationKeypad, true);
  assert.equal(c.coreService.decPrivateModes.bracketedPasteMode, true);
  assert.equal(c.coreService.decPrivateModes.origin, true);
  assert.equal(c.coreService.decPrivateModes.wraparound, false);
  assert.equal(c.coreService.modes.insertMode, true);
  assert.equal(c.coreService.isCursorHidden, true);
  assert.equal(c.coreMouseService.activeProtocol, "DRAG");
  assert.equal(c.coreMouseService.activeEncoding, "SGR");
  assert.equal(c.coreService.decPrivateModes.cursorStyle, "bar");
  assert.equal(c.coreService.decPrivateModes.cursorBlink, true);
  setInputEnabled(t, true);
  assert.equal(c.optionsService.options.disableStdin, false);
  const output = [];
  t.onData((v) => output.push(v));
  c.coreMouseService.triggerMouseEvent({
    col: 2,
    row: 1,
    x: 0,
    y: 0,
    button: 0,
    action: 1,
    ctrl: false,
    alt: false,
    shift: false,
  });
  assert.deepEqual(output, ["\x1b[<0;3;2M"]);
  t.dispose();
});
test("UTF8 mode1005 encodes coordinates beyond byte range, modifiers and releases through actual mouse service", () => {
  const t = terminal(512, 3),
    s = snapshot({ cols: 512, rows: 3 });
  s.modes.mouseTracking = "vt200";
  s.modes.mouseEncoding = "utf8";
  applySnapshot(t, s);
  setInputEnabled(t, true);
  const output = [];
  t.onData((v) => output.push(v));
  const mouse = t._core.coreMouseService;
  mouse.triggerMouseEvent({
    col: 300,
    row: 1,
    x: 0,
    y: 0,
    button: 0,
    action: 1,
    ctrl: true,
    alt: true,
    shift: true,
  });
  mouse.triggerMouseEvent({
    col: 300,
    row: 1,
    x: 0,
    y: 0,
    button: 2,
    action: 0,
    ctrl: false,
    alt: false,
    shift: false,
  });
  assert.deepEqual(output, [
    "\x1b[M" + String.fromCodePoint(60, 333, 34),
    "\x1b[M" + String.fromCodePoint(35, 333, 34),
  ]);
  assert.deepEqual([...Buffer.from(output[0])], [27, 91, 77, 60, 197, 141, 34]);
  const next = structuredClone(s);
  next.sequence = "1";
  next.modes.mouseTracking = "x10";
  applyDelta(t, delta(next, "0"));
  setInputEnabled(t, true);
  mouse.triggerMouseEvent({
    col: 300,
    row: 1,
    x: 0,
    y: 0,
    button: 0,
    action: 1,
    ctrl: true,
    alt: true,
    shift: true,
  });
  assert.equal(output.at(-1), "\x1b[M" + String.fromCodePoint(32, 333, 34));
  t.dispose();
});
test("active alternate switch keeps both grids and clears old link registry on a later full state", () => {
  const t = terminal(),
    s = snapshot();
  s.normal.lines[0] = line(8, "normal");
  s.alternate.lines[0] = line(8, "alt");
  applySnapshot(t, s);
  const next = structuredClone(s);
  next.sequence = "1";
  next.active = "alternate";
  next.alternate.cursor = { x: 2, y: 1 };
  next.alternate.lines[0].cells[0].hyperlink = {
    id: "a",
    uri: "https://example.invalid",
  };
  applyDelta(t, delta(next, "0"));
  assert.equal(t.buffer.active.type, "alternate");
  assertBuffer(t, next.normal, "normal");
  assertBuffer(t, next.alternate, "alt");
  assert.equal(t._core._oscLinkService._dataByLinkId.size, 1);
  const last = structuredClone(next);
  last.sequence = "2";
  last.alternate.lines[0].cells[0].hyperlink = null;
  applyDelta(t, delta(last, "1"));
  assert.equal(t._core._oscLinkService._dataByLinkId.size, 0);
  t.dispose();
});
test("invalid schema, shape, profile, unsafe effects and bounds fail closed without accepting input", () => {
  for (const mutate of [
    (s) => (s.profile = "other"),
    (s) => (s.version = 2),
    (s) => (s.rows = 513),
    (s) => (s.sequence = "18446744073709551616"),
    (s) => (s.outputOffset = "01"),
    (s) => (s.clipboard = "secret"),
    (s) => (s.normal.lines[0].cells[0].text = "\x1b"),
    (s) => (s.normal.lines[0].cells[0].width = 0),
    (s) => (s.colors[259] = { r: 1, g: 2, b: 3 }),
    (s) =>
      (s.normal.lines[0].cells[0].hyperlink = {
        id: "x",
        uri: "javascript:alert(1)",
      }),
    (s) => (s.modes.mouseEncoding = "unknown"),
  ]) {
    const t = terminal(),
      s = snapshot();
    applySnapshot(t, s);
    setInputEnabled(t, true);
    const before = inspect(t);
    const bad = structuredClone(s);
    mutate(bad);
    assert.throws(() => applySnapshot(t, bad), ProjectionError);
    assert.deepEqual(inspect(t), before);
    assert.equal(t._core.optionsService.options.disableStdin, true);
    assert.throws(() => setInputEnabled(t, true), ProjectionError);
    t.dispose();
  }
  assert.throws(
    () => applySnapshot({ _core: {} }, snapshot()),
    ProjectionError,
  );
});
test("delta rejects stale epoch/sequence, skipped updates and offset regression until explicit resync", () => {
  for (const mutate of [
    (d) => (d.sessionEpoch = "old"),
    (d) => (d.state.sequence = "0"),
    (d) => (d.state.sequence = "2"),
    (d) => (d.previousSequence = "1"),
    (d) => (d.state.outputOffset = "4"),
  ]) {
    const t = terminal(),
      s = snapshot({ outputOffset: "5" });
    applySnapshot(t, s);
    const next = structuredClone(s);
    next.sequence = "1";
    next.outputOffset = "6";
    const event = delta(next, "0");
    mutate(event);
    assert.throws(() => applyDelta(t, event), ProjectionError);
    assert.throws(() => applyDelta(t, delta(next, "0")), ProjectionError);
    applySnapshot(t, next);
    setInputEnabled(t, true);
    t.dispose();
  }
});

test("input cannot be enabled by resize/event callbacks during incomplete projection", () => {
  const t = terminal(),
    s = snapshot();
  applySnapshot(t, s);
  setInputEnabled(t, true);
  let attempted = false;
  t.onResize(() => {
    attempted = true;
    assert.throws(() => setInputEnabled(t, true), ProjectionError);
  });
  const next = snapshot({
    cols: 10,
    rows: 4,
    sequence: "1",
    outputOffset: "1",
  });
  applyDelta(t, delta(next, "0"));
  assert(attempted);
  assert.equal(t._core.optionsService.options.disableStdin, true);
  setInputEnabled(t, true);
  t.dispose();
});
