export const PROFILE = "lomi-rust-grid-v1-experimental";
export const LIMITS = Object.freeze({
  rows: 256,
  cols: 512,
  lines: 10000,
  cells: 32768,
  text: 128,
  title: 4096,
  uri: 4096,
});
export class ProjectionError extends Error {
  constructor(message) {
    super(message);
    this.name = "ProjectionError";
  }
}
export function check(ok, message) {
  if (!ok) throw new ProjectionError(message);
}
export function object(value, keys, name) {
  check(
    value !== null &&
      typeof value === "object" &&
      !Array.isArray(value) &&
      [Object.prototype, null].includes(Object.getPrototypeOf(value)),
    `${name}: expected object`,
  );
  const actual = Object.keys(value).sort();
  check(
    actual.length === keys.length &&
      actual.every((key, i) => key === [...keys].sort()[i]),
    `${name}: unknown/missing field`,
  );
}
const integer = (v, min, max, name) =>
  check(
    Number.isSafeInteger(v) && v >= min && v <= max,
    `${name}: integer out of bounds`,
  );
const boolean = (v, name) =>
  check(typeof v === "boolean", `${name}: expected boolean`);
const choice = (v, values, name) =>
  check(values.includes(v), `${name}: unsupported value`);
const text = (v, max, name) =>
  check(
    typeof v === "string" &&
      v.length <= max &&
      !/[\u0000-\u001f\u007f-\u009f\ud800-\udfff]/u.test(v),
    `${name}: invalid text`,
  );
export function u64(v, name) {
  check(
    typeof v === "string" && /^(0|[1-9][0-9]{0,19})$/.test(v) && !/[^0-9]/u.test(v),
    `${name}: expected canonical u64`,
  );
  const n = BigInt(v);
  check(n <= 18446744073709551615n, `${name}: overflow`);
  return n;
}
function rgb(value, name) {
  object(value, ["r", "g", "b"], name);
  for (const k of ["r", "g", "b"]) integer(value[k], 0, 255, `${name}.${k}`);
}
function color(value, name) {
  check(value !== null && typeof value === "object", `${name}: expected color`);
  if (value.kind === "default") object(value, ["kind"], name);
  else if (value.kind === "indexed") {
    object(value, ["kind", "index"], name);
    integer(value.index, 0, 255, name);
  } else {
    object(value, ["kind", "r", "g", "b"], name);
    choice(value.kind, ["rgb"], name);
    for (const k of ["r", "g", "b"]) integer(value[k], 0, 255, `${name}.${k}`);
  }
}
const FLAGS = ["bold", "dim", "italic", "inverse", "hidden", "strike", "blink"];
function cell(value, name) {
  object(
    value,
    [
      "text",
      "width",
      "fg",
      "bg",
      "flags",
      "underlineStyle",
      "underlineColor",
      "hyperlink",
    ],
    name,
  );
  text(value.text, LIMITS.text, `${name}.text`);
  integer(value.width, 0, 2, `${name}.width`);
  check(
    value.width !== 0 || value.text === "",
    `${name}: spacer contains text`,
  );
  color(value.fg, `${name}.fg`);
  color(value.bg, `${name}.bg`);
  check(
    Array.isArray(value.flags) &&
      value.flags.length <= FLAGS.length &&
      new Set(value.flags).size === value.flags.length,
    `${name}: invalid flags`,
  );
  for (const flag of value.flags) choice(flag, FLAGS, `${name}.flag`);
  integer(value.underlineStyle, 0, 5, `${name}.underlineStyle`);
  if (value.underlineColor !== null)
    color(value.underlineColor, `${name}.underlineColor`);
  if (value.hyperlink !== null) {
    object(value.hyperlink, ["id", "uri"], `${name}.hyperlink`);
    text(value.hyperlink.id, 1024, `${name}.link.id`);
    text(value.hyperlink.uri, LIMITS.uri, `${name}.link.uri`);
    check(
      /^(https?:|mailto:)/i.test(value.hyperlink.uri),
      `${name}: unsupported hyperlink URI scheme`,
    );
    try {
      new URL(value.hyperlink.uri);
    } catch {
      check(false, `${name}: invalid hyperlink URI`);
    }
  }
}
function buffer(value, snapshot, alternate, total) {
  object(value, ["lines", "baseY", "cursor", "savedCursor"], "buffer");
  integer(value.baseY, 0, LIMITS.lines - snapshot.rows, "buffer.baseY");
  check(!alternate || value.baseY === 0, "alternate buffer has scrollback");
  check(
    Array.isArray(value.lines) &&
      value.lines.length === value.baseY + snapshot.rows &&
      value.lines.length <= LIMITS.lines,
    "buffer: inconsistent line count",
  );
  total.count += value.lines.length * snapshot.cols;
  check(total.count <= LIMITS.cells, "snapshot exceeds cell limit");
  for (const cursor of [value.cursor, value.savedCursor]) {
    object(cursor, ["x", "y"], "cursor");
    integer(cursor.x, 0, snapshot.cols, "cursor.x");
    integer(cursor.y, 0, snapshot.rows - 1, "cursor.y");
  }
  for (const line of value.lines) {
    object(line, ["wrapped", "cells"], "line");
    boolean(line.wrapped, "line.wrapped");
    check(
      Array.isArray(line.cells) && line.cells.length === snapshot.cols,
      "line: wrong column count",
    );
    for (let x = 0; x < line.cells.length; x++) {
      const c = line.cells[x];
      cell(c, `cell[${x}]`);
      if (c.width === 2)
        check(
          x + 1 < snapshot.cols && line.cells[x + 1]?.width === 0,
          "wide cell lacks spacer",
        );
      if (c.width === 0)
        check(x > 0 && line.cells[x - 1]?.width === 2, "orphan spacer");
    }
  }
}
export function validateSnapshot(s) {
  object(
    s,
    [
      "profile",
      "version",
      "sessionEpoch",
      "sequence",
      "outputOffset",
      "rows",
      "cols",
      "active",
      "normal",
      "alternate",
      "modes",
      "title",
      "cursorStyle",
      "colors",
    ],
    "snapshot",
  );
  check(
    s.profile === PROFILE && s.version === 1,
    "unsupported terminal profile/version",
  );
  text(s.sessionEpoch, 128, "sessionEpoch");
  check(s.sessionEpoch.length > 0, "empty sessionEpoch");
  u64(s.sequence, "sequence");
  u64(s.outputOffset, "outputOffset");
  integer(s.rows, 2, LIMITS.rows, "rows");
  integer(s.cols, 2, LIMITS.cols, "cols");
  choice(s.active, ["normal", "alternate"], "active");
  const total = { count: 0 };
  buffer(s.normal, s, false, total);
  buffer(s.alternate, s, true, total);
  object(
    s.modes,
    [
      "applicationCursorKeys",
      "applicationKeypad",
      "bracketedPaste",
      "insert",
      "origin",
      "wraparound",
      "sendFocus",
      "cursorVisible",
      "mouseTracking",
      "mouseEncoding",
    ],
    "modes",
  );
  for (const [key, value] of Object.entries(s.modes))
    if (!key.startsWith("mouse")) boolean(value, `modes.${key}`);
  choice(
    s.modes.mouseTracking,
    ["none", "x10", "vt200", "drag", "any"],
    "mouseTracking",
  );
  choice(s.modes.mouseEncoding, ["default", "utf8", "sgr"], "mouseEncoding");
  if (s.title !== null) text(s.title, LIMITS.title, "title");
  object(s.cursorStyle, ["shape", "blinking"], "cursorStyle");
  choice(
    s.cursorStyle.shape,
    ["block", "underline", "bar"],
    "cursorStyle.shape",
  );
  boolean(s.cursorStyle.blinking, "cursorStyle.blinking");
  check(
    Array.isArray(s.colors) && s.colors.length === 269,
    "colors: expected 269 entries",
  );
  s.colors.forEach((c, i) => {
    if (c !== null) {
      check(i <= 258, "unsupported dim/bright palette override");
      rgb(c, `colors[${i}]`);
    }
  });
  check(
    new TextEncoder().encode(JSON.stringify(s)).byteLength <= 8 * 1024 * 1024,
    "snapshot exceeds 8 MiB",
  );
  return s;
}
export function validateDelta(delta) {
  object(
    delta,
    ["profile", "version", "sessionEpoch", "previousSequence", "state"],
    "delta",
  );
  check(
    delta.profile === PROFILE && delta.version === 1,
    "unsupported delta profile/version",
  );
  u64(delta.previousSequence, "previousSequence");
  validateSnapshot(delta.state);
  check(
    delta.sessionEpoch === delta.state.sessionEpoch,
    "delta epoch mismatch",
  );
  return delta;
}

// Production patches carry structured cells, never terminal escape sequences.
// Validate retained topology and bounded runs before allocating a candidate grid.
export function projectPatch(previous, patch) {
  validateSnapshot(previous);
  object(patch, ["profile", "version", "format", "sessionEpoch", "previousSequence", "sequence", "outputOffset", "rows", "cols", "update"], "patch");
  check(patch.profile === PROFILE && patch.version === 1 && patch.format === "grid-patch-v1", "unsupported grid patch");
  check(typeof patch.sessionEpoch === "string" && patch.sessionEpoch.length === 36 && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(patch.sessionEpoch) && patch.sessionEpoch.replaceAll("-", "") !== "0".repeat(32), "invalid patch epoch");
  check(patch.sessionEpoch === previous.sessionEpoch && patch.profile === previous.profile && patch.version === previous.version, "stale patch context");
  const seq = u64(patch.previousSequence, "previousSequence");
  check(seq === u64(previous.sequence, "sequence") && u64(patch.sequence, "sequence") === seq + 1n, "noncontiguous patch sequence");
  check(u64(patch.outputOffset, "outputOffset") >= u64(previous.outputOffset, "outputOffset"), "patch output offset regressed");
  integer(patch.rows, 2, LIMITS.rows, "patch.rows");
  integer(patch.cols, 2, LIMITS.cols, "patch.cols");
  check(patch.rows === previous.rows && patch.cols === previous.cols, "patch geometry mismatch");
  check(new TextEncoder().encode(JSON.stringify(patch)).byteLength <= 8 * 1024 * 1024, "patch exceeds 8 MiB");
  const update = patch.update;
  check(update !== null && typeof update === "object", "missing patch update");
  if (update.kind === "checkpoint") {
    object(update, ["kind", "state"], "checkpoint");
    validateSnapshot(update.state);
    check(update.state.sessionEpoch === patch.sessionEpoch && update.state.sequence === patch.sequence && update.state.outputOffset === patch.outputOffset, "checkpoint envelope mismatch");
    return update.state;
  }
  object(update, ["kind", "metadata", "normal", "alternate"], "sparse");
  choice(update.kind, ["sparse"], "patch.kind");
  object(update.metadata, ["active", "modes", "title", "cursorStyle", "colors"], "patch metadata");
  const budget = 8 * 1024 * 1024;
  const encodedBytes = value => new TextEncoder().encode(JSON.stringify(value)).byteLength;
  const emptyBuffer = change => ({ lines: [], baseY: change.baseY, cursor: change.cursor, savedCursor: change.savedCursor });
  // Empty lists include their brackets. Count row/cell payload and commas below
  // before allocating replacement rows or cloning any repeated cell strings.
  let prospectiveBytes = encodedBytes({ ...previous, ...update.metadata, normal: emptyBuffer(update.normal), alternate: emptyBuffer(update.alternate), sequence: patch.sequence, outputOffset: patch.outputOffset });
  check(prospectiveBytes <= budget, "expanded snapshot exceeds 8 MiB");
  const cellBytes = new WeakMap();
  function cellSize(value) {
    if (!cellBytes.has(value)) cellBytes.set(value, encodedBytes(value));
    return cellBytes.get(value);
  }
  let totalCells = 0;
  function plan(change, old, alternate) {
    object(change, ["baseY", "lineCount", "previousBaseY", "previousLineCount", "retainedStart", "retainedLines", "cursor", "savedCursor", "rows"], "buffer patch");
    for (const key of ["baseY", "previousBaseY"])
      integer(change[key], 0, 4096, key);
    check(!alternate || (change.baseY === 0 && change.previousBaseY === 0), "alternate history forbidden");
    integer(change.lineCount, patch.rows, LIMITS.cells, "lineCount");
    integer(change.previousLineCount, patch.rows, LIMITS.cells, "previousLineCount");
    check(change.lineCount === change.baseY + patch.rows && change.previousLineCount === change.previousBaseY + patch.rows, "patch line count mismatch");
    check(change.previousBaseY === old.baseY && change.previousLineCount === old.lines.length, "stale retained buffer");
    totalCells += change.lineCount * patch.cols;
    check(totalCells <= LIMITS.cells && change.previousLineCount * patch.cols <= LIMITS.cells, "patch exceeds cell budget");
    integer(change.retainedStart, 0, change.previousLineCount, "retainedStart");
    integer(change.retainedLines, 0, Math.min(change.previousLineCount - change.retainedStart, change.lineCount), "retainedLines");
    for (const cursor of [change.cursor, change.savedCursor]) {
      object(cursor, ["x", "y"], "patch cursor");
      integer(cursor.x, 0, patch.cols, "cursor.x");
      integer(cursor.y, 0, patch.rows - 1, "cursor.y");
    }
    check(Array.isArray(change.rows) && change.rows.length <= change.lineCount, "invalid changed rows");
    let previousRow = -1, appended = change.retainedLines;
    const changedBytes = new Map();
    for (const row of change.rows) {
      object(row, ["index", "wrapped", "cells"], "row patch");
      integer(row.index, previousRow + 1, change.lineCount - 1, "row index");
      previousRow = row.index;
      boolean(row.wrapped, "row.wrapped");
      const added = row.index >= change.retainedLines;
      if (added)
        check(row.index === appended++, "missing appended row");
      check(Array.isArray(row.cells) && row.cells.length <= patch.cols, "invalid changed cells");
      let end = 0;
      for (const run of row.cells) {
        object(run, ["index", "repeat", "cell"], "cell run");
        integer(run.index, end, patch.cols - 1, "cell index");
        integer(run.repeat, 1, patch.cols - run.index, "cell repeat");
        check(!added || run.index === end, "appended row has holes");
        end = run.index + run.repeat;
        cell(run.cell, "patch cell");
      }
      check(!added || end === patch.cols, "incomplete appended row");
      // Inspect the effective row through borrowed cells before cloning it.
      let runIndex = 0;
      const effective = [];
      for (let x = 0; x < patch.cols; x++) {
        while (runIndex < row.cells.length && row.cells[runIndex].index + row.cells[runIndex].repeat <= x)
          runIndex++;
        const run = row.cells[runIndex];
        effective.push(run && run.index <= x ? run.cell : old.lines[change.retainedStart + row.index].cells[x]);
      }
      let rowBytes = encodedBytes({ wrapped: row.wrapped, cells: [] }) + patch.cols - 1;
      for (let x = 0; x < patch.cols; x++) {
        const c = effective[x];
        rowBytes += cellSize(c);
        check(rowBytes <= budget, "expanded row exceeds 8 MiB");
        check(c.width !== 2 || (x + 1 < patch.cols && effective[x + 1].width === 0), "wide patch cell lacks spacer");
        check(c.width !== 0 || (c.text === "" && x > 0 && effective[x - 1].width === 2), "orphan patch spacer");
      }
      changedBytes.set(row.index, rowBytes);
    }
    check(appended === change.lineCount, "missing appended rows");
    prospectiveBytes += change.lineCount - 1;
    for (let y = 0; y < change.lineCount; y++) {
      prospectiveBytes += changedBytes.get(y) ?? encodedBytes(old.lines[change.retainedStart + y]);
      check(prospectiveBytes <= budget, "expanded snapshot exceeds 8 MiB");
    }
    return () => {
      const lines = old.lines.slice(change.retainedStart, change.retainedStart + change.retainedLines);
      for (const row of change.rows) {
        const cells = row.index < change.retainedLines ? [...lines[row.index].cells] : Array(patch.cols);
        for (const run of row.cells)
          for (let x = run.index; x < run.index + run.repeat; x++)
            cells[x] = run.cell;
        lines[row.index] = { wrapped: row.wrapped, cells };
      }
      return { lines, baseY: change.baseY, cursor: change.cursor, savedCursor: change.savedCursor };
    };
  }
  const normal = plan(update.normal, previous.normal, false), alternate = plan(update.alternate, previous.alternate, true);
  const next = { ...previous, ...update.metadata, normal: normal(), alternate: alternate(), sequence: patch.sequence, outputOffset: patch.outputOffset };
  validateSnapshot(next);
  return next;
}
