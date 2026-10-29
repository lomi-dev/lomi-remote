import {
  PROFILE,
  ProjectionError,
  check,
  validateSnapshot,
  validateDelta,
  projectPatch,
  u64,
  object,
} from "./schema.mjs";
export {
  PROFILE,
  ProjectionError,
  LIMITS,
  validateSnapshot,
} from "./schema.mjs";
export const XTERM_VERSION = "6.0.0";
/** Shared privacy policy for clients that install xterm parser handlers. */
export function installTerminalProfile(terminal) {
  return [8, 4, 10, 11, 12, 104, 110, 111, 112].map((id) =>
    terminal.parser.registerOscHandler(id, () => true),
  );
}
const attached = new WeakMap();
const FG = {
  inverse: 0x4000000,
  bold: 0x8000000,
  blink: 0x20000000,
  hidden: 0x40000000,
  strike: 0x80000000,
};
const BG = { italic: 0x4000000, dim: 0x8000000 };
const TRACKING = {
  none: "NONE",
  x10: "X10",
  vt200: "VT200",
  drag: "DRAG",
  any: "ANY",
};
const colorBits = (c) =>
  c.kind === "default"
    ? 0
    : c.kind === "indexed"
      ? 0x2000000 | c.index
      : 0x3000000 | (c.r << 16) | (c.g << 8) | c.b;
function internals(t) {
  const c = t?._core,
    b = c?._bufferService,
    h = c?._inputHandler,
    l = c?._oscLinkService,
    m = c?.coreMouseService;
  check(
    typeof t?.reset === "function" &&
      typeof t.resize === "function" &&
      c &&
      b?.buffers &&
      c.coreService?.decPrivateModes &&
      c.optionsService?.rawOptions,
    "unsupported xterm 6 terminal shape",
  );
  if (typeof c.open === "function")
    check(
      c._themeService && c._renderService,
      "browser terminal must be opened before projection",
    );
  for (const buf of [b.buffers.normal, b.buffers.alt])
    check(
      typeof buf?.getBlankLine === "function" &&
        typeof buf.getNullCell === "function" &&
        typeof buf.clearAllMarkers === "function" &&
        typeof buf.lines?.set === "function",
      "unsupported xterm buffer shape",
    );
  check(
    typeof b.buffers._onBufferActivate?.fire === "function" &&
      typeof b._onScroll?.fire === "function" &&
      typeof h?._onTitleChange?.fire === "function" &&
      typeof h._onColor?.fire === "function" &&
      typeof h._onRequestRefreshRows?.fire === "function" &&
      typeof h._onCursorMove?.fire === "function",
    "unsupported xterm event shape",
  );
  check(
    l?._entriesWithId instanceof Map &&
      l._dataByLinkId instanceof Map &&
      typeof l.registerLink === "function" &&
      typeof l.addLineToLink === "function" &&
      typeof l.getLinkData === "function",
    "unsupported xterm hyperlink shape",
  );
  check(
    typeof m?.addEncoding === "function" &&
      ["NONE", "X10", "VT200", "DRAG", "ANY"].every((k) => m._protocols?.[k]) &&
      m._encodings?.DEFAULT &&
      m._encodings?.SGR,
    "unsupported xterm mouse shape",
  );
  check(
    c._writeBuffer?._pendingData === 0 && !c._writeBuffer._isSyncWriting,
    "queued PTY writes are forbidden",
  );
  return c;
}
function disable(t) {
  const options = t?._core?.optionsService?.options;
  if (options && typeof options === "object") options.disableStdin = true;
}
function fail(t, error) {
  disable(t);
  attached.delete(t);
  throw error;
}
// xterm6 removed mode1005. Register a bounded UTF8 encoder using the same event
// code semantics as its DEFAULT encoder, after xterm's tracking/modifier filter.
function utf8Mouse(e) {
  let code = (e.ctrl ? 16 : 0) | (e.shift ? 4 : 0) | (e.alt ? 8 : 0);
  if (e.button === 4) code |= 64 | e.action;
  else {
    code |= e.button & 3;
    if (e.button & 4) code |= 64;
    if (e.button & 8) code |= 128;
    if (e.action === 32) code |= 32;
    else if (e.action === 0) code |= 3;
  }
  const params = [code + 32, e.col + 32, e.row + 32];
  check(
    params.every((v) => Number.isInteger(v) && v >= 32 && v <= 2047),
    "UTF8 mouse coordinate out of bounds",
  );
  return "\x1b[M" + String.fromCodePoint(...params);
}
function encodeCell(buffer, cell, linkId) {
  const result = new (buffer.getNullCell().constructor)();
  result.setFromCharData([0, cell.text, cell.width, 0]);
  result.fg = colorBits(cell.fg);
  result.bg = colorBits(cell.bg);
  for (const flag of cell.flags) {
    if (FG[flag]) result.fg |= FG[flag];
    if (BG[flag]) result.bg |= BG[flag];
  }
  if (cell.underlineStyle) result.fg |= 0x10000000;
  result.extended.underlineStyle = cell.underlineStyle;
  result.extended.underlineColor =
    cell.underlineColor === null ? 0 : colorBits(cell.underlineColor);
  result.extended.urlId = linkId;
  // underline-color alone also requires extended attributes to survive setCell.
  if (cell.underlineStyle || cell.underlineColor !== null || linkId)
    result.bg |= 0x10000000;
  return result;
}
function project(t, s, isSnapshot, previous) {
  let c = internals(t);
  check(
    s.normal.baseY <= c.optionsService.rawOptions.scrollback,
    "xterm scrollback capacity too small",
  );
  if (isSnapshot) {
    t.reset();
    c = internals(t);
  }
  const b = c._bufferService,
    buffers = b.buffers;
  const oldActive = b.buffer,
    oldScroll = oldActive.ydisp,
    wasAtBottom = oldScroll === oldActive.ybase;
  const sameDimensions = t.cols === s.cols && t.rows === s.rows;
  const selection = t.getSelectionPosition?.();
  const sameActive =
    (s.active === "normal" ? buffers.normal : buffers.alt) === oldActive;
  let selectionPreserved = !isSnapshot && sameDimensions && sameActive;
  if (selection && selectionPreserved) {
    const before = previous[s.active].lines;
    const after = s[s.active].lines;
    for (let y = selection.start.y; y <= selection.end.y; y++) {
      if (JSON.stringify(before[y]) !== JSON.stringify(after[y]))
        selectionPreserved = false;
    }
  }
  if (!selectionPreserved) t.clearSelection?.();
  // Disable input across reset/resize, which may fire consumer callbacks.
  disable(t);
  if (!sameDimensions) t.resize(s.cols, s.rows);
  check(
    buffers.normal.lines.maxLength >= s.normal.lines.length,
    "xterm scrollback capacity too small",
  );
  const links = c._oscLinkService;
  buffers.normal.clearAllMarkers();
  buffers.alt.clearAllMarkers();
  links._entriesWithId.clear();
  links._dataByLinkId.clear();
  links._nextId = 1;
  for (const [name, data] of [
    ["normal", s.normal],
    ["alt", s.alternate],
  ]) {
    const target = buffers[name];
    // Register hyperlinks on the correct buffer/absolute row. Distinct buffer
    // namespaces avoid xterm's id+URI deduplication sharing markers across grids.
    buffers._activeBuffer = target;
    target.lines.length = data.lines.length;
    target.ybase = data.baseY;
    target.scrollTop = 0;
    target.scrollBottom = s.rows - 1;
    for (let y = 0; y < data.lines.length; y++) {
      target.y = y - data.baseY;
      const line = target.getBlankLine(
        target.getNullCell(),
        data.lines[y].wrapped,
      );
      for (let x = 0; x < s.cols; x++) {
        const cell = data.lines[y].cells[x];
        let linkId = 0;
        if (cell.hyperlink) {
          linkId = links.registerLink({
            id: `${name}:${cell.hyperlink.id}`,
            uri: cell.hyperlink.uri,
          });
          links.getLinkData(linkId).id = cell.hyperlink.id;
        }
        line.setCell(x, encodeCell(target, cell, linkId));
      }
      target.lines.set(y, line);
    }
    target.x = data.cursor.x;
    target.y = data.cursor.y;
    target.savedX = data.savedCursor.x;
    target.savedY = data.savedCursor.y;
    target.ydisp = isSnapshot
      ? target.ybase
      : target === oldActive && !wasAtBottom
        ? Math.min(oldScroll, target.ybase)
        : target.ybase;
  }
  const active = s.active === "normal" ? buffers.normal : buffers.alt;
  buffers._activeBuffer = active;
  if (isSnapshot || oldActive !== active)
    buffers._onBufferActivate.fire({
      activeBuffer: active,
      inactiveBuffer: active === buffers.normal ? buffers.alt : buffers.normal,
    });
  // Force handler's cached active buffer to agree even though no parsing occurs.
  c._inputHandler._activeBuffer = active;
  b.isUserScrolling = active.ydisp !== active.ybase;
  const mode = c.coreService.decPrivateModes;
  Object.assign(mode, {
    applicationCursorKeys: s.modes.applicationCursorKeys,
    applicationKeypad: s.modes.applicationKeypad,
    bracketedPasteMode: s.modes.bracketedPaste,
    origin: s.modes.origin,
    wraparound: s.modes.wraparound,
    sendFocus: s.modes.sendFocus,
    cursorStyle: s.cursorStyle.shape,
    cursorBlink: s.cursorStyle.blinking,
  });
  c.coreService.modes.insertMode = s.modes.insert;
  c.coreService.isCursorHidden = !s.modes.cursorVisible;
  c.coreService.isCursorInitialized = true;
  c.coreMouseService.addEncoding("LOMI_UTF8", utf8Mouse);
  c.coreMouseService.activeProtocol = TRACKING[s.modes.mouseTracking];
  c.coreMouseService.activeEncoding = {
    default: "DEFAULT",
    utf8: "LOMI_UTF8",
    sgr: "SGR",
  }[s.modes.mouseEncoding];
  c.coreMouseService._lastEvent = null;
  const paletteChanges = [];
  for (let i = 0; i <= 258; i++) {
    if (
      isSnapshot ||
      JSON.stringify(previous?.colors[i]) !== JSON.stringify(s.colors[i])
    ) {
      const rgb = s.colors[i];
      paletteChanges.push(
        rgb === null
          ? { type: 2, index: i }
          : { type: 1, index: i, color: [rgb.r, rgb.g, rgb.b] },
      );
    }
  }
  // These are explicit set/restore effects, never OSC input or color queries.
  if (paletteChanges.length) c._inputHandler._onColor.fire(paletteChanges);
  c._inputHandler._windowTitle = s.title ?? "";
  if (isSnapshot || s.title !== previous?.title)
    c._inputHandler._onTitleChange.fire(s.title ?? "");
  b._onScroll.fire(active.ydisp);
  c._inputHandler._onCursorMove.fire();
  c._inputHandler._onRequestRefreshRows.fire({ start: 0, end: s.rows - 1 });
  return {
    paletteChanges,
    title: s.title,
    selectionPreserved,
  };
}
function guardRawWrites(t) {
  const reject = () => {
    throw new ProjectionError(
      "raw PTY writes are forbidden for structured renderer",
    );
  };
  t.write = reject;
  t.writeln = reject;
  t._core.write = reject;
  t._core.writeSync = reject;
}
export function applySnapshot(t, s) {
  disable(t);
  attached.delete(t);
  try {
    const state = structuredClone(s);
    validateSnapshot(state);
    internals(t);
    const effects = project(t, state, true);
    guardRawWrites(t);
    attached.set(t, { state, ready: true });
    return effects;
  } catch (error) {
    return fail(t, error);
  }
}
export function applyDelta(t, delta) {
  disable(t);
  try {
    const previous = attached.get(t);
    attached.delete(t);
    check(previous?.ready, "snapshot required before delta");
    delta = structuredClone(delta);
    validateDelta(delta);
    check(
      delta.sessionEpoch === previous.state.sessionEpoch,
      "stale session epoch",
    );
    const sequence = u64(previous.state.sequence, "sequence");
    check(
      u64(delta.previousSequence, "previousSequence") === sequence &&
        u64(delta.state.sequence, "sequence") === sequence + 1n,
      "noncontiguous sequence",
    );
    check(
      u64(delta.state.outputOffset, "outputOffset") >=
        u64(previous.state.outputOffset, "outputOffset"),
      "output offset regressed",
    );
    internals(t);
    const effects = project(t, delta.state, false, previous.state);
    attached.set(t, { state: structuredClone(delta.state), ready: true });
    return effects;
  } catch (error) {
    return fail(t, error);
  }
}
export function applyPatch(t, patch) {
  disable(t);
  try {
    const previous = attached.get(t);
    attached.delete(t);
    check(previous?.ready, "snapshot required before patch");
    const state = structuredClone(projectPatch(previous.state, patch));
    internals(t);
    const effects = project(t, state, false, previous.state);
    attached.set(t, { state, ready: true });
    return effects;
  }
  catch (error) {
    return fail(t, error);
  }
}

/** Apply an authenticated, assembled control event that advances the host grid
 * sequence without changing cells. The transport must first validate the full
 * terminal/subscription context. Resize and arbitrary sequence jumps require a
 * real grid patch or a new snapshot; they are never accepted as no-op events.
 */
export function advanceStream(t, event) {
  disable(t);
  try {
    const previous = attached.get(t);
    attached.delete(t);
    check(previous?.ready, "snapshot required before stream event");
    object(event, ["kind", "sessionEpoch", "previousSequence", "sequence"], "stream event");
    check(event.kind === "controlChanged", "unsupported no-op stream event");
    check(event.sessionEpoch === previous.state.sessionEpoch, "stale session epoch");
    const sequence = u64(previous.state.sequence, "sequence");
    check(u64(event.previousSequence, "previousSequence") === sequence
      && u64(event.sequence, "sequence") === sequence + 1n,
    "noncontiguous sequence");
    internals(t);
    attached.set(t, { state: { ...previous.state, sequence: event.sequence }, ready: true });
    return { paletteChanges: [], title: previous.state.title, selectionPreserved: true };
  } catch (error) {
    return fail(t, error);
  }
}
export function setInputEnabled(t, enabled) {
  disable(t);
  check(typeof enabled === "boolean", "input enabled must be boolean");
  if (!enabled) {
    disable(t);
    return;
  }
  check(
    attached.get(t)?.ready,
    "validated snapshot/delta required before input",
  );
  internals(t);
  t._core.optionsService.options.disableStdin = false;
}

const keypadHooks = new WeakMap();
const KEYPAD = {
  Numpad0: "p",
  Numpad1: "q",
  Numpad2: "r",
  Numpad3: "s",
  Numpad4: "t",
  Numpad5: "u",
  Numpad6: "v",
  Numpad7: "w",
  Numpad8: "x",
  Numpad9: "y",
  NumpadDecimal: "n",
  NumpadDivide: "o",
  NumpadMultiply: "j",
  NumpadSubtract: "m",
  NumpadAdd: "k",
  NumpadEnter: "M",
  NumpadEqual: "X",
};
/** Optional unmodified DEC application-keypad human-input intent hook.
 * The consumer must authorize/control-lease-check every intent before PTY I/O.
 * Nothing is automatically sent to onData or to the host by this hook.
 */
export function installApplicationKeypadHook(t, emitIntent) {
  internals(t);
  check(
    typeof t.attachCustomKeyEventHandler === "function" &&
      typeof emitIntent === "function",
    "browser keypad hook requires terminal and intent consumer",
  );
  check(!keypadHooks.has(t), "keypad hook already installed");
  const core = t._core,
    previous = core._customKeyEventHandler;
  const handler = (event) => {
    if (previous && previous(event) === false) return false;
    const current = attached.get(t),
      final = KEYPAD[event.code];
    if (
      event.type !== "keydown" ||
      !final ||
      event.location !== 3 ||
      event.shiftKey ||
      event.ctrlKey ||
      event.altKey ||
      event.metaKey
    )
      return true;
    if (
      !current?.ready ||
      !current.state.modes.applicationKeypad ||
      core.optionsService.rawOptions.disableStdin
    )
      return true;
    event.preventDefault();
    event.stopPropagation();
    emitIntent({
      kind: "human-input",
      inputType: "application-keypad",
      data: "\x1bO" + final,
      sessionEpoch: current.state.sessionEpoch,
      sequence: current.state.sequence,
    });
    return false;
  };
  t.attachCustomKeyEventHandler(handler);
  keypadHooks.set(t, handler);
  let disposed = false;
  return {
    dispose() {
      if (disposed) return;
      disposed = true;
      if (core._customKeyEventHandler === handler)
        core._customKeyEventHandler = previous;
      keypadHooks.delete(t);
    },
  };
}
