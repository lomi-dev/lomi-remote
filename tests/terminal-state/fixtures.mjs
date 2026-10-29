import headless from "../../packages/terminal-renderer/node_modules/@xterm/headless/lib-headless/xterm-headless.js";
import { PROFILE } from "../../packages/terminal-renderer/src/index.mjs";
export const terminal = (cols = 8, rows = 3) =>
  new headless.Terminal({
    cols,
    rows,
    scrollback: 100,
    allowProposedApi: true,
  });
export const blank = (overrides = {}) => ({
  text: "",
  width: 1,
  fg: { kind: "default" },
  bg: { kind: "default" },
  flags: [],
  underlineStyle: 0,
  underlineColor: null,
  hyperlink: null,
  ...overrides,
});
export const line = (cols, text = "", wrapped = false) => ({
  wrapped,
  cells: Array.from({ length: cols }, (_, i) =>
    blank({ text: [...text][i] ?? "" }),
  ),
});
export const buffer = (cols, rows) => ({
  lines: Array.from({ length: rows }, () => line(cols)),
  baseY: 0,
  cursor: { x: 0, y: 0 },
  savedCursor: { x: 0, y: 0 },
});
export function snapshot({ cols = 8, rows = 3, ...overrides } = {}) {
  return {
    profile: PROFILE,
    version: 1,
    sessionEpoch: "fixture-session",
    sequence: "0",
    outputOffset: "0",
    rows,
    cols,
    active: "normal",
    normal: buffer(cols, rows),
    alternate: buffer(cols, rows),
    modes: {
      applicationCursorKeys: false,
      applicationKeypad: false,
      bracketedPaste: false,
      insert: false,
      origin: false,
      wraparound: true,
      sendFocus: false,
      cursorVisible: true,
      mouseTracking: "none",
      mouseEncoding: "default",
    },
    title: null,
    cursorStyle: { shape: "block", blinking: false },
    colors: Array(269).fill(null),
    ...overrides,
  };
}
export const delta = (state, previousSequence) => ({
  profile: PROFILE,
  version: 1,
  sessionEpoch: state.sessionEpoch,
  previousSequence,
  state,
});
export function inspect(t) {
  const buffers = t._core._bufferService.buffers;
  function grid(b) {
    return {
      baseY: b.ybase,
      cursor: { x: b.x, y: b.y },
      savedCursor: { x: b.savedX, y: b.savedY },
      lines: Array.from({ length: b.lines.length }, (_, y) => {
        const l = b.lines.get(y);
        return {
          wrapped: l.isWrapped,
          cells: Array.from({ length: t.cols }, (_, x) => {
            const c = l.loadCell(x, b.getNullCell());
            const ext = l._extendedAttrs[x];
            return {
              text: c.getChars(),
              width: c.getWidth(),
              fg: c.fg,
              bg: c.bg,
              underlineStyle: ext ? (ext._ext & 0x1c000000) >>> 26 : 0,
              underlineColor: ext?.underlineColor ?? null,
              hyperlink: ext?.urlId
                ? t._core._oscLinkService.getLinkData(ext.urlId)
                : null,
            };
          }),
        };
      }),
    };
  }
  return {
    rows: t.rows,
    cols: t.cols,
    active: buffers.active === buffers.normal ? "normal" : "alternate",
    normal: grid(buffers.normal),
    alternate: grid(buffers.alt),
  };
}
export const write = (t, data) =>
  new Promise((resolve) => t.write(data, resolve));
