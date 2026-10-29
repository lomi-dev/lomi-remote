# Experimental Rust-grid xterm renderer

This package projects `lomi-rust-grid-v1-experimental` version 1 structured state
into exactly **@xterm/xterm 6.0.0**. Rust owns PTY parsing and its partial
UTF-8/CSI/OSC/DCS state. The client applies cell/mode state and uses xterm for
rendering and input encoding. It does not restore a second output parser.

Consumers pin `@xterm/xterm` 6.0.0. This canonical renderer helper is shared by
the desktop, web and mobile clients; it contains no emulator or browser runtime.
`node_modules` is not part of the artifact.

## Consumer contract

Use a dedicated fresh xterm 6 terminal with no pending writes. For the browser,
call `terminal.open(element)` before projecting state, so palette effects have a
live theme service. Provide sufficient `scrollback` for the approved state.

```js
import {
  applySnapshot,
  applyDelta,
  setInputEnabled,
  installApplicationKeypadHook,
} from "@lomi/terminal-renderer-experimental";

applySnapshot(terminal, approvedSnapshot); // explicit attach/resync; resets
applyDelta(terminal, approvedDelta); // full state; preserves live view

const keypad = installApplicationKeypadHook(terminal, (intent) => {
  // Consumer must check session, focus, current control lease, and input limits
  // before forwarding this human-input intent. No I/O happens automatically.
  inputController.accept(intent);
});
setInputEnabled(terminal, hasCurrentControlLease);
// Later: setInputEnabled(terminal, false); keypad.dispose();
```

Every update first disables input. It becomes eligible for explicit enabling
only after schema, sequencing, bounds, grids, links, modes, title and palette
have been applied. Resize/event callbacks cannot enable input mid-projection.
An invalid update disables input and requires an explicit valid snapshot before
accepting further deltas. A snapshot is an explicit attach/resync boundary;
its authorized session identity and freshness must be checked by the consumer.
A delta must match the attached epoch, name the exact previous sequence,
advance by one canonical u64, and never regress the output offset.

The snapshot schema matches the Rust state's `Snapshot`; delta shape is:

```js
{
  profile: "lomi-rust-grid-v1-experimental", version: 1,
  sessionEpoch: "approved epoch", previousSequence: "41", state: snapshot42
}
```

Unknown/missing fields, malformed cells, orphan wide spacers, unsupported
profiles/modes, unsafe link schemes and out-of-bounds values reject the entire
update. Current bounds are rows 2–256, columns 2–512, 32,768 total cells across
both grids, 10,000 lines per buffer, 128 UTF-16 code units per cell, and 8 MiB
serialized state. Names/titles/links also have explicit string bounds. Sequences
and offsets are canonical decimal strings through u64::MAX. No clipboard field,
raw OSC, C0/C1 cell text, or OSC52 data is accepted. There is no fallback to raw
PTY replay. Public `write`/`writeln` and core write entry points throw after attach.
This is an API guard against accidental use, not a security boundary against
arbitrary JavaScript with access to private terminal internals.

## Rendering and input behavior

- Both normal and alternate grids are populated independently. Buffer activation
  bypasses xterm's ordinary switch functions, which would clear inactive data.
  Widths, combining text, continuation lines, saved/current cursor, all seven
  DTO flags, raw underline style/color, indexed/default/RGB colors and hyperlinks
  are projected directly.
- Hyperlink markers and the OscLinkService registry are rebuilt on each full
  state, with separate internal buffer namespaces and original public id/URI.
  Only absolute http, https and mailto links are currently supported. Other URI
  schemes reject state. URI activation policy still belongs to the consumer.
- Palette slots 0–255 and foreground/background/cursor slots 256–258 generate
  explicit xterm color SET/RESTORE events. These are never color queries and
  produce no PTY replies. Non-null Alacritty dim/bright overrides 259–268 reject
  state until resolved RGB rendering has been qualified.
- Application cursor/keypad, bracketed paste, focus, insertion, origin, wrapping,
  cursor visibility/style/blink and mouse tracking/encoding are synchronized
  before input can be enabled. xterm's normal data/binary input streams still
  need the consumer's human-input classification and control-lease admission.
- xterm 6 removed UTF8 mouse encoding. A bounded custom mode1005 encoder is
  installed with `CoreMouseService.addEncoding`, preserving xterm's tracking
  filters and event-code semantics. DEFAULT and SGR use xterm's built-ins.
- xterm 6 stores application-keypad mode but its browser encoder does not use it.
  The optional explicit hook emits human-input intents for unmodified numpad
  digits, decimal, divide/multiply/subtract/add, Enter and equal. Modified keys
  are deliberately unhandled by this hook. It never writes to a PTY, acquires a
  lease, or emits programmatic terminal replies. Disposal restores the previous
  custom key handler. These limited mappings are not complete keyboard-layout,
  IME, modifier, accessibility or mobile-keyboard qualification.
- Attach/resync resets. Live deltas do not reset. Same-buffer/dimension deltas
  preserve the numerical local scroll position; a selection remains only while
  its selected rows remain identical. Buffer/dimension changes or changed
  selected rows clear it. There is no logical history-line identity in the DTO,
  so preservation across eviction/reflow is limited. xterm markers/decorations
  are not preserved across full grid replacement.

## Runtime boundary

The adapter depends on the pinned xterm 6 internal service and buffer shapes
described above. It applies structured terminal state; it does not parse PTY bytes,
authorize control, or issue PTY input. Consumers must provide their own
authenticated connection, render acknowledgement, input classification, and
control-lease checks.

## Qualification boundaries

The adapter relies on private xterm 6 services, buffers, bit masks and events.
Shape checks reject missing internals; the exact package/lockfile pins are part
of the compatibility boundary. There is no runtime version-string API in xterm.
Upgrading, substituting builds or installing addons requires fresh review and
qualification. WebGL, canvas addons, other browsers, mobile platforms and
long-running stress behavior are not qualified.

xterm's hyperlink ExtendedAttrs exposes its own dashed-link underline appearance;
the raw requested underline metadata is retained, but this visual
override remains a compatibility limit. Font shaping, Unicode versions, color
rounding, dim/bold rendering and the Rust engine's original escape-sequence
semantics can still differ from an ordinary xterm PTY parser. Projection equality
proves agreement with structured Rust state, not arbitrary CLI compatibility or
interchangeable emulator behavior. The profile remains experimental.
