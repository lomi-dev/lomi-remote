# S0.1 terminal qualification experiment

This harness **rejects** the stock `vt100=0.16.2` ANSI snapshot candidate.
Passing regression tests means known observations remain reproducible. It does
not mean S0.1 passed. No production terminal profile is defined here.

From the repository root:

```sh
cargo test -p lomi-terminal-spike
cargo run -p lomi-terminal-spike -- report
cargo run -p lomi-terminal-spike -- qualify # expected exit 1
npm ci --prefix tests/terminal --ignore-scripts
npm test --prefix tests/terminal
npm run qualify --prefix tests/terminal # expected exit 1
```

The Rust executable owns the candidate model and emits synthetic fixtures and
reset + `Screen::state_formatted()` restore bytes. The development-only Node
oracle feeds the original chunks to pinned `@xterm/headless=6.0.0`, separately
feeds the candidate checkpoint to a fresh xterm, then compares both buffers,
cell text/width/common attributes, cursor, scrollback, modes and title before
and after identical live continuation and resize. Only case identifiers and
booleans appear in evidence; there are no captured user transcripts or secrets.
The fixtures command emits synthetic bytes for the local oracle only.

The bounded replay fixture processes 2,000 synthetic lines into an eight-line
scrollback model. Restore uses the model formatter, with **no prefix replay**.
This checks behavior after replay is discarded; it is not a multi-hour soak.
The stock formatter exports the active screen, not a complete checkpoint. Inactive
buffers, parser continuation, saved cursor, origin/scroll regions, hyperlinks,
scrollback and resize/reflow require independent handling; a visible-text match
is insufficient. New candidate implementations must change this explicit
experimental profile rather than silently adding unlimited replay.

The Alacritty probe constructs its actual Rust terminal model, enters alternate
screen and returns to preserved normal content. It is **unqualified**: no
Alacritty-to-xterm serializer or pending-parser adapter is implemented. The probe
only establishes that a model exists, not that its internal state is exportable.
Relevant inspected sources are the pinned Cargo registry packages:
`vt100/src/screen.rs` (`state_formatted`), `vt100/src/parser.rs`,
`alacritty_terminal/src/term/mod.rs`, and `vte/src/ansi.rs` (`Processor`).

The xterm query probe verifies actual DSR/DA replies and an output-only observer
filter. It does not establish production host response ownership. Real shell,
vim/less/top/tmux fixtures, long soak, every terminal mode/attribute, pending
string/control states, OSC 52 side effects, hyperlink internals and production
multi-observer response routing remain unqualified. These are blockers, not
optional skipped success cases. Full hidden parser-state equality cannot be
proved through the xterm public buffer API.

No Node package or runtime is required by the Rust executable. The npm lockfile
and package are local to this development oracle; they import no sibling app.

Recorded on macOS aarch64 with rustc 1.98.1 and Node v22.22.3:

| Comparison | Matching cases | Rejected cases | Qualification |
| --- | ---: | ---: | --- |
| Native active formatter | 6 | 7 | rejected |
| Actual xterm checkpoint + continuation | 3 | 10 | rejected |

`native-observations.json` and `xterm-observations.json` contain the observed
machine-readable results. Native equality misses several xterm incompatibilities,
which is why the native result cannot substitute for the oracle. Four Rust
regression tests and the Node regression assert their complete expected case
outcomes. Both qualification commands return status 1.
