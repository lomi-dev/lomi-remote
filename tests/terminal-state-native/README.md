# Experimental authoritative Rust terminal evidence

Run `cargo test -p lomi-terminal-state` and
`cargo clippy -p lomi-terminal-state --all-targets -- -D warnings`.
Emit compact structured projection fixtures with
`cargo run -q -p lomi-terminal-state --bin state-fixtures`.
The companion `tests/terminal-state/rust-oracle.mjs` consumes that JSON.

The native tests attach by taking repeated snapshots at every byte cut of
UTF-8, CSI, OSC, DCS, hyperlink, and actual colored `git diff --no-index`
output, continue the same host parser, then compare with uninterrupted state.
The CLI capture runs local Git on temporary synthetic files; it is neither
an interactive PTY capture nor evidence for arbitrary CLI compatibility.
The emitter includes 24 synthetic scenarios plus a bytewise parser stream.
Raw DEC mode 47 is unsupported by Alacritty 0.26; the alternate-buffer tests
use 1049 and do not assert equality with the original raw-xterm fixture.

Only Rust receives raw output. Attach has no side effects, parser reset, replay,
clipboard access, or response generation. A full-state delta is one ordered
feed/resize event; snapshots themselves do not advance the sequence. Output
length is the canonical decimal count of accepted PTY bytes, including pending
parser bytes. Resize advances the sequence without advancing output offset.
The host must atomically snapshot and subscribe while serializing feed/resize;
this prototype is a single-owner in-memory model, not a transport implementation.

Bounds: 2..256 rows, 2..512 columns, at most 4096 history rows and 32768 total
cells across both buffers, 64KiB per output chunk, conservative 8MiB projected
cell expansion budget plus exact 8MiB serialized snapshot limit. Crossing the
cell budget faults the wrapper and rejects further feed/resize. The triggering
chunk has already been parsed and must not be retried. Reply queues hold at
most 64 messages / 8192 bytes; overflow drops replies and increments a counter.
DSR/DA are generated once on the host. Unset color queries use deterministic
16-color/cube/grayscale defaults, foreground/cursor 229 and background 0;
text-size queries use qualified 8x16 logical cells, not measured client pixels.
Explicit palette colors are resolved synchronously by the vendored engine.
OSC52 and kitty keyboard are disabled. No event payload or secret is logged.

Real interactive Vim PTYs have separate macOS and Linux evidence in
`tests/terminal-pty` and `artifacts/terminal-linux/evidence.json` respectively.
This is a bounded CLI check, not arbitrary interactive-application coverage.

Not qualified: multi-hour soak, all input encodings, all platform PTYs,
transport attach atomicity, process recovery after host restart,
renderer library upgrades, or arbitrary equivalence with raw xterm parsing.

The vendored profile also bounds OSC accumulation to 64KiB and discards the
whole overflowing OSC; titles to 4096 bytes (oversize ignored), title stacks to
64 entries, hyperlink URI to 2048 bytes and explicit IDs to 256 bytes (oversize
links disabled), and combining marks to 64 per cell (extra marks ignored).
These are declared compatibility limits, not truncation hidden as full fidelity.
Dependency `log` macros compile out through `max_level_off`, preventing upstream
parser/terminal diagnostics from emitting PTY text or title-stack payloads.
Structured host counters contain no payloads. Colors above indexed 255 and
palette slots 259..268 are rejected pending a supported renderer mapping.

Projection follows the renderer's text rules: lengths count UTF-16 code units
(cell text 128, title 4096, hyperlink ID 1024, URI 4096), C0/C1 controls are
forbidden, and Rust strings cannot contain unpaired UTF-16 surrogates. Host
projection removes control characters from cell/title text and omits trailing
cell scalars beyond 128 UTF-16 units without splitting a scalar. Thus an astral
base character plus 64 astral combining marks projects the base plus 63 marks;
the live parser retains its bounded original cell. Strict DTO deserialization
rejects invalid text rather than normalizing caller-supplied snapshots.

OSC8 links retain metadata only for valid WHATWG HTTP, HTTPS, or mailto URLs
with valid bounded ID/URI text. The exact existing `url=2.5.8` dependency parses
URLs. File, javascript, malformed, or control-bearing links project as null;
visible cells and their attributes remain intact. These are intentional link
activation limits, not a restriction on displaying CLI output containing file
links. Vendor OSC10/11/12 setters stop at public palette index 258; higher OSC4
indices are ignored, and real host fixtures verify they never emit private
palette entries rejected by the renderer.

Synchronized output (DEC 2026) retains at most the upstream 2 MiB pending buffer.
The owner schedules `sync_deadline()` independently of PTY reads and invokes
`expire_sync(monotonic_now)` after 150 ms. A flush advances the state sequence
without advancing the output-byte offset, and host replies are generated once.
Observer snapshots remain pure and cannot flush the parser. The interactive
fixture services this timer even during idle reads. Feed, timer flush and resize
all enforce the expanded-state budget; a budget fault requires owner recovery
and must never cause automatic output/input retry.
