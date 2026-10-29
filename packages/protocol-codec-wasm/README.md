# Private protocol wire codec

This package exposes the canonical Rust protocol validators and generic logical
message framing through WebAssembly.
It is private and is not published. Its browser runtime uses no Node built-ins.
Native Cargo builds do not enable the optional `browser` feature or require Node,
WASM tooling, or the WASM target.

Initialize explicitly with fetched bytes or a compiled `WebAssembly.Module`:

```js
import {
  initializeProtocolCodec, protocolValidateWire, protocolValidateResponseFor,
  ProtocolMessageEncoder, ProtocolMessageAssembler,
} from './src/index.mjs';
const bytes = await fetch(new URL('./generated/protocol_codec_bg.wasm', import.meta.url))
  .then(response => response.arrayBuffer());
initializeProtocolCodec(bytes);
protocolValidateWire('rpc-request', rawRequestJson);
protocolValidateResponseFor(rawRequestJson, rawResponseJson);
```

Validators return `undefined` on success and throw an `Error` with a closed code
on failure. Initialization is mandatory (`CODEC_NOT_INITIALIZED`); no fallback
validator exists. Malformed input yields `INVALID_ARGUMENT`, and oversized raw
JSON yields `RESOURCE_EXHAUSTED`. Raw strings must reach these functions before
any `JSON.parse`/object serialization, to preserve duplicate keys and malformed
Unicode. The adapter checks the 1 MiB UTF-8 budget without allocating an encoded copy
and rejects unpaired UTF-16 before wasm-bindgen encoding. Strings longer than
the UTF-16 code-unit budget reject immediately; bounded strings receive one
UTF-8 counting pass. Both request and response pass preflight before either
is copied to WASM. Kind identifiers also have a 64-byte preflight limit. Rust
rejects duplicate JSON keys before typed Serde decoding.

Kinds use schema filenames without `.schema.json`, including PascalCase HTTP
DTO names. Rust type names are also accepted for the non-HTTP wire roots.
`rpc-response` requires the dedicated request-bound validator. `foundation-types`
is a schema catalog, not a message, and is rejected. All exposed roots have the
1 MiB control-message budget; no assembled 8 MiB snapshot DTO is exposed.

Checks cover Rust wire shape, canonical encodings, capabilities, error and
receipt cross-field semantics, checked RPC/stream semantics, and response
correlation. Local IPC JSON receives the canonical four-byte length prefix
internally and uses checked local decoders. Hello DTO validation does not verify
an OS peer or complete an authenticated hello exchange. Trusted database state,
principal rights, current epochs, cryptography, authority and semantic stream
assembly remain the responsibility of their existing trusted validators.

## Generic logical-message framing

`ProtocolMessageEncoder` and `ProtocolMessageAssembler` use the same canonical
Rust `message_framing` module as native callers. JavaScript performs bounded
input checks and ownership adaptation; it does not encode or assemble frames.
Initialize the codec before constructing either class. For one ordered channel
direction:

```js
const encoder = new ProtocolMessageEncoder();
const assembler = new ProtocolMessageAssembler();
try {
  const id = encoder.begin(1, opaqueBytes); // Exact decimal string, starting at 1.
  for (let frame; (frame = encoder.nextFrame()) !== null;) {
    // In product integration, authenticate/encrypt the entire frame, including
    // its header, and await transport backpressure before requesting the next.
    const completed = assembler.push(frame, monotonicMillisecondsString());
    if (completed) consumeCompleteBytes(completed.kind, completed.id, completed.bytes);
  }
} finally { encoder.dispose(); assembler.dispose(); }
```

Kinds are numeric: 1 RPC request, 2 RPC response, 3 workspace frame, 4 terminal
frame, 5 file-watch frame. The module owns at most one logical message per
instance, up to 1 MiB. `nextFrame()` returns one frame, up to 16,384 plaintext
bytes including its 32-byte `LMF2` version-1 header. Nonfinal fragment payloads
are exactly 16,352 bytes; the final fragment has the exact remainder. A 1 MiB
message therefore uses 65 fragments. The separate future encrypted transport
bound is 16,448 bytes (plaintext + 24 outer + 24 binding + 16 tag); exposing
framing does not change the existing crypto or transport limits.

`begin` returns a canonical decimal u64 message ID. `push(frame, nowMs)` returns
`{kind, id, bytes}` at exact completion or `null`; `nextFrame()` returns `null`
when idle. IDs and clock milliseconds are exact decimal strings, never JavaScript
Numbers. Clock strings must be canonical unsigned u64 (zero allowed); clock
regression, overflow, unknown header fields, noncanonical chunks, gaps,
duplicates, changed identity, interleaving and replay fail closed. The first
fragment starts a fixed 5,000 ms deadline. Call `expire(nowMs)` on a scheduled
timer even while no frames arrive; new fragments never extend the deadline.
Completed bytes remain opaque, including split or invalid UTF-8. Decode only
after completion. The WASM completion bridge transfers its owned bytes once
and frees its temporary object rather than exposing a copying payload getter.

Public adapters reject wrong types, oversized byte arrays and oversized clock
strings with constant-time preflight before WASM copies. Byte inputs must be
Uint8Array views backed by ordinary fixed ArrayBuffers; shared and resizable
buffers are rejected. Intrinsic getters avoid hostile user accessors, and plain
views prevent wasm-bindgen from reading subclass overrides. Errors are fixed
`INVALID_ARGUMENT` or `RESOURCE_EXHAUSTED` codes without input content. Every
input error permanently disposes the Rust instance and frees its wrapper;
`dispose()` is permanent and idempotent. Rust Debug implementations expose byte
counts only. Disposal drops owned allocations; it is not memory zeroization.

Callers must dispose both directions on current crypto authority change,
disconnect, rekey, abort or channel failure, and must apply transport
backpressure. This package supplies the native/WASM wire API; application and
transport lifecycle wiring, AEAD integration, authorization, semantic domain
application, effect gates, render ACKs, aggregate host quotas and separately
bounded 8 MiB semantic snapshot assembly remain unimplemented here. Original
domain chunks are unchanged. A 1 MiB per-channel limit is not a whole-host
budget and does not solve semantic snapshot assembly.

Framing tests live in `test/codec.test.mjs` after the existing initialization
cases. Native core unit tests and actual WASM tests share the canonical module
and independent fixed-header references. Source integration and authored tests
alone do not constitute a successful build or runtime qualification.

`node scripts/build.mjs` runs the pinned Rust/wasm-bindgen build and records exact
source, tool, feature, input binary and generated artifact SHA-256 provenance.
`node scripts/build.mjs --check` rebuilds and compares generated bytes and
provenance. Provenance excludes its own digest to avoid a self-hash cycle.
`node --test test/*.test.mjs` exercises actual WASM against the Rust-generated
positive/negative corpus and raw-input/semantic regressions. Node is used only
for development tooling and tests.
