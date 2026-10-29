# Remote E0 contracts (private draft)

Rust DTOs in `crates/lomi-remote-protocol` own the wire model. The Rust
`generate-contracts` binary emits JSON Schema 2020-12 and OpenAPI 3.1 for the
25 logical HTTP routes. This package generates declarations and standalone Ajv
2020 validators from those schemas; no TypeScript wire interfaces are copied.
The contract remains draft E0, the terminal profile is experimental and
unqualified, and S0.5 is not frozen. OpenAPI declares no deployed server.

Node 22 is development tooling only. The generated runtime is a bundled ES
module with no external imports or Node builtins; browser/native hosts need
`TextEncoder` and `BigInt`. Ajv helpers are bundled with pinned esbuild during
generation. The package is private and has no publish task.

## Development

From the repository root:

```sh
npm --prefix packages/remote-contracts ci --ignore-scripts --no-audit --no-fund
cargo run -p lomi-remote-protocol --bin generate-contracts
npm --prefix packages/remote-contracts run generate
node packages/protocol-codec-wasm/scripts/build.mjs
cargo run -p lomi-remote-protocol --bin generate-contracts
cargo run -p lomi-remote-protocol --bin generate-contracts -- --check
npm --prefix packages/remote-contracts run check
npm --prefix packages/remote-contracts test
npm --prefix packages/remote-contracts run typecheck
```

The final Rust generation refreshes hashes of generated client artifacts.
The WASM build also refreshes provenance hashes of Rust sources.
Client generation reads schemas, never the root manifest, so no manifest hashes
itself or participates in a fixed point. `--check` compares exact generated
bytes; it does not update files. The client manifest hashes source inputs,
exact dependency lock, schemas and outputs. All root manifest artifact paths are repository-relative (`pathBase: repository`);
its verifier rejects absolute paths, parent traversal and symlink escapes.
The client manifest labels its input paths as repository-relative and its output
paths relative to `packages/remote-contracts/generated`.
The root manifest hashes schema,
OpenAPI, client outputs, terminal profile and existing crypto vectors/provenance.

## Runtime boundary

`validateShape(kind, value)` and `decodeShape(kind, json)` enforce schema shape,
closed fields, scalar encodings, collection limits, Unicode scalar strings and
`x-lomi-maxUtf8Bytes` annotations. Decode rejects duplicate JSON fields and
imposes transport byte limits with a bounded UTF-8 scan before encoding or WASM
copying. Object predicates accept only plain JSON data and reject serialization
hooks, accessors, custom prototypes, sparse arrays and non-JSON values before
serialization or schema reads. A shape check alone does not establish the
Rust validated wrapper's cross-field invariants.

Initialize the canonical Rust WASM codec before checked decoding:

```js
import {
  initializeProtocolCodec, protocolValidateWire, protocolValidateResponseFor,
} from '../protocol-codec-wasm/src/index.mjs';
import { initializeCanonicalCodec, decode, checkResponse } from './src/index.mjs';

await initializeProtocolCodec(wasmBytesOrModule);
initializeCanonicalCodec({
  validateWire: protocolValidateWire,
  validateResponseFor: protocolValidateResponseFor,
});
const request = decode('rpc-request', originalJson);
if (!checkResponse(request, response)) throw new Error('Invalid remote response.');
```

`decode` runs the schema boundary and the canonical Rust codec against the
original JSON before returning a value. `validate` returns false without an
initialized codec. Standalone `rpc-response` checked decoding is refused; use
`decodeResponse(request, rawResponseJson)` so the exact request is mandatory. `checkResponse` delegates request/method/context/operation,
terminal receipt, file preview and Git page correlation to Rust. Adapter methods
must throw on failure; adapter injection is trusted application configuration.
Public failures contain a static safe message, never Ajv details or payloads.

Authentication, ownership, capability authority, current epochs/fences,
cryptographic CBOR/signatures, admission stores, atomic snapshot installation,
stream reassembly and deadlines still require their trusted runtime checks.
Tokens belong in request bodies, headers/cookies or the first WSS frame, never
URLs. A credential transport does not establish server-owned H/C/E class.
`OrderedSequence` rejects gaps until explicit reset after resync; each
subscription/session needs its own guard. No API retries or replays requests.

Rust validates the generated request/security corpus while generating it.
Consumer tests use those same JSON values and the Rust-owned text parity corpus.
Types are generated and tested through the package's actual `exports` entry.
