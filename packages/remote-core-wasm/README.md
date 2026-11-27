# Remote core (WASM)

The sans-I/O client core (`crates/lomi-remote-core`) for the web worker. Private, not published.
The same Rust boundary (`bridge::call` / `bridge::free`) is exposed to iOS (C ABI) and Android (JNI);
see `crates/lomi-remote-core/README.md` for the operations, argument layouts and key handling.

```js
import { initializeRemoteCore, coreCall, coreJson, decodeRecords, coreFree } from './src/index.mjs';
initializeRemoteCore(await fetch(new URL('./generated/remote_core_bg.wasm', import.meta.url)).then(r => r.arrayBuffer()));
const { handle } = coreJson(0, 'link.new', { contractHash, seed });
const out = decodeRecords(coreCall(handle, 'link.start', { token, expiresAt, monoMs, wallMs }));
coreFree(handle);
```

`coreCall` returns the data bytes or throws `CoreError` (`error.detail.code`). Initialization is mandatory.
`npm run build` regenerates `generated/` and `provenance.json`; `npm run check` verifies them;
`npm test` runs the shared vectors against the built module. Keys are passed as `Uint8Array`; zero the
array after the call (`array.fill(0)`). The worker keeps the key only as a non-extractable WebCrypto
wrapping key; unwrap just before `directory.seal` / `directory.open`.
