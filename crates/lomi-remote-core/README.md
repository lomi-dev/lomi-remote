# lomi-remote-core

Sans-I/O client core (relay link state machine, session request/response, sealed Host directory,
client tunnel).
One boundary serves every platform: `bridge::call(handle, op, args, payload)` and `bridge::free(handle)`.

| Platform | Binding | Artifact |
|---|---|---|
| Web worker | wasm-bindgen `call`, `free` | `packages/remote-core-wasm` (`generated/remote_core_bg.wasm`) |
| iOS | C ABI `lomi_core_call`, `lomi_core_bytes_free`, `lomi_core_free` (`src/ffi.rs`) | static library, `LomiRemoteCore.xcframework` |
| Android | JNI `dev.lomi.core.LomiRemoteCoreModule.nativeCall/nativeFree` (+ the same C symbols) | `liblomi_remote_core.so` (arm64-v8a, x86_64) |

Build everything with `scripts/build-remote-core.sh`; run the shared vectors in every compilation
with `scripts/test-remote-core-targets.sh`.

## Calling convention

* `handle`: `u32`, 0 for stateless operations and for operations that create an instance. Instances
  (`link.new`, `directory.new`, `directory.open`, `tunnel.new`) return `{"handle": n}`. Call `free(handle)` when done
  (idempotent). At most 64 live instances (`handleLimit`).
* `args`: strict JSON object (UTF-8, empty = `{}`; integers only, safe-integer range, depth <= 8).
* `payload`: raw bytes, meaning per operation.
* Result: first byte `0` = ok, then data; first byte `1` = error, then JSON `{"code": ...}`.

All times come from the platform: `monoMs` (monotonic) and `wallMs` (Unix ms) in `args` of every link
operation that takes time; the core has no clock, socket, RNG or timer (the one exception: Noise
ephemeral keys inside the tunnel handshake come from the OS RNG, `getrandom`, which on the web is
`globalThis.crypto.getRandomValues`). The link seed is a platform
random integer (`link.new`).

## Operations

Stateless (handle 0): `version` (data: text), `frame.decode {fromRelay}` + frame payload (JSON frame),
`frame.canonical {fromRelay}` (canonical bytes), `session.request {contractHash, refreshCredential?}`
(`{method, path, headers, body}`), `session.parse {status}` + body (`{outcome: "full" | "degraded", ...}`;
errors: `unauthorized`, `updateRequired`, `outcomeUnknown`, `http` (+`status`, `retryable`), `tooLarge`,
`malformed`). Errors of `frame.*`: `framing`, `encoding`, `shape`.

Link (`link.new {contractHash, seed, maxInflight?, callTimeoutMs?, connectTimeoutMs?, readyTimeoutMs?,
backoffMinMs?, backoffMaxMs?, refreshLeadMs?, minRefreshIntervalMs?, silenceMs?}`): `link.start {token, expiresAt, +now}`, `link.stop`,
`link.onOpen`, `link.onClose`, `link.onMessage` (payload = one WebSocket binary message), `link.tick`,
`link.call {name, args, +now}`, `link.refreshToken {token, expiresAt, +now}`, `link.nextDeadline`
(`{deadline}`), `link.isReady`, `link.lastServerFrame` (`{monoMs}`: monotonic time of the last relay frame on
this connection, `null` when not connected). Data is a record list: `tag u8 | len u32 BE | body`; 1 connect, 2 send
(body = bytes to put on the socket), 3 close, 4 event (JSON, `type` = `ready`, `server`, `callStarted`,
`callDone`, `tokenRefreshNeeded`, `tokenRefreshed`, `tokenRefreshFailed`, `stale`, `tokenNeeded`, `disconnected`,
`stopped`, plus the tunnel events below), 5 stream message (tunnel, below). The platform executes
connect/send/close and re-arms its timer from `link.nextDeadline`, which also covers the link's tunnels
(`link.tick` ticks them too).

Tunnel (client side of `03-protokol.md` sections 3-6, `src/tunnel.rs`). A tunnel runs on a Ready link and the
bridge wires them together: every link operation (`onMessage`, `onClose`, `tick`, `stop`, ...) also feeds the
link's circuit traffic (`0x10 DATA` frames, `circuit.closed` events, the results of the tunnel's own
`circuit.open`/`circuit.close` calls, link loss) to the tunnels attached to it and returns their records in the
same list, and everything a tunnel sends (calls, DATA) leaves as ordinary `send` records of the link. So the
platform has no `tunnel.onRelay`: it keeps calling `link.onMessage` with every WebSocket message and executes the
records. The tunnel's own call results are not shown as `callDone`; unclaimed `circuit.closed` is shown as `server`.

* `tunnel.new {link, deviceBundle, hostBundle, hostFingerprint, contractHash, accountId, hostId, hello}` +
  payload = the 97-byte device identity seed blob (wipe your copy after the call; the core keeps only a
  zeroizing `Identity` until the tunnel is open or closed). Returns `{handle}`. Bundles are the serde JSON of
  `SignedBundle`; `hostFingerprint` (hex 64) is the pinned Host; `accountId`/`hostId` hex 32; `hello` =
  `{deviceName, deviceKind: web|mobile|desktop, authEpoch, hostAccessEpoch, runtimeGeneration,
  resume: [{kind, cursor}], sendDirectory}` (`deviceBundle` is filled in by the core, as serde JSON of the bundle).
* `tunnel.start {random, +now}`: `random` = 64 hex chars (32 platform random bytes: circuit id, nonce). Sends
  `CALL circuit.open` and Noise message 1 as two back-to-back sends. Fails with `started` when run twice.
* `tunnel.tick {+now}`, `tunnel.nextDeadline` (`{deadline}`), `tunnel.close {+now}` (asks the relay to drop the
  circuit, reason `requested`), `tunnel.openStream {kind, params?, +now}` (`terminal`, `chat`, `files.watch`,
  `transfer`; `params` camelCase as in the protocol DTOs; first record is the event `streamStarted {stream}`),
  `tunnel.send {stream, +now}` + payload (one logical message up to 1 MiB; stream 0 takes an `RpcEnvelope` as JSON;
  what the stream/tunnel windows do not allow yet is queued, up to 1 MiB per stream, then `backpressure`),
  `tunnel.closeStream {stream, +now}`, `tunnel.cursors` (no args: `{cursors: [{stream, kind, cursor}]}`; with
  `{stream, cursor}`: records the cursor of a live stream). Errors: `notOpen`, `unknownStream`, `tooLarge`,
  `backpressure`, `badRpc`, `duplicateRequest`, `unknownKind`, `badParams` and the protocol error names
  (`kindNotAllowed`, `tooManyStreams`, ...). There is no `tunnel.credit`: the core returns credit to the Host as
  it hands data to the platform (a message larger than one 64 KiB window could not finish otherwise).
* Events (type, `tunnel` = handle): `tunnelState {state}` with `opening`, `handshake`, `awaitingGreeting`,
  `approvalPending` (+`code`, `deadline` = monotonic ms), `open` (+`directory`), `closed` (+`reason`);
  `updateRequired {olderSide}`; `staleEpoch {authEpoch, hostAccessEpoch, runtimeGeneration}`; `outcomeUnknown
  {requestId}` (one per rpc request still unanswered when the tunnel closed; never resent); `streamOpened {stream,
  kind, requestId?}` (Host-opened: `directory`, `transfer`); `streamClosed`; `streamReset {stream, code}`. A complete
  logical message is record tag 5: `stream u32 BE | bytes` (stream 0 = rpc response JSON).
* Close reasons: `requested`, `handshake`, `handshakeTimeout` (10 s from `start`), `approvalTimeout` (120 s),
  `codeMismatch`, `staleEpoch` (second one), `updateRequired`, `decrypt`, `encrypt`, `protocol`, `linkDown`, the
  relay's `circuit.closed` reason (`peer_closed`, `link_closed`, `stale_authority`) and the lowercased
  `circuit.open` error (`unavailable`, `busy`, `rate_limited`, `invalid_argument`, `timeout`). A closed tunnel
  stays closed: open a new one (`tunnel.new`); nothing is replayed.
* `StaleEpoch`: the core takes the Host's epochs into `hello`, sends `circuit.close` for the old circuit and
  retries once on a new circuit. Circuit id and nonce of the retry are derived (SHA-256) from the same 32
  random bytes, so no second randomness round trip is needed.
* Resume: the core cannot read stream payloads, so the platform's stream decoder reports cursors with
  `tunnel.cursors {stream, cursor}`; read them back (also after `closed`) to fill `hello.resume` of the next
  `tunnel.new`. A cursor is dropped when its stream closes or resets.
* Message 4 (the Host's first transport message) is a postcard `HostGreeting`, not a frame batch.

Directory: `directory.new {accountId, deviceId}`; `directory.open {accountId, deviceId, minKeyId}`;
`directory.applySession` (payload = the 200 response body), `applyReadyState {state}`,
`applyEvent {name, data}` (all return `{effect: unchanged | changed | revoked}`), `setHostName`,
`setWorkspaceName`, `snapshot` (Hosts for the UI), `wipe`, `seal`.

## Token refresh and liveness

* `tokenRefreshNeeded` fires at `max(now + remaining/2, expiry - refreshLeadMs)` (default lead 60 s,
  so a 300 s device token is refreshed after 240 s) and never twice within `minRefreshIntervalMs`
  (default 30 s). A failed refresh is asked again after that interval until the token expires.
* While Ready, `silenceMs` (default 8000, 0 = off) without any relay frame emits `stale` (`silentMs`),
  closes the socket and reports `disconnected` with cause `silence`; the usual backoff reconnect
  follows. The relay sends `authority.fresh` to device links every 2 s, so a healthy link is never
  silent that long. `link.lastServerFrame` lets the platform bound how stale the last
  authorization confirmation is, for example to gate sensitive actions.

## Keys and nonces

Raw key bytes never go through JSON. They are the platform's, per call, and the core copies them into
a zeroizing `Key` for the duration of the call:

* `directory.seal` payload: `key_id u32 BE | key[32] | nonce[24]` (fresh random nonce per seal).
* `directory.open` payload: `n u8 | n x (key_id u32 BE | key[32]) | blob` (several keys during rotation).

Callers must zero their key buffers right after the call: the JS wrapper and the Kotlin module
wipe the payload of `directory.seal` / `directory.open` for you (so build a fresh payload per call),
and the JNI layer and the core wipe their own copies. Swift cannot wipe the `Data` copy the Expo
bridge makes, so on iOS only the JS array and the core's copy are cleared. A WASM module cannot reach its input copy in
linear memory, so the web key lives in the worker only for the duration of the call.

`tunnel.new` takes the identity seed blob as payload like the keys above: wipe it after the call (the platform
wrappers still have to be taught this op).

Handles are process-global: every caller in the process (every worker, module or script sharing the
library) can use or free any handle, so all of them must be in one trust domain. Do not load the
library into a process that runs untrusted code.

Where each platform keeps the key (not implemented here): iOS, a random 32-byte key in the Keychain
(`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`), read just before seal/open; Android, a random
key wrapped by a non-exportable AndroidKeyStore AES-GCM key, unwrapped just before seal/open; web, a
non-extractable WebCrypto wrapping key (IndexedDB) around the 32-byte key, unwrapped in the worker just
before the call. Overwrite the key buffer after the call. On logout/revoke: destroy the key, raise
`min_key_id`, call `directory.wipe` and `free`.

## Vectors

`test-vectors/relay-frames.v1.json` (see `PROVENANCE.md`) and `test-vectors/core-scenarios.v1.json`
(owned here) run through `call` in `tests/shared_vectors.rs` (via the C ABI) and
`packages/remote-core-wasm/test/vectors.test.mjs`. The seal output in the scenarios is a golden value
produced by this core (XChaCha20-Poly1305), not an independent reference.
