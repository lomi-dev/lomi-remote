# Unqualified v3 Chromium / WASM / native proof

This fixture executes canonical grant/context 3 admission and Noise XX in real
Chromium with the Rust WASM build, then exchanges encrypted frames with an
independent native Rust subprocess. It is a bounded development experiment and
never advertises production qualification or native Windows support.

From the repository root:

```sh
python3 tools/run_crypto_v3_browser.py \
  --output artifacts/crypto-v3-browser/report.json
```

The runner checks installed wasm-bindgen **0.2.126** matches the Cargo pin, uses
Node **22.22.3** and the already pinned Playwright **1.62.1**, and records actual
Chromium version, commands, exits and check totals. It builds debug WASM with
`browser,test-fixtures`: crypto's existing release guard rejects fixture seeds
in release builds. Web glue/WASM files and reports go only under ignored
`artifacts/crypto-v3-browser/`, never the provenance-checked crate tree. It uses
explicit local tool paths and a minimal environment; the native peer receives an
empty environment. Chromium runs a new temporary profile with no permissions,
service workers or remote HTTP requests. No browser storage, snapshots, payload
logs, private key serialization or real credentials are used.

`BrowserHandshakeV3` takes signed grant/admission JSON and separate expected
context, independent current authority/membership, host/consumer pins and `now`
(as a JS BigInt, checked for u64 range without wasm-bindgen wrapping). All boundary objects are typed, bounded and reject unknown
fields. Authority u64s are canonical decimal strings via the existing protocol
type. The wrapper calls the canonical `SignedChannelAdmissionV3::verify`, which
also verifies the signed grant, before consuming its verified token in
`Handshake::new_v3`. It has no raw prologue constructor and never negotiates a
legacy fallback. `BrowserChannel` retains the existing transport/disposal logic.

Expected state and pins must be supplied by a trusted production authority
adapter. They are not populated from received signed input by this wrapper. This
lab defines them in the independent native fixture setup; mutation tests prove
signed bytes cannot override those explicit trusted inputs. This point-in-time
admission is not an authorization freshness lease for later operations.

The native peer checks the original frozen `tests/grant-v3/vectors.json` and the
new public `native-vectors.json` before serving commands. WASM compares native
canonical JSON, CBOR and signatures for workspace and terminal contexts. It then
runs both browser-initiator and browser-responder XX handshakes against native
Rust and exchanges transport data in both directions. A second browser-generated
ephemeral identity shares only the same opaque Better Auth session binding; it
gets a distinct grant/channel/key. Disposing window A does not close window B.
No Better Auth cookie/session mechanism or grant issuance service is implemented
by this fixture; session binding here is synthetic trusted metadata.

Negative cases include purpose, endpoint pins, key and signature substitution,
authority epochs/generation/membership, capabilities/closure, strict u64s, schema
extras, downgrade, deadline, identity mismatch, replay, frame tamper and disposal.
They reject before data or close the existing transport as appropriate. Two
individually valid purpose contexts also fail during mixed XX before transport.
Rust disposal does not promise to erase caller-owned JavaScript plaintext copies. Legacy
browser exports and old vectors remain available for historical evidence only;
new code explicitly uses the v3 class and false v3 qualification gate.

The native peer allows at most 256 bounded 128 KiB JSON lines, eight sessions and
bounded frames/payloads. Each Node RPC has a five-second deadline, the browser
experiment has a whole-run deadline, and the parent runner owns command process
groups. Cleanup closes the native peer, browser server/process, loopback HTTP
server and temporary profile before reporting success. The report retains native exit
code, signal and forced-termination status. Only an unforced exit 0 can pass;
nonzero exit or forced termination fails the proof while all remaining cleanup
steps still run. Real-peer shutdown regressions inject exit 73 after EOF and an
EOF hang, and check failure reporting, remaining cleanup and process reaping.
The focused native guards
can be rerun after the build:

```sh
python3 -m unittest discover -s tests/crypto-v3-browser -p 'test_*.py'
```

Remaining gates: native Windows/ConPTY runtime, mobile ABI/physical devices,
production authority/revocation/freshness, secure key lifecycle/storage, release
provenance and deployment. A successful browser runtime proof alone does not
qualify the product, terminal profile or all client integrations.
