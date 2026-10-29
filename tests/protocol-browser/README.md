# Canonical contracts in an actual browser

Run after generating both contract packages, from the repository root:

    python3 tests/protocol-browser/run.py
    python3 -m unittest discover -s tests/protocol-browser -p 'test_*.py' 

The harness uses the pinned development Playwright/Chromium installation in
packages/terminal-renderer. The host product requires neither Node nor a browser.
An exact allowlist serves synthetic fixtures, generated validators and canonical
Rust WASM on loopback. A fresh browser context blocks service workers and tests
initialization refusal, the shared native/WASM corpus, text byte/control limits,
request-bound responses, duplicate fields, invalid Unicode and oversized input.
Unbound shape-only responses are counted separately from canonical parity.

Every input hash must remain unchanged during execution. The wrapper writes a unique incomplete attempt synchronously before project
helper imports or Node startup, then uses `tools/owned_process.py` to impose a
90-second deadline. The Node harness also invalidates evidence before dynamically
importing Playwright. SIGINT/SIGTERM request cancellation and unwind through
cleanup without uncaught signal exceptions. Browser and HTTP-server
shutdown are independently bounded; cleanup failure preserves failed evidence.
artifacts/protocol-browser/evidence.json records versions, counters, input hashes
and cleanup. Lifecycle regressions seed a prior passing artifact, interrupt real
owned Chromium and both loopback listeners, verify failure/incomplete evidence,
and check that those exact processes/listeners are gone. Separate import-failure
and forced-deadline cases verify that startup/termination cannot preserve stale
success. Tests keep their interrupted evidence in temporary directories, so the
normal evidence artifact remains the actual browser run.

This does not qualify a production transport, authority, mobile
runtime or complete client application.
