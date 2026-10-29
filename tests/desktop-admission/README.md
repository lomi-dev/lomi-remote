# E0 actual desktop native admission bridge

This opt-in spike connects the baseline desktop's real `project_write_guard`
entry points to the canonical admission host in a separate Unix process. It
uses a client-only feature of `lomi-admission-spike`; DTOs and framing have one
canonical implementation. The host alone owns SQLite and physical scope checks.
`AcquireUnscoped` stores JSON `null` as its scope and conflicts with every scope,
including persistent quarantined scopes. Existing serialized scoped rows remain
readable; no schema is deleted, recreated, or silently reset.

`desktop.patch` applies to detached desktop revision
`2cef452c39eb8b455c8d2ae1251310dc870c50bb`. `source-manifest.json` records original
and patched source hashes. `bridge.rs` and `support.rs` are included directly
from this canonical directory by the patched desktop. Do not edit the main
`lomi` checkout. Default desktop behavior is unchanged when the feature is off;
release builds reject qualification features.

The actual entry points are `activate`, `admit`, `admit_unscoped`, and
`Lease::check`. The existing managed MCP policy branch checks the same native
lease before entering its effect scope. Native or otherwise unqualified guard
Drop disconnects and quarantines. Only editor `write()` (synchronous in-process
I/O) and the controlled no-effect probe explicitly permit Finish-on-drop.
Generic asynchronous/subprocess/MCP writes remain conservatively quarantined.
Multiple-path file admissions use the global opaque scope for this spike;
there is no partial multi-path admission. Normal native completion is not yet
wired to a qualified remote settlement hook.

The probe starts a minimal real Tauri application with only EditorFiles state,
which calls the actual `save_editor_file` command function with real Window and
AppHandle, with a private native window and no webview. It bypasses normal auth, credentials, runtime recovery, CLI discovery,
and frontend startup. This is not a renderer invocation or full desktop run.
A fixed inert Rust child is spawned only by the fixture after real guard
activation; no paid CLI or fake task/account/attempt validation is used.
The child is terminated and waited through its owned Rust Child handle before
reconciliation. No PID adoption or liveness inference authorizes release.

Run from the `lomi-remote` root after preparing the detached worktree:

```sh
git -C artifacts/e0-admission-checkout apply ../../tests/desktop-admission/desktop.patch
cargo test -p lomi-admission-spike --lib
cargo check -p lomi-admission-spike --no-default-features
python3 tools/run_desktop_admission.py
CARGO_TARGET_DIR="$PWD/artifacts/e0-admission-target" cargo check --manifest-path artifacts/e0-admission-checkout/src-tauri/Cargo.toml --no-default-features --lib
```

The runner expects the prepared private target at `artifacts/e0-admission-target`.
On macOS use an APFS clone of an existing matching target to avoid a large fresh
build; keep at least 8 GiB free. Frontend build dependencies can be read through
verified symlinks to the main checkout's installed node_modules when package.json
and pnpm-lock.yaml hashes match. Create a private minimal dist/index.html for the
Tauri build. The build uses the fixture AI bundle. No global pnpm change is
needed. `--skip-build` uses previously built binaries, copying each to the fresh
private run directory before launch so later Cargo output cannot change it.

`artifacts/desktop-admission.json` is reset to failure before setup. It records
aggregate checks, tool versions, binary hashes and cleanup. Every run uses an
exclusive random bundle identity, private Application Support directory, HOME,
child HOME, root/project/socket/database and temporary state. The actual native
startup branch never initializes production settings or credentials. Logs do
not contain file contents, terminal bodies, secrets or environment dumps.

Qualified: real native guard IPC; real editor command blocked by external host
Native; same-native renewal helper used by managed MCP; opaque guard admission;
remote File/Git fences across native connection loss, host restart and expiry;
owned child kill+wait followed by explicit reconcile and successful writes.

Unqualified: full execution::run dispatch and its task/account/attempt/fence
validation, authenticated managed/unscoped SessionRequestPolicy execution,
renderer IPC and dirty editor flow, ordinary native completion settlement,
normal startup and product host/Desktop migration, Linux and Windows. The GUI
probe lives separately in tests/desktop-e0. This artifact must not be described
as full E0 Desktop or product host qualification.

## Runner lifecycle and cached build binding

Build commands use `tools/owned_process.py`: each command owns a new process
session; timeout or interruption terminates and reaps its owned process group,
including Cargo/Node descendants. Host and desktop fixture processes also own
separate process groups. Cleanup steps are independent: a failure or interrupt
cannot skip later sockets, process groups, paths, or the outermost failed evidence
write. Path removal runs as a bounded owned command. A possible native child is
recorded before the spawn request is sent, and only the owned Child kill+wait
reply clears that uncertainty. Desktop success additionally requires unforced
exit code zero; code/signal/forced cleanup are recorded.

A successful controlled `--locked` build writes
`artifacts/desktop-admission-build-receipt.json` and preserves the exact three
binaries in `artifacts/e0-admission-build/`. The receipt binds all tracked desktop
files, canonical host/probe/runner sources, workspace manifests and locks,
installed Node dependency contents and links, explicit features, target triple,
compiler/Cargo/Node/Xcode versions, and the digest of the sanitized build
environment to the produced binary hashes. Inputs are compared before and after
the build. No receipt is synthesized for an arbitrary pre-existing binary.
`--skip-build` verifies exact current inputs and preserved binary hashes before
creating a fixture or launching any host/desktop process. It rejects missing,
stale, changed, or malformed receipts. This is local build evidence, not a signed
supply-chain trust boundary against an actor able to rewrite the complete proof.
A change to proof code also invalidates the receipt and requires another controlled
incremental build. Target caches may be pruned after binary preservation; verified
skip-build runs use the preserved binaries.

```sh
python3 -m unittest discover -s tests/desktop-admission -p 'test_*.py' -v
python3 -m unittest discover -s tests/tools -p test_owned_process.py -v
python3 tools/run_desktop_admission.py
python3 tools/run_desktop_admission.py --skip-build --exit-wrapper-73
python3 tools/run_desktop_admission.py --skip-build --lose-native-reply
python3 tools/run_desktop_admission.py --skip-build
```

The two fault runs must return failure. The actual exit wrapper lets the real
native desktop complete its replies then returns 73; its evidence is kept in
`artifacts/desktop-admission-exit73.json`. The lost-reply fault happens after the
real native spawn and must still perform the owned child's kill+wait during
cleanup; evidence is `artifacts/desktop-admission-lostreply.json`. Neither fault
may be reported as a successful qualification run.


The receipt now validates the three actual detached-checkout `node_modules`
symlinks, requires their resolved paths to equal the approved installed trees,
and records both link text and resolved paths alongside content hashes. Retargeting
a link to a tree with even identical bytes is rejected. Missing/unreadable roots
and traversal errors fail closed.

The Rust-only native fixture explicitly clears `build.dev_url` and all configured
webviews, then creates only a real native Tauri Window. It consumes no frontend
page or mutable dist assets. The no-frontend configuration is compiled from
receipt-bound `support.rs`. The normal native probe checks that its real native
window exists and that there is no webview. To verify that an already-running
unapproved development server cannot supply a page, run:

```sh
python3 tools/run_desktop_admission.py --skip-build --dev-server-sentinel
```

This starts an owned HTTP sentinel on `127.0.0.1:1420` before the desktop, counts
all accepted connections without logging their contents, requires zero connections,
and retains `artifacts/desktop-admission-devserver.json`. It refuses startup when
the port is already occupied and never modifies another listener. The usual 38
native checks are retained; the real no-frontend check and sentinel check add two.
