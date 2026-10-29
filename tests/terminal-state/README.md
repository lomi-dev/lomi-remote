# Synthetic structured-state checks

From the repository root, after the pinned renderer npm dependencies are installed:

```sh
python3 tools/check_terminal_state.py
```

The runner executes the locked Rust `state-fixtures` emitter and then the Node
Rust-to-xterm projection oracle sequentially. Both use `owned_process.run_owned`
with an owned process group and bounded deadlines. It prints only the oracle's
aggregate result. Its artifacts are:

- `artifacts/terminal-state/synthetic-fixtures.json`: synthetic terminal state.
- `artifacts/terminal-state/evidence.json`: exact argv, working directory,
  deadlines, exit codes, durations, OS/tool versions and completion status.

Environment variable values, arbitrary failed stdout/stderr, user terminal
payloads and credentials are not recorded. A new run removes the old fixture
before starting. Timeout or interruption leaves evidence incomplete, with a
nonzero runner exit; neither case can reuse a previous fixture as success.
`--timeout SECONDS` changes each fixture/oracle deadline (maximum 600 seconds).

The fixture remains `qualified: false` and passing projection tests do not
qualify arbitrary CLI behavior, native interactive lifecycles or production use.
Headless and Chromium tests run separately through the renderer package scripts:

```sh
npm test --prefix packages/terminal-renderer
npm run test:browser --prefix packages/terminal-renderer
```

See the renderer package README for the private xterm API/version boundary,
profile limits and optional input hook behavior.

`python3 tools/check_terminal_state.py --interactive` runs the actual Vim PTY
harness before projecting its structured states. It records the same command
metadata plus payload-free native observations in
`artifacts/terminal-state/interactive`. It requires `/usr/bin/vim` and does not
read user configuration or files. For the dedicated disposable Linux Lima VM,
`python3 tools/run_linux_terminal_fixture.py` transfers approved source files,
builds Rust in the guest and runs the fixture in a bounded systemd cgroup. Only
synthetic states return to the host oracle; the guest host has no Node or GUI
dependency. This VM runner installs development Vim inside that disposable VM.

The Rust emitter now includes `patchFormat: "grid-patch-v1"` and a production
`patches` array beside each preserved legacy `deltas` array. The headless oracle
checks both paths at every attachment boundary. Two additional repeated-scroll
fixtures exercise history growth/trim and Unicode/styles, for 28 fixture groups.

`applyPatch` validates the profile, session epoch, contiguous sequence, monotonic
output offset, prior geometry, retained history, changed row/cell runs and final
wide-cell topology before projection. It counts prospective UTF-8 JSON snapshot
bytes before expanding runs or cloning a replacement model. A compact patch
cannot bypass the 8 MiB state bound through repeated long cells. Any failure
invalidates input until an explicit valid snapshot is applied.

Run `python3 tools/check_terminal_state.py` before the browser script so it reads
the current Rust fixture artifact. Chromium projects all production patches and
attachment boundaries with the same shared cell oracle as headless xterm. It
also runs the shared malformed corpus and a compact expansion regression,
asserting zero replacement-model clones on rejection and zero PTY parser calls.
`artifacts/terminal-state/browser-patch-evidence.json` records only counters,
completion, browser version, fixture hash and source hashes; no cell payloads.
A fresh browser run first marks that evidence incomplete and verifies source
hashes did not change during the proof.
