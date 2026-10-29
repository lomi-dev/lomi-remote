# E0 evidence register

This register distinguishes bounded executable proofs from product acceptance.
**E0 is not accepted and E1–E7 are not complete.** No REQ-01–REQ-17 is fully
verified. Tests use synthetic data; artifacts must contain no real terminal/file
payload, credentials, ciphertext or environment dumps.

## Baseline and environments

The complete adjacent `remote-server` specification and project instructions were
read before creating this separate Git repository. Existing main checkouts were
clean at the audited revisions:

| Repository | Revision |
| --- | --- |
| lomi | 2cef452c39eb8b455c8d2ae1251310dc870c50bb |
| auth-app | 42520daa05127239608b818cc33354c18a135848 |
| remote-web | 65c580fa69275eaaa6678e3ebc103a1b616be4b6 |
| mobile-app | 1d7a9c668e20627629f658acddb87da94f71de94 |
| auth-frontend | 1551166ff60b183d6845e71d3cd513204c102f80 |

Native development: macOS 27.0.1 build 26A434 arm64, Rust/Cargo 1.98.1,
Python 3.14.7, Node 22.22.3, Bun 1.3.14, PostgreSQL 17.8 (Postgres.app).
The macOS executor pins CLT Git 2.54.0 (Apple Git-157), not the shell launcher
Git 2.50.1. Exact Cargo/npm/Bun dependency resolution and upstream source hashes
are preserved in locks and provenance manifests.

Disposable Linux VM: Lima 2.2.1, Ubuntu 24.04.5 ARM64, kernel
6.8.0-146-generic, glibc 2.39, systemd 255, Rust/Cargo 1.98.1. No host filesystem
mount, forwarded user agent, Node or GUI is used by native host fixtures. Homebrew
Lima was installed on the Mac; guest build dependencies, Vim and experimental
bubblewrap prerequisites were installed in the disposable VM.

Supplied Windows test machine: Windows 10 Enterprise LTSC 10.0.19044 x64,
passwordless pinned SSH, elevated operator, SSH session 0. Rust 1.98.1 was
installed side by side; the existing default toolchain was preserved. No reboot,
logoff, automatic service startup or modification of unrelated user data was
performed. This Windows 10 feasibility result does not qualify Windows 11,
Windows Server or ARM64.

## Integrated reproduction

From this repository:

```sh
python3 tools/check.py --pg-bin /Applications/Postgres.app/Contents/Versions/17/bin
```

The current reviewed E0 aggregate passed **39/39** expected command results
(`artifacts/checks-reviewed-e0.json`, run started 2026-10-19T00:59:42Z): formatting,
workspace Clippy, 104 workspace Rust tests/doctests, 43 crypto feature tests,
ten durable-update fault tests, generated-schema drift, 36 Python tool tests,
12 desktop-admission runner tests, 11 Windows preservation/executor tests,
Linux/macOS runner lifecycle regressions, provenance/tamper checks, historical
negative qualifications, xterm/Chromium projection and input, interactive Vim,
actual v3 WASM/native interop, real enrollment/Better Auth PostgreSQL suites,
two actual PostgreSQL shutdown faults, and the 264-channel authority benchmark.
Counts from different commands overlap and are not summed. This is regression
evidence for that source snapshot; final desktop native fixes and Windows WASI
runtime remain separate proofs under review.

`artifacts/checks-reviewed-e0.json` records exact argv, environment versions, expected/actual
exit codes, durations and redacted log paths. An incomplete/interrupted run is
failed. Exit 0 for a regression reproducing an expected rejection does not pass
the rejected candidate. GitHub workflow source is prepared, not executed or
published. WASM/browser tooling and Vim are development dependencies only.

## Current bounded proofs

| Area | Executed result | Evidence and remaining boundary |
| --- | --- | --- |
| Original checkpoint candidate | Stock vt100: native 6 matches/7 failures; xterm 3 matches/10 failures | `tests/terminal/*observations.json`; rejected historical candidate |
| Structured Rust terminal | 26 groups, 246 projections, 82 attach boundaries; headless and real Chromium input/rendering | `tools/check_terminal_state.py`, `tests/terminal-state*`; profile remains experimental, wider CLI/soak/client qualification pending |
| Interactive PTY | Native macOS and Linux Vim: seven milestones, 39 projections and 13 attach boundaries each | `tools/check_terminal_state.py --interactive`, `tools/run_linux_terminal_fixture.py`; private synthetic HOME/CWD, no payload logs |
| Domain/admission | Six pure-domain, four IPC/process tests, two client tests; actual Tauri bridge 39 checks, 40-check dev-server sentinel plus real retarget/exit73/lost-spawn-reply faults | `artifacts/desktop-admission.json`, `tests/desktop-admission`; independent final review closed, actual dependency binding and native-only window verified, zero dev-server connections; full native-agent execution remains unqualified |
| Actual desktop mixed views | Native Workbench/CodeMirror preserves dirty text, stable private IDs, selection and undo; observer attach retains two PTYs | `artifacts/desktop-e0/run-frfm69gx/result.json`, `tests/desktop-e0`; final independent review open; observer is a fixture projection and Tauri still owns PTYs |
| Linux service | Current reviewed fixture passes 40 lifecycle checks, seven native tests and nine driver tests | `artifacts/services-linux/evidence.json`; selected-source rebuild then nologin service/SSH disconnect/actual reboot/cleanup; local and guest selected hashes match; existing dependency workspace reused |
| macOS service/storage | 20 native checks plus 11 runner regressions; independent review closed | `tools/run_macos_service_fixture.py`, `artifacts/services-macos/evidence.json`; UUID LaunchAgent, private Keychain lock/read refusal/unlock, unchanged default/search list, complete cleanup |
| Windows service/storage | Four policy checks and 16 native service/fault checks passed | `tests/services-windows/`, `artifacts/windows/native-9bc026e3-4ede-46eb-a61c-fa1f1de91565.json`; actual LocalService/session-0 ConPTY/DPAPI and owner-bound cleanup; separate `ssh-disconnect-024ed63f-3e57-4d10-bb27-619d3f6985cd.json` passes three fresh-SSH phases and independent absence checks; no boot/logoff qualification |
| macOS Git | Six adversarial native tests | Fixed root-owned executable; hardlinks, replacement/runtime and deprecated Seatbelt remain unqualified |
| Historical Linux Git | Native helper/fork/network/write denial, 12 groups plus two review regressions | `tools/run_linux_git_spike.py`; outside-stat and private-hardlink counterexamples remain in this historical candidate |
| New Linux Git namespace | 18 native groups / 15 operations, five prerequisite lifecycle cases; all four findings closed | `artifacts/git-linux-isolation/evidence.json`; pinned root FD/sealed snapshots/empty namespaces/capability drop; prerequisite file and live policy absent after cleanup |
| Portable Git WASI | Packed-repo/index status, staged/unstaged diff, log and show match native Git on macOS; adapter probes and 16 security/broker groups pass | `artifacts/git-wasi/report.json`; gix 0.88.0/Wasmtime 49.0.3, two guest-only pinned portability patches; policy closure review and native Windows runtime pending, production snapshot broker unqualified |
| Enrollment/rotation | 33 tests, 158 assertions, real PG17 fsync and limited role | `tools/run_enrollment_spike.py`; canonical PoP, immutable binding, single exchange, recovery, rotation/reuse/global revoke/crash cases; product integration pending |
| Actual Better Auth | 20 tests, 146 assertions, actual pinned 1.7.6 handlers and limited PG role | `tools/run_auth_binding_spike.py`; opaque session FK, two windows, refresh/revoke, immutable pre-account key commitment/account assignment; product routes and OS receipt pending |
| Canonical crypto | 43 native tests/doctests; 70 crate files plus explicit proof paths audited against original source | `tools/check_crypto_source.py`; original Snow sources/algorithms/licenses preserved, independent API2/application2/grant3 |
| Actual crypto browser | 79 checks, 34 admission negatives, five XX handshakes; six bounds/shutdown regressions | `tools/run_crypto_v3_browser.py`; Chromium 151.0.7922.34 with WASM/native peers, abnormal shutdown fails evidence, independent review closed; mobile/production freshness pending |
| Authority lock/load | 264 channels / 528 sockets, four real PG/relay scenarios, five lifecycle fault regressions | `tools/run_authority_lock_spike.py`; pinned existing relay only, p95/revoke/stall measurements and actual post-deadline sends recorded; no new authority qualification |
| Durable TUF | Ten tests including restart/root rotation/process crash/FIFO rejection | `crates/lomi-update-trust`, `tests/update-trust`; offline verifier wrapper only, no installer activation/HTTP/Windows/power-cut qualification |

Useful exact commands, in addition to the aggregate runner:

```sh
cargo test --locked -p lomi-remote-crypto --features browser,test-fixtures
cargo test --locked -p lomi-update-trust --features fault-injection
python3 tools/check_crypto_source.py --source-repo ../lomi
python3 tools/check_terminal_vendor.py
python3 tools/run_crypto_v3_browser.py --output artifacts/crypto-v3-browser/report.json
python3 tools/run_auth_binding_spike.py --pg-bin /Applications/Postgres.app/Contents/Versions/17/bin --output artifacts/auth-binding.json
python3 tools/run_authority_lock_spike.py --pg-bin /Applications/Postgres.app/Contents/Versions/17/bin
node --test tests/authority-lock/lifecycle.test.mjs
python3 -m unittest discover -s tests/services-macos -p 'test_*.py' -v
```

Native platform runners have prerequisites and exact-resource ownership rules in
their READMEs; do not run service scripts on arbitrary machines. Windows failed
attempts are preserved as incomplete; the successful SCM-owner fault test
supersedes the failed operator-context ConPTY probe without rewriting history.

## Review and interpretation

The independent `gpt-6-astra` reviewer has closed corrections for provenance,
owned-process cleanup, Git fixture environment injection, IPC/descriptor/worker
lifecycle, PostgreSQL expiry/stop evidence, canonical account binding, v3 browser
shutdown, macOS setup/deadlines and authority load reporting. See
[review.md](review.md). New Linux namespace and Windows failure-preservation findings are closed.
Desktop admission and portable WASI policy corrections are closed; actual
desktop GUI corrections are independently closed, and fresh controlled native
proof run-17qwotlv passed. Windows and Linux WASI native proofs passed 11 and
12 groups; runner reviews are closed. Review of a probe is not
product release approval.

Authority measurements use the actual pinned baseline global lock and relay.
SQL read ordering is distinct from response delivery. Actual stale-frame send
counts are recorded; zero attempts means sockets were already closed. Socket
close time has a separate scheduler observation allowance. An overload-safe
close does not qualify availability under a six-second database stall.

The terminal serializer profile changes output interpretation deliberately:
Rust alone parses PTY output and answers DSR/DA; pinned xterm consumes structured
state. Projection equality is not a claim of raw xterm parser equivalence.
Idle synchronous-output timeout, combining/control-string limits, safe title/link
projection and resource faults are tested separately. Ordinary shells still run
with the OS account's authority; a workspace root is not a shell sandbox.

## Remaining acceptance

E1 product host/IPC/store/PTY/CLI/TUI foundations now exist and have focused
actual process tests; integrated terminal RPC acceptance remains in progress.
No installable release, new production Remote API/relay, FileService,
complete Git service, desktop/WWW/mobile migration, production sharing/logout integration,
all-client method matrix, clean-machine signed installation, update activation,
restore/migration cutover, release security approval or product 24/72-hour soak
has been completed. macOS LaunchDaemon/FileVault/pre-login boot, Windows reboot
without login, supported OS/architecture matrix and physical mobile devices
remain unqualified. Do not infer these from cross-compilation or synthetic tests.

The main application checkouts remain unchanged. Two detached desktop worktrees
under ignored artifacts contain actual-editor/native admission experiments;
these are bounded E0 proofs and are not an application migration. Nothing was committed, pushed,
released or deployed to production. Only explicitly owned synthetic services,
private test stores and disposable VM prerequisites were operated on.
