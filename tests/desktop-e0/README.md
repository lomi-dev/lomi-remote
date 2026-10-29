# Native desktop E0 fixture (S0.3)

This opt-in macOS ARM64 fixture exercises the audited desktop at
`2cef452c39eb8b455c8d2ae1251310dc870c50bb`. It is test support in
`lomi-remote`, not a product migration or desktop source-of-truth fork.
The patch applies only to an isolated detached checkout. Never apply it to the
working desktop repository or include its qualification feature in a release.

## What it checks

- The actual main Tauri Workbench mounts its ordinary Dockview/FileEditor and
  CodeMirror runtime. Fixture input goes through the native WebView DOM input
  and CodeMirror DOMObserver; it never assigns the retained editor state.
- A separate Rust fixture process drives the canonical `lomi-domain-spike`
  `HostDomain`. Snapshots reconcile into the actual Workbench session setter,
  retaining private file panel references. It moves one terminal out of a mixed
  tab and closes the remaining terminal in that mixed tab.
- Document ID, private panel ID, text hash, dirty state, disk/buffer revisions,
  selection and undo/redo history survive those operations. Undo and redo are
  executed afterward. The disk file hash remains unchanged.
- Two native windows display the same revisioned host projection. The second
  window is a deliberately narrow fixture projection, with no Workbench or
  `useRemoteWorkspaces`. Attach leaves the actual Tauri PTY count unchanged.
  The observer's attempt to invoke production `load_session` is rejected.
- A stale host mutation CAS is rejected without changing the current revision.

The domain driver is the existing **synthetic E0 domain**, not the product
host. Existing PTYs still belong to Tauri. This proves native editor retention
and a second view without another desktop PTY allocation. It does **not**
qualify host-owned PTYs, two full production Workbenches, IPC write admission,
native execution/MCP effect branches, or E4 migration behavior.

## Reproduce

Create a detached worktree at the audited desktop revision, then apply the
canonical patch from this directory:

```sh
git -C ../lomi worktree add --detach \
  ../lomi-remote/artifacts/e0-desktop-checkout \
  2cef452c39eb8b455c8d2ae1251310dc870c50bb
git -C artifacts/e0-desktop-checkout apply \
  ../../tests/desktop-e0/patches/desktop.patch
```

Supply the audited dependencies by read-only symlinks for root `node_modules`,
`packages/ai-runtime/node_modules` and
`packages/remote-terminal-runtime/node_modules`. The runner enforces the exact audited checkout plus the canonical eight-file
patch, rejects unrelated tracked/untracked input, verifies provenance source
hashes, and compares the audited pnpm lock hash to the installed dependency lock and invokes explicit Node CLI
paths. It never invokes the mismatched global pnpm or changes its default.
The requested package-manager version and installed metadata digest are recorded
in provenance.

The pinned Node runtime archive used by the desktop build must already exist in
`src-tauri/target/ai-runtime/`. Cargo dependencies must be cached for the runner's
`--locked --offline` builds. Missing build-only artifacts can be fetched
separately and verified before launching; the fixture never downloads providers
or uses an account.

```sh
python3 tools/run_desktop_e0.py          # read-only preparation checks
python3 tools/run_desktop_e0.py --run    # builds and launches real fixture windows
```

Only `--run` launches GUI processes. The runner creates a new `0700` run root,
exclusive bundle identifier, private HOME/ZDOTDIR, private project and exclusive
app data directory beneath that HOME. No inherited auth/configuration environment
or `.env` files are used. The probe disables account credential initialization,
push startup and production update requests. Runtime origins point to loopback.
Vite uses `envDir: false` and a private cache. The observer bypasses the production
invoke gate only for two feature-only fixture commands and only for its exact
webview/window labels; production trust is unchanged.

Executables run from private copies. The runner stops and waits for only its own
process groups and removes its exclusive app data and HOME in `finally`.
Each `--run` completes a controlled, offline build, records source/dependency
contents (following actual dependency package links), toolchain, Cargo
configuration, explicit environment and both desktop/domain executable hashes,
and verifies the receipt against a fresh input snapshot before launch. A failed
build cannot produce a receipt. Historical binaries and the older provenance
`nativeEvidence` record have no controlled build receipt and are not current
qualification evidence. The default private target is
`artifacts/e0-desktop-build-target`; builds require at least 8 GiB free.

The probe reads the committed Workbench state after reconciliation, checks
canonical terminal-to-tab membership and retained private panel IDs, and visits
each actual rendered tab to check Dockview pane IDs and nonoverlapping, nonzero
geometry. A deliberately ignored Workbench setter must be rejected before the
real move. A separate native launch shortens the feature-only watchdog and must
exit by itself with code 2.

Receipts, hashes and fixture-only native WebView screenshots remain under
`artifacts/desktop-e0/run-*/`. `result.json` records command exits and cleanup. Cleanup attempts each owned
process stop and exclusive directory removal independently; any failure marks
the run failed while preserving the result. Run fault-injection regression
checks with `python3 -m unittest discover -s tests/desktop-e0 -p 'test_*.py'`.
Inspect the screenshots before accepting a native result. Diagnostic logs must
not contain buffer contents, account material or inherited environment dumps.

`probe.ts` and `support.rs` are the canonical harness sources. The generated patch
contains those sources at their expected desktop import paths plus the bounded
feature/Workbench seams. `provenance.json` binds the audit, patch and sources.
