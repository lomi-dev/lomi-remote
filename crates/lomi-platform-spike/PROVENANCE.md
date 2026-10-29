# Source provenance

This standalone spike adapts the Seatbelt profile, fixed Git environment,
file-descriptor-pinned `fchdir`, bounded concurrent pipe draining, runtime file
identity checks, and strict stderr handling from:

- Repository: local Lomi application repository (`../lomi`).
- Source: `src-tauri/crates/lomi-control-core/src/git_read.rs`.
- Inspected repository HEAD: `2cef452c39eb8b455c8d2ae1251310dc870c50bb`.
- Inspected file SHA-256:
  `a9e4ec16564c402b8df0a9b79c8c4ac13e322441f87e2c1454e12e6599ee71fe`.
- Inspection/adaptation date: 2026-10-19.

The inspected working-tree file is identified by its digest; HEAD alone does
not assert that it was unchanged. The original application's domain types,
protocol, project-directory guard and full Git operation catalog are not copied.
There is no sibling-repository Cargo dependency or build-time source import.
The PTY/IPC smoke fixture is new code using portable-pty 0.9.0.

Release approval still needs the source owner's licensing/provenance review;
recording local provenance is not a claim that this spike is releasable.
