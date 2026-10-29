# Lomi Remote

`lomi-remote` is the Rust host, CLI/TUI, shared protocol, and signed-update
implementation for Lomi Remote. It provides local host management, authenticated
remote workspaces, terminal and file access, Git operations, and platform service
lifecycle support.

The canonical product requirements are in [`docs/specs/remote-server`](docs/specs/remote-server/README.md).
Operator recovery and credential procedures are in
[`docs/operations/recovery.md`](docs/operations/recovery.md). Release installation,
update, and uninstall procedures are in [`release/README.md`](release/README.md).

## Build and run

Install the latest published release on Linux or macOS:

```sh
curl -fsSL https://lomi.dev/remote/install.sh | sh
```

Check and apply updates to an existing installation:

```sh
lomiremote update --check
lomiremote update --confirm
```

The updater verifies signed TUF metadata and preserves the existing service and
profile. macOS requests administrator access. Windows publication requires an
Authenticode certificate; its installer is prepared but Windows packages are
not yet published. See the [tag release runbook](release/tag-releases.md).

## Build from source

Use the pinned Rust toolchain and workspace lockfile:

```sh
cargo build --locked -p lomiremote
cargo run --locked -p lomiremote -- --help
```

Release-specific target requirements and bundle preparation are documented in
[`release/README.md`](release/README.md). The release workflow builds signed
bundles from tagged source and the pinned public trust root.

## Canonical contracts and consumer snapshots

Rust owns the canonical protocol and cryptography. Generated contract schemas,
WASM packages, and consumer snapshots are checked against their canonical source:

```sh
cargo run --locked -p lomi-remote-protocol --bin generate-contracts -- --check
npm run check --prefix packages/remote-contracts
npm run check --prefix packages/protocol-codec-wasm
npm run check --prefix packages/authority-crypto-wasm
node scripts/check-cross-target-provenance.mjs
```

The terminal dependency inventory and local patches can be verified with
`python3 tools/check_terminal_vendor.py`.
