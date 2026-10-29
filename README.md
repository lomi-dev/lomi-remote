# Lomi Remote

Independent repository for the Rust `lomiremote` host, CLI/TUI and shared
contracts. The implementation specification is currently in the adjacent
`remote-server` directory; application repositories retain independent history.

The code now includes the native host and TUI, device login, Cloud publication,
v2 relay consumers, shared desktop ownership, Explorer, isolated Git services,
and signed-bundle installation/update recovery. Production qualification and
publication remain open. The current implementation-only phase runs compilation,
type checking, artifact generation, and source review; runtime and acceptance
tests are deferred to the user. macOS coalition containment remains explicitly
experimental under ADR-012.

See [progress](docs/implementation/progress.md),
[decisions](docs/implementation/decisions.md) and
[evidence](docs/implementation/evidence.md), plus the current
[delivery status](docs/implementation/delivery-status.md), for scope and results.
Operator procedures are in [recovery and credentials](docs/operations/recovery.md)
and [release and updates](release/README.md).

For local Linux development only, `tools/install_linux_local.py` can copy an
already-built `lomiremote` binary into `~/.local/bin`. First build the binary,
calculate its SHA-256 locally, then pass both the path and digest explicitly:

```sh
cargo build --locked -p lomiremote
sha256sum target/debug/lomiremote
python3 tools/install_linux_local.py --binary target/debug/lomiremote --sha256 EXPECTED_SHA256
```

Run it as `~/.local/bin/lomiremote version`, or add `~/.local/bin` to `PATH`
for the current shell.

This installs an unsigned, unreleased development build for Linux x86_64 or
aarch64. It does not download anything, configure login, sharing, a service or
autostart, or qualify the host for production use. Existing unrelated files and
symlinks at the destination are preserved by refusing the install. Each
verified binary is stored by its SHA-256 in a dedicated object directory; the
`lomiremote` command is atomically switched to the new object only after the
staged copy passes the same digest check.

The locally supplied digest detects a mismatched copy; it does not establish
the publisher's identity or binary authenticity. Release trust requires signed
metadata and the qualified update verifier, which this helper does not provide.

Use the pinned toolchain and lockfile:

```sh
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Run `python3 tools/check.py` for the full local E0 regression set and redacted
command/exit-code evidence under `artifacts/`. This development runner requires
POSIX process groups; it does not qualify Windows. It cleans its owned group on
timeout/interruption; fixtures that create separate sessions retain their own
cleanup responsibilities. The runner also asserts that
incomplete terminal candidates and release provenance are rejected. A successful
runner exit means those expected observations were reproduced; **E0 remains
unqualified**. The prepared CI workflow runs the probes on Linux and macOS; it
has not been executed on GitHub. Native VM, SCM and storage proofs use separate
bounded runners and do not become platform qualification merely by compiling.

For repeatable, bounded product checks, select a scope:

```sh
python3 tools/check.py --scope host
python3 tools/check.py --scope consumer
python3 tools/check.py --scope web
python3 tools/check.py --scope git
python3 tools/check.py --scope consumer --list
```

The host scope runs the HTTP, remote-connection, ingress-driver, original-operation
deadline and Git executor Rust tests. The git scope runs the isolated Git service
tests against real repositories. The consumer scope runs its Python source/owner
tests, the Bun runtime and S5 adapter/composition suites, and strict TypeScript
checking of those modules. These checks do not launch the database qualification.
The web scope
runs the remote-web Bun unit suite and runs Astro check when its local CLI,
`@astrojs/check`, TypeScript, and Node 22.12+ are available. Missing Astro
check dependencies fail preflight without an install. These scopes do not
install packages or run database, browser, SSH, or release qualification
suites. Bun commands use
`--no-env-file`; commands run with a private temporary home and temp directory.
Each invocation writes one private worklog and one JSON report in a fresh
`artifacts/scoped-checks/<scope>-<uuid>/` directory. Pass `--output` to put the
report at another fresh path; an existing path is preserved and rejected.
`--list` prints the selected commands without invoking them. These checks
record local regression results only and always leave `stageQualified` false.

The development browser proofs require Node 22.22.3, the lockfile-pinned npm
packages, Chromium through Playwright 1.62.1, Rust's `wasm32-unknown-unknown`
target and wasm-bindgen CLI 0.2.126. The interactive terminal proof requires Vim.
These are test dependencies; the Rust host fixtures do not require Node or GUI.

The aggregate runner installs the lockfile-pinned `packages/remote-contracts`
dependencies with npm lifecycle scripts disabled. It verifies Rust schema and
SDK generation drift, rebuilds and checks the canonical protocol WASM artifacts,
and runs SDK, TypeScript, WASM and actual Chromium protocol regressions. The
browser checks run after the terminal renderer's pinned Playwright installation.
The CI dependency step installs Chromium's Linux system dependencies before the
runner; local Linux environments must provide those dependencies too.

The Windows and Linux WASI Git runner unit tests use local synthetic fixtures
and mocked transports. The aggregate runner selects `test_runner.py` explicitly;
it does not invoke the separate native Linux worker suite or build/run WASI Git
and desktop qualification environments.

Add `--pg-bin /path/to/postgresql17/bin` to `tools/check.py` to include the
synthetic enrollment store, actual Better Auth 1.7.6 binding and real PostgreSQL
shutdown-failure regressions. Each proof uses its own private socket-only
cluster, an explicit limited runtime role and synthetic identities.

`tools/source_manifest.py` records file SHA-256 digests and sibling repository
revisions without copying their content. `--release` deliberately refuses release
in this E0 repository. It is not a signed manifest or TUF installer.

`node scripts/check-cross-target-provenance.mjs` is the deterministic workspace
cross-target source-provenance and release-preflight gate. It verifies the cross-target hash
inventory in `CROSS-TARGET-PROVENANCE.json`, runs the existing remote-contract,
both WASM package, remote-web snapshot, and mobile crypto provenance checks, and
requires exact canonical/vendor inventories apart from the documented adaptations
and pinned mobile-only crypto package inputs. Mobile TypeScript hashes identify
handwritten contract sources; they do not imply generated or shared code. After
an intentional source change, regenerate with
`node scripts/check-cross-target-provenance.mjs --write` and review the manifest.
Passing this gate establishes source and snapshot consistency only; it does not
claim production readiness, release qualification, or device acceptance.
Product build and device qualification remain separate; this gate does not build
native iOS or Android artifacts or run SQL/PostgreSQL checks.

To verify the existing auth foundation against an isolated, temporary PostgreSQL
cluster, with installed sibling `auth-app` dependencies, run:

```sh
python3 tools/auth_baseline.py --pg-bin /path/to/postgresql/bin --output artifacts/auth-baseline.json
```

This creates its own socket-only cluster and applies existing migrations there.
It ignores inherited database URLs and application `.env` files, stops the cluster
and retains only command/exit-code totals. It does not qualify the new enrollment,
credential recovery, principal classes or limited database roles.

Development terminal interoperability tests may use Node as an xterm oracle.
It is not a host dependency. These tests use synthetic data only. Do not use
application credentials, terminal transcripts or project files as fixtures.

`lomiremote auth configure --remote-api-origin https://remote.example --confirm`
can explicitly pin a trusted operator-supplied Remote API origin alongside the
required identity and provider options. The pin must be a canonical HTTPS origin
distinct from `--origin`; no origin is inferred. Existing configuration without
a pin can install one once while preserving every other configuration field.
Exact retries are accepted; replacing or removing the pin is rejected. This
configuration does not yet enable a data transport or cloud publisher.
