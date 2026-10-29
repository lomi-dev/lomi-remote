# Lomi Remote release and update path

The release path packages platform signed executables around the bounded TUF
verifier in `lomi-update-trust`. The build does not create a trust root, sign
TUF metadata, upload a public release, or deploy an application.

## Whole-release manifest

`release-set.schema.json` defines the closed format-1 JSON manifest for a
staging or release set. It records host, API, identity, relay, canonical Web,
Desktop and mobile versions and immutable source commit/tree state; the
HTTP/RPC/IPC/grant/context/terminal-profile compatibility tuple; canonical
contract and fixture digests; SQLite current and rollback schema bounds; the
Prisma migration-set digest; and each artifact's digest, target, toolchain,
runtime dependencies, SBOM, license, signature and notarization references.
It also records content-digested public TUF-root and update-policy revisions,
qualification report references and states, date, environment and known
limitations. The schema rejects unrecognized fields and the reader rejects
duplicate JSON keys.

Targets use canonical lowercase OS names `linux`, `macos`, `windows`, `android`,
`ios`, and `web`; architectures use `x86_64`, `aarch64`, Android ABI names,
`wasm32`, or `universal` as appropriate. The reader accepts only these explicit
aliases and writes their canonical forms: OS `darwin`/`osx` → `macos`,
`win`/`win32` → `windows`, `iphoneos` → `ios`, `browser` → `web`; architecture
`amd64`/`x64` → `x86_64`, `arm64` → `aarch64`, `arm64v8a` → `arm64-v8a`, and
`armv7` → `armeabi-v7a`. Other spellings are rejected.

Release mode requires Host binaries for Linux, macOS, and Windows at both
`x86_64` and `aarch64`; their ABI values are `gnu`, `darwin`, and `msvc`,
respectively. It requires Desktop bundles for macOS x86_64/arm64, Linux x86_64,
and Windows x86_64. It requires at least one mobile application package for
each of Android and iOS, with an architecture valid for that platform. Desktop
does not declare Linux ARM64 or Windows ARM64 support. Server API, identity,
and relay artifacts are Linux containers. A `web/universal` Web bundle is
required for release coverage; a `web/wasm32` artifact is auxiliary and cannot
substitute for the Web client bundle. Desktop release coverage also requires
one `update_metadata` artifact at `web/universal` with ABI `json`; optional
detached-signature records use the same target with ABI
`detached-signature`. These metadata artifacts cannot stand in for any native
Desktop bundle.

Host binaries, Desktop bundles, and mobile packages (including `native_mobile`)
require a `passed` signature declaration. A container, Web bundle, pure
WebAssembly payload, or Desktop `update_metadata` artifact may declare its
signature `not_applicable`; if its signature is declared applicable, its state
must be `passed`, never `pending` or `failed`. macOS Host and Desktop native
artifacts require a `passed` notarization declaration. Other artifact/platform
combinations require notarization to be `not_applicable`. Preparation mode
accepts missing target rows and incomplete attestations, then reports them as
missing or pending release gates.

Validate or canonicalize a supplied manifest offline:

```sh
python3 release/release_set.py validate ./release-set.json \
  --mode preparation \
  --source host=../lomi-remote \
  --artifact host-linux-x86_64=./dist/lomiremote \
  --canonical-out ./release-set.canonical.json
```

Source and artifact mappings are optional and read-only. A source mapping must
name the exact worktree root. It compares the manifest's commit and tree, checks
index and worktree differences separately, checks untracked files and recurses
through initialized submodules. It rejects executable clean/process filters and
special index states before diffing; uninitialized or unverifiable submodules
cannot be declared clean. An artifact mapping compares its recorded size and
SHA-256 with the local regular file using a no-follow open; platforms without
no-follow support fail closed. The tool does not fetch references, inspect
credentials, write source repositories or execute mapped artifacts. Input size
and inventory counts are bounded. Canonical JSON uses sorted keys, compact
UTF-8 encoding and a trailing newline; the reported SHA-256 covers those exact
bytes.
`--canonical-out PATH` creates a new file without overwriting an existing one;
use `--canonical-out -` to emit the canonical JSON on stdout.

Preparation mode may omit release sections or record pending work. It always
reports `PREPARATION_ONLY` and lists missing or pending release declarations.
`--mode release` requires all seven components, clean immutable source
revisions, artifacts, matching schema bounds, and completed qualification and
signature/notarization declarations. It checks the required Host, Desktop and
mobile platform inventories and rejects component/kind/target mismatches. Its
`RELEASE_MANIFEST_DECLARATIONS_VALID` result validates recorded states and any
explicitly mapped local files only. It does not independently verify report
contents or cryptographic signatures, run product qualification, approve a
release, or publish it. No release manifest or qualification result is
generated by this tooling.

The separate coordinated publication workflow additionally passes
`--require-complete-mappings`. This requires an actual local Git mapping for
each of Host, API, Identity, Relay, Web, Desktop and Mobile, plus an actual file
for every globally unique declared artifact ID. Missing mappings fail before
canonical output. This opt-in leaves preparation and narrow offline catalog
validation unchanged. It binds source commits/trees/clean state and file
hashes/sizes; qualification reports and signature states still require their
independent acceptance and signing evidence.

The publisher checks out protected `LOMI_AUTH_REPOSITORY`/`LOMI_AUTH_SHA` and
`LOMI_MOBILE_REPOSITORY`/`LOMI_MOBILE_SHA` pins in addition to Host/Web/Desktop.
API, Identity and Relay share the account repository commit. Its draft must
contain all declared component payloads, including exported container archives
and Mobile artifacts. Ambiguous identical-payload declarations are rejected.
Both the initial validation and the final production-approved step recheck
all seven source mappings and the whole artifact inventory before publication.
See the [Desktop publication runbook](../../lomi/docs/releases.md#publishing).

## Release build inputs

The Host artifact workflow also requires `LOMI_RELEASE_SET_MANIFEST_FILE` on its
runner and the independent `release_set_sha256` workflow input. It snapshots the
bounded public input, checks its digest, and runs preparation validation with an
exact clean Host source mapping before building. The canonical declaration is
uploaded beside the signed bundle. This records the coordinated source set; it
does not turn an artifact build into qualification or publication. Keep the
manifest outside mapped source worktrees so generating it does not dirty them.

Run `release/build_release.py` on a native release runner with the pinned Rust
toolchain and platform signing tools installed. The target triple must match
the runner because release identity is read from the built executable. The
build requires:

- Five public compile-time pins: `LOMI_HOST_IDENTITY_ORIGIN`,
  `LOMI_HOST_REMOTE_API_ORIGIN`, `LOMI_HOST_RELAY_ENDPOINT`,
  `LOMI_HOST_CLIENT_ID` and `LOMI_HOST_REMOTE_WEB_ORIGIN`. The independently
  configured HTTPS Web origin is used only to construct a workspace link with
  public IDs; it is never inferred from identity/API/relay responses.
- An offline, operator supplied **public** TUF root file and its independently
  recorded SHA-256 digest. The root is embedded in `lomi-update-trust`; the
  raw root file is not copied into the bundle.
- The canonical HTTPS directory URL used for TUF metadata and targets.
- The TUF target names and minimum existing-profile schema. The build runs
  the native artifact's `lomiremote version --json` command and takes the
  release version and maximum profile schema from that exact binary. The
  target metadata operator must write those values and the platform into
  identical `lomiRelease` custom metadata for every binary target. A fresh
  profile has no stored schema and initializes with the new host's current
  schema.

  ```json
  {
    "format": 1,
    "platform": "windows-x86_64",
    "version": "1.2.3",
    "minProfileSchema": 4,
    "maxProfileSchema": 5
  }
  ```

- For macOS, a Developer ID signing identity, its ten character Team ID, and
  an existing `notarytool` keychain profile. The build signs the CLI, updater,
  shell installer and then submits the archive for notarization.
- For Windows, a signing certificate with its private key already available
  in the current user's certificate store, the certificate thumbprint, and an
  HTTPS timestamp service. The build signs all executables and the generated
  PowerShell installer, then verifies their signatures.
  Use an exact 40-hex certificate thumbprint. Both signed TUF targets must also
  carry identical `lomiAuthenticode` custom metadata:
  `{"format":1,"thumbprint":"<40 uppercase hex characters>"}`. The generated
  `build-manifest.json` includes the complete `tufTargetCustom` declaration for
  the metadata operator; the builder does not sign or publish TUF metadata.

The workflow is manual and runs only on the dedicated `lomi-release` runners.
Every runner needs Bash because the workflow assembles argument arrays in Bash;
the Windows runner also needs PowerShell, the Windows SDK signing tools and the
MSVC build toolchain.
Those runners must provide `LOMI_UPDATE_ROOT_FILE`; the workflow input carries
only its independent public digest. Signing identities stay in the runner's
OS signing store or configured CI credential provider. The workflow uploads a
workflow artifact for review; it never creates a GitHub Release or publishes
to the TUF origin.

`build-manifest.json` records the lockfile and protocol hashes, clean source
revision and Git tree, target triple, Rust toolchain versions, target hashes,
and the embedded root digest. Release builds refuse a dirty checkout or a
checkout without a commit. The companion `source-manifest.json` binds the
source fingerprint to the clean Git tree, lockfile, workspace/updater/app
manifests, pinned Rust toolchain file, and protocol file hashes.
The `targets/` files are unsigned TUF
target candidates. An operator must sign and publish metadata through the
separate TUF ceremony before installers can update from them.

Example on a provisioned macOS release runner:

```sh
python3 release/build_release.py \
  --platform macos-aarch64 \
  --release-origin https://updates.example.invalid/lomi/ \
  --target-name macos/aarch64/lomiremote \
  --minimum-profile-schema 4 \
  --public-root /offline/release-root.json \
  --public-root-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --macos-signing-identity 'Developer ID Application: Lomi (ABCDEFGHIJ)' \
  --macos-team-id ABCDEFGHIJ \
  --macos-notary-profile lomi-release \
  --output dist/macos-aarch64
```

The example URL, digest, signing identity and paths are placeholders. Product
version and maximum schema come from the compiled binary.
The build rejects a missing root, mismatched digest, missing signing identity,
unlocked dependencies, unsupported target name or incompatible schema range.

## Linux installer bootstrap

The Linux `install.sh` and bundled updater are the first code that runs, so a
TUF signature fetched by that updater cannot authenticate the updater itself.
For `linux-x86_64` and `linux-aarch64`, the release builder therefore requires
an operator-managed Ed25519 key pair and the independently recorded SHA-256 of
its canonical 44-byte SubjectPublicKeyInfo DER public key:

```sh
python3 release/build_release.py \
  --platform linux-x86_64 \
  --release-origin https://updates.example.invalid/lomi/ \
  --target-name linux/x86_64/lomiremote \
  --minimum-profile-schema 4 \
  --public-root /offline/release-root.json \
  --public-root-sha256 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
  --linux-bootstrap-public-key /offline/lomi-bootstrap-ed25519.pub.der \
  --linux-bootstrap-key-sha256 aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
  --linux-bootstrap-signing-key /offline/lomi-bootstrap-ed25519.pem \
  --output dist/linux-x86_64
```

The signing private key is never copied into the bundle. For an encrypted PEM
key, provide its passphrase only through `LOMI_LINUX_BOOTSTRAP_KEY_PASSPHRASE`;
the builder removes it from its own environment before invoking build tools,
then exposes it only to the OpenSSL signing subprocess by environment-variable
name. It closes stdin, bounds OpenSSL output, and applies a timeout. It signs a
small canonical fixed-line manifest with OpenSSL 3 Ed25519, then verifies the
64-byte signature against the independently pinned public DER key before
reporting success. No key is generated by the builder.

The Linux output directory contains the ZIP plus `<archive-base>.bootstrap-manifest`,
`<archive-base>.sig`, `<archive-base>.der`, `<archive-base>.install.sh`, and
`install-command.txt`. Publish the ZIP and its sidecars at the same canonical
HTTPS `--release-origin` used by the updater. Publish the exact contents of
`install-command.txt` on the independently authenticated product installation
page. That command contains the literal SHA-256 of the generated preflight
script; it downloads the script into a private temporary directory and checks
that digest before executing it. The generated text is one `/bin/sh -c` command;
append `uninstall` to select the installer's uninstall mode. Never use an
adjacent checksum or command file from an unauthenticated bundle as the
independent pin.

The preflight pins the platform, TUF target, product version, embedded root
digest, artifact origin, and exact archive basename, size, and digest. Before
extracting or executing bundle code, it bounds downloads to the expected size
plus one byte, checks the downloaded public-key digest against the independently
pinned key fingerprint, compares the manifest with its expected canonical
contents, verifies the Ed25519 signature, and checks the archive digest. Linux
targets must match the machine's Linux architecture before any download.
Targets and Linux release runners need OpenSSL 3; targets also need curl,
sha256sum, unzip, GNU coreutils `head -c`, and the standard system shell and
core utilities. Run the authenticated preflight command for Linux install and
update; `install.sh` inside the ZIP is an internal entry point after the bundle
has been authenticated. The macOS and Windows bootstrap paths are unchanged.

Rotate the bootstrap key only after publishing the next public-key fingerprint
through the independent installation channel. A key or fingerprint delivered
only inside the bundle cannot authenticate that bundle.

### Installation page input

The existing `lomi-web` site now has a `/server/` route. It contains setup,
startup, system requirements and removal guidance without advertising an
unapproved release. The release builder writes `installation-entry.json` and
a hash-named copy of the public TUF root beside each platform archive. Linux
entries retain the exact generated `install-command.txt` bytes and their hash.
The release workflow uploads these public files with the build artifacts.

After the complete release set has passed its separate approval gates, assemble
its site input offline:

```sh
python3 release/build_installation_catalog.py \
  --release-set /reviewed/release-set.json \
  --release-set-sha256 REVIEWED_CANONICAL_RELEASE_SET_SHA256 \
  --release-origin https://updates.example.invalid/lomi/ \
  --bundle linux-x86_64=/reviewed/linux-x86_64 \
  --bundle linux-aarch64=/reviewed/linux-aarch64 \
  --bundle macos-x86_64=/reviewed/macos-x86_64 \
  --bundle macos-aarch64=/reviewed/macos-aarch64 \
  --bundle windows-x86_64=/reviewed/windows-x86_64 \
  --bundle windows-aarch64=/reviewed/windows-aarch64 \
  --output /reviewed/installation-catalog.json
```

These paths, origin and digest are placeholders. Each archive must be declared
as the corresponding Host binary artifact in the canonical release set. The
five Linux bootstrap files (preflight, manifest, signature, public DER key and
`install-command.txt`) must also be declared as `installer_metadata` Host
artifacts for their exact Linux target. Their individual hashes and sizes must
already belong to the independently approved release set. The adjacent unsigned
`installation-entry.json` is an index, not a source of trusted executable bytes.
The generator checks release-ready declarations, all six archive hashes/sizes,
public-root consistency and actual sidecar/command bytes. It does not perform
qualification, verify recorded signature declarations, sign or upload files.

Review the resulting catalog as part of the separate publication step. Publish
the referenced archive and public sidecar bytes at their exact URLs, including
`release-set.json` and the hash-named root. Supply its exact UTF-8 JSON bytes as
the public site build argument `LOMI_REMOTE_INSTALLATION_CATALOG_JSON`, and its
independently reviewed SHA-256 as `LOMI_REMOTE_INSTALLATION_CATALOG_SHA256`.
The catalog file has no trailing newline; do not reformat it after approval.
Both arguments are public metadata, never credentials. Without both inputs the
page keeps downloads disabled. An inconsistent configured input fails the site
build; the page never fetches install commands from the CMS or release origin.
Enabling these inputs and deploying the site remain explicit release actions.

## Install and update

For Linux, use the authenticated preflight command above; do not execute
`install.sh` directly from an unauthenticated archive. On macOS, use the explicit
administrator-managed command below; on Windows, run `install.ps1` from the
extracted platform bundle. On macOS,
extract the ZIP with `ditto -x -k` so the shell installer's extended-attribute
code signature is preserved. The installer checks the bundle's embedded root
pin and native code signature before using the updater. On Unix,
`lomi-update-trust` verifies
the selected target directly over HTTPS with redirects disabled, bounds every
metadata and target response, checks the signed platform/schema policy, and
commits the TUF state before activation. On Windows, the CLI and its managed
login helper are both independently verified from one TUF snapshot and must
carry the same signed release policy.

The ordinary sh and PowerShell install/uninstall commands accept
`--version VERSION`, `--install-dir ABSOLUTE_PATH`, and `--no-path`; uninstall
also accepts `--purge` to request removal of profile data. The macOS
administrator commands also accept those sh options. `--purge` is valid only
with uninstall. `--version` pins the exact
version of the authenticated bundle. A different value is rejected; obtain that
version's installer through the authenticated installation channel instead of
redirecting an existing installer to unrelated assets. The updater compares
the bundle version with the signed `lomiRelease.version` before reading the
target bytes or activating them, including both Windows executables. A reused
TUF target name cannot silently change the requested version. `--install-dir`
overrides `LOMI_INSTALL_DIR` subject to the same ownership checks and fixed
macOS administrator path. The installers leave PATH and shell profiles alone;
`--no-path` makes that policy explicit. Their full-path setup command works in
a new shell session as well.

On Linux, root first-run selects an ordinary account before any Host setup.
It hands only a sealed copy of its already running release image to the fresh,
permanently unprivileged selected-account process. That process installs the
exact compiled release through the embedded TUF root into its own private
installation, then executes its stable installed CLI for the wizard and
service registration. It does not transfer root's credentials or private trust
state, change permissions under `/root`, or write through the user's home as
root. An existing healthy selected-account installation is reused without an
update. An interrupted existing activation requires the authenticated installer
recovery path, which owns session warnings and managed-service shutdown.

For an existing profile, the installer requires a live authenticated owner to
answer `maintenance prepare --json`. It will not infer schema 0 for an existing
profile whose owner is stopped or unavailable. It displays the terminal count,
waits for the fixed grace period, then stops the registered OS service or the
manual daemon. The updater acquires the profile owner lock before and through
target activation; if a host races the stop, installation fails before changing
the active release.

Each platform keeps content addressed verified objects and a stable regular
executable path. On Unix the service path is `lomiremote`; on Windows the pair
is `lomiremote.exe` and `lomiremote-host.exe`. The active and previous pointers,
stable executables, and `activation.pending` marker share a crash recovery
journal. The marker is written before the first replacement and remains until
the paired active and previous pointers and regular executables are synced.
The host CLI and helper refuse startup whenever that marker exists or is
unreadable. Before invoking the installed CLI, a later installer asks the
standalone updater whether recovery is pending. If it is, the updater stops a
registered service through the native service adapter, acquires the profile
owner lock, reads the actual SQLite schema read-only, checks the journal's
content hashes and signed policy shape for every referenced object, and checks
the restored active pair against that schema. Retained rollback targets are
schema-checked again at rollback time. Recovery restores the complete
journaled executable pair and pointers. It removes the
deny marker only after that coherent state is restored. If service shutdown,
the owner lock, the database schema, either executable, or policy cannot be
verified, the installer stops and leaves the marker in place. It never invokes
the blocked CLI or guesses schema zero during recovery.

After activation the installer verifies the platform signature and starts the
prior host mode. If startup fails, it attempts rollback only after an
authenticated live owner reports the current profile schema. The updater
checks the previous signed release's maximum schema before replacing either
binary. If the current schema cannot be authenticated, it leaves the verified
release and recovery state intact and refuses an unsafe rollback.

Fresh installs reserve a private profile directory and persistent owner lock,
but do not create the host SQLite database or start the host. Holding the same
owner lock used by host startup prevents a concurrent first launch during
activation. The installer prints the exact shell-quoted full-path `setup`
command, including an explicitly configured profile path; a PATH change is not
required to reach the wizard. It does not run a wizard through installer stdin.
Existing profiles must be live for an update in this release path;
stopped-profile migration is intentionally not guessed.

macOS requires an explicit administrator-managed installation for every Host
mode, because the default terminal backend needs the protected image and root
custodian:
`sudo ./install.sh admin-install ACCOUNT [manual|login|boot]` and
`sudo ./install.sh admin-uninstall ACCOUNT [manual|login|boot]`. Omitting the mode
selects `boot`, preserving the earlier command form. The account name is required
on every invocation; the installer does not infer a target from `HOME` or the
invoking administrator. A missing standard profile is prepared by a separate
helper that permanently drops to the selected account before accessing its
directories. A custom profile must already exist with private account ownership.
The system release directory is fixed at
`/Library/Application Support/LomiRemote/Install/ACCOUNT_UID`, where the UID is
resolved from the explicitly selected account, root-owned mode 0755 so the
LaunchDaemon account can traverse it; trust state, activation objects, and the
recovery journal remain root-private, while the stable host executable is
root-owned mode 0555. The ordinary `install.sh` install/update route prints the
required administrator command and exits before changing installation or
profile state. Its legacy private uninstall route remains available. After a
successful administrator install, the script prints the exact
`sudo -H -u ACCOUNT -- ... setup --account ACCOUNT --mode MODE` command with the
protected executable and profile paths safely quoted. Device login, workspace
selection and sharing consent remain in that selected-account wizard.
A nonempty `LOMI_INSTALL_DIR` is accepted for an
administrator-managed install only when it exactly matches this protected
per-account path; setting it to that path behaves the same as leaving it unset.
On Linux, `LOMI_INSTALL_DIR` continues to select the user install location.
Before any service stop or release update, the updater creates or validates an
O_EXCL root-only binding between the install directory, selected account UID,
canonical profile path, and Host mode. Legacy bindings without a mode are
accepted only as `boot`. Updates, rollback, recovery and uninstall must use the
bound mode; changing it requires a separate explicit migration. The binding
remains with TUF state after uninstall, so a different account or mode cannot
adopt the install directory.
Service changes through this protected CLI require administrator credentials
and the existing explicit account/mode. An ordinary-user service command cannot
replace this binding with a per-user Login registration; read-only status
remains available.
For updates and recovery, the installer asks the selected account's live host
for maintenance status, then the updater validates the exact mode-specific
registration and manager job, stops the selected Host, and holds the
service-adapter locks and that account's profile owner lock while checking the
actual database schema and activating or recovering the signed release. If
registration, account, permissions, schema, or either lock cannot be
authenticated, it stops without changing the release. The separate root
terminal custodian is positively drained before changing its executable, then
restored before the account Host resumes. An update resumes only a Host that
was running before maintenance; enabled autostart alone does not start a
stopped Host. Uninstall delegates the complete lifecycle to the bound installed
CLI before removing the program.

All three modes use the protected CLI and the separate root terminal custodian.
`manual` registers no Host autostart and does not start a fresh Host. `login`
registers the selected account's LaunchAgent without starting a fresh Host;
it starts at that account's next login or through an explicit service start.
`boot` installs and starts the selected account's LaunchDaemon. Host work always
runs as the selected account, while the custodian alone has root privileges.
Installing the companion does not log in, configure sharing, or create a shell.
Existing profile ownership and permissions remain unchanged.

## Windows file security service

Windows editor and Git replacements preserve the existing file's complete
security policy, including its audit SACL. Ordinary host accounts cannot read
or reproduce that audit policy themselves. An elevated administrator uses the
signed Windows bundle to install the separate metadata broker for an explicit
host account SID:

```powershell
.\install.ps1 file-security install --owner-sid S-1-5-21-ACCOUNT-SID --confirm-system-service
```

Replace the example SID with the actual ordinary host account SID. The install
mode requires the explicit `--confirm-system-service` flag. The signed installer
verifies its own Authenticode signature and the bundled updater before taking
this branch. The updater fetches the primary CLI target from the bundle's fixed
release origin, verifies its TUF signature and Windows platform policy, then
passes protected content-addressed bytes to the broker adapter. The downloaded
staging CLI is never executed with elevation. Install configures automatic
system startup and starts the broker immediately. The ordinary host continues
to run under its dedicated nonadministrator account.

The updater keeps pinned trust state and source images in a per-owner
ProgramData release area protected for the administrator identity that first
created it. The selected host account cannot write that area. A different
administrator identity cannot adopt it. Malformed or mismatched trust state
fails closed, and uninstall retains the TUF state for future reinstall or
upgrade operations.

Upgrade uses the selected signed release and preserves the broker's prior
running state. Both signed images remain pinned, and the protected journal makes
an interrupted upgrade resumable by running the same command again. The prior
signed release can also finish a pending transaction as a rollback. An
interrupted configuration/registration change fails closed at broker startup
until reconciliation completes. Upgrade the broker before restarting the
ordinary host after a broker release change:

```powershell
.\install.ps1 file-security upgrade --owner-sid S-1-5-21-ACCOUNT-SID --confirm-system-service
```

Uninstall removes only the broker service registration and preserves both the
host profile and updater trust state:

```powershell
.\install.ps1 file-security uninstall --owner-sid S-1-5-21-ACCOUNT-SID
```

The broker accepts metadata requests only from the configured account, creates
private temporary files under that account, and never publishes project
contents. Temporary-file deletion runs under the ordinary host account. A
disconnected client can leave an owner-private temporary file for owner-side
recovery. Removing the broker preserves project files and the normal host
profile.
If the broker is unavailable, replacements that require audit preservation fail
closed instead of silently dropping audit policy.

## Uninstall

On macOS, use `install.sh admin-uninstall ACCOUNT MODE` for the protected Host;
`install.sh uninstall` retains its legacy private-install role. On Linux, use
`install.sh uninstall`; on Windows, use `install.ps1 uninstall`. For a Windows
SCM Host, use `install.ps1 host-service uninstall --account ACCOUNT --confirm`
and add `--purge` when requesting profile removal.
Each installer delegates a configured installation to its installed CLI so the
shared lifecycle fences the Host, attempts cloud access revocation, and removes
the program while retaining offline cleanup state when needed. Use `--purge` to
request profile removal as part of that lifecycle. If the installed CLI or
profile identity cannot be verified, the installer fails closed and gives
recovery and central account revocation guidance. An already absent program is
reported as such; the installer does not claim cloud access was revoked. The
default preserves workspace configuration and TUF anti-rollback metadata under
`INSTALL_DIR/trust`. Keeping this TUF state prevents a later reinstall from
accepting older repository metadata. Removing that trust directory manually is
an explicit security reset and permits the next install to bootstrap again from
its embedded public root.

## Current release boundary

This code prepares the signed build/install/update/uninstall path. No production
public root, private signing identity, notarization credential, signed TUF
metadata, or deployed service is included in this repository. A release runner
must be provisioned and the signed target metadata must be created and reviewed
before any generated bundle can update a user installation. Runtime acceptance
on Linux, macOS, Windows x64/ARM64, interruption injection, and rollback against
schema migration remain operator acceptance work; no acceptance is claimed by
this build code alone.
