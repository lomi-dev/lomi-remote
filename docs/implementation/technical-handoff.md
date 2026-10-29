# Technical implementation handoff

Date: 2026-10-29.

This handoff covers the requested implementation-only phase. It records current
source integration and compilation. It does not accept E1–E7, qualify an
operating system, or approve production publication. No new product tests,
device runs, service installations, signing operations or deployments were
performed in this phase. Historical results retain their original scope.

## Current implementation checkpoint

The first-run specification audit led to the following connected product code:

- [The setup coordinator](../../crates/lomiremote/src/setup.rs) persists the
  `draft → enrolled → local-configured → service-ready → shared` stages,
  stable login/import identifiers and the selected native binding. The real
  [entry adapter](../../crates/lomiremote/src/setup_entry.rs),
  [native runtime](../../crates/lomiremote/src/setup_runtime.rs) and
  [TUI](../../crates/lomiremote/src/setup_view.rs) are called from both default
  launch and `setup`. Completed configuration returns to the dashboard.
  Sharing rechecks the reviewed root/import identity, runtime and current
  authorization in the Store transaction; uncertain publication is observed
  without resubmitting consent.
- Native account selection runs the Host in an ordinary account. Unix
  privileged setup uses a fresh child with permanently replaced credentials;
  Windows uses a fresh native logon and verifies its suspended target token
  before release. Windows passwords are read only from the real hidden console
  into bounded zeroizing storage. Managed startup requires an existing profile
  and checks the setup journal's Host identity before migration or runtime
  changes. A missing database is not recreated from a recorded UUID.
- Windows administrator service management now binds a protected, signed
  CLI/helper pair to the selected SID and signed release metadata. It reserves
  first-install intent before a selected-account initializer, verifies the
  resulting schema before SCM installation, and retains update/recovery
  fences. Ordinary selected-account Start/Stop holds a read-only management
  lock and has only query/start/stop service rights. A known logon failure
  records `CredentialsRequired`; repair requires an explicit transient
  password. The PowerShell Host-service branch stages the protected CLI and
  checks its signer and embedded public root before execution.
- [Host operational observations](../../crates/lomi-host/src/unix/operator.rs),
  canonical IPC and [the CLI adapter](../../crates/lomiremote/src/operator.rs)
  now connect doctor, access, service controls, workspace details/rename,
  registered shell profiles and bounded structured diagnostics. Unknown native
  state is reported as unknown. Fresh dashboard connections verify the same
  Host identity before sending an operation.

The dashboard now includes workspace-name filtering with identity-preserving
selection, bounded single-line paste handling and bracketed-paste cleanup.
Service failures show closed, platform-specific recovery guidance. Failed setup
identifies the service stage and explains the temporary foreground option,
including the macOS requirement for installed signed administrator components.

The additive canonical `doctor.report` method carries bounded checks and the
last retained closed error code. DNS/TLS fields describe actual recent Host
HTTPS attempts, expire to unknown, and never cause probes or retries. Proxy use
is explicitly disabled by transport policy. Configuration, transport,
authorization, permission and malformed-frame errors remain distinct. The CLI
and TUI produce read-only native reports when the Host is unavailable. The
original `doctor` method retains its original diagnostic vocabulary.

Both native IPC clients now use
[one response-binding validator](../../crates/lomi-platform/src/ipc_result.rs)
for the additive methods. It checks the exact result variant, current
Host/runtime and requested workspace/import IDs, guarded consent scope,
renamed target/name and diagnostic cursor/limit. Independent source review
closed the reported rejection and error-classification findings.

Interruption-safe first-profile initialization now has owner-private durable
Creating/Complete receipts, native profile/account identity checks and
same-connection SQLite/WAL recovery. Complete pins both the actual Host and IPC
profile IDs. A known identity is never reconstructed from a missing database.
The macOS updater also has signed-image Pending/Complete receipts and a
defensive coherent snapshot of the actual schema and typed identity. These
receipt paths passed independent source review. A root-owned readable macOS
identity projection now pins both IDs at initialization and every startup mode.
The updater carries a positively observed legacy identity across its lock
handoff and permits only same-identity reinstall after uninstall. Missing or
changed identity remains fenced. These paths compile on both Mac architectures
and have no remaining material finding in the independent source review.
Interrupted Windows credential repair and identity pinning have also passed
independent source review, including both sides of the marked completion write
and fresh-password retry.

The explicit durable-publication observer and synchronous, one-shot Git receipt
boundary are now implemented and source-reviewed. Ordinary cache invalidation
may pause I/O; a durable unacknowledged publication closes other transports.
The Started Git continuation now accepts its own exact retained writer ticket.
Its control lane refreshes only the existing runtime/heartbeat and exact
approved pairing; both peer and heartbeat freshness remain bounded separately
under the original request, signed grant and credential ceilings. Cancellation
drains the actual executor before releasing its writer. Independent source
review closed this own-operation/control/receipt slice. No suspend-and-retry
publication policy change has been approved.
Typed local and remote terminal adapters now capture exact session descriptors
while the Git ticket is retained. Input/resize consume a lock-free IO watch so
Store/Domain guards are dropped before PTY work. The local slice passed source
review. Registry publication and fair sibling/same-connection scheduling have
since passed source review as recorded below; runtime acceptance remains open.

The same pass found and corrected missing normal remote
`operation.status/cancel` dispatch and rejection of all stored operation rights.
Receipt lookup now derives the immutable stored rights and binds the original
actor, workspace and operation to the current peer. Cancellation registers one
typed Shared writer under the verified authority, retains it across pre-Store
contention and never retries the Store call. Its expiry includes the original
request, peer and heartbeat freshness, signed grant and credential ceilings.
Independent source review closed these authority, contention and expiry
findings. The exact-active-Git cancellation lane signals only the matching
executor and retains the repository guard until physical completion.

The scheduling correction now passed independent source review: an eight-message
FIFO bounds retained output allocations, reserves room before async effects,
and preserves logical-message ordering while serving the Git-owning channel and
round-robin siblings. Existing nonterminal responses/streams resume only under
their exact fresh rights. Final and duplicate Git receipts retain their original
Store-derived rights, including `git.execute`, across queued delivery and writer
release. The channel budget is 32, accounting for separate workspace and terminal
transports. The earlier CLI/Desktop checks below precede the last receipt and
shell corrections; they are not final runtime qualification.

The Store completion path now explicitly distinguishes the six terminal-domain
mutations from file/Git effects. Only terminal mutations may submit a workspace
projection or queue a Cloud publication. Git retains its repository-state token
and durable operation events without queuing an unchanged resource projection.
Existing pending publications are preserved. The Store library compiles at the
`lomi-git-store-classification-20261028` checkpoint; both Host receipt callers
now require unchanged workspace/peer state and no pending publication. The
later Host/Store and Desktop compilation checkpoints include this source path;
they do not qualify its runtime behavior.

The release validator now requires the six Host targets, current four Desktop
targets, Android/iOS application packages and the canonical Web bundle.
Platform-specific signature/notarization declarations cannot be bypassed with
an unrelated artifact or an inapplicable platform label. Desktop metadata is a
separate `update_metadata` artifact kind; its JSON and detached signatures must
also be hash-bound before publication. Tag builds now prepare a signed draft.
A separate manual publisher validates a reviewed manifest, protected source
pins and artifact bytes again after the production approval. Final independent
review of exact asset/updater bindings and downstream AUR rerun bindings has
closed its reported findings. These are source-reviewed release product-code
gates; no publication was run.
The full specification audit remains open; this handoff does not declare that
only tests remain.

The next first-run source pass found and corrected the missing full-path setup
guidance in fresh Unix and Windows installers. Every macOS Host mode now routes
through the existing explicit administrator/account/mode installer; an ordinary
Mac install exits with that command before changing disk state. Successful
administrator installation prints the exact selected-account setup command.
Independent source review closed these routing and quoting findings.

The inaccessible root-private Linux executable handoff has a new Linux-only
sealed-image continuation and selected-account installation path. It uses the
running root image, a fresh permanently unprivileged process, compiled public
release coordinates and the existing TUF activation engine; no root credentials
or private trust state are transferred. Healthy selected-account installations
are reused without an update. A pending existing activation is left for explicit
installer recovery rather than silently stopping its service from plain setup.
The sealed-image/TUF path passed source review. A subsequent security pass
found that its Unix credential-drop helper still inherited the administrator's
controlling TTY. The new private-PTY/session boundary, bounded interactive and
noninteractive output relays, scoped signal handling, one-shot EOF and terminal
restoration passed independent source review and platform checks on Linux
x86_64 and macOS aarch64. Non-TTY streams are preserved. Linux also arms parent
death after the credential drop; macOS uses normal private-PTY hangup, without
claiming containment of deliberately detached descendants. A lost or signaled
setup result is reported as uncertain (exit 7) and is never automatically run
again by the parent.

The sh and PowerShell installers now accept exact bundle-version pins,
absolute install-directory overrides and explicit no-PATH mode. Pinned updater
entrypoints verify signed `lomiRelease.version` before downloading target bytes
or activating them, including the Windows administrator Host path and both
Windows executables. Windows PowerShell 5.1 path checks now use Framework APIs
rather than the unavailable Core-only `IsPathFullyQualified` method. Independent
source review closed the option/version/compatibility findings. The macOS updater
compiles at `lomi-installer-version-pin-macos-20261028`; Linux cross-compilation
stops at the missing `x86_64-linux-gnu-gcc` C tool before product Rust checking.
The Linux platform helper itself passes its target check. No test or runtime
acceptance is inferred from these source/compilation results.

The `lomi-git-operations-installer-integrated-20261028` checkpoint compiles the
native CLI and updater together on macOS (public root compilation fixture).
`lomi-git-operations-desktop-integrated-20261028` compiles native Desktop against
the same Host/platform sources. The later
`lomi-remote-cancel-final-cli-20261028` and
`lomi-remote-cancel-final-desktop-20261028` checks also pass with the typed
cancellation writer and freshness fixes. The head-of-line scheduling and channel
capacity changes above are not included in that compilation checkpoint.

A separate source audit traced all 39 canonical RPC variants through normal
ingress, current-rights admission and their concrete execution paths, including
the dedicated stored-operation rights gate. This establishes source routing;
it does not establish method-by-client runtime acceptance. The later independent
scheduling review above closes the reported source finding.

The subsequent product-workflow audit found four additional required source
gaps. The canonical ordinary-shell bundle and typed native/WSL launch descriptor
now have source-reviewed production callers, so headless profiles do not depend
on Desktop-generated hooks. The original request gate bounds shell materialization
and every WSL helper launch. Host-side bounded OSC 7 parsing, atomic CWD stream metadata and Desktop's
separate `observedWorkingDirectory` now passed independent source review. The
grid payload/profile is unchanged; explicit null clears the observation without
changing the configured start folder or restart policy. Canonical contract,
WASM and consumer-snapshot regeneration is complete at the Oct 29 checkpoint.
The six existing
canonical metadata examples were mechanically updated with the required null
member; no new test scenarios were added or executed.

The CLI now has read-only `logs [--follow] [--json]` code on one authenticated
runtime connection, bounded pages and a closed diagnostic vocabulary. Its
malformed-frame classification passed source review and an integrated CLI
compilation checkpoint. The existing `lomi-web` site now has a
`/server/` installation adapter. Downloads require independently pinned public
catalog input. The offline catalog generator binds every Linux bootstrap file
and command to approved `installer_metadata` hashes in the release set; native
archive verification precedes extraction and script execution. These paths
passed source review and the site type check. Actual release input and
publication remain separate, unperformed operations.

The populated workspace removal workflow now has schema-12 Store intent,
exact-session checkpoints, uncertainty/recovery and finalization APIs. Independent
source review closed migration, namespace-overlap and stale native-start
findings. Host native editor/Git starts carry the original context/root/fence
into the guarded Store transaction. The exact-epoch TerminalService stop API is
saved. The actor/coordinator now performs the original-authority physical stop
once, records each exact-session cleanup, and reserves closed bookkeeping turns
for settlement without extending physical authority. Read-only removal status,
CLI and TUI preserve uncertain outcomes and do not repeat cleanup after a lost
response. Independent source review closed these paths; the CLI compilation
checkpoint and the later connected CLI library check include the final
lost-response error mapping correction.

Top-level CLI update/uninstall, the Windows trusted maintenance handoff and
identity-preserving profile purge are in implementation/integration review. Spec ADR-19
records the purge inventory: mutable Host data and Git credentials may be
cleared only after positive revoke acknowledgement; installation identity,
public identity binding, project roots and TUF anti-rollback state remain.
Offline uninstall retains revoke obligations and reports them. These are
product-code work, not deferred tests.

The later management/storage audit found missing Identity v2 portal routing,
selective account Host management, local Host naming and Linux Secret Service.
The explicit production/development proxy allowlists and direct-browser,
read-only Host inventory are implemented. Account-page confirmation prepares
management authority only for the selected mutation, preserves the captured
epoch and reconciles lost replies through reads. Host-wide management revoke now
fences pending approved enrollments, which also have exact withdrawal and
lifecycle-read routes. Independent source review closed the reported findings;
Auth and portal typechecks pass. It does not use the Remote runtime table or widen its ACL;
connection and sharing status are explicitly unobserved.

Local names now use bounded `LocalHostName`, native OS hostname defaults,
one-time Store initialization, compare-and-set IPC and resumable setup/status
presentation. Interrupted changes retain their original CAS expectation and
allow a new reviewed choice without overwriting a concurrent name. Independent
source review and the current native Host/CLI library check pass. No name is
published as plaintext Cloud inventory metadata. Linux Secret Service now uses
the exact account's authenticated local session bus, pins the service owner and
persistent collection, and retains the common profile storage lock. Locked or
unavailable storage fails closed without a prompt or plaintext fallback.
Independent source review closed default-collection drift and socket-write
deadline findings; Linux and native platform checks pass. Owned bundle buffers
are erased, but zbus transport copies do not provide a whole-transport
zeroization guarantee. All six purge/storage findings are now source-review
closed. Restricted purge opening preserves terminal evidence; a schema-14
ledger retains up to 4,096 attempt IDs without eviction; all provider clears
confirm durability on retry. Store, Host and native platform checks pass.
The Windows platform library now compiles with the maintenance module; the full
Windows CLI cross-check remains blocked by C SDK availability.

The `lomi-host-metadata-*-20261029` generation checkpoint refreshes canonical
Rust/JS contracts, both WASM packages, Web/mobile snapshots, native mobile
protocol inputs and cross-target provenance. Auth consumes the same rebuilt
authority archive through content-addressed package and Bun SHA-512 pins.
Desktop, Web and mobile typechecks pass. The macOS `release-maintenance` binary
path compiles with public fixture pins; no production root, certificate,
signature, release activation or publication was used.

Installer uninstall now enters the shared installed-CLI lifecycle before any
frontend recovery or service stop. Native exit codes and durable handoff
acceptance are preserved. Unix checks the exact activated or journal-prior
image before execution; PowerShell treats a missing native exit result as
uncertain failure instead of reusing a prior probe's success. Independent
source review closed both paths. Shell syntax and the native updater binary
check pass. `EmptyHostProfile` additionally retains the actual native owner
lock and permits only the persistent lock file, checking both its named object
and directory before/after. The updater can remove a never-configured ordinary
installation under that proof without generating Host IDs. Its source review
and Linux/macOS/Windows platform checks pass. CLI caller integration and Windows
worker phases have since passed the source reviews recorded below.

The next lifecycle review found concrete product-code gaps in Cloud revoke ACK
observation, protected macOS owner/root routing, default update selection,
interrupted activation, Windows copied-worker handoff and failed-health rollback.
Those caller corrections now passed independent source review, including
selected-owner readiness, exact result-code proof, reserved stop/re-fence
budgets, phase-independent ACK observation, final login-intent cancellation and
exact identity retention across recovery. Windows Boot discovery, per-owner
metadata/traverse-only root grants under a bounded cross-owner ACL lock, native
console prompts and copied-worker status guidance also passed source review.
The final macOS CLI binary check with `release-maintenance` passes at
`lomi-maintenance-final-cli-bins-20261029`. A worker's earlier plain CLI check
without a target was an Apple-host check, not Linux evidence. Full Linux
CLI/updater cross-checking still lacks its C toolchain. The Windows platform
library compiles, but the full Windows CLI cross-check is blocked before Rust type checking by missing
Windows C SDK headers. No SDK was installed.

The new offline maintenance API now holds the real selected-owner lock and
validates the complete receipt, native profile object and both durable IDs. It
opens only the existing SQLite database, allowing ordinary WAL recovery without
Host schema migration, runtime allocation or cleanup-evidence loss. An explicit
logout cancels active and deferred login intent atomically with the authorization
fence; a no-intent pending retry retains its generation. Existing unfinished
workspace-removal manifests keep their exact fence. Independent source review
closed these findings, and the final Host/Store library check passes at
`lomi-maintenance-offline-fence-final-20261029`.

macOS release activation now checks strict Developer ID Application signatures
and the exact compiled Team pin on content objects before journal/pointer
publication, including recovery and rollback. The updater and CLI use the same
release-builder signer input; a macOS release-root release build requires that
pin. The staged file is privately owned, opened without symlink traversal and
rechecked against its pinned metadata and path. Independent source review found
no remaining material issue in this slice; platform/updater compilation passes
at `lomi-macos-release-team-source-20261029`. No native signature or certificate
operation was executed. Desktop native compilation also passes at
`lomi-host-metadata-desktop-native-20261029`, with its dependency lock refreshed
for the connected Host/platform graph. These results do not declare technical
completion or production readiness.

The later E4 audit found a first-use Desktop selector dead end: settings mounted
the same client that rejected absent target references. The client now has an
explicit selector entry for settings and a workspace entry for URL-based remote
windows. Only the latter rejects a missing/invalid parsed reference. The normal
selector reaches the canonical inventory/approval panel and native adapter;
connection and terminal creation retain their existing explicit choices.
Independent source review and Desktop type checking pass at
`lomi-desktop-remote-selector-types-20261029`. The production Desktop Vite build
also passes at `lomi-desktop-selector-production-build-20261029`. Remote Web's
Astro build passes at `lomi-remote-web-canonical-production-build-20261029`,
including zero type diagnostics and canonical worker/WASM/static-artifact
validation. An initial direct Vite invocation was the wrong entry command for
that Astro project and failed before transforming modules; it establishes no
product build failure or passing result.

The followup E7 audit found missing actual-source/artifact bindings for the
account and Mobile components in the coordinated publisher. Its opt-in
complete-mapping mode now requires all seven local Git checkouts and every
declared artifact file. The workflow pins the account and Mobile repositories,
uses the same account commit for API/Identity/Relay, and repeats all source and
artifact checks after production approval. The draft must contain every product
payload, including exported container archives; Desktop updater checks remain
scoped to Desktop metadata. Independent source review found no remaining
material issue in this slice. YAML parsing, syntax
checking all 11 shell blocks and parsing all four embedded Python blocks plus
the validator pass; no workflow, release input, signing or publication was run.

The platform library also passes explicit checks for both
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` at
`lomi-platform-linux-targets-final-20261029`. This is platform-library evidence,
not a full Linux Host/CLI build. Both previously supplied LAN build hosts timed
out at SSH connection admission during compiler discovery; no remote build,
service or product test was started. Access to an existing Linux/Windows build
environment remains requested for the full target checks.

The current mobile Rust product module builds in release mode for the physical
iOS target and both simulator targets at
`lomi-mobile-ios-canonical-rust-build-20261029`. Its device archive and the
combined simulator archive were packaged into the actual vendored
`LomiMobileCrypto.xcframework`, with copied library/header hashes verified
against those compiled inputs. The build record binds the current module
`PROVENANCE.json` and Cargo lock; no app was installed or run and no signing
identity was accessed. The existing crypto provenance verifier still passes.
An Android-target Rust check stops in `ring`'s C build because Android NDK
compilers are absent; it does not establish Android Rust/FFI compilation.
Only missing locked Cargo dependency sources were fetched, without installing
a toolchain or SDK. Full Android native packaging remains unverified.

The later VPS discovery resolved the Linux x86_64 compiler limitation without
installing anything: Rust 1.98.1 was present and could be selected explicitly
instead of setting a global default. A private, hash-verified 815-file input
copy passed native `cargo check --release` for the CLI and updater binary
targets with the actual `release-maintenance,linux-setup-handoff` feature set.
`lomi-native-linux-release-features-final-20261029` records the final compiler
result, and the input inventory stayed unchanged. Its source SHA-256 is
`326e3d5e01f7d8873db19d63f2ce4d98cbc693c34935d825fc102c5b660aa350`;
all admitted local files still match. The private build cache remains available
for further code fixes; its owned SSH control connection was closed. No Host
or updater executable, service, test, login, sharing or Git operation was run.
The initial ordinary Unix updater call incorrectly passed `Some(version)` to
an exact-string API, and the managed Mac caller omitted `Some` for its optional
version API. Both source call sites are corrected. An intermediate release
check also rejected a noncanonical compilation-fixture relay path; correcting
that input did not change product validation policy. Native Mac aarch64 CLI and
updater release-profile checks now pass at
`lomi-native-macos-release-features-final-20261029`, with macOS deployment target
14 and public fixture pins. No release signing identity was accessed.

Desktop Linux's first-run auth adapter previously listed only protected files,
despite the Host/TUI supporting Secret Service. The native adapter now lists
Secret Service first and builds the canonical no-keychain/no-file-ack config.
The protected-file alternative still requires explicit OS-permissions consent,
and the exhaustive UI provider labels use the generated union. Provider changes
clear file consent. Independent source review and the type/native Mac checks
pass at `lomi-desktop-linux-keyring-*-20261029`; the frontend production bundle
was rebuilt. Full Linux Desktop SDK/runtime verification is not inferred.

The subsequent full native macOS `cargo build --release` linked both the CLI
and updater with `release-maintenance`. The checkpoint is
`lomi-native-macos-release-link-final-20261029`; its local JSON record contains
the output sizes and SHA-256 values. Both outputs are arm64 Mach-O executables;
the CLI declares minimum macOS 14 and links only system libraries, Security and
CoreFoundation. The 815-file admitted source inventory still matches the Linux
checkpoint above. These builds embed public fixture origins/root/team pins;
they are compilation artifacts, not production-signed releases. Neither
executable was run.

The complete local iOS staging application also passed the Release native build
at `lomi-mobile-ios-app-native-link-final-20261029`, using the existing locked
Pods and the refreshed Rust XCFramework. This compiles Swift/native modules,
links the application and packages the current Metro/Hermes bundle. The output
is `dev.lomi.mobile.staging`, minimum iOS 16.4, with code signing explicitly
disabled and no automatic package resolution or package updates. Its local JSON
record binds the executable and `main.jsbundle` hashes. The installed Pods
manifest matches `Podfile.lock`. This is not a signed production IPA, device
execution or iOS acceptance result; no application was installed or launched.

A further bounded independent source review of Windows CLI/SCM/logon-helper/
updater packaging and Android ABI/build-hook/Gradle/Kotlin/JNI integration
reported no additional material code finding. This source review does not
establish complete Windows or Android product compilation, native application
packaging or runtime acceptance. Their missing SDK/NDK environments remain
compilation limits.

The subsequent full Desktop build exposed a real native artifact collision:
the canonical protocol is both a build dependency and an application dependency,
and its two feature-resolved units emitted the same unhashed `rlib`/`cdylib`
paths. The
canonical protocol now builds normally as `rlib`; its WASM builder explicitly
requests `cdylib` through Cargo. Independent source review closed this change,
the native Desktop release link passed without an explicit `--target`, and both
WASM builders passed. Canonical Web/mobile snapshots and cross-target provenance
were regenerated. Auth now pins the immutable authority package
`lomi-authority-crypto-wasm-sha256-62c51fa9b0ac8b44382d022a985f43fbecbb35b87c192768575adb6cf4bba4be.tgz`
and its exact SHA-512 in `bun.lock`, without running an install. The archive's
public TypeScript API and runtime wrapper match the preceding package; the
compiled WASM and source provenance changed. The normal Remote Web and Desktop
frontend production builds pass with the new WASMs. Bare native Cargo linking
does not prove Tauri asset embedding; the explicit `tauri/custom-protocol`
Desktop build is tracked separately below.

The new admitted Host input inventory SHA-256 is
`93dafa61e89d94bd0a16ca39c4543585567fa142466a30ff00f286397c3c7314`.
Both native macOS arm64 and Linux x86_64 CLI/updater full release builds pass
with this unchanged 815-file input copy at
`lomi-native-{macos,linux}-release-protocol-rlib-20261029`. Linux includes
`release-maintenance,linux-setup-handoff`; Mac includes `release-maintenance`.
The Linux ELF dynamic dependency inspection lists only libc, libm, libgcc and
the system loader. Public fixture release pins remain in these compilation
artifacts. No executable was run and the owned VPS SSH control connection is
closed. This does not qualify Ubuntu/Debian ABI baselines or other architectures.

The mobile confirmation audit found and closed a stale native Alert path:
close/restart previously could select a replacement session after reconnect
under the same pane. Confirmation now retains the exact Core, attachment,
navigation scope, channel generation and signed session/epoch hint. It checks
them before creating an operation ID or entering the journal/dispatch path,
and gates old completion UI. Current capabilities/pending state are read at
confirmation. Ended-terminal restart remains permitted. Independent source
review closed this finding and found no corresponding issue in the remaining
mobile confirmations or shared Web/Desktop terminal actions. Product TypeScript
passes; lint reports zero errors and 16 warnings. No tests were run.

After both corrections, the iOS Rust libraries were rebuilt for device and both
simulator architectures, privately staged and atomically repackaged into the
XCFramework. Its source provenance SHA-256 is
`822b320e31eb9a6e9a5e4859b8035c3d1734c42271fd1a9ba02ae88c0d2c17e9`.
The full unsigned staging Release app rebuild passes at
`lomi-mobile-ios-app-confirmation-protocol-rlib-build-20261029`; its JSON record
binds the executable and JavaScript bundle hashes and positively matches the
copied device Rust library to the newly built XCFramework. This supersedes the
earlier app checkpoint for current source coverage, without device execution,
signing or production IPA creation.

## Requirement coverage

The IDs below come from `remote-server/00-cel-i-wymagania.md`. The links identify
the implemented paths; their runtime acceptance remains separate.

| Requirement | Current implementation |
| --- | --- |
| REQ-01: headless Rust host | [Host entry and platform dispatch](../../crates/lomi-host/src/lib.rs), CLI and service adapters use the Rust coordinator without Tauri, WebView or the old Remote Node helper. |
| REQ-02: one owner | [Shared profile](../../crates/lomi-platform/src/lib.rs), [owner domain](../../crates/lomi-host/src/unix/owner_domain.rs) and [Desktop bridge](../../../lomi/src-tauri/src/shared_host.rs) use stable imported workspace identities and the Host lifetime lock. |
| REQ-03: device authorization | [Host auth worker](../../crates/lomi-host/src/unix/auth.rs), [credential lifecycle](../../crates/lomi-host-auth/src/lib.rs) and [identity credentials](../../../auth-app/src/host-credentials.ts) retain exchange/rotation recovery and central revocation. |
| REQ-04: shared consent policy | [Setup coordinator](../../crates/lomiremote/src/setup.rs), [TUI wizard](../../crates/lomiremote/src/setup_view.rs) and Desktop use the same Host share/unshare policy. Setup consent additionally binds the reviewed root/import, runtime and authorization generation. Login does not imply sharing. |
| REQ-05: terminal service | [Terminal service](../../crates/lomi-terminal/src/lib.rs), [remote terminal](../../crates/lomi-host/src/unix/remote_terminal.rs) and shared renderer implement snapshots, streams, input/resize leases and reconnect. |
| REQ-06: terminal management | [Remote edit admission](../../crates/lomi-host/src/unix/remote_terminal_rename.rs) and [PTY lifecycle](../../crates/lomi-host/src/unix/remote_terminal_lifecycle.rs) connect create/split/rename/move/close/restart to the shared domain and receipts. |
| REQ-07: private views | [Desktop projection/merge](../../../lomi/src/shared-host.ts) and [Workbench ownership](../../../lomi/src/Workbench.tsx) preserve local editors, browsers, drafts and protected AI terminals. |
| REQ-08: Explorer | [File engine](../../crates/lomi-files/src/lib.rs), [remote reads](../../crates/lomi-host/src/unix/remote_files.rs), native watches, Web/Desktop Explorer and mobile support bounded listing, name search, preview and revision-checked path mutations. Search descendants are read-only until a verified directory is entered. |
| REQ-09: Git | [Git service](../../crates/lomi-git/src/lib.rs), isolated WASI reads, network worker and [Host mutations](../../crates/lomi-host/src/unix/remote_git_mutations.rs) implement status/diff/log/show, stage/unstage/commit/fetch/ff-only pull/push, physical repository guards and uncertain outcomes. |
| REQ-10: client service parity | [Remote Web workspace](../../../remote-web/src/RemoteV2Workspace.tsx), its Desktop adapter and [mobile Core](../../../mobile-app/src/remote/core.ts) use generated contracts and the shared RPC core. Mobile includes Explorer search and paginated Git reads. |
| REQ-11: attachment without shell creation | Existing-terminal open and restored views use attach. Creation/restart are explicit separate mutations. Browser window identity is durable locally and scoped to the current authorization/window. |
| REQ-12: independent Host lifetime | Native owner/service adapters outlive GUI/TUI attachments. Persisted descriptors do not claim to restore a lost PTY. The default [macOS custodian](../../crates/lomi-terminal/src/supervisor/macos_privileged.rs) uses a separate privileged controller and positive cleanup proof. |
| REQ-13: revoke and no replay | [Remote ingress](../../crates/lomi-host/src/unix/remote_ingress.rs) retains original deadlines and fresh gates before effects. Journals preserve unknown results; remote status/cancel uses stored rights and a retained, freshness-bounded writer. Started/final/duplicate Git output retains bounded FIFO scheduling and original stored rights. Terminal input is not persisted or retried. Pending Cloud publication remains fail-closed. |
| REQ-14: E2EE and privacy | [Canonical crypto](../../crates/lomi-remote-crypto/src/lib.rs), generated boundaries and native/WASM adapters protect channel data. Client background/revoke paths clear plaintext and control intent. View hints contain identifiers only. |
| REQ-15: installation and recovery | [Release builder](../../release/build_release.py), [Linux authenticated bootstrap](../../release/linux-bootstrap.sh.in), native signatures, [updater](../../crates/lomi-update-trust/src/lib.rs), activation marker and schema policy cover install/update/rollback/uninstall. Mac administrator installations bind Manual/Login/Boot mode. |
| REQ-16: migration and private data | Desktop import/binding reconciliation, mixed-view merging, joined native file effects and durable receipts preserve projects and private editor state. Default packaging excludes the old Remote helper while retaining private Chat/AI resources. |
| REQ-17: canonical sources | [Cross-target provenance](../../CROSS-TARGET-PROVENANCE.json), generated contract/renderer snapshots, [release-set schema](../../release/release-set.schema.json) and its preparation workflow bind source revisions, compatibility, artifacts and recorded qualification declarations. |

Consumer configuration, ownership, lifecycle and typed authority/error paths are
implemented in the identity/API sources. Cloud publication/heartbeat and lost-ACK
GET reconciliation are connected in [the worker](../../crates/lomi-host/src/unix/cloud.rs)
and [durable publication state](../../crates/lomi-host-store/src/cloud_publication.rs).
Full S5–S7 and real-relay acceptance are not established by this source map. The
historical S7 run failed its completion check and remains failed; no new timing
result is inferred from compilation.

## Final source-review corrections

The final review closed the reported Mac custody, service-mode, updater,
shared-RPC deadline/buffer, artifact provenance and release-manifest findings.
It also closed the following product integration findings:

- Browser refresh reattaches the exact saved pane/session only after fresh
  approved pairing and workspace snapshot membership checks.
- Mobile process restart first rehydrates the exact saved pairing through a
  bounded GET and the normal signature/authority checks. An unknown result
  fences replacement pairing creation and uses capped read-only backoff.
- Mobile navigation does not save a terminal intent before navigating. Only
  the focused, validated terminal route publishes its hint. Cancelled writes
  remain hidden until withdrawal is confirmed; optional storage failure does
  not silently prevent a current authorized terminal attachment.
- Mobile name search and Git diff/history/show have bounded continuation,
  explicit truncation and current-context guards for delayed responses.
- Linux authenticates the bootstrap command's downloaded script against its
  literal independent digest, then verifies the key, signed manifest and
  archive before running bundle code. Signing passphrases reach only the
  OpenSSL signing subprocess. Actual keys were not accessed.

## Compilation and artifact evidence

The recorded compilation checkpoints have these results. Later changes under
implementation above require their own checks before closure:

| Check | Result and scope |
| --- | --- |
| Rust CLI/Host | `cargo check -p lomiremote --bins --locked`: passed on macOS with the default privileged terminal backend. |
| Native Desktop | `cargo check --manifest-path src-tauri/Cargo.toml --bins --locked`: passed on macOS after service routing and default packaging changes. Existing warnings remain. |
| Updater | `cargo check -p lomi-update-trust --bins --features release-root --locked`: passed on macOS. The repository's public compilation fixture supplied the root input; this does not establish a production trust root. |
| Desktop frontend | TypeScript and production Vite bundle: passed after the shared Remote Web changes. |
| Remote Web | Normal `pnpm run build`: passed, including Astro diagnostics, both static routes, CSP/output checks and canonical Worker/WASM asset digests. |
| Mobile frontend | Final TypeScript and iOS/Android Metro+Hermes exports: passed. These are JavaScript/bytecode builds, not physical-device or complete native application qualification. |
| Release code | Python source compilation, release-workflow YAML/Bash/embedded-Python syntax, installer/template shell syntax and the generated command's shell template: passed. Release/signing code was not executed. |
| Managed provenance | Snapshots regenerated; mobile inventory verifies 91 crypto, 26 protocol, 14 native-product, 13 build and 14 remote-adapter inputs. Cross-target manifest regenerated. |

The connected first-run CLI/Host, native Desktop and macOS updater also pass
compilation at the `lomi-first-run-*-20261028` checkpoints. Native platform
checks pass for macOS, Linux and Windows. This does not establish complete
Windows Host/updater typechecking: their C dependencies stop at missing Windows
SDK headers before the affected Rust product modules can be compiled.

The newer `lomi-first-run-ipc-bindings-final-20261028` checkpoint compiles the
CLI/Host after the shared native result validator and Doctor integration. At
the `lomi-doctor-*-20261028` checkpoints both WASM packages and generated
contracts were rebuilt, Remote Web's normal production build and Desktop/mobile
TypeScript passed, and the iOS crypto XCFramework was rebuilt for device and
both simulator architectures. Android crypto JNI libraries also rebuilt for
ARM64 and x64. These are library/source builds, not mobile app or device
acceptance.

`node scripts/sync-remote-web-packages.mjs` now also regenerates the mobile
native protocol from the canonical Rust source. It checks existing snapshot
bytes, materializes only the canonical workspace edition/rust-version Cargo
adaptations, and updates the snapshot provenance. Its `--check` verifies the
canonical manifest as well as protocol source; no manual wire-copy or digest
edit is needed for this integration. Cross-target provenance was regenerated.

The later `lomi-identity-*-20261028` checkpoints compile the CLI and native
Desktop with the completed administrator identity integration, and refresh both
WASM provenance records after the updater dependency graph change. Consumer
snapshot and mobile provenance checks pass. They do not qualify the still-active
Cloud receipt/closure change or execute any product acceptance scenario.

Final transient build outputs are in `/tmp/lomi-desktop-product-final-20261028`,
`/tmp/lomi-mobile-workspace-export-ios-final` and
`/tmp/lomi-mobile-workspace-export-android-final`. Remote Web's normal build
is in its `dist/` directory. Build logs use the `lomi-*-final-20261028` prefix in
`/tmp`; they are local compilation evidence, not release artifacts.

## Remaining verification and release operations

The six scenarios in `remote-server/07-realizacja-i-odbior.md` remain unaccepted.
Their implementation paths are covered above: Linux bootstrap/device login and
service lifetime; shared Desktop/TUI workspace; simultaneous Web/mobile
attachment; private mixed views; unshare/revoke and uncertain effects; signed
updates with schema-safe recovery. No new scenario was executed in this phase.

Remaining qualification includes Consumer S5–S7, actual Cloud/relay/reconnect and
lost-ACK behavior, target-system boot/logon/logoff/secret storage/containment,
client method parity, physical Android/iOS, OS/architecture matrix, soak,
performance and the external security review. Full Windows Host/updater
compilation still needs the Windows C SDK environment; the existing laboratory
Windows 10 does not qualify Windows 11 or Windows Server. Windows 10 can still
provide compiler evidence if its Rust/MSVC/SDK environment becomes accessible;
that does not require running product acceptance there. Current Android Rust/JNI
compilation and application packaging need the NDK, independently of physical
device availability. Full Linux arm64, Mac Intel and Windows arm64 product
builds also remain unproven with the currently available target tools. These
compiler limits prevent declaring the whole implementation-only scope complete.

The final Desktop build at `lomi-desktop-embedded-assets-release-20261029`
passes with `--features tauri/custom-protocol`. Its fresh compiler dependency
record binds all 112 current `dist` files, including both regenerated WASMs.
The local JSON record binds the executable SHA-256
`675d7a4307bc822ab9439ff31438966dd1a19aba4cce4f134a38bf74d945f996`
and asset digests. This is the embedded-frontend compilation checkpoint;
the earlier bare-Cargo results establish native linking only. No installer was
bundled and the program was neither executed nor production-signed.

The final source-provenance checkpoint
`lomi-protocol-rlib-final-source-provenance-20261029` also passes: 67 generated
schemas/declarations/validators, both WASM outputs, runtime snapshots, mobile
source inventories and the cross-target manifest match current inputs. These
are compiler and source-artifact checks, without product tests. The known
production-source findings reported in this phase are closed; full platform compilation and the
separate qualification results remain required.

Release operations also require clean committed source revisions, the
whole-release declaration, real public origins/TUF root and signed metadata,
provisioned signing identities and Linux bootstrap key/pins. The exact generated
Linux installation command must be distributed through the independently
authenticated installation page. Cutover, renewed sharing consent and
publication are separate explicit operations. No production approval is implied
by this handoff; failures found during qualification may require code changes.
