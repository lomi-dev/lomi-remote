# Product delivery status

Updated: 2026-10-29. Production acceptance remains open. Progress is tracked by
accepted scenarios; unit-test counts are not a percentage of product completion.
The detailed evidence history remains in [progress.md](progress.md).

## Current coding scope

The current instruction is implementation only. No new automated, browser,
device, service, VM, or acceptance tests are being run. Implementers compile,
check types, generate distributable artifacts, and obtain independent source
review. Historical passing results below apply to their original source
checkpoints and do not qualify the new integration.

The current product code includes journaled Git mutations and network actions,
native file watchers and file mutations, local and relay workspace subscriptions,
mobile v2 terminal/Explorer/Git actions, a shared Web/desktop Git panel, shared
desktop host ownership, release bootstrap pins, and interrupted activation
recovery. Desktop integration, macOS custody, and administrator-managed updates
have source-reviewed implementations and scoped compilation. Client view
restoration, mobile Explorer search, Git read pagination and authenticated Linux
bootstrap now have source-reviewed implementations and final frontend builds.
The resumable first-run coordinator is now connected to the CLI and TUI,
native account selection, device authorization, workspace import, service
readiness and guarded sharing consent. Completed setup returns to the
dashboard; reconnects and service startup retain the durable Host identity.
The Windows administrator service/updater and protected PowerShell Host
bootstrap are connected in source, including an explicit transient credential
path and read-only selected-account service control. Doctor, access, bounded
structured logs, workspace details/rename and registered shell profiles now
use canonical Host IPC and native observations. These integrations compile on
macOS; the Windows platform library also compiles for its native target.
The owner initialization receipts, Windows identity/credential-repair lifecycle
and protected macOS startup identity/reinstall paths have passed source review.
The durable-publication closure observer, exact one-shot Git receipt and own
Started continuation/control/pairing-refresh paths have source-reviewed
corrections. They preserve heartbeat, grant/session revoke and original budgets.
Typed local/remote terminal adapters are saved, and the local slice passed
source review. Normal remote operation status/cancel now has concrete dispatch,
stored-rights admission and a retained typed cancellation writer. Independent
source review closed its authority, Busy-retention and freshness findings.
Registry/sibling/same-connection scheduling now passed source review, including
bounded message ordering, pre-effect reservations and original StoredRights on
all final/duplicate Git receipt paths. The registry allows 32 bounded transports
to account for separate workspace/terminal channels per client. Final integrated
checks must include the last shell and receipt corrections.
Store completion now queues Cloud publication only for terminal-domain
mutations, while file/Git effects preserve their own revisions and operation
events. The Store library compiles; Git receipt callers now require no outbox.
The separate manual publisher and its complete manifest/updater/asset bindings
have passed source review.
The next first-run pass corrected full-path setup guidance, routes every macOS
Host mode through its protected administrator installation, and adds a sealed
Linux root-to-selected-account image handoff with per-user TUF activation.
Installer version/directory/no-PATH options and signed version checks are saved.
The Linux sealed-image/TUF path and installer option/version changes passed
source review. Private-PTY isolation of the administrator terminal during the
Unix account switch, bounded relays and signal/EOF restoration now also pass
source review and Linux/macOS platform checks. Windows PowerShell 5.1 path
validation passed source review;
full Linux CLI/updater cross-checking lacks `x86_64-linux-gnu-gcc`, while its
platform helper and the macOS updater compile.
Full Windows Host/updater compilation
is blocked before Rust typechecking by unavailable Windows C SDK headers.
The integrated macOS CLI/updater and native Desktop checks passed. The later
CLI and Desktop checks also pass with the retained cancellation writer and
freshness fixes. They precede the remaining channel scheduling/capacity changes.
A separate source audit traced all 39 canonical RPC variants through normal
dispatch and admission; client runtime acceptance remains deferred.
Technical completion has not yet been declared. The current map and compilation checkpoint are in
[technical-handoff.md](technical-handoff.md).

A further workflow audit found missing Host-owned shell integration, populated
workspace removal, promised CLI automation entrypoints and the installation
page. The shared native/WSL shell builder, profile-owned assets and original
prelaunch cancellation gate passed source review. The bounded Host CWD parser,
atomic stream metadata and Desktop observed/configured separation also passed
source review; canonical regeneration is complete at this checkpoint.
`logs [--follow] [--json]` is implemented and source-reviewed, and its integrated CLI checkpoint
compiles. The new
`lomi-web` `/server/` adapter and offline catalog generator passed source review
and site type checking; downloads remain disabled without independently approved
release input. Populated workspace removal now has independently reviewed
schema-12 Store foundation and guarded native editor/Git starts. Its Host
orchestration, exact-session stop/checkpoints, read-only status IPC and CLI/TUI
flow passed source review. The connected CLI library check includes the final
lost-response classification correction. Top-level CLI `update`/`uninstall`,
the Windows trusted maintenance handoff and identity-preserving profile purge
remain under implementation/review. They are product-code work. Purge inventory and
offline revoke semantics are recorded in spec ADR-19; implementation completion
and runtime acceptance have not been declared.

A subsequent source audit found four further mandatory integration gaps: the
Identity v2 proxy paths, selective account Host management, the local editable
Host name, and a working Linux Secret Service provider. The narrow production
and development proxy allowlists and owner-scoped account inventory/UI are now
implemented and typecheck. Host-wide management revoke now fences prior pending
enrollments. Approved incomplete enrollment has its own exact withdrawal action
and lifecycle read for uncertain replies. Independent source review closed the
revocation, ownership, tombstone-state and no-replay findings. Local Host names
now have native hostname defaults, bounded persistence, CAS IPC, resumable setup
and status/dashboard presentation. Interrupted changes retain the original CAS
precondition and permit an explicitly reviewed new choice. Source review closed
the resume dead end, and the connected native library check passes.
Linux Secret Service now has an account-bound private-profile provider, explicit
keyring/protected-file choices and no automatic unlock or fallback. Its exact
collection binding and operation-wide socket deadlines passed independent source
review, and the platform library compiles for Linux and macOS. Transport buffers
inside zbus are not guaranteed to be zeroized; the provider's owned secret buffers
are. Purge Store schema 14 retains up to 4,096 operation identities without
eviction, preserves unresolved terminal evidence and confirms provider-clear
durability. All six material purge/storage review findings are closed. Store,
Host and native platform checks pass. Windows platform checking reaches the
maintenance module, whose caller findings have since passed source review.

Canonical Rust contracts, JS validators, both WASM bridges, Web/mobile snapshots
and native mobile protocol provenance have been regenerated. Auth now pins the
rebuilt authority archive and its exact SHA-512 in the existing Bun lockfile
without installing dependencies. Desktop, Web and mobile typechecks pass. The
`release-maintenance` CLI path compiles on macOS using public compilation fixture
pins; those pins are not a production release root or signer.

The installer uninstall frontends now delegate to the actual installed CLI
before recovery or service shutdown and propagate accepted/uncertain results.
Unix pre-execution validation binds the CLI to its activated or journal-prior
content digest; native signature checks remain. PowerShell failed launches
cannot inherit a successful probe's exit code. Independent source review closed
these changes; shell syntax checking and the native updater build pass.
An affine native proof now distinguishes a positively empty reserved profile
from a missing database in an initialized profile, without creating files or
inventing identity. Its library/API review and Linux/macOS/Windows platform
checks pass. The public maintenance caller and Windows handoffs have since
passed the source reviews recorded below.

The lifecycle review identified and corrected caller gaps in actual revoke ACK
observation, selected-owner macOS maintenance, default update selection,
interrupted activation and failed-health rollback. The generic, protected Mac
and Windows copied-worker caller findings are now source-review closed. Exact
identity is retained across recovery; temporary revoke runtimes stop before
final offline fencing, purge and removal. The acknowledgement uses lock and
generation authority rather than presentation phase. Windows stopped-state
proof, per-owner capsule inspection, console-only credential prompts and the
retained worker's usable status command also passed source review. Two
supporting slices are source-review closed: exact-identity owner-side
offline fencing (including cancellation of active/deferred login intent and
preservation of unfinished workspace-removal manifests), and strict macOS
Developer ID Application/compiled Team verification before activation,
recovery or rollback publishes pointers. Host/Store and platform/updater
compilation pass. The final macOS `release-maintenance` CLI binary check passes
at `lomi-maintenance-final-cli-bins-20261029`. The connected native Desktop build
passes too. A plain Host-target CLI check on this Mac was initially described
by its worker as Linux; that description was corrected. It provides no Linux
CLI evidence. Full Linux CLI/updater cross-checking still lacks its C toolchain.
Full Windows CLI cross-compilation remains blocked by missing Windows C SDK headers before
Rust source checking; no SDK installation or runtime verification was performed.

The ordinary Desktop Remote settings entry now explicitly opens the shared
host/workspace selector, while a dedicated remote window requires a valid
parsed target. The previous first-target dead end is closed in the actual UI
callers. Independent source review and Desktop type checking pass at
`lomi-desktop-remote-selector-types-20261029`; its production Vite bundle also
builds at `lomi-desktop-selector-production-build-20261029`. Remote Web's actual
Astro build passes at `lomi-remote-web-canonical-production-build-20261029` with
zero diagnostics and verifies canonical worker/WASM/static output. An initial
direct Vite command was inapplicable to that Astro project and is not a passing
build result. No browser/native UI run occurred.
The followup E7 audit found that whole-release publication previously mapped
only Desktop/Host/Web sources and Desktop artifacts. The publisher now supplies
all seven source mappings and every declared artifact file at both validation
and the final approved recheck, with protected account/Mobile source pins and
an explicit complete-mapping validator mode. This slice passed independent
source review; YAML, shell and embedded Python syntax checks pass. Publication
and signature/qualification evidence remain separate and unperformed.

The final platform-library check explicitly passes both Linux GNU targets
(x86_64 and aarch64). The current iOS Rust product module builds for device and
both simulator targets, and its generated XCFramework now contains the matching
compiled archives and current headers. Crypto source/build provenance passes.
These are compilation and packaging results, not device acceptance. Android
Rust/FFI checking stops before product compilation at a missing NDK C compiler.
Both supplied LAN hosts timed out during read-only compiler discovery, so full
Linux/Windows Host builds still need an available build environment. No remote
build, service installation or product test was started.

The subsequent compiler discovery found the already installed Rust 1.98.1 on
the supplied VPS; only its default selection was unset. An isolated source copy
then passed native Linux x86_64 `cargo check --release` for both CLI and updater
binary targets with `release-maintenance` and `linux-setup-handoff`, using public
compilation pins. The final 815-file input inventory matches the current Remote
sources (SHA-256 `326e3d5e01f7d8873db19d63f2ce4d98cbc693c34935d825fc102c5b660aa350`)
and stayed unchanged during the check. This supersedes the earlier Linux x86_64
build-environment limitation, not the remaining ARM64/platform qualification
gates. The matching macOS aarch64 release-profile CLI/updater checks also pass.
These are compiler checks, not generated or executed release binaries.

Those checks found and closed two updater CLI version-argument mismatches:
ordinary Unix installation takes an exact string, while managed macOS
installation takes the optional exact-version value. Desktop Linux now also
advertises Secret Service and accepts its canonical configuration through the
existing Host adapter. Protected-file configuration retains explicit consent;
the UI names each provider and clears consent when selection changes. This
caller integration passed source review, Desktop type checking, the native Mac
Rust check and the current production frontend bundle build. No Linux Desktop
GUI runtime or secret provider was exercised.

### Current implementation closure

The source-completeness pass found additional integration work beyond the
previous milestone summaries. The active changes add Web/mobile terminal
management, v2-only Web entry and independent remote windows, shared local
desktop Explorer/Git panels, read-only recovery of uncertain operations, and
automatic local workspace-stream recovery.

Native write admission introduced the persistent host coordinator in schema 11
(the current Store schema is 14).
Short editor effects run in a no-exec host-owned executor with durable input
staging, joined-worker completion, and an acknowledgement outbox. Unacknowledged
results remain available after an extended disconnect. Long native jobs use a
signed helper captured from the authenticated OS peer and a pinned prelaunch
binding. Desktop persists participation, bind attempts, verified finish and
acknowledgement obligations. Rejected or never-started jobs require the pinned
schema-2 release journal and independently checked empty process state before
their ownership fence can be retired.
Client finish messages, expiry, and IPC loss do not prove completion.

Desktop Explorer create, rename, copy, move, duplicate, Trash and recursive
delete now run through the guarded joined Host executor and its durable
acknowledgement outbox. The Unix and Windows source review closed the reported
publication, cleanup, hardlink and metadata findings. A separate integration
audit found that folder moves containing registered workspace roots require
coordinated Host Store and desktop-binding relocation. The live Native Host
executor now prepares those plans under sorted workspace actors, binds the
engine's selected source identity, joins the worker, and atomically settles
roots/import aliases with its receipt and fence. Removing registered roots
first revokes their sharing and stops their actual terminal sessions; an
ancestor workspace keeps its own terminals and sharing when only a child folder
is removed. Unprovable outcomes retain quarantine. This live Native integration
passed independent source review and combined CLI/desktop compilation.
Known Native receipts now reconcile desktop bindings through captured IDs and
monotonic generations, a private cross-process lock, and an atomic apply ledger.
Pending binding settlement blocks overlapping source/destination operations;
binding I/O failure preserves the known file result and defers ACK/Trash cleanup.
This desktop integration passed source review and compilation. Authoritative
Host binding lookup now reconciles captured IDs with generation/root/canonical
CAS checks. Every Active binding is compared with the current Session path;
Retired bindings preserve local projects, editors and drafts and cannot be
automatically reimported. Uncertain native receipts require positive stopped
disposition, reconcile bindings before status-only ACK, and persist visible
warnings until explicit acknowledgement. Restart refreshes same-Host proof;
unknown effects and terminal input are never executed again. The reported
restart, warning-loss, relocation and reimport findings are source-review closed.
Desktop discard/ignore commands now use that same owner-local pipeline. Safe
Git preparation runs in the bounded WASI worker with separate read-only input
and writable output capabilities. It parses original Git configuration,
preserves selected node kinds, restores from the index, and guards untracked
Trash after authorization. The platform publishers preserve metadata and
check the selected entry, repository markers, HEAD/index/ref state, and final
parent binding. Independent source review closed the reported findings; the
integrated CLI and desktop compile at that checkpoint. External linked Git
metadata adapters and Windows real-symlink publication now have implementation
changes under integration and independent source review. The external service
review closed its snapshot, accounting, marker, and nested-ignore findings.
Windows symlink review closed the broker sharing, metadata, inheritance,
directory-backed replacement and post-IPC validation findings. Publication uses
session-bound restoration of the complete captured security policy and exact
metadata verification; uncertain effects are never retried. The Windows
nofollow link reader now supplies the next Git snapshot without opening the
target. The native and Windows x64 file libraries compile. These source results
do not qualify Windows ACL or durability behavior at runtime.
These additions do not
expand remote v1. MCP Git integration is described below.

The namespace Store now has durable plans, retained physical proof data,
transactional root/import-alias updates, and checked recovery tokens. Read-only
directory pins bind full filesystem identities and creation times. Held-parent
censuses prove exact entry spelling without path-based directory enumeration.
The retained proof includes every guarded root, including unaffected ancestors;
partial removal verifies those ancestors before releasing a fence. The live
Native Host path is connected as described above. Local RPC and encrypted
remote directory rename/empty-directory remove now use namespace coordination
with genuine remote permits and receipts. Sorted workspace actors precede
admission, FileRoot binds the selected entry identity, and the final publication
gate uses only local atomics and the original deadline. The retained remote
announcement spans preparation, effect and atomic root/alias/receipt completion.
Deferred completion retains physical pins and all guarded workspace fences,
including during reconciliation. Child-root retirement with pending Cloud
publication closes the connection under the existing fail-closed rule. Source
review closed the queue-continuity and cancellation/permit-loss findings.
Native-only partial-remove and uncertain
recovery dispositions conservatively retire requested registrations while
preserving an uncertain file receipt. Moved shell profiles retain their original
identities and use owner-side relative CWD overrides. A strict read-only restart
adapter is connected at startup and through rate-limited maintenance. Its
prepared manifest retains an OS-installation/process-incarnation witness;
recovery requires independently verified old-process retirement as well as the
actual held owner endpoint. Linux checks both the procfs PID view and the time
namespace before interpreting start times; macOS compares process start time
without treating an executable UUID change as retirement. Move recovery needs
positive birth-witnessed root identities. Remove recovery retires requested
registrations and preserves the uncertain file result. Missing or ambiguous
evidence retains quarantine. Source review closed the reported proof findings;
runtime restart acceptance remains open.
Remote restart recovery is also connected to the same startup/maintenance path.
It requires the actual held owner endpoint, independent old-process retirement,
and complete persisted physical manifests. Moves need positive Applied or
NoChange evidence; remote removals only settle positive NoChange. Inconclusive
removals retain quarantine. Both remote recovery observations preserve the
original OutcomeUnknown/Unknown receipt. No native-only retirement disposition
is accepted for a remote operation.
Independent review also corrected removal to wait for every other reserved
operation, including reserved terminal layout edits, before tombstoning roots.
MCP editor save now uses the joined Host
executor and a guarded IPC exchange, preserving its live authorization callback
after queuing and at publication checks. Guarded saves use strict no-follow
resolution. Confirmed success survives local receipt-cleanup errors. Save As
binds the observed absence or disk hash, and recovered saves compare the receipt
against the current disk before clearing dirty state. These changes passed
combined compilation and independent source review.

MCP project file mutations and artifact exports now use that same guarded,
joined Host executor. The canonical project-file engine owns create, move and
private trash staging; the desktop performs only the later transfer from private
recovery storage to the system Trash. Artifact exports stage raw, hash-verified
bytes and preserve original source authority and the 4 MiB limit. Both flows
retain durable status-only recovery and do not replay an uncertain execution.
Authorization precedes fresh filesystem validation; only fast local deadline,
cancellation and approval-age checks run after the final temporary-file checks.
Reserved publisher staging names are hidden and rejected by public file APIs.
Independent source review closed the publication-ordering findings. Core,
desktop binaries and the Mac Host compile together; Windows file/protocol
libraries compile, while full Windows Host checking lacks the MSVC C headers.

The native Git approval/execution engine has been extracted into a Host-usable
crate with neutral DTOs and an explicit macOS ARM64 qualification gate. A shared
physical common-repository lease now exposes the existing Host Git lock to that
integration and binds native cwd to an admitted directory descriptor. The MCP
Git Host coordinator and desktop MCP bridge are now connected in source. They
use owner-selected workspace roots, the physical common-repository lease,
closed requests and exact approval hashes. Their failure and restart paths
have received integration corrections and independent source review. The
connected Host and desktop compiled at that source checkpoint; later Desktop
filesystem/Git work requires a fresh integrated compilation.
The extracted executor reports only observed process-group/pipe closure and
always requires independent custody proof before a writer fence may retire.
That observation is not proof that detached helpers have stopped.
The canonical engine now also owns closed, operation-specific requests and
prepared approval plans. The Host Store has a separate durable Git job journal
with one-shot execution, exact custodian binding, quarantine, and acknowledged
result retention. Joined editor completion cannot release a Git fence. Backup
reuse compares every schema table, including all native journals. These layers
compile and have received source review. The connected executor releases a
trusted read-only preparation helper first, then commits Running before any
allowed mutator decision. Prepare and execute carry only the remaining
original MCP deadline, bounded to 120 seconds; frame decoding retains its
separate 10-second limit without restarting the operation clock.

The macOS native-job custody lifecycle is available in a reusable native crate. It retains
the existing exact Darwin witness, held launchd worker, raw pipe transport,
schema-2 release journal and sealed-coalition retirement check. Other targets
fail closed. Native Git now has a whole-plan worker and separate deny-default
policy. Its policy permits the admitted Git runtime, hooks and network actions
while protecting Host control paths and denying local-address IP delegation.
The policy, custody recovery, cleanup, and durable desktop acknowledgement
outbox have received independent source review. Native Git's final policy also
protects the reserved Desktop staging namespace and limits hardlink publication
to admitted writable roots. Default terminal custody has its separate integration
described below.

The current IPC changes have been regenerated into the shared schema packages,
both release WASMs and the mobile Rust snapshot. The iOS device/simulator and
both Android JNI libraries were rebuilt. Desktop/mobile TypeScript and Astro
checks pass; the desktop web bundle builds. Mobile lint has no errors and 15
existing warnings. These are compilation and static-source results, not new
runtime or acceptance evidence.

The source inventory confirms active v2 browser onboarding, desktop workspace
imports/private-view filtering, Explorer/Git panels in all clients, and signed
installer/update/rollback paths. Remote registered-root coordination, durable
desktop reconciliation, and the macOS service/update mode integration described
below now have source-reviewed implementations. Owner-local linked Git metadata and Windows symlink
publication now have source-reviewed implementations and scoped compilation.
The default macOS terminal path is now connected to a separate root custodian,
per-terminal launchd controller, authenticated account client, and fixed CLI
entry points. The trusted helper permanently drops to the selected account
before reading user command data or spawning it. An exec-success acknowledgement
is sent only after the OS spawn handshake succeeds. A no-start refusal requires
durable positive cleanup; lost responses and unknown generations remain fenced.
The original Host authorization is rechecked after the durable start intent and
before a one-shot exec release. There is no ordinary-user fallback in the default
backend. Root registration, peer pinning, controller/helper handshake, bounded
nonblocking control I/O, and cleanup/reboot recovery passed independent source
review. The review also closed incomplete journal directory publication/deletion
and concurrent census races: complete Prepared directories are published
atomically, Cleaned directories retire before leaf deletion, and startup cleans
only the separate bounded staging/retired namespaces under the broker lease.
The integrated CLI and desktop compile with the default privileged backend and
the mode integration. The updater's release-root feature also typechecks using
the repository's public compilation input; this is not a production trust-root
or signature qualification.

The same audit identified that manual and login Hosts were missing companion
provisioning despite remaining advertised modes. Explicit administrator-managed
manual/login/boot support is now connected across the platform maintenance
barrier, mode-bound updater metadata, CLI, and installer. A manual
Host gains neither a service registration nor autostart. A login Host uses
the selected account's exact LaunchAgent; boot uses its exact LaunchDaemon.
Updates resume only the actual prior mode/running state. Fresh standard
profiles are prepared by a synchronous helper that drops privileges before user
filesystem access. Nonstandard administrator install paths are rejected before
profile creation or activation, preserving the shared protected executable pin.
Current launchd cohort allocation and the target-system lifecycle remain runtime
qualification work; source review and compilation do not establish those facts.
Independent review closed fresh-image and Login registration publication,
logged-out Login inspection, native supplementary groups, authenticated manual
owner stopping, protected mode binding, and missing-image uninstall findings.
Ordinary-user service mutations through the protected installed CLI now require
the administrator's mode-aware path. This prevents the legacy per-user adapter
from accidentally replacing a Manual installation with a Login registration;
read-only status and the root-selected modes remain available. Source review
closed this routing finding and the CLI compiles after the correction.
The initial-install barrier requires absent images, free ownership, no Host
registration/job/plist in either launchd domain, and no surviving custodian;
it never stops or adopts an existing owner as a first installation.

The terminal dependency update adds only existing `lomi-platform` and SHA-256
dependency edges in the two Cargo locks; no package versions changed. Both
release WASMs were rebuilt, their Remote Web snapshots synchronized, and the
cross-target provenance manifest regenerated for the new canonical lock input.

Web, Desktop and mobile now use one transport-neutral RPC core from the canonical
contract package. Native Rust or browser WASM still validates every wire boundary.
The shared core owns envelopes, response correlation, monotonic deadlines,
bounded queues, known-pre-send versus uncertain outcomes, and independent stream
buffers per receiver. The actual Worker and Tauri adapters forward the fresh
send guard and honor refused start decisions before framing or native invocation.
Mobile HTTP/pairing types now narrow generated contracts while retaining all
identity, signature, account/session, runtime/epoch, grant and expiry checks.
Independent source review closed the deadline, callback, ownership and adapter
findings. Mobile/Desktop TypeScript, Web Astro diagnostics, Web/Desktop production
bundles, and iOS/Android Metro+Hermes exports compile. A bundler-only import error
in the mobile stream adapters was corrected. No application was launched.
Generic mobile byte/UUID helpers now have their own module; active applications
no longer import the retained legacy V1 relay/framing module. Desktop default
build hooks and bundle resources also exclude the old Remote Node terminal
helper. Its opt-in nonrelease probe/evidence source remains; private Chat/AI Node
resources are preserved. The default Desktop Rust build compiles after this
packaging change. Source artifact pins and mobile build-input hashes include the
shared RPC source and direct local-snapshot resolver configuration.

Browser refresh now restores an exact terminal target only after the current
approved pairing and a fresh workspace snapshot prove its membership. Mobile
stores only a scoped nonsecret target hint. After process death it first GETs
the old pairing and repeats normal signature/authority verification; uncertain
reads fence replacement pairing creation and use capped read-only backoff.
Only the focused validated terminal route persists a hint, with cancellation
withdrawal and failed-withdrawal visibility fencing. Optional storage failure
reports that the view cannot be remembered while allowing a still-current
authorized attachment. No restore path creates/restarts a shell or stores input.
The mobile Explorer now has paginated filename search, read-only descendant
hits and stat-verified directory entry. Git diff/log/show retain exact
repository/state/selector continuation with bounded pages and explicit
truncation. Delayed reads are fenced across focus, activity and scope changes.
These client changes passed independent source review, final Desktop/Web
production builds and final iOS/Android Metro+Hermes exports.

An offline whole-release manifest schema and canonicalizer now record the seven
product components, immutable source state, compatibility/schema bounds,
artifact/toolchain/SBOM/license references, public update-root/policy revisions,
and qualification declarations. Optional source inspection disables executable
Git helpers and rejects partial/promisor stores and unsupported index states;
artifact hashing binds a no-follow regular-file descriptor to the named file.
Independent source review closed the reported Git-isolation, cleanliness and
artifact-identity findings. The Host release workflow pins a bounded input by an
independent digest, validates its preparation declarations against the checkout,
and retains its canonical form beside the bundle. YAML and embedded Python
syntax checks pass. The workflow and manifest CLI have not been executed; the
manifest does not establish signatures, qualification, or publication.

Linux release code now signs a bounded archive manifest with an independently
pinned Ed25519 public key and emits verification sidecars and a generated
installation command. The command pins the downloaded preflight's exact digest;
the preflight verifies native platform, key, canonical signed manifest and
archive before extracting or running bundle code. The operator must distribute
the literal command through the independently authenticated installation page.
Signing passphrases are removed from the build environment and reach only the
signing subprocess. Source review and Python/shell/workflow syntax checks pass;
no key access, signing, installation or release build was performed.

Remote v1 permits preview and path mutations, not arbitrary file-content
editing; the sharing disclosures now describe that actual scope.

Native editor and Git publishers now preserve and revalidate security metadata,
stage with restrictive permissions, and keep post-publication uncertainty.
Windows full audit-SACL preservation now has an explicitly installed metadata
broker for an ordinary host account. Its signed pinned executable runs as a
separate System service with automatic system startup. It receives user-granted
source/parent handles, returns no privileged handles or raw audit ACLs, and can
copy policy only onto its own new temporary object. Ordinary-user publishers
perform the final rename and private-temp cleanup. The Windows library checks
pass; independent source review closed the broker, service and publisher
findings. Runtime and target-system qualification have not been performed in
this coding phase.
The broker also has a resumable signed-image upgrade command. It preserves the
existing SCM service, journals both pinned endpoints before service changes,
and can reconcile forward or back after interruption. This command passed the
Windows platform library check and independent source review. The signed
Windows installer now has an explicit per-SID administrator mode for broker
installation, upgrade and removal. Its updater uses embedded-root TUF metadata,
retains the trust lock through SCM application, stages protected source bytes,
and recovers a pending transaction before fetching a newer release. Elevated
bootstrap copies the updater into protected storage before verification and
execution. The C# bootstrap and actual Windows storage adapter compile; the
native updater and release-root feature compile on macOS. Full Windows updater
compilation still lacks Windows C SDK headers, and PowerShell parsing and
Windows behavior have not been exercised.

Git remote inventory now supplies selector kinds, supported actions, and readable
reference names. Clients preserve commit text and select method-appropriate
references. The WASI status producer exposes renamed paths separately so an
unstage can restore both sides. Mobile consumes generated contract declarations
from an in-repository snapshot and journals operation IDs before sending; no
file contents or terminal input enter that journal. Desktop resolves shared
runtime packages from canonical outputs and uses one React instance.

The earlier ADR-012 experimental macOS cohort backend remains disabled. The
default privileged terminal backend is connected as described above. Forced
whole-custodian death remains Unknown and retains its ownership fence; target
kernel/launchd containment has not been qualified at runtime.

## Acceptance gates

| Gate | Current evidence | Required next result |
| --- | --- | --- |
| E1/E2: Consumer | Current-source bootstrap and three runtime gates passed. A separate fresh ACL-pending S5 reference capture passed its catalog, migration and replay checks. | Full current S5 qualification against its target-bound bundle, then S6 and S7. |
| E1/E2: host and Cloud | Windows dedicated-account SCM, guarded identity initialization and operational TUI/IPC are connected. Started Git scheduling, exact rights, publication fail-closed behavior and maintenance callers have source-reviewed corrections; the native Host/CLI compile. Historical runtime checks apply only to their original checkpoint. | Real-relay/browser and target OS service/secret acceptance, including terminal I/O, heartbeat and revoke during Git. |
| E3 | Remote Web v2, authenticated Linux bootstrap and the resumable CLI/TUI first-run wizard are connected. Setup binds account, Host identity, workspace, service readiness and explicit sharing consent. | Qualify clean Ubuntu/Debian installation, phone login/consent, shell, reboot, no replay and unshare against the current Host integration. |
| E4 | Shared Host imports, private-view merging, native Desktop v2 transport, workspace streams and terminal management have source-reviewed implementations and Mac compilation. A followup audit found and closed the first-target selector dead end; the explicit selector/workspace entry routing passes source review and Desktop type checking. | Two-desktop/browser and OS lifecycle acceptance. |
| E5 | Git read/write/network RPCs and file mutations use the Host journal; all clients have Explorer/Git panels. Repository guards, watchers, mobile search/pagination, uncertainty and Started Git scheduling have source-reviewed implementations and Host compilation. | Exercise real repositories, cancellation, terminal concurrency and uncertainty on target systems. |
| E6 | All clients use the canonical RPC core and generated boundaries. Final Web/Desktop bundles and iOS/Android Hermes exports compile. View restoration, mobile search and Git pagination have closed source reviews. | Complete method parity and physical-device acceptance. |
| E7 | Bundle builder, Linux authenticated preflight, native update/rollback/recovery, Mac manual/login/boot, Windows protected service activation and the separate manifest-bound manual publisher have source-reviewed implementations. | Actual signing, complete Windows Host/updater compilation with its SDK, OS matrix, soak, performance and final scenarios. |

Cutover and publication remain separate explicit steps after these gates.

## Current verified integration

The 29 October implementation-only checkpoint now includes full native macOS
arm64 and Linux x86_64 release builds/links of the CLI and updater after the
canonical protocol artifact-collision fix. The unchanged 815-file admitted Host
source inventory is `93dafa61e89d94bd0a16ca39c4543585567fa142466a30ff00f286397c3c7314`.
The native Desktop release build with `tauri/custom-protocol` and both frontend
production builds pass. Its compiler dependencies bind all 112 current frontend
files, including both regenerated canonical WASMs. The earlier bare-Cargo
Desktop build is retained as native-link evidence only.
The complete unsigned iOS staging Release application also rebuilds with the
current Rust XCFramework, JavaScript bundle and source-reviewed stale terminal
confirmation fix. These builds use fixture pins where release configuration is
required. No executable was run, application installed, product test executed,
signing identity accessed or release published. Full Windows product compilation
still needs its C SDK, and current Android Rust/JNI compilation still needs the
NDK. Full Linux arm64, Mac Intel and Windows arm64 product builds also remain
unproven with the available tools. The known production-source findings are closed,
but these compiler limits prevent declaring the whole code phase complete.
Details and exact checkpoint names are in
[the technical handoff](technical-handoff.md).

The fresh Consumer run
[`fd8a30c9-755d-4f9b-a585-e07577437466`](../../staging/consumer-scram/namespace-current-consumer-runtime-runs/fd8a30c9-755d-4f9b-a585-e07577437466/execution-result.json)
passed typed resolver, legacy authorization lifecycle and raw scalar fallback
exclusion. Its source and retained-output checks passed after cleanup. This is
the three-gate runtime result; it does not replace full S5–S7 acceptance.

The passing combined host result is retained in
[`host-c115a778`](../../artifacts/scoped-checks/host-c115a778-2d07-44c0-b9b6-f126c1160337/report.json):
HTTP 64/64, connection gates 52/52, ingress 54/54, original operation deadline
1/1 and Git executor 4/4. This verifies the corrected terminal-purpose fixture
together with the Git and pre-expiry scheduling changes.

The earlier failed aggregate result remains in
[`host-9834b34f`](../../artifacts/scoped-checks/host-9834b34f-da35-4077-9232-ae0c4c1382d4/report.json).
Its four Git TLS/Noise cases passed; the sole failure was the terminal-purpose
fixture waiting beyond its five-second control lease. Neither result alone
qualifies the whole Cloud/relay/browser scenario.

## Work organization

- Host/Cloud and Consumer work owns its assigned Rust/runtime files.
- Client work owns desktop, Web and mobile integration files.
- Git/Explorer work owns its engine and explicitly assigned file-broker APIs.
- The integrator owns contracts, file ownership, integration and final evidence.
  A reviewer checks security-sensitive or cross-component changes independently.

Implementers run their own scoped compilation and type checks and fix ordinary errors
before handing work back. Independent changes run concurrently. Shared Cargo
builds use its cache lock; tests may reuse an already compiled binary only when
the relevant source has not changed. Timing-sensitive whole-product runs wait
for a suitable integration slot.

Each iteration delivers working behavior or a reproduced defect with a tested
correction. Existing runners are extended instead of introducing another runner
for each attempt. One worklog records each coherent change. Earlier failed
results retain their original outcomes.

The v1 scope and required security properties remain fixed. Features explicitly
excluded from v1 are not added to this delivery path.

## External qualification inputs

The available Windows 10 laboratory does not qualify Windows 11 or Windows
Server. A physical Android device has not been provided. The iPhone and VPS
were made available earlier, but their full product acceptance remains open.
These resources, signing and the release matrix are prepared alongside product
implementation; they do not substitute for actual target-system results.
