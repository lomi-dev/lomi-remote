# Implementation progress

Current acceptance gates and work organization are tracked in
[delivery-status.md](delivery-status.md). The entries below retain the detailed
history and do not replace those gate decisions.

### 2026-10-26 — Remote Web builds against one checked package snapshot

Remote Web now resolves its protocol, contracts and authority packages from
the checked generated snapshots. Vite uses those entries for both the page and
Worker; metadata-only package shims direct Bun and TypeScript to the matching
runtime and declaration files. Builds verify the package manifests, shim
metadata and emitted assets. Mixed stale/current WASM, including both emitted
dot- and hyphen-hashed filenames, is rejected. The installed stale package was
left in place to demonstrate that the corrected build does not consume it.

Independent review and [root verification](../../staging/consumer-scram/namespace-remote-web-builds/final-shim-release-8f013787d4ed/bounded-source-build-acceptance.json)
accepted the nine-file change and the isolated build. All 209 product inputs
match the current tree and retained snapshot. The focused protocol, contract,
channel, Worker and resolver suites passed 69 tests with 393 expectations;
Astro reported zero errors, zero warnings and four hints. Vite still reports a
large-chunk warning. The output contains one canonical protocol WASM and two
identical authority WASM assets. The channel-success harness also now uses the
current accepted Rust inventory fixture while retaining its schema checks and
assertions.

The canonical protocol generator's offline `--check` reproduced its artifacts
from current Rust sources. Root additionally verified all 25 provenance inputs
and four generated output hashes. This establishes this package/build boundary;
the full production Rust/WASM/mobile manifest gate and actual joined
host/relay/browser acceptance remain open.

### 2026-10-26 — Firefox TLS preflight passes; mixed product WASM blocks admission

The fresh [Firefox transport preflight](../../staging/consumer-scram/namespace-browser-tls-proofs/1a667812-486c-4a50-a23a-3da18e98460b/result.json)
passed all seventeen checks in 25.930 seconds. Two independent trusted profiles
completed HTTPS and actual binary WSS echoes. Separate profiles rejected the
unknown issuer and the same-CA wrong SAN with the expected Firefox errors; the
wrong-SAN endpoint also passed its independent TLS health control. Six local
proxy tunnels and zero external attempts were recorded. All four browser
process receipts, listener/context closure and runtime removal passed. Source
review and independent evidence review accepted only this private transport
scope; product login, actual host/relay clients and full E1/E2 remain untested.

The startup correction gives Firefox a private `CFFIXED_USER_HOME`. Cleanup
removes macOS-created ACLs only from four known directories in that owned
temporary home, after browser/server quiescence. Both ACL mutation and its
verification use retained directory descriptors. A regression swaps an ancestor
immediately before mutation and proves that the outside directory ACL remains
unchanged. Fifteen focused tests and TypeScript checking passed. Earlier failed
results retain their original outcomes and separate cleanup receipts.

The separate JoinedCloud native fixture now creates one terminal before share,
keeps the same actor and terminal alive after unshare, and waits for a distinct
correlated stop before terminal/workspace cleanup. Absolute admission deadlines
cover its connect, IPC and polling paths, including all post-stop calls and the
actual shutdown budget. Independent source review and the [root component checks](../../staging/consumer-scram/namespace-joined-native-proofs/b99f27e1-71da-465a-ab45-aed26fa64985/component-proof.json)
passed feature compilation and seven focused tests with all 512 Rust inputs
stable. This does not execute the ignored joined fixture or qualify live shell
and revoke behavior.

An isolated production Remote Web build passed type checking, static generation
and the static-output check. Root verification then found two different
protocol-codec WASM binaries in its output: stale installed package bytes and
the current generated snapshot. The [separate artifact admission](../../staging/consumer-scram/namespace-remote-web-builds/5b616714-adf3-4a34-8b66-07da218108b7/root-protocol-admission.json)
rejects that build for joined integration while preserving its original static
build result. A durable package-resolution and manifest check is in progress;
no production or full E3/E6 acceptance is claimed.

### 2026-10-26 — Joined transport foundations pass component verification

The managed fixture can now select a separate test-only JoinedCloud mode with
explicit Auth, Remote API and WSS roots. Peer and channel transports use their
existing public-I/O lease factory. Joined current-pairing reads use actual
HTTPS; a real 401 returns failure without consuming a scripted reply. Default
and CloudOnly tests retain their closed transport behavior.

The joined startup accepts a pinned terminal-worker binary and executes a
private read-only snapshot of the verified bytes. The snapshot remains alive
through managed shutdown; failed cleanup or unwinding preserves it. Replacing
the original file cannot replace the selected worker. The conflicting
`owned-host-fixture` mode is rejected before profile startup. Unix guards and
canonical temporary-parent handling also cover the reviewed Windows-cfg and
macOS temporary-path issues; this is not a Windows build or runtime result.

Independent source review accepted the five-file delta. The separate
[root component verification](../../staging/consumer-scram/namespace-joined-native-proofs/622dcd7e-429a-41fe-b3d7-6221e6a91418/component-proof.json)
passed the production library check and eight focused tests, with all 512 Rust
inputs stable and exactly five changes from the preceding native build. Its
[owned scratch cleanup](../../staging/consumer-scram/namespace-joined-native-proofs/622dcd7e-429a-41fe-b3d7-6221e6a91418/scratch-cleanup.json)
is recorded separately. These checks do not establish a joined host/relay run,
live terminal shutdown, browser behavior or full E1/E2 acceptance.

The private Firefox TLS preflight has passed actual certificate/NSS setup and
its source/toolchain gate, but browser readiness under Bun and Node remains failed. The
[bounded launch diagnostic](../../staging/consumer-scram/namespace-browser-tls-launches/7fd85ee1-57a2-41e6-963f-8bf074dfb25a/root-proof.json)
retains the 15-second readiness timeout and Firefox launch/exit logs; no HTTPS
or WSS browser request passed. A [Node comparison](../../staging/consumer-scram/namespace-browser-tls-node-diagnostics/20bba8ea-01c4-4ef7-9bbd-d9b2fd362d7e/result.json)
using the same Firefox, private profile, preferences and environment also timed
out before readiness. The failure is therefore not specific to Bun; its local
cause is not yet established. The two failed Bun runtimes were removed only
after observing that no process from the pinned Firefox bundle remained;
separate cleanup receipts preserve both original failed results. The actual
joined fixture and product browser consumer integration remain in progress.

### 2026-10-26 — Formal private managed-host Cloud fixture passes

The fresh [archived managed-host run](../../staging/consumer-scram/namespace-managed-cloud-runs/28238fe8-cb7d-4520-bcb1-76793ecb72d3/run/result.json)
passed with 1,764 physical inputs sealed before execution and 1,270 retained
owner pins, including two root-controller pins. The owned phase completed in
60.203 seconds; its complete launcher took 67.101 seconds. All twenty
coordinator checks, sixteen runtime checks and nine native stages passed.
The actual managed actor enrolled its HostStore identity through Local IPC,
received approval from the persisted synthetic browser-manager session, shared
a workspace, and drove registration, runtime claim, publication and heartbeat
through the configured Auth and Remote HTTPS listeners. This private browser
approval does not qualify the phone or browser login UI.

A separate process passed the [post-execution verifier](../../staging/consumer-scram/namespace-managed-cloud-runs/28238fe8-cb7d-4520-bcb1-76793ecb72d3/run/post-verification.json)
in 10.164 seconds. It rechecked the source archive, raw output bindings and
redacted observations after runtime removal. Retained public certificate, CA
and root bytes support offline OpenSSL chain and loopback-IP verification;
private keys are excluded. The observations bind registration and the first
empty runtime GET at epoch 1 to the actual claim request at generation 0,
then the claimed generation 1 and epoch 2 to heartbeat, publication and the
current runtime, authorization and identity rows. PostgreSQL exited zero;
the owned profile and runtime are absent. Independent review accepted the
[bounded private fixture evidence](../../staging/consumer-scram/namespace-managed-cloud-runs/28238fe8-cb7d-4520-bcb1-76793ecb72d3/run/bounded-formal-managed-host-acceptance.json),
including a separate TLS check and process/runtime absence before future
target reuse. The producer's qualification flags remain false.

The [preceding formal attempt](../../staging/consumer-scram/namespace-managed-cloud-runs/3db303a3-1d16-4442-b446-515f6adb275e/run/result.json)
remains failed. Its native actor passed, but the new observation validators
incorrectly equated the earlier registration epoch with the epoch advanced
by the first runtime claim. Independent review accepted only that attempt's
[failed evidence and normal cleanup boundary](../../staging/consumer-scram/namespace-managed-cloud-runs/3db303a3-1d16-4442-b446-515f6adb275e/run/bounded-failed-run-cleanup.json)
before target reuse. The corrected validators check the exact predecessor and
current epochs, the signed-bigint boundary and both possible timings of the
registration database snapshot. Their focused checks passed 26 Python tests
and 23 Bun tests with 174 expectations. Product sources, roles, workload and
deadlines were unchanged by this correction.

This is a private host-only integration checkpoint. Real relay/Noise clients,
terminal writers, reconnect and central revoke, credential rotation/restart,
OS services and boot, full E1/E2 and production qualification remain open.

### 2026-10-26 — Private managed-host enrollment and Cloud diagnostic passes

The first passing [managed-host diagnostic](../../staging/consumer-scram/namespace-managed-cloud-diagnostics/ba990369-83a3-40ee-9481-46d00fa27b5c/diagnostic-proof.json)
completed in 80.187 seconds. The native managed actor configured authentication
through Local IPC, enrolled its own HostStore identity, obtained approval from
a genuine persisted synthetic browser-manager session, registered, reached
Ready, imported and shared a fresh workspace, and drove the configured Cloud
worker through real HTTPS listeners around the current Auth and Remote apps.
No Ready state or host credentials were injected. The browser approval is a
private fixture action; it does not qualify the phone/browser login UI.

The retained markers record one enrollment, three device-poll responses, one
exchange and one registration, followed by three runtime reads, one claim,
one shared-workspace publication and one heartbeat. All twenty coordinator
checks, sixteen runtime checks and nine native stages passed. The native test
exited zero, joined its actor and released the original owner lock. Two genuine
restricted-role probes passed; the single cloned database was dropped, all
clients/listeners closed, PostgreSQL exited zero and the owned profile and
runtime were removed. Source and retained-output bookends match.
Independent read-only review accepted the
[bounded diagnostic evidence](../../staging/consumer-scram/namespace-managed-cloud-diagnostics/ba990369-83a3-40ee-9481-46d00fa27b5c/bounded-diagnostic-acceptance.json),
including 1,268 source pins, all 512 native build inputs, raw capture bindings
and final process/runtime absence before any future target reuse.

The three preceding failed diagnostics remain unchanged. They exposed an
artifact-argument serialization mismatch, an administrator-only setting read
through an application role, and an enrollment-code value captured before its
asynchronous response arrived. Their fixes preserve the restricted roles and
target checks. Separate bounded receipts retain the first two explicit cleanup
boundaries and the third normal cleanup before each target reuse.

This is a private diagnostic result with the original qualification flags
still false. A formal archived run with retained public TLS/context inputs is
still required. Public certificate/root bytes were deleted with the runtime;
the diagnostic retains their hashes. Detailed database/config correlations
also need separate redacted observations if the formal verifier must replay
them independently. Real relay connections, multiple native clients, reconnect,
central revoke, terminal/shell behavior, OS boot/service qualification and full
E1/E2 acceptance remain open.

### 2026-10-26 — Bounded ingress registry passes component tests

The auth worker now owns a channel-keyed registry of at most eight ingress
drivers sharing its existing Coordinator. Duplicate and excess admissions are
rejected before driver creation or ticket requests. Live idle connections stay
registered after their maintenance operation expires; per-channel failure
removes that connection, while global authorization loss discards the registry.

Admission only queues a candidate. One shared round-robin selection advances
one ticket, connection or frame stage, rotating before the selected work.
Failed newcomers cannot reset that selection or give another channel an extra
stage. Default and `cloud-fixture` component runs passed the registry tests,
actual-handoff admission limits and the real two-client TLS/Noise/PTY case.
The latter also exercises six failed newcomer admissions while both existing
clients remain connected. Independent source review accepted the scheduling
and teardown boundaries. The retained
[focused checks](../../staging/consumer-scram/namespace-source-transitions/0f9ef416-2703-421b-b6c4-c5e40473e97e/proof/registry-fairness-8311464f-7436-4e98-9681-b15f65494690/manifest.json)
record exact commands and source hashes. The duplicate test uses a genuine
incoming handoff against a test-seeded occupied registry key because the
protected Store rejects minting a second acknowledgement for that channel ID.

Root verification also passed the production library check and the complete
ingress-driver suites: 39 default tests and 41 `cloud-fixture` tests, with all
512 Rust inputs stable. The retained
[root component proof](../../staging/consumer-scram/namespace-real-relay-transport-proofs/d2b503d3-f638-4dd4-b363-0cc10f4e34fd/component-proof.json)
binds those executions to their sources. A subsequent two-attribute change
marks the old standalone scheduling helpers as test-only, removing the new
production dead-code warning. That exact delta passed independent source
review and final production/default-test/feature-test
[compilation checks](../../staging/consumer-scram/namespace-real-relay-transport-proofs/46345dc5-551e-48d6-8ec5-2a7fa1f3f07f/component-proof.json).
The earlier executed test receipts remain bound to their original sources.

The new ignored managed-host fixture is inside the Rust input tree and compiles
with `cloud-fixture`. It uses actual Local IPC configuration, device enrollment
and workspace sharing, with a fresh short profile separate from PostgreSQL's
socket directory. Its native Cloud cycle has not run. These are component
results; the joined real relay, managed actor and central revoke acceptance
remain open, as do full E1/E2 and production qualification.
The earlier private Cloud acceptance remains bound to its archived Rust
sources and worker binary; it does not qualify these later runtime changes.

### 2026-10-25 — Current private normal S7 passes

The fresh [normal S7 run](../../staging/consumer-scram/namespace-s7-runs/ecb7e6a1-98a5-4328-9bbc-a276c1381a88/result.json)
passed in 204.924 seconds, with the existing workload/deadlines and no diagnostic
observer. Its pinned validator reproduces both 1,000/10,000 growth stages,
four private production-flow seed receipts, seven lookup and three pending
plans per stage, ten cascade rollback plans, two source-TTL rollback plans,
nineteen lifecycle categories and fifteen zero cleanup counters.

Independent review verified all 1,222 archive/current files, 756 pins, five
original output buffers and exact recomputed strict summary. PostgreSQL exited
zero and the private runtime is absent. The new
[bounded S7 acceptance](../../staging/consumer-scram/namespace-s7-runs/ecb7e6a1-98a5-4328-9bbc-a276c1381a88/bounded-current-private-s7-acceptance.json)
qualifies this current 317-file source's private normal Consumer S7 lane.
Original producer labels remain unchanged. Earlier failures remain recorded;
this pass does not establish the cause of their timing variation or transfer
qualification to the whole consumer, E1/E2, deployment or production path.

### 2026-10-25 — Private Cloud ACK and owner-restart gate passes

The corrected [private Cloud run](../../staging/consumer-scram/namespace-s6-runs/058a2a56-c162-46de-bdae-f57b834eaa2e/result.json)
passed in 36.733 seconds: one actual product test, 687 assertions, three genuine
restricted-role probes and all sixteen coordinator checks. Its 74 closed
markers validate 51 real TLS requests, publication/permission refresh,
same-owner and fresh-Worker reconciliation after lost TCP ACK, valid-lease
predecessor fencing, expired-lease owner restart, initial claim and shared-owner
behavior. Uncertain publication is reconciled without a second PUT.

Independent review accepted all 1,753 archived/current files, 1,279 pins,
original reports/provenance and PostgreSQL/runtime cleanup. The separately
scoped [acceptance receipt](../../staging/consumer-scram/namespace-s6-runs/058a2a56-c162-46de-bdae-f57b834eaa2e/bounded-cloud-worker-ack-restart-acceptance.json)
records the cleanup boundary before the next normal S7 reused the private
runtime path. Original producer labels remain unchanged. This closes the
recorded private API/TLS ACK/restart lane; full relay/WSS, E1/E2 and production
acceptance remain open.

The subsequent ingress test seam can use a pinned HTTPS ticket endpoint and
the configured WSS endpoint while retaining closed scripted defaults. Its
focused loopback case and forty ingress-driver tests passed; default library
and test compilation also pass. Bounded [component logs](../../staging/consumer-scram/namespace-real-relay-transport-proofs/eaea63e0-bb3f-46e6-acee-c46fa6a3a297/log-capture.json)
retain the executed-source distinction and the initial default-test failure.
A separate one-line cfg fix restores compilation of an existing diagnostic
test. These results use a fake authority and do not qualify the joined real
relay/HostAuth/CloudWorker lifecycle; that integration is the next E1/E2 step.

The fixture-only fix retains the durable store lock while placing temporary
IPC in a short private directory, preserving the production endpoint limit.
It passed compilation and 41 Cloud unit tests, including the actual fixture's
lock/readiness/reopen and unwind cleanup regression. Seven external-fixture
unit cases were ignored; the subsequent actual Cloud run supplies its own
separate evidence. The updated owner also passed eighteen Python tests.

### 2026-10-25 — Cloud ACK reconciliation observed; restart fixture fails

The [canonical private Cloud run](../../staging/consumer-scram/namespace-s6-runs/d8186e8f-8cf0-40a0-bd4f-a20def26594b/result.json)
failed: one actual product test, 111 assertions, no passing aggregate result.
Independent review verified all 1,753 source/archive files, 1,279 pins, the
bootstrap, genuine restricted-role probes and the failed report chain.
PostgreSQL exited zero and is absent. The private runtime was deliberately
retained by the conservative artifact cleanup gate; this is not evidence of
an open database client.

The retained public markers observe publication/permission refresh and both
lost-TCP-ACK cases, including reconciliation by a fresh Worker without a
second PUT. They do not qualify the complete Cloud lane. Restart, initial
claim and shared-owner acceptance remain incomplete. A separate
[supplemental capture](../../staging/consumer-scram/namespace-cloud-failed-evidence/d506e2ff-2bc6-4267-9ce5-f2b4a50b408a/supplement.json)
preserves these partial markers without changing the original failed outputs.
After independent review and metadata-only identity/absence checks, a separate
[explicit cleanup](../../staging/consumer-scram/namespace-cloud-failed-evidence/d506e2ff-2bc6-4267-9ce5-f2b4a50b408a/explicit-root-cleanup.json)
removed that synthetic runtime. The original failed cleanup receipts still
describe their original boundary; no credentials or private keys were read.
Static diagnosis found that the restart fixture's local `host.sock` path is
122/139 bytes, exceeding the existing 100-byte endpoint limit before any
restart-phase HTTP request. A fixture correction and fresh normal run are
required; the production endpoint limit remains unchanged.

### 2026-10-25 — Query timing narrows the S7 investigation

The [private query diagnostic](../../staging/consumer-scram/namespace-s7-runs/9a61b627-06f7-4ccf-b9f2-0fe266b6bc70/result.json)
also failed during `exchange-batch`. Its independently verified failed
evidence contains 444,956 observed query calls and complete database cleanup.
The web and mobile principal-read templates each ran 14,514 times, with summed
client-observed durations of 66.950 and 68.074 seconds. The user cleanup DELETE
took 6.369 seconds for this incomplete workload; it is not comparable with the
earlier full-population cleanup measurement.

These timings include client scheduling and can overlap. Seven callback
queries were unsupported, and the observer changes unhandled-rejection
reporting; measurement completeness and qualification remain false. The
[query mapping](../../staging/consumer-scram/namespace-s7-runs/9a61b627-06f7-4ccf-b9f2-0fe266b6bc70/query-timing-analysis.json)
identifies the exact production templates, not a proven root cause.

The subsequent [read-only plan measurement](../../staging/consumer-scram/namespace-principal-plan-runs/ecb3a147-011a-48e5-8c42-e74d68256461/result.json.principal-plan.json)
passed with one legitimately issued web/mobile pair in 38.685 seconds overall.
Web planning/execution measured 3.395/0.120 ms; mobile measured 1.672/0.068 ms.
Both plans used ten index scans. Independent review accepted all 1,233 source
files, 747 pins, sixteen diagnostic checks, original reports and complete
PostgreSQL/runtime cleanup. This single-pair observation does not establish
the cause or scaling of the S7 timeout. No authorization checks, growth points
or normal S7 deadlines have been removed or relaxed.

### 2026-10-25 — Renewed private consumer and SQL results

Independent review accepted the normal Consumer S6 and core SQL lanes for the
317-file Auth successor. Consumer S6 passed 875 assertions and three genuine
restricted-role probes. Core passed 125 tests / 3,020 assertions across eleven
fresh clone cycles. Each lane's 1,227 source files, 748 pins, complete output
chain and final PostgreSQL/runtime removal were independently verified.
See the [consumer run](../../staging/consumer-scram/namespace-s6-runs/7ef23a05-13d6-497c-825e-01db3925d0b2/result.json)
and [core run](../../staging/consumer-scram/namespace-s6-runs/88a83766-97fc-4d99-8a3d-2168122e010e/result.json).

The renewed [four-profile bootstrap/S5 matrix](../../staging/consumer-scram/namespace-product-runs/8c6f2303-5e7b-43f8-a5c6-616559599990/matrix.json)
also passed all native runs and postchecks. Its selected full S5 lane retained
251 captures (398,309,307 bytes), 80 helper denials, 28 owner-operation denials
and eleven negative ACL checks. Independent review verified every raw capture,
all four retained result chains and final cleanup, then accepted the
[private profile matrix](../../staging/consumer-scram/namespace-product-runs/8c6f2303-5e7b-43f8-a5c6-616559599990/bounded-profile-matrix-acceptance.json)
and [selected full S5 lane](../../staging/consumer-scram/namespace-product-runs/8c6f2303-5e7b-43f8-a5c6-616559599990/bounded-full-selected-s5-acceptance.json).

The new bounded Cloud artifact helpers passed 32 filesystem tests and source
review. Real private TLS provisioning then verified the certificate chain,
key match, loopback SAN and both copied binary hashes, followed by complete
artifact/runtime removal. This [standalone provision proof](../../staging/consumer-scram/namespace-cloud-provision-runs/b53d38c7-cbcb-40bb-90e7-a398224970f6/provision-proof.json)
does not execute the Cloud runtime. The later canonical Cloud attempt and its
incomplete restart coverage are recorded above. S7, the full E1/E2 path and all
broader production gates remain open.

### 2026-10-25 — Successor admission passed; full S7 remains blocked

The 317-file Auth successor passed eight fresh independent reference runs,
the three current runtime gates, and private bootstrap input validation.
These results cover their recorded preparation scopes; predecessor S5/S6/core
results do not transfer to the changed source.

The first normal full S7 run with the eight additive indexes failed after
429.528 seconds. Its driver stopped during `exchange-batch`, retained only
the 1,000-principal growth observation and five delete plans, and did not
reach the 10,000-principal observation or lifecycle checks. Cleanup completed:
the clone was dropped, PostgreSQL exited zero and the runtime was removed.
Root postcheck verified all 1,222 source files, 756 pins and retained outputs.
The [failed normal run](../../staging/consumer-scram/namespace-s7-runs/3fc60f5e-e7d9-4bcd-88de-21a00c270702/result.json)
does not qualify S7 or the index performance change. The new failure location
requires measurement before attributing it to a query or machine load.

### 2026-10-25 — Measured S7 cleanup deadline failure

The unchanged S7 workload retained both growth points and all lifecycle/plan
observations, but still failed its final completion check. A private diagnostic
measured the user cleanup DELETE and its cascades at 192.401 seconds, beginning
at observer offset 194.905 seconds. Web and mobile cleanup took 239.053 ms and
13.396 ms. This identifies the whole-query cost spanning the driver deadline;
it does not attribute that cost to a particular FK or index.

Independent review verified 1,216 archived source files, 756 pins, eight retained
outputs, and complete PostgreSQL cleanup. The [failed diagnostic integrity
receipt](../../staging/consumer-scram/namespace-s7-runs/be16ac41-d78f-4486-81fc-369c83c1f1d8/failed-evidence-review.json)
preserves the failed result. S7 and production qualification remain false.
An additive index/source successor is now being prepared; earlier S5/S6/core
acceptance remains limited to its recorded source rather than transferring to
the changed code.

The additive migration and matching Prisma indexes passed independent source
review and 30 focused tests (913 assertions; one existing database-gated skip).
Prisma 7.10 regenerated the client, and TypeScript passed. An attempted Cloud
runtime run compiled both Rust fixture binaries and applied all 28 migrations,
then failed before the Cloud test: the legacy runner applied baseline grants
outside the mandatory typed-required bootstrap transaction. The guard was
preserved. Source/dependency bookends matched, PostgreSQL stopped, and the
private runtime was removed. The [failed runtime receipt](../../../auth-app/artifacts/cloud-worker-recreation-cascade-20261025/4bd35a8b-3274-4c64-88e6-462d19827bdc/runtime-proof.json)
does not qualify Cloud or the index performance change. The next Cloud lane
must use the admitted canonical bootstrap and its disposable test clone.

### 2026-10-23 — Consumer runtime privilege probe at bootstrap

`auth-app/ops/remote-db-bootstrap.ts` now checks the existing Consumer 004
invoker-lock path under `SET LOCAL ROLE lomi_runtime`. The `FOR SHARE` probes
use `WHERE false`, so they verify required SELECT/UPDATE privileges without
reading account or session rows. Bootstrap also verifies binding-read access
and EXECUTE on the liveness guard, and fails closed with a generic error when
the runtime ACL is incomplete. A source test pins the role boundary and
read-only probe set.

Validation: `bun run check` passed; 13 focused bootstrap/inspection tests
passed and one existing PostgreSQL metadata test was skipped. The isolated
Consumer runtime runner passed on PostgreSQL 18.6 with Bun 1.4.2, exited 0,
stopped its private cluster, and reported zero TCP listeners. Its receipt keeps
`productionQualified=false`; it exercises current migrations/grants, not the
staged derivative-consumer v3 candidate or production deployment. Consumer
S5–S7 remain open. [Runtime proof](../../../auth-app/artifacts/consumer-runtime-lock-privilege-rerun-20261023/d8a7948e-8fa0-45fb-aea2-17599949b565/runtime-proof.json).

### 2026-10-23 — Consumer v3 source-derived ACL contract

The isolated v3 successor now documents the source-derived roles, table reads,
trigger callers, typed wrapper grants, legacy scalar retirement, and unresolved
catalog/default-privilege closure. Independent review corrected the `FOR SHARE`
UPDATE privilege requirements, nested helper EXECUTE grants, and the distinction
between trigger-creation and DML-time function privileges. Static checks now
assert those exact source and role mappings.

The candidate validator passed 182 pure static checks; focused source tests
passed 5/5. All 18 source pins and the successor-manifest provenance digest
match. No SQL or PostgreSQL ran. Runtime routes still call the legacy scalar
functions, v3 ops grants and catalog/ACL pins remain absent, and Consumer
S5–S7 remain unqualified.

### 2026-10-23 — E4 private-view sharing regression guard

The desktop host projection already sends terminal tabs only and filters
agent-controlled terminals. Added an explicit regression case proving that a
local editor path, private browser URL, and chat conversation ID are absent
from the shared projection. The focused `remote-workspaces` suite passed
10/10 with Node 22.

This protects the existing privacy boundary; it does not add the missing
workspace owner migration, import flow, or remote workspace selector. See the
[desktop projection test](../../../lomi/tests/remote-workspaces.test.ts).

### 2026-10-23 — E3 source provenance and regenerated consumer snapshots

Added a hash-pinned cross-target preflight for canonical Rust crypto/protocol,
schemas, WASM packages, Remote Web snapshots and mobile vendored/product
inputs. Its serial integration test passed 3/3 tests and ran the generator,
both WASM checks, Remote Web snapshot check and mobile provenance check. The
first check exposed stale generated protocol WASM after a Rust protocol change;
the WASM output and Remote Web snapshots were regenerated, after which the
preflight passed.

The mobile crypto Rust/native adapter suite passed 71 unit and doctest cases on
macOS. Remote Web passed 154 tests / 740 expectations, its static production
build and output guard, and IndexedDB identity/lifecycle checks in Chromium,
Firefox and WebKit. Evidence and exact scope are in the [cross-target local
preflight report](../../artifacts/cross-target-provenance/2026-10-23/report.json).
After package regeneration, the synthetic browser terminal fixture was also
rerun: 19 reported lifecycle/navigation/reconnect/pane-isolation/no-replay
checks passed with four controlled input events and zero CSP violations.

This does not establish one generated contract source in all product clients:
mobile contract-facing TypeScript is still handwritten and only drift-checked.
It does not include a native iOS/Android build, physical-device acceptance,
clean VPS install, deployed relay shell, or unshare race. E3 remains open.

### 2026-10-23 — Remote Web v2 local build and browser identity checks

`remote-web` passed all 154 Bun unit tests and `astro check` with Node 22.12+
(0 errors, 0 warnings, 4 editor hints). The production static build and output
guard also passed. Vite reported its existing raw JavaScript chunk-size warning;
the largest entry was 3.0 MB raw / 170 KB Brotli. Chromium, Firefox, and WebKit
each verified encrypted IndexedDB window identity survives a refresh and that
`pagehide` blocks terminal input until `pageshow` resumes the view.

The terminal regression fixture passed in Chromium, Firefox and WebKit (19
reported lifecycle, navigation, reconnect, pane-isolation and no-replay checks;
four input events in each run). It uses the local synthetic fixture and is not
the real Remote v2 host/relay acceptance.

This covers local browser identity and lifecycle code only. It does not qualify
the clean-host install, phone approval/consent, deployed relay shell, reconnect
without input replay, unshare races, or E6 device/browser parity. See the
[bounded run report](../../artifacts/remote-web-local-browser/2026-10-23/report.json)
for commands, tool versions and the exact fixture limits.

### 2026-10-23 — Ubuntu VPS x86_64 cold-boot service

Built the frozen 1,370-file source archive on the user-provided Ubuntu
24.04.5 x86_64 VPS with `cargo build --locked --offline -p lomiremote`.
Installed one UUID-owned boot-mode systemd user service under `woro-vps`,
temporarily enabled linger, and cold-rebooted the VPS. The first successful SSH
login after boot verified the product service active earlier in the same boot.
Cleanup removed the exact unit and private fixture, restored `Linger=no`, and
reported zero fixture processes. The account-bound journal matcher passed its
5 focused tests; the existing boot-evidence tests passed 15/15.

Evidence: [remote lifecycle report](../../artifacts/linux-vps-boot/369c8f345962461fbcb220ed369a3282/report.json), [frozen source manifest](../../artifacts/linux-vps-boot/369c8f345962461fbcb220ed369a3282/source-manifest.json).
The VPS is not a pristine host; this result covers only an isolated service
fixture. It does not qualify the full E1/E2 matrix, consumer database flow,
Cloud/relay, clean installation, or release.

### 2026-10-23 — Linux product cold-boot service lifecycle

Ran `python3 -B tools/run_linux_product_host.py --with-boot-service --run`
against the dedicated Ubuntu 24.04.5 ARM64 `lomi-e0` VM. The product binary
built with SHA-256 `07cb501a127b46c4aac5d9ef9e659cd8f598b3e830ce51eefef3951839d02d4d`;
32 native test blocks passed 821 tests, with 0 failures and 2 ignored. Separate
SSH phases verified that the host kept the same runtime and shell session and
that the shell counter advanced from 1 to 2 after disconnect.

The boot-mode systemd user service was installed with a temporary linger change,
the VM was cold-stopped and started, and journal monotonic timestamps proved
the product unit active before the first observed SSH login. Cleanup removed
the exact service and product fixture, restored the original `Linger=no` state,
and reported zero owned fixture processes. Evidence: [run report](../../artifacts/product-linux/81fd44d8-2d08-4608-b09d-8133078c9587/report.json), [native test log](../../artifacts/product-linux/81fd44d8-2d08-4608-b09d-8133078c9587/native-product-tests.log).

This is an ARM64 disposable-VM result (`passed=true`, `qualified=false`). It
does not qualify clean production installation, Cloud/relay, Consumer S5–S7,
the full target matrix, or release readiness.

### 2026-10-23 — S6 pending web source fixture

Added an isolated source-only SQL builder for one synthetic web pending
approval case. It seeds only fixed S6 fixture values, inserts the intent under
`lomi_runtime`, checks that no proof/service/web actual/consent was issued,
forces the named deferred pending-intent guard, and commits the disposable
positive fixture. Its negative client-binding case catches exactly SQLSTATE
23514 and rolls back. A read-only review found that the first builder accepted
realistic client and credential-shaped values; validation now accepts only the
reserved fixture constants, with rejection tests.

Eight pure Python tests pass. The source builder covers the pending approval,
client-binding rejection, partial source-consumption rejection, legacy
upgrade/remint rejection, and source-only immutability attempts for all 33
non-consumption approval snapshot fields. The immutability case checks the
expected trigger diagnostic, unchanged pending row, and absent authority, then
ends with rollback.
No SQL, PostgreSQL process or network command was run. This does not qualify
the pending-intent behavior: S5 has not passed, the builder has not executed
against PostgreSQL, the other S6 lifecycle cases are not implemented, and all
S7 race/plan cases remain unrun.

### 2026-10-23 — Cloud lost-ACK reconciliation and owner restart

A previously overlooked successful runtime receipt closes the earlier open
Cloud lost-ACK/restart question for its bounded local fixture. The Rust
CloudWorker ran against the actual Remote runtime handler over pinned loopback
TLS. The handler committed a publication and the fixture dropped its TCP ACK;
the host kept its old publication cursor and pending intent, then reconciled
through GET without repeating the PUT. A second run preserved the HostStore
across owner-process exit, reopened a new owner, reconciled state, and completed
the next admitted generation without republishing the ambiguous operation.
The 9-request restart receipt and 4-request lost-ACK receipt both report their
tests selected/passed, matching routes, and no repeated PUT. The evidence log
and frozen-input archive hashes match the receipt.

The same runtime receipt records Cloud publication, heartbeat and permission
refresh passing, plus central revoke fencing both live clients and returning
401 on the next runtime GET. A separate active-channel fixture passed
reconnection under the shared grant, no application-frame replay, lost commit
ACK recovery, and closure of four relay sockets on grant revoke. Its error
capture and run log are hash-bound.

Receipts: [Cloud lost-ACK/restart](../../../auth-app/artifacts/cloud-worker-restart-pg18-tcp-drop-clt-20261023/e82ef717-6afa-4550-b3f6-9875d2910405/runtime-proof.json), [active relay](../../../auth-app/artifacts/cloud-unshare-active-relay-rerun-20261023g/a42750d8-c52c-4237-9d5b-cd1ec79e2d3d/runtime-proof.json).

These are local PostgreSQL 18.6 and loopback TLS/relay fixture results; cleanup
completed with zero PostgreSQL TCP listeners. They do not qualify deployed
Cloud/relay endpoints, production TLS, cross-host behavior, soak, or release
targets. The receipts explicitly keep `productionQualified=false`.

### 2026-10-23 — Consumer candidate inventory drift successor

The copied v2 static candidate no longer matched the active Auth
`consumer_inventory` function: migration 006 had added the host's signed key
commitment and initial commitment to the inventory response. The current Remote
API requires both fields, and its focused inventory suite passed 123/123.
The old v2 candidate was left unchanged. A separate v3 source successor now
retains the current migration function and preserves both commitment fields
in its adapted operator root. Its 167 pure static checks and 5 focused tests
pass; predecessor files are SHA-256 pinned and catalog/ACL pins remain NULL.

No SQL or database behavior was tested. The v3 operator remains fail-closed,
and this source correction does not install the derivative-consent flow or
qualify Consumer S5–S7.

### 2026-10-23 — Consumer S5 source-only bounded-capture successor

A new isolated successor now joins the pinned positive-auth SQL, case plan,
and closed diagnostic parser to a fakeable bounded-pipe adapter. The adapter
rejects partial EOF, oversized or malformed chunks, unbounded chunk
containers, child exit/reap/ownership failures, cancellation, deadline faults,
non-monotonic clocks, non-finite timestamps, and oversized integer
timestamps. Raw diagnostics are collapsed to generic failure. Its runtime
entrypoint remains closed; it cannot launch a process, execute SQL, or connect
to PostgreSQL.

The pure test passed 13/13 and pins the SQL and case-plan SHA-256 values. The
diagnostic parser was byte-for-byte compared with its pinned source. This is
source-only coverage, not a new runtime result: Consumer S5 remains
unqualified and S6/S7 remain NOT_RUN.

### 2026-10-23 — Ubuntu product service cold-boot proof

The source inventory now ignores only the exact UUID-named private runner
view created under the pinned Linux product test package. A symlink at that
reserved directory itself and symlinks elsewhere remain rejected. All 11
source-manifest tests passed, including three regression checks for this
exception; the current source scan contains 1,359 files.

The product Linux runner then completed on the disposable Ubuntu 24.04
aarch64 Lima VM. The native product build and tests passed; the `lomi-host`
suite contributed 545 passing tests. A temporary `systemd --user` service
with linger enabled was active after a real VM cold stop/start and before the
first observed SSH login. Cleanup removed the unit and fixture, restored the
original linger state, and left zero owned fixture processes. The full report
is [here](../../artifacts/product-linux/7e165239-ab9c-4e13-846c-93f0d8929f94/report.json).

The report says `complete=true`, `passed=true`, and `qualified=false`. This is
a bounded product-host boot/service proof on one disposable Linux target. It
does not cover clean installation, account/device-code login, deployed Cloud
or relay, browser shell, or release qualification.

The Windows SSH host key is pinned, but neither the SSH agent nor any local
private-key candidate authenticated as `woro-server`. The probe stopped before
running a remote command, and no Windows fixture was installed. The available
host is the previously identified Windows 10 lab, which cannot qualify the
Windows 11 or Server release targets even after access is restored.

### 2026-10-23 — Local Host regression and production gates rechecked

The current macOS `lomi-host` library suite passed 541/541 with
`DEVELOPER_DIR=/Library/Developer/CommandLineTools`. This process-local
selection avoids changing the machine-wide developer directory or Xcode
license state. The suite covers the local TLS/Noise host, terminal/file
mutations, watch/revoke fences, Cloud worker state machines, and confirms that
Git RPCs remain fail-closed as unsupported.

Xcode 27.1 is already installed at `/Applications/Xcode.app`, but Apple’s
license is still unaccepted; `xcrun devicectl` therefore cannot enumerate the
iPhone. `idevice_id -l` returned no device identifiers. No physical iOS
acceptance ran. Full Xcode build and device testing still require the machine
administrator to review and accept the license.

A read-only containment audit reconfirmed that default macOS PTY cleanup owns
only the original process group. The optional process-scan/coalition backends
do not prove race-free descendant termination, so enabling them by default
would weaken the safety claim. A separate Git ingress audit found no host-side
`git.*` implementation: contracts and Linux-only feasibility spikes exist,
but the spikes do not establish production isolation on macOS, Windows, or
other Linux targets. Both items remain release blockers; no feature was
enabled from these audits.

### 2026-10-23 — Consumer positive-auth eleven-call result reconciliation

An earlier private run did execute eleven positive SQL call checks. Its
controller summary records the in-server rollback comparison, 134 public-log
retirements, retained-child cleanup, and private-data disposal, while keeping
`fullS5Qualified=false` and S6/S7 `NOT_RUN`. It is not accepted: the bound
`root-check.json` says `rootOuterPrivateAbsent=false` and
`PASS_PENDING_INDEPENDENT_ROOT_RESULT_REVIEW`; `root-audit.json` also leaves
independent review open, while the enclosing receipt claims acceptance and
absence. `verification.json` records `OPEN_CONFLICTING_ROOT_RECORDS` and no
downstream reconciliation artifact. The exact old outer path is absent now,
but that does not rewrite the conflicting historical observations. The
separate current positive-auth controller still has no OS-root admission or
runtime appointment. Do not count the old eleven-call run toward S5 acceptance.

### 2026-10-23 — Trusted bootstrap tests with Command Line Tools

The earlier bootstrap test blocked on the Xcode license when it used the
selected Xcode developer directory. Running the same test with a process-local
`DEVELOPER_DIR=/Library/Developer/CommandLineTools` compiled the C fixture and
passed 17/17 cases. No Xcode license or global developer-directory setting was
changed. This validates only the local fake-filesystem/bootstrap harness; the
bootstrap is still not installed in a root-owned location, no OS-root
admission exists, and Consumer positive-auth SQL was not run.

### 2026-10-23 — Consumer S5 four-CTAS rejection subset

The separately pinned four-case pre-012 CTAS runner completed against three
private PostgreSQL 18.6 databases. All four cases returned the expected
`55000` rejection, and each before/after set matched all three databases'
pristine raw catalog projection. This produced 12 rollback comparisons across
27 public sections. The startup status was 0; cleanup recorded stop 0 and
post-stop status 3.

The outer controller observed exit 0 in 88.44 seconds. The pinned evidence
reader and `completion_is_admissible()` both returned true. Root observation:
[validation](../../artifacts/consumer-derivatives-v2-s5-pre012-ctas-supervised-root-result/ee402526-a90a-4f4c-83a3-918236683327/root-validation.json),
[outer observation](../../artifacts/consumer-derivatives-v2-s5-pre012-ctas-supervised-root-result/ee402526-a90a-4f4c-83a3-918236683327/external-observation.json).
The indexed runtime evidence remains at the exact private source view recorded
in that validation; moving it would invalidate its inode-bound evidence index.

Preparing that view exposed missing loader aliases and PostgreSQL share files
in the earlier source-only materialization. The additive runtime-view helper
now validates 14 exact library links, the four executable hashes, and a pinned
1,928-entry `share/postgresql` tree (1,027 files, 26 directories, 875 relative
links). Its six focused tests passed. The original Postgres.app and historical
proof locks were not changed.

This is only the bounded four-case rejection slice. The runner explicitly
records `fullS5Qualified=false`, global catalog/TOAST proof false, S3/S4 not
run, and business/lifecycle coverage false. Consumer S5–S7 and production
qualification remain open.

### 2026-10-23 — CTAS S5 source closure revalidation

The pinned Python 3.14 source-only `sealing.test.py` passed 22/22 checks for the
current S5 constructor hardening. The prepared CTAS4 supervised test and its
admission prerequisite both stop at source-closure checks before PostgreSQL or
Node starts. The CTAS lock expects the historical constructor SHA-256
`7edfc912…`; current `construct.py` is `b9ec75b1…`. Its recursive historical
admission chain also pins that earlier constructor and four older
`admission-supervised` files. Those old pins are intentional provenance for
prior accepted evidence, so they were not refreshed in place.

The positive-authorization recorder suite also passed 9/9 pure tests. The
current successor controller remains `NOT_RUN`; a historical eleven-call run
is provisional because its root cleanup/review records conflict, as documented
above. Neither result qualifies full S5 or a successful authorized Consumer
product lifecycle.

An independent source review initially questioned the CTAS parser's required
advisory-lock blank line, then retracted the finding after checking the
unchanged 012 operator's void-valued `pg_advisory_xact_lock` query. A direct
no-process parser probe accepted exactly one such blank row and rejected its
absence. No SQL was run and no parser change was made. The four CTAS cases
remain unexecuted; the prior bounded S5 result and all full-S5/S6/S7 gates keep
their existing scope.

The next CTAS step is a separately frozen successor containing the complete
historical dependency closure and a reviewed resolver, with current S5 source
inputs pinned independently. Existing locks and accepted proof artifacts stay
unchanged; refreshed hashes alone do not admit a runtime appointment.

### 2026-10-23 — Mobile source checks and Android debug build

On Node 22.23.3, the mobile lint, both TypeScript checks, all 289 unit tests,
renderer provenance/CSP, crypto provenance, and app configuration checks passed.
`pnpm check` stopped at `release:check`: Xcode 27.1 is installed, but Apple’s
license has not been accepted. No Xcode setting or license state was changed.

The Rust mobile crypto wrapper and vendored core passed 71 tests. Release
libraries built for Android ARM64 and x86_64, and Gradle `assembleDebug`
completed successfully. The local 160 MiB APK contains
`liblomi_mobile_crypto.so` for both ABIs; SHA-256 is
`718d49861527a1579decddaed1a1d63d85816b7e0a22e4bbe3b1538ea8120080`.
This is a local debug build, not a signed release. `adb devices -l` and
`idevice_id -l` returned no physical devices, and no device smoke test ran.

This does not qualify mobile v2 method parity, the shared Rust/WASM/mobile
production manifest, physical Android/iPhone acceptance, or E6/E7.

### 2026-10-23 — Consumer PostgreSQL metadata inspection without a skip

The private `--suite consumer` runner now creates a second, exact-name
`lomi_auth_staging` database inside its UUID-owned socket-only PostgreSQL 18.6
cluster. It deploys the frozen migrations and permission SQL there, then passes
the staging URL only to the legacy metadata-inspection test after verifying
the URL has no password and points to that run's private socket. The existing
production bootstrap target policy was not changed.

The metadata inspection passed against the real database. The full bounded run
reported 978 tests passed, zero skipped, and zero failed; Prisma validation and
Auth typecheck passed. The private cluster stopped, its post-stop check passed,
and the TCP listener count was zero. Evidence: [runtime proof](../../../auth-app/artifacts/consumer-staging-metadata-fixture-rerun-20261023/22f246c1-df6b-4f92-8af2-c6fb1df90743/runtime-proof.json) and [runtime log](../../../auth-app/artifacts/consumer-staging-metadata-fixture-rerun-20261023/22f246c1-df6b-4f92-8af2-c6fb1df90743/runtime-proof.log).

This is fixture evidence for current direct web/desktop Consumer behavior. It
does not qualify derivative-consumer approval/exchange, full S5–S7, production
deployment, or the OS/client release matrix.

### 2026-10-23 — Cloud publication/unshare through the real handler and relay

The pinned PostgreSQL 18.6 transport diagnostic passed with the actual Cloud
worker, Better Auth runtime handler, private TLS listener, and two active relay
channel sockets. It made 463 assertions. Immediately before the worker starts,
the channel is admitted and its database expiry is still in the future; after
publication, the same expiry is still in the future, both sockets close, the
channel authority check fails, and the durable transport row is closed. The
handler received exactly two publication PUTs. PostgreSQL was socket-only,
reported zero TCP listeners, and the owned cluster stopped and passed its
post-stop status check.

Evidence:
`../../auth-app/artifacts/cloud-unshare-active-relay-rerun-20261023h/c03ca306-4752-43de-bb97-ca6f26787244/runtime-proof.json`.
This proves this bounded local Cloud/relay slice only. Noise transport
qualification, multi-client soak, deployed Cloud cycle, production TLS, and
full Consumer S5–S7 remain open.

### 2026-10-23 — Consumer S0 frozen-source verification

The permitted source-only checks passed: `validate.py` reported 53 static
input/AST/allowlist/recipe checks, and `prepare.py --check-inputs` verified the
named public inputs and frozen candidate. Neither command invoked PostgreSQL,
checked executable versions, launched a child process, or executed SQL.

This closes only the static S0 check. No PostgreSQL appointment was admitted;
S1–S8 remain NOT_RUN, and Consumer S5–S7 are not accepted.

### 2026-10-23 — product Host and user-service lifecycle on Ubuntu VPS

A private archive of the exact 1,344-file source snapshot built on the
user-authorized Ubuntu 24.04.5 x86_64 VPS with Rust/Cargo 1.98.1. The selected
product-host command passed 819 tests in 32 suites; two existing tests were
ignored. The Linux run includes real TLS/Noise two-client single-PTY coverage,
unshare/revoke fences before input and during snapshot/watch, files.watch
acknowledgement/resume and native inotify same-mtime edits. Across separate
SSH connections, the host runtime and terminal session survived disconnect,
and reopening the view did not create another shell. The unprivileged
`systemd --user` fixture passed its 9 prepare and 23 verification checks for
ownership, SSH detachment, restart/crash recovery, PTY cleanup and interrupted
uninstall. The exact marked service, temporary test directory and remote
source tree were removed after evidence capture.

Evidence: [run report](../../artifacts/product-linux-vps/cc81ca51-b68a-44b0-b399-404cf40e0980/report.json), [build log](../../artifacts/product-linux-vps/cc81ca51-b68a-44b0-b399-404cf40e0980/build.log), [host test log](../../artifacts/product-linux-vps/cc81ca51-b68a-44b0-b399-404cf40e0980/product-host-tests.log), and [frozen source archive](../../artifacts/product-linux-vps/cc81ca51-b68a-44b0-b399-404cf40e0980/frozen-source.tar.gz).

This is a bounded host regression and current-user service result. It does not
test reboot/boot without a logged-in user, a clean install, device-code
enrollment, deployed Cloud relay/fan-out, browser/mobile shell, or a long
multi-host soak. E3 and full E1/E2 remain open.

### 2026-10-22 — Cloud TCP-drop acceptance blocked by the local Xcode license

The PostgreSQL 18.6 attempt for a real TCP drop, CloudWorker restart, cursor
reconciliation and multi-client revoke stopped while linking the Rust transport
driver: Apple `cc` requires the installed Xcode license to be accepted. The
private database was never started and cleanup completed. This is no test
result, not a product failure. The earlier limited Cloud fixture on PostgreSQL
16.15 remains the latest passing evidence.

Receipt:
`../../../auth-app/artifacts/cloud-worker-restart-pg18-tcp-drop-20261022/a1f316d0-cb4d-4351-adab-794a7d6f7f99/runtime-proof.json`.

### 2026-10-22 — iPhone acceptance blocked by the Xcode license gate

Xcode 27.1 is installed and selected, but `xcodebuild` and `xcrun devicectl`
require the local administrator to review and accept Apple's license. No iPhone
build or device test ran. `adb` still detects no Android device. The license
cannot be accepted from this session without the Mac administrator password.

### 2026-10-22 — Consumer S5 recorder protocol check

The allowed source-only recorder test passed 7/7 without starting a child
process or PostgreSQL. The prepared `positive-auth.sql` still has no admitted
runtime integration; exact catalog comparison, credential-safe execution,
admission and S5–S7 acceptance remain open.

### 2026-10-22 — macOS PTY containment and host Git audit

The default macOS PTY worker only contains its original process group. Existing
tests retain a background-descendant counterexample after normal shell exit.
The optional coalition backend is disabled and its process scans do not prove
an atomic fork-drain or complete descendant termination. No production change
was made. The host also has no GitService: every remote Git call is still
rejected as unsupported. A read-only repositories/status slice needs a pinned
repository model, safe isolation and stable file-entry mapping first.

### 2026-10-22 — Remote Web and mobile static gates

On Node 22.23.3, Remote Web passed `pnpm check` (zero errors, four hints),
140/140 tests, static production build/output verification, 24 auth-bootstrap
checks, and IndexedDB identity recovery in Chromium, Firefox and WebKit. These
are bounded client/contract checks, not live relay/shell acceptance or the
full E6 method matrix.

Mobile passed both typechecks, 289/289 tests, renderer, crypto provenance and
configuration checks. `pnpm check` stopped at `release:check`: `xcodebuild`
returned 69 because the Apple license is unaccepted. No iPhone build or
physical-device acceptance ran.
The full Remote Web browser crypto fixture also stopped before launching
browsers because linking its native Rust peer requires the same Xcode license
(exit 69). The three-engine IndexedDB persistence test is narrower than E6.

Desktop passed `pnpm check`, `pnpm test` (306/306 plus AI runtime 45/45), and
the frontend `pnpm build`. The generated Workbench chunk is 1,089 kB and Vite
warns about chunks over 500 kB. These checks do not build the native Rust host,
installer or qualify the E7 resource targets.

### 2026-10-22 — Consumer 64-window limit returns a canonical 429

Extended the real Consumer runtime test to register 63 distinct window
identities under one authorization, then race two valid challenges. Exactly
one succeeds; the other returns `RESOURCE_EXHAUSTED` with `retryable=true` and
`effect=none`. The persisted count remains 64. This checks the HTTP boundary,
concurrent serialization and database postcondition with the actual handler
and limited PostgreSQL roles.

Validation: the private PostgreSQL 18.6 Consumer suite passed: 7 runtime/schema
tests; 961 passed, 1 skipped, 0 failed across 16 files; Prisma validation and
TypeScript passed. The socket-only cluster stopped and cleanup completed.
Receipt:
`../../../auth-app/artifacts/consumer-window-cap-race-429-20261022/cacd6b45-8216-40f6-8579-7fc7271cdc70/runtime-proof.json`
(SHA-256 `8d256b0d15fb96058ae9305fc4b0f81ddf528dbd91219f2c9395d067d0ac73b5`).
The receipt states `productionQualified=false`; full S5/S6/S7 remain open.

### 2026-10-22 — Linux workspace rerun and file identity fix

The Unix file-entry identity now includes filesystem birth time in addition to
device and inode, using `statx` for Linux and native birth-time fields on macOS.
Configured protected paths fail closed when their identity cannot be read. This
prevents a stale entry token from resolving to a replacement after inode reuse.

Validation: local macOS `cargo fmt --all -- --check` and
`cargo test --offline -p lomi-files` passed (23 tests); Linux cross-target
`cargo check --offline --target x86_64-unknown-linux-gnu -p lomi-files` passed.
On Ubuntu 24.04 x86_64, `cargo test --offline -p lomi-files` passed 26/26 and
`RUST_TEST_THREADS=1 cargo test --offline --workspace --all-targets --quiet`
passed with exit code 0. The first parallel workspace run had one
`lomi-terminal` PTY spawn failure; that exact test passed alone and the serial
workspace rerun passed. This does not qualify the supported OS/service matrix,
full Consumer/Cloud, or product release.

### 2026-10-22 — zakres pełnych lokalnych testów

Pełny `bun test` w `auth-app` uruchomił 72 pliki: 1 325 zaliczeń, 29
pominięć, 100 niepowodzeń i 1 błąd. Widoczne błędy DB wskazują brak lokalnego
PostgreSQL `127.0.0.1:54329`; bez izolowanej bazy nie można odróżnić wszystkich
awarii środowiska od błędów kodu ani uznać odbioru Consumer/Cloud.
Wcześniejszy przebieg `pnpm check` w `mobile-app` na Node 22 przeszedł lint,
oba typechecki, 289 testów, renderer, provenance, config i wtedy dostępne
release source checks. W tamtym pomiarze `adb devices -l` i `idevice_id -l`
wykryły zero urządzeń; aktywny developer directory to Command Line Tools.
Późniejszy stan Xcode 27.1 i niezaakceptowanej licencji jest zapisany wyżej.
Windows SSH potwierdził build 10.0.19044, który nie kwalifikuje Windows 11 ani
Windows Server. Te wyniki nie zastępują odbioru docelowych hostów i urządzeń.

### 2026-10-22 — Cloud utrata ACK i restart procesu właściciela

Dodano do prywatnego odbioru CloudWorker przebieg, w którym proces zapisuje
intencję publikacji, traci ACK po zatwierdzeniu publikacji seq 8, kończy się,
a nowy proces otwiera ten sam profil. Odbiór sprawdza claim wygasłej dzierżawy,
GET, heartbeat i jedną publikację seq 1 w nowej generacji, końcowy kursor
lokalny i Cloud oraz brak ponowienia starego PUT. Binarium testowe Rust
skompilowało się (`cargo test -p lomi-host --features cloud-fixture
cloud_worker_reconciles_lost_ack_after_owner_process_restart --no-run`).

Nie uruchomiono odbioru: brak prywatnego PostgreSQL, tokenu i TLS fixture;
Bun zgłosił skip. To jest skompilowany test harness, nie potwierdzony cykl
Cloud ani integracja z produkcyjnym relayem.

### 2026-10-22 — Remote Web v2 bootstrap and browser checks

Added a browser-bootstrap regression proving that an authenticated account
with the configured v2 relay mounts the pairing panel and requests inventory
through the same-origin cookie transport. It checks GET-only behavior,
`X-Lomi-Request`, same-origin credentials, and absence of bearer authorization.
The older inventory fixtures now include the relay flag and canonical host
commitment fields required by the current contract.

Validation: `bun test tests` 137/137 (686 assertions); Node 22
`bun run build` passed `astro check` (45 files, 0 errors, 0 warnings, 4 hints),
static build, and output integrity; `bun run test:auth-bootstrap` passed all
24 checks; `bun run test:browser-identity` passed Chromium, Firefox, and WebKit.
The bundler reports chunks over 500 kB. These are mocked/bootstrap and
identity-persistence checks, not a live relay, host, or shell acceptance.

### 2026-10-22 — Remote Web v2 uses a separately trusted relay endpoint

The authenticated Remote account now carries `REMOTE_RELAY_V2_URL` only when
`REMOTE_RELAY_V2_ENABLED` is active. The API validates the dedicated secure
WebSocket path; Remote Web validates the exact production, staging, or local
endpoint and passes it only to the v2 pairing/channel path. The legacy v1
client still uses `relayUrl`, and v2 remains opt-in. An independent review
found and closed a disabled-feature exposure; account, mobile, native, and
ticket responses now omit the v2 URL while the gate is off.

Validation: Auth config tests 2/2; Remote Web tests 137/137 (686 assertions);
`astro check` 0 errors/0 warnings (4 hints); static production build and output
integrity passed. IndexedDB identity restoration passed Chromium, Firefox, and
WebKit. These checks do not establish a deployed relay/host round trip, clean
Ubuntu/Debian acceptance, or full E3/E6; the default product path remains v1.

### 2026-10-22 — Linux systemd-user fixture po SSH detach i reboot

Na Ubuntu 24.04 ARM64 Lima VM `lomi-e0` świeży prywatny snapshot bieżących
źródeł zbudował i przetestował `lomi-service-fixture`. Wszystkie fazy przeszły:
prepare 26/26, after-disconnect 2/2, rzeczywisty restart VM i after-reboot
8/8, cleanup 4/4. Sprawdzenia obejmują zachowanie PTY po zakończonej sesji
SSH, restart systemd-user przy boot bez sesji użytkownika, odrzucenie PID ze
starej epoki i sprzątnięcie fixture. Build i natywne testy crate'a przeszły.

Raport: `artifacts/services-linux/evidence.json` (SHA-256
`afe2cffce88f3a57f178781c190c857c3d854b6aad88c7d1ff60186074e6c593`).
Receipt ma `qualifiedProductHost=false`; to testowy systemd-user fixture na
jednej VM, nie instalacja produktu, systemowa usługa ani czysty odbiór VPS.
Cloud/relay, produkcyjne revoke/watch/Git, inne Linux targety, pełne E1/E2
i E3–E7 pozostają otwarte.

### 2026-10-22 — wcześniejszy pomiar urządzeń fizycznych do E6

Przed późniejszym wyborem Xcode 27.1 `adb devices -l` wykrył zero urządzeń,
`emulator -list-avds` zwrócił pustą listę, a `idevice_id -l` wykrył zero
urządzeń iOS. Wtedy były tylko macOS Command Line Tools, bez Xcode
`xcodebuild`, `devicectl` ani `simctl`. Fizyczne scenariusze Android/iOS z
odbioru E6 nie zostały wykonane.

### 2026-10-22 — lokalne credentiale do podpisu E7

Keychain zgłasza jedną ważną tożsamość Developer ID Application i zero
Developer ID Installer. Windows 10 host laboratoryjny ma zero certyfikatów
Code Signing z kluczem prywatnym w `CurrentUser`/`LocalMachine`.
Notarization credentials i pipeline podpisanych metadanych nie zostały
zweryfikowane; niczego nie podpisano ani nie opublikowano.

### 2026-10-22 — host odrzuca niezaimplementowane Git RPC

Na macOS bieżący `lomi-host` przeszedł natywny test TLS/Noise
`real_tls_noise_git_methods_are_refused_without_any_result_until_a_git_service_exists`
(1/1). Potwierdza to brak sfabrykowanego `git.repositories` i zachowanie
fail-closed. GitService, jego metody produktu, izolacja platformowa i revoke
podczas operacji pozostają niezaimplementowane.

### 2026-10-22 — Remote Web v2: świeża zgoda przy wznowieniu

Niezależny przegląd klienta wykrył, że ręczne połączenie i reconnect ufały
zapisanej zgodzie bez ponownego odczytu jej stanu. Przed otwarciem nowego
kanału klient teraz pobiera aktualny pairing, wymaga nadal aktywnego `approved`,
sprawdza konto/sesję/autoryzację i fingerprint tożsamości okna, a potem ponownie
pobiera inventory i porównuje workspace, epoch, runtime i podpis hosta. Zmiana
sesji, klucza albo revoke zatrzymuje próbę; unmount anuluje oczekujące żądania.
Mutacje terminala nie są ponawiane.

Walidacja: Remote Web `bun test tests` 135/135 (680 asercji),
`bun x tsc --noEmit` i `git diff --check` przeszły; statyczny build przeszedł
`astro check` (45 plików, 0 błędów/ostrzeżeń, 4 hints), render i kontrolę
wyjścia. Test przeglądarkowy z fixture v1 zakończył się kodem 0; trwała
tożsamość IndexedDB po refresh przechodzi Chromium, Firefox i WebKit.
Fixture v1/helpery nie stanowią integracyjnego odbioru tego komponentu v2.

E3 nadal nieodebrane: nie było czystego VPS Ubuntu/Debian, logowania kodem na
telefonie, wdrożonego relay, powrotu po restarcie hosta ani testów utraty sieci
i unshare na prawdziwym hostcie. Klient v2 jest opt-in obok aktywnej ścieżki v1.

### 2026-10-22 — Remote Web v2: pairing, terminal i Explorer

Bieżący `App` montuje jawny panel v2 obok dotychczasowej ścieżki v1. Po
świadomym potwierdzeniu klient rejestruje trwałą tożsamość okna, tworzy albo
wznawia pairing, sprawdza aktualny host/workspace/authority i otwiera kanał
relay/Noise. `RemoteV2Workspace` pobiera snapshot workspace, może otworzyć
istniejący terminal, utworzyć nowy tylko po osobnym kliknięciu i wyświetla
Explorer. Mutacja utworzenia zapisuje operation ID przed wysłaniem; po utracie
odpowiedzi klient sprawdza status i nie ponawia mutacji.

Aktualna walidacja: `bun test tests` 132/132 (667 asercji); trwała tożsamość
IndexedDB po odświeżeniu przeszła Chromium, Firefox i WebKit. Build pod Node
22.12.0 przeszedł `astro check` (44 pliki, 0 błędów/ostrzeżeń, 4 hints),
statyczny build oraz integralność outputu.

Powrót do zatwierdzonego widoku v2 po refresh używa wyłącznie tab-local
`sessionStorage` intent z tuple sesji, identyfikatorem okna i ID pairing.
Odtworzenie ponownie sprawdza pairing, inventory i authority; terminal creation
pozostaje osobną akcją, a input nie jest zapisywany ani powtarzany. Intent jest
czyszczony również przy braku pasującej tożsamości lub rekordu pairing. Testy
helpera pokrywają walidację tuple/status/storage, ale nie są pełnym testem
odświeżenia komponentu na żywym handlerze/relay.

To jest podłączona, opt-in ścieżka v2, nie odbiór E3: bootstrap konta i główna
ścieżka nadal zawierają v1; nie wykonano czystej instalacji na targetowym VPS,
logowania telefonem, realnego shell/Explorer przez wdrożony relay ani testu
utraty sieci/unshare na prawdziwym hoście. Nie dowodzi też pełnej zgodności
metod v1 na desktopie i urządzeniach mobilnych.

### 2026-10-22 — natywny product-host proof na Windows 10 LTSC

Na labowym Windows 10 Enterprise LTSC 19044 (x64, Rust 1.98.1) bieżący,
zamrożony build `lomiremote` przeszedł natywny host proof: CLI, SQLite, IPC,
ConPTY i syntetyczny prywatny workspace. SSH-continuity start/stop, MSVC Clippy
i rustfmt również przeszły; raport potwierdza usunięcie fixture'a i zero jego
pozostałych procesów. Receipt:
`artifacts/product-host-windows/b3e3aeab-75dc-4d58-b4ea-555f45122722.json`
(SHA-256 `dd512f4895eef778413d49754902b17eb6bd144cd42c554157301b20e380a396`).

Zakres jawnie nie obejmuje SCM, poświadczeń ani rzeczywistego workspace i nie
kwalifikuje Windows 11/Server ani macierzy wydania. Pozostają otwarte pełny
boot/logon/logoff, systemowe sekrety oraz odbiór E1/E2.

### 2026-10-22 — Cloud heartbeat i centralny revoke z dwoma klientami

Naprawa dotyczyła fixture testowego: podczas attachu i oczekiwania na oba
terminale ten sam CloudWorker nie odnawiał heartbeat. Lokalny test przesuwał
jedynie znacznik obserwacji, więc rzeczywiste 5-sekundowe freshness wygasało
przed `Parked`. Fixture teraz przechodzi przez rzeczywisty CloudWorker i lokalny
handler HTTPS, zapisuje aktualne `PeerEligibility`, a po zaparkowaniu klientów
przestaje odpytywać Cloud, aby nie ścigać się z revoke. Produkcyjny limit i
fail-closed pozostały bez zmian.

Rerun `runtime` przeszedł z kodem 0. Dwa połączone kanały TLS/Noise zostały
zamknięte po centralnym manager revoke; epoch hosta wzrósł, wszystkie rodziny
autoryzacji zostały cofnięte, supervisor otrzymał rzeczywiste HTTP 401, wspólny
owner został zablokowany, obaj klienci zamknęli kanały, a stan runtime nie uległ
zmianie. Siedem tras Cloud fixture zgadzało się z oczekiwaną kolejnością.
Handler suite: 961 pass, 1 skip, 0 fail i 7808 asercji; Prisma, TypeScript,
build Rust oraz cleanup przeszły. PostgreSQL 18.6 był prywatny i socket-only;
został zatrzymany. `liveSourceChangedDuringRun=false`.

Receipt: `artifacts/cloud-actual-handler-refresh/b2a37672-001c-4e71-a994-bcb535ac7647/runtime-proof.json`
(SHA-256 `c6a503d53dfcbc9d38e24d67b8f70a7dd7110aa2daa7e0c2868718a70322bf87`),
log SHA-256 `0746ef84a2092df30878088f27b63ecfa54b891f5d84dc12efaf7e35afa34ade`.
`productionQualified=false`: to ograniczony lokalny dowód Cloud, bez wdrożonego
relay, restartu hosta w usłudze, cross-host fanout ani kwalifikacji produkcyjnej.

### 2026-10-22 — przygotowanie statycznej bramki consumer S5–S7

Poprawiono preparer: katalog wejść bierze teraz z lokalizacji pliku manifestu,
który jest przypięty w `inputs.lock.json`, zamiast ze starszej gałęzi staging.
Validator przypina bieżący digest tego manifestu. Przeszło 53 kontrole
statyczne, kontrola zamrożonych wejść i generowanie prywatnego planu.
Receipt `artifacts/consumer-derivatives-plan/e1d69230-d471-40d1-aaa2-3a16b5bd673f`
ma `PREPARED_NOT_EXECUTED`, `postgresInvocations=0`; S5/S6/S7 nie zostały
uruchomione i nadal są otwarte.

### 2026-10-22 — Cloud lost-ACK na rzeczywistym handlerze: dowód częściowy

Prywatny fixture PostgreSQL 18.6 / Bun 1.4.2 zbudował Rust transport driver i
binarium testowe, zastosował migracje i ograniczone granty oraz uruchomił
rzeczywisty handler aplikacji i Rust CloudWorker przez lokalny TLS. Markery
potwierdzają publikację i refresh uprawnień, lost ACK po rzeczywistym TCP drop,
zachowany intent, brak advance sekwencji, reconcile przez GET bez ponownego
PUT oraz recovery po restarcie. Przeszedł też marker ACK po zamknięciu drugiego
klienta.

Agregat **nie przeszedł**: Bun 6/7; test centralnego revoke z dwoma klientami
nie doczekał parkowania obu terminali (`UnexpectedEof` w TLS/Noise fixture).
`shutdownAndCleanupCompleted=true`, klaster zatrzymany, źródła stabilne podczas
przebiegu, `productionQualified=false`. Nie zaliczam centralnego revoke ani
pełnego E2 na podstawie pozytywnych podmarkerów.

Receipt: `artifacts/cloud-actual-handler/586ae1ec-f051-4d4b-9b07-f954c25b866d/runtime-proof.json`
(SHA-256 `46a281c013c27549f2eb47ed1bcd38c0f4794b00e92be115b47df6be99a7ba91`),
log SHA-256 `00c71d8859c7848007422e2c956eb145b528afe33cf084db51e18b66b8f8e6a9`.

### 2026-10-22 — produktowy Host na Ubuntu 24.04 ARM64

Świeże, zamrożone archiwum bieżących źródeł przeszło na Ubuntu 24.04 ARM64
(kernel 6.8.0-147-generic, glibc 2.39): natywny build `lomiremote` oraz
`tools/test-host.sh -p lomi-platform -p lomi-host-store -p lomi-terminal
-p lomi-host -p lomiremote` (główna biblioteka Host: 541/541; wszystkie
uruchomione zestawy zakończyły się kodem 0). Przeszła także ciągłość po
zamknięciu niezależnego SSH oraz tymczasowy systemd-user lifecycle: rozłączenie,
restart/crash/stop, zachowanie tożsamości, brak automatycznego shella i cleanup
fixture'a bez pozostałych procesów.

Raport: `artifacts/product-linux/3e4c5788-ed33-4ad5-b4bb-2291b9799da6/report.json`
(SHA-256 `cd94090428b613f331ad61d2e5aa326e05fd6bc5df5ebc2c2b6e9262baf4e92a`).
To ograniczony dowód hosta na jednej architekturze: raport ma
`qualified=false`; systemd-user nie testuje bootu/rebootu, instalatora,
uprawnień konta systemowego, Cloud/relay ani pozostałej macierzy. Nie zamyka
E1/E2 ani gotowości wydania.

Pierwsza próba z macOS `experimental-macos-session-cleanup` na macOS 27 nie
przeszła supervision: 8/13 testów nie domknęło cleanupu. Skaner pomijał
zombie/kończące się procesy dopiero po `getsid` i traktował ich `ESRCH` jako
globalny błąd. Po poprawce kolejność filtrowania i zbieżność sprawdzają tylko
obserwowane procesy tej samej sesji; supervision przechodzi 13/13, lib 26/26,
formatowanie przechodzi, a niezależny review nie znalazł materialnego problemu.
Funkcja nadal pozostaje opt-in: nie dowodzi containmentu przy fork churn ani
escape przez `setsid`, więc nie zamyka wymogu produkcyjnego.

### 2026-10-22 — aktualny lint i pełny Host na Linux laboratoryjnym

Po poprawce testowego harnessu (bez zmiany zachowania produkcyjnego) świeże
archiwum źródeł `3d508fd35b320d9a174680d4d1e96c531a2202aaf32257267a862d96258cd299`
przeszło na Arch Linux x86_64: `cargo clippy --offline -p lomi-host
--all-targets -- -D warnings` oraz pełne `cargo test --offline -p lomi-host`
(535/535; 0 niepowodzeń). Snapshot używał istniejącego cache `target` poza
katalogiem źródeł. Arch jest tylko hostem laboratoryjnym, nie kwalifikuje
Ubuntu/Debian z macierzy. Test prywatnego `cloud-fixture` i PostgreSQL nie był
w tym przebiegu uruchamiany; E2, usługi na czystym systemie i odbiór produkcyjny
pozostają otwarte.

### 2026-10-22 — bieżące bramki pakietów hosta

Na bieżącym checkoutcie przeszły zestawy `lomi-host-auth` (64 testy),
`lomi-host-http` (60) i `lomi-host-store` (127) oraz Clippy dla wszystkich
targetów tych trzech pakietów z `-D warnings`. Wraz z wcześniej zapisanym
wynikiem 535/535 dla biblioteki `lomi-host` potwierdza to te zakresy kodu.
Nie zamyka to E1/E2, testów usług na docelowych systemach, ścieżek konsumenta
ani macierzy wydania.

### 2026-10-22 — dodatkowe dowody Consumer, Cloud i mobile

Aktualny fixture `auth-app` `runtime` przeszedł na macOS z prywatnym
PostgreSQL 18.6, pinned Bun 1.4.2 i Rust 1.98.1. Faktyczny handler Better
Auth oraz Rust CloudWorker przez loopback TLS potwierdziły publikację i
odświeżenie uprawnień, utratę ACK po dropie TCP, brak przesunięcia kursora
przed uzgodnieniem, zachowanie intencji, reconciliację bez ponownego PUT oraz
odtworzenie po restarcie bez ponownego PUT. Oddzielny przebieg `runtime`
potwierdził centralny revoke i zamknięcie dwóch klientów pod wspólnym ownerem;
listener i prywatna baza zostały zatrzymane. Dowód jest w
`../auth-app/artifacts/cloud-runtime-tcp-drop-macos-20261022/f6e02d09-3869-4ec4-afa4-539a2cd292fd/runtime-proof.json`.

To nadal lokalny handler/fixture i loopback TLS, a nie wdrożony Cloud ani
produkcyjny relay. Nie kwalifikuje publikacji E2 ani awarii realnej usługi.
`productionQualified=false`.

W `mobile-app` `pnpm check` przeszedł lint, oba typechecki, 289 testów,
kontrole pochodzenia renderera i crypto, konfigurację release oraz higienę
archiwum. `pnpm crypto:test` przeszedł 24 testy Rust w pakietach mobile crypto,
core crypto i workspace. Nie wykonano jeszcze builda ani uruchomienia na
iPhonie: pełny Xcode jest w trakcie instalacji. `adb devices` nie widzi
urządzenia Android, więc fizyczny odbiór Androida pozostaje otwarty.
`remote-web` potwierdził trwałość tożsamości okna w natywnym IndexedDB po
odświeżeniu w Chromium, Firefox i WebKit; to nie obejmuje pełnej sesji v2.

Zdalny host Ubuntu 24.04.5 LTS jest osiągalny i ma targetową wersję systemu,
ale nie wykonano na nim instalacji E3 ani nie potwierdzono czystego stanu.
Laboratoryjny Windows host to Windows 10 Enterprise LTSC 21H2, więc nie
kwalifikuje Windows 11 ani Windows Server 2022+. Nie wykonano tam odbioru
targetowego SCM.

W desktopie projekcja współdzielenia nadal publikuje wyłącznie terminale;
edytor, przeglądarka, chat i zadania agentów nie są panelami zdalnymi.
Desktop ma lokalny Explorer, ale nie ma klienta `files.*`/v2 dla hosta ani
zdalnego selektora workspace. Integracja Explorera wymaga najpierw tego
transportu i ponownej kontroli ownera/revoke. Host nadal odrzuca metody Git;
bez izolowanego snapshot-brokera nie należy ich odblokowywać.

Przed kolejną walidacją procesu znaleziono i zakończono 18 osieroconych
`lomi-pty-supervision-fixture --internal-pty-worker` z PPID 1, żywych od
ponad sześciu godzin, z martwymi bezpośrednimi dziećmi i wysokim CPU.
Wyłącznie te worker’y testowe dostały SIGTERM. To środowisko nie jest dowodem
soak; containment i cleanup potomków na macOS pozostają otwarte.

### 2026-10-22 — dodatkowa walidacja Consumer i Remote Web

Świeży pełny przebieg testów `auth-app` na prywatnej bazie PostgreSQL 18.6
zakończył się wynikiem 1,443 passed, 29 skipped, 0 failed i 14,833
assertions (72 pliki). Skipy obejmują testy wymagające jawnie skonfigurowanych
ról/endpointów oraz native load; wynik nie jest pełnym odbiorem S5–S7.
Izolowany runtime Consumer na Bun 1.4.2 zakończył się wynikiem 7/7 testów
ograniczonych ról oraz 961 passed, 1 skipped, 0 failed w regresjach. Prywatny
fixture E2 dla migracji i uprawnień DB również zakończył się `exitCode=0`;
wszystkie usługi i katalogi tymczasowe zostały zamknięte.

`remote-web` ma teraz test pomyślnego przejścia klienta przez orchestrację
v2: create, admission poll, ticket, uwierzytelnienie relay/Noise i utworzenie
transportu. Test stubuje crypto i relay, więc nie jest dowodem poprawności
krypto ani integracji z wdrożonym relayem. Pełny `bun test` przechodzi: 140/140
testów i 697 assertions. `PATH=/opt/homebrew/opt/node@22/bin:$PATH bun run
build` przechodzi: Astro ma 0 błędów, 0 ostrzeżeń i 4 hints, statyczny build
oraz kontrola wyjścia przechodzą. Vite nadal zgłasza duży chunk JavaScript.

Powyższe wyniki są lokalnymi testami i prywatnymi fixture'ami; nie zamykają
publikacji/heartbeat/revoke na wdrożonym Cloud, instalacji i shellu E3 na VPS,
testów host-service na macOS/Windows/Linux ani E4–E7. Osobny fixture Cloud
z utratą TCP i restartem workera jest obecnie uruchomiony; wynik zostanie
dopisany po zamknięciu raportu.

### 2026-10-22 — CloudWorker lost-ACK restart: actual-handler fixture passed

The corrected private fixture forwards the generation publication to the
actual Remote runtime handler over loopback TLS. It drops the TCP connection
after the handler commits sequence 8, then starts a separate Worker process
using the same durable HostStore. The restarted Worker observes the expired
lease, claims the new generation, reconciles its cursor, and publishes only
sequence 1 in that new generation. The receipt verifies the exact nine-route
sequence, final generation/cursor and local binding, the preserved profile,
and no repeated PUT. The aggregate runtime proof also confirms that central
revoke closed both live clients and that Cloud permission refresh passed.

Evidence: [runtime proof](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/6ba2870c-d049-4a2d-834e-8acc5b2bbc9f/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/6ba2870c-d049-4a2d-834e-8acc5b2bbc9f/runtime-proof.log).
The proof records successful cleanup and PostgreSQL 16.15, but
`productionQualified`, `productionPostgres186Qualified`, and
`boundedPostgres186FixturePassed` are false. This is an actual application
handler/Worker fixture, not a deployed Cloud relay or production deployment.
It does not close full E1/E2, Consumer S5–S7, OS service acceptance, or E3–E7.
Fail-closed behavior was not changed.

### 2026-10-22 — Cloud lost-ACK recovery after worker restart: passed fixture

Corrected the restart fixture to model the expired-lease path. The Cloud GET
returns no live runtime after lease expiry; the host invalidates the old local
binding and ambiguous publication intent, preserves the workspace outbox, and
defers Claim to a subsequent GET. This keeps the production fail-closed policy
unchanged. The fixture now checks the exact nine-request sequence, final
generation/cursor/workspace state, local ACK and binding, unchanged Store bytes
at process handoff, and exactly two PUTs: the committed old-generation
sequence 8 and one new-generation sequence 1.

On the user-authorized Ubuntu 24.04.5 x86_64 VPS, the runtime harness passed:
7/7 selected PostgreSQL-backed runtime files, 962/962 Rust tests across 16
files, Prisma validation, auth-app typecheck, and legacy non-database
regressions. PostgreSQL 16.15 used an owned socket-only fixture; the Rust
CloudWorker used pinned private loopback TLS against the actual Remote runtime
handler. Lost-ACK injection, restart reconciliation, no repeated PUT,
publication/heartbeat, permission refresh, central revoke and both live
clients closing all passed. The private cluster shut down and cleanup passed.
`cargo fmt --all -- --check` and `bun run check` also pass locally.

Evidence: [runtime proof](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/6ba2870c-d049-4a2d-834e-8acc5b2bbc9f/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261022/6ba2870c-d049-4a2d-834e-8acc5b2bbc9f/runtime-proof.log).
The receipt explicitly says `productionQualified=false`: it proves the real
Rust worker and application handler over a private fixture, not the deployed
Cloud/relay, target service matrix, E3 shell acceptance, or product release.

### 2026-10-22 — E6 RPC parity inventory foundation

Added `contracts/client-rpc-parity.json` with all 39 canonical Rust RPC
methods and per-client source-evidence status for desktop, Remote Web and
mobile. Git remains explicitly blocked and the inventory claims no acceptance
tests. `tools/check_rpc_parity_manifest.py` checks that wire names and Rust
variants match the canonical `methods!` declaration; focused tests cover
method-set drift, duplicate wire names and the Git block. The validator and
all four tests pass.
This is an inventory guard only: it does not connect the missing client
methods or pass E6's browser/device acceptance matrix.

### 2026-10-22 — E7 update verifier test attempt

Started the documented `lomi-update-trust` fault-injection test command with a
temporary target directory. Cargo downloaded and began compiling the locked
`tough`, AWS-LC and SQLite dependencies. The build was stopped before the test
binary ran when free space fell to 1.4 GiB; the temporary target was removed,
and free space returned to 1.6 GiB. No E7 verifier test result is claimed.
The existing offline verifier remains limited to signature verification and
does not implement installer activation, update transport, rollback or
platform qualification.

### 2026-10-22 — CloudWorker restart fixture: two-step recovery expectation

The restart fixture now models the two distinct owner turns required after the
sequence-8 publication committed but its TLS acknowledgement was lost. The
first GET must settle the retained local intent and clear the outbox; because
that Store reconciliation has an effect, it cannot also mint a claim
continuation. A second GET may then obtain claim admission for the expired
lease. The expected handler route sequence includes both GETs before claim,
followed by the new-generation GET, heartbeat and sequence-1 publication.
Production fail-closed behavior was not changed.

`cargo fmt --all -- --check` and the Auth TypeScript check pass. The isolated
runner built both Rust fixture binaries, but stopped before initializing its
private PostgreSQL cluster: available disk was 2,081,103,872 bytes against its
2,147,483,648-byte reserve. The revised restart scenario has therefore not
run and no Cloud restart acceptance is claimed. Receipt:
`../auth-app/artifacts/e2-runtime-evidence-rerun1/3e809429-5d37-41e1-87e3-aeda77ab1ada/runtime-proof.json`
(SHA-256 `f233924de6f38f92cc893ca79f9aec871f171be85a1b5b4c7540554e235e8463`).

Review of the expected route list found nine requests after adding the separate
reconciliation GET, while the aggregate assertion still expected eight. The
assertion now matches the nine explicit routes; `bun run check` passes. This
corrects the fixture but does not replace the blocked private PostgreSQL run.

### 2026-10-22 — Remote Web v2 Explorer name search

The v2 Explorer now calls `files.searchNames` for the open host-resolved
directory, loads cursor pages, drops responses from canceled or superseded
searches, and renders matching files and directories. Selecting a file opens
the existing preview; selecting a directory opens that directory. Name search
does not search file contents. Search results do not carry a parent chain, so
the breadcrumb trail for a deeply nested result is not reconstructed.

Validation: Explorer and v2 transport tests pass 16/16; Astro check reports
0 errors, 0 warnings and 4 existing hints; the static production build and
output-integrity check pass. This is opt-in Remote Web v2 UI coverage, not a
live relay/host acceptance or desktop/mobile Explorer integration.

### 2026-10-22 — natywne watchery Linux, macOS i Windows

`files.watch` używa teraz natywnych powiadomień na Linuxie (inotify), macOS
(kqueue vnode dla przypiętego katalogu i do 64 bezpośrednich plików, z limitem
dostosowanym do wolnych deskryptorów)
oraz Windows (`ReadDirectoryChangesW` overlapped z buforem 16 KiB). Zdarzenie
uzbraja watcher ponownie przed odrzuceniem starego uchwytu, aby uwzględnić
utworzone lub podmienione pliki. Przepełnienie, utrata/błędny rekord i błędy
backendu zamykają watch przez resync. Pięciosekundowe uzgadnianie fingerprintu
pozostaje zabezpieczeniem dla zmian ścieżki nadrzędnej i ograniczeń adaptera.

Na macOS przeszły natywnie testy hosta `unix::remote_files_watch::tests`
(11/11), w tym edycja pliku o tym samym rozmiarze po przywróceniu mtime,
ponowne uzbrojenie po utworzeniu pliku oraz poprawny resync po usunięciu
katalogu. Świeży rerun na bieżącym checkoutcie ponownie przeszedł 11/11; build
test harness trwał 1m23s, a testy 0.71s. Świeży rerun
`cargo test --locked -p lomi-files` również przeszedł 20/20, w tym test przy
niskim `RLIMIT_NOFILE`.
Na Windows `cargo test -p
lomi-files` przeszło natywnie na Windows 10 (29/29), w tym oczekiwanie bez
zdarzenia, dwa kolejne cykle zdarzeń, anulowanie ośmiu bezczynnych watcherów
oraz zmianę treści pliku o tym samym rozmiarze i przywróconym mtime na
katalogu głównym i zagnieżdżonym. Test ujawnił odmowę dostępu z `ReOpenFile`;
wdrożony adapter używa teraz overlapped `CreateFileW` dla katalogu głównego i
asynchronicznych otwarć `NtCreateFile` względem zweryfikowanych uchwytów dla
potomków. Niezależny review nie wykazał pozostałego problemu bezpieczeństwa i
zaproponował dodatkowe testy rearm/cancel, które teraz przechodzą. `cargo check -p lomi-files --tests --target
x86_64-pc-windows-msvc` przechodzi. Pełny `cargo check -p lomi-host --tests`
dla Windows nie dotarł do kodu hosta: cross-kompilacja C dla `ring` nie
znalazła `assert.h`. Windows 10 jest wyłącznie hostem laboratoryjnym, nie
kwalifikowanym targetem wydania.

Zapis testów i identyfikatory źródeł: `artifacts/windows-files-watch/2026-10-22/`.

### 2026-10-22 — ponowny lokalny odbiór consumer authority

Na bieżących źródłach wykonano świeży `--suite consumer` z prywatnym,
socket-only PostgreSQL 18.6 i przypiętym Bun 1.4.2. Przeszło 7 testów
PostgreSQL / 1 182 asercje, 961 regresji bez bazy / 7 808 asercji z jednym
wcześniejszym skipem, walidacja Prisma i TypeScript. Obejmowało to kontrolę
retencji wyzwań: wygasłe, niezużyte wyzwanie jest usuwane, a zużyte wyzwanie
oraz opublikowana tożsamość zachowują się zgodnie z ograniczonym kontraktem.
Cleanup zatrzymał klaster, potwierdził zero listenerów TCP i brak zmian
źródeł.

Receipt:
`../auth-app/artifacts/consumer-authority-refresh/eb893538-eb8c-4acc-bac5-990f2ee0e5f6/runtime-proof.json`
(SHA-256 `fed286721deb79a40823a1069ea4bb54666deb30b333b8a22d26aab0472f9e15`;
log SHA-256 `f8b2246aef199487769b8f9ad48b96750126b1a57df42c74267a562c26fc5dbf`).
To dowód lokalnego, ograniczonego fixture'a, z `productionQualified=false`;
nie zamyka S5–S7 ani pełnego E1/E2.

## 2026-10-22 — CloudWorker restart aggregate fixture passes

Updated the private fixture cascade to account for the restarted runtime's new
generation/epoch, and corrected the runner's exact restart-route marker from
4 to 9. The full runtime suite now passes 7/7. The runner also completed the
legacy non-database regressions, Prisma validation, Auth TypeScript check, and
private PostgreSQL cleanup with exit code 0. This exercises the actual local
Remote runtime handler and Rust CloudWorker over loopback TLS; it does not
qualify deployed relay behavior, multi-host fanout, target OS service matrices,
or E2 production acceptance. No production Cloud or fail-closed behavior was
changed.

Receipt:
`../auth-app/artifacts/host-credentials-runtime-generation-fix-20261022-5/74cd50f2-db0c-4e7a-8fac-a335de5124a3/runtime-proof.json`
(SHA-256 `46c5de423af1b146cfb5f715dcd0a6f304d7a0d53309cfd938aff59d12f93a23`);
log SHA-256
`5736caab724540c48931ef009beea642d123b855498cfdc66d88bb013cf6f3b2`.

### 2026-10-22 — kontrola dryfu roli prunera S5

Operatorowy inspektor schematu sprawdza teraz, czy `lomi_consumer_challenge_pruner`
nadal nie ma LOGIN, członkostw, uprzywilejowanych flag PostgreSQL ani prawa
CREATE w `public`. Odczyt metadanych jest współdzielony z wąskim testem bazy;
walidator odrzuca brak roli oraz każdy sprawdzany dryf. Testy metadanych
przechodzą 11/11 (433 asercje), TypeScript i kontrola formatowania przechodzą,
a niezależny review nie znalazł problemu materialnego.

Prywatny fixture PostgreSQL 18.6 przeszedł 7 testów bazodanowych / 1 180
asercji, w tym odczyt rzeczywistej roli przez ten sam helper co inspektor;
regresje przechodzą 958/958 / 7 742 asercje. Prisma i TypeScript przechodzą,
źródła nie zmieniły się podczas przebiegu, a klaster został zatrzymany.
`pg_ctl status` zwrócił 3 po prawidłowym zatrzymaniu, bo serwer już nie działał.
Receipt: `../auth-app/artifacts/consumer-challenge-pruning-20261022-pruner-role-db-proof/83959a9c-b314-4ec0-8014-a3373e268a1f/runtime-proof.json`.
To dowód prywatnego fixture'a, nie inspekcja staging/production ani pełne
zamknięcie S5/S6/S7.

### 2026-10-22 — ponowny test wznowienia Cloud Worker

W rerun13 faza przed restartem przeszła: publication i retained intent po
utraconym ACK pozostały w HostStore. Po otwarciu nowego ownera fixture zakończył
się w `recovery_result_auth_error` przed wysłaniem GET (`restart requests = 0`);
ukryty szczegół błędu uniemożliwia dokładniejsze ustalenie przyczyny.
Sześć pozostałych testów runtime/SQL przeszło (784 asercje), Rust fmt i build
testu `cloud-fixture` przeszły, snapshot źródeł był stabilny, prywatny klaster
został zatrzymany. Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun13/21b97274-5c4c-4a17-8f01-c66097757f46/runtime-proof.json`.
Brak GET oznacza, że ten run nie daje dowodu o zachowaniu endpointu po restarcie;
zmiana fail-closed nie była wykonana, a E2 nadal pozostaje otwarte.

### 2026-10-22 — CloudWorker restart fixture diagnosis

The restarted test owner now performs the real volatile Ready checkpoint after
opening the synthetic credential bundle. Rerun20 exposed a fixture replay:
process two's scripted rotation returned the same access/refresh pair that
process one had persisted, which `HostAuth::accept_rotation` correctly
rejects. The fixture script now derives distinct synthetic credentials from
the fresh rotation ID; production Cloud/Auth behavior is unchanged.

Rerun26 phase one reached `before_network_0`, `before_network_1`,
`outcome_unknown`, retained the durable intent, and exited its owner. The
remote precondition passed at publication sequence 8, and the exact HostStore
file hash was preserved across handoff. Phase two reported
`records_auth_unlocked_no_revoke`, `records_snapshot_some`,
`claim_admission_missing`, and `reconciled_by_get`; the post-step state was
`action_get`, pending absent, outbox nonempty, ACK missing, binding missing.
The child exited 101 before test completion. This is not a successful
reconciliation proof; why the claim continuation is withheld remains
unresolved. Rust TLS observed 20 aggregate requests, but restart-specific
route/count markers were not finalized, so no exact restart route sequence or
no-repeat-PUT result is claimed.

Formatting and the `cloud-fixture` test binary compile passed. The private
PostgreSQL 18.6 runtime suite reports 6 passed / 1 failed (784 assertions);
the cluster was stopped (stop exit 0, follow-up status 3). Source hashes were
unchanged and cleanup completed. Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun26/a2a774a1-9a09-4c68-8014-4911f7c3ecaf/runtime-proof.json`.
The diagnostics and synthetic credential changes are fixture-only; E2 remains
open.

### 2026-10-22 — odczytowy dostęp do hosta laboratoryjnego Linux

Po potwierdzeniu nowego klucza z konsoli usunięto stary wpis `known_hosts` i
zalogowano się przez SSH jako `test-user`. Host zgłasza Arch Linux rolling,
x86_64, kernel 7.2.11. To przywraca możliwość diagnostyki laboratorium, ale
nie kwalifikuje wymaganych Ubuntu 22.04+ ani Debian 12+ targetów. Wykonano
wyłącznie identyfikację systemu; nie uruchomiono testów produktu ani zmian
usługi.

### 2026-10-22 — odczytowy odczyt targetu macOS

Lokalne środowisko testowe to Apple Silicon z macOS 27.0.1 i FileVault On.
Nie znaleziono Lomi/remote LaunchDaemon; widoczny proces `application.dev.lomi.desktop`
jest procesem GUI, nie usługą hosta. Nie przeprowadzono boot, zablokowanego
Keychain ani LaunchDaemon lifecycle testu. To identyfikuje dostępny target, ale
nie kwalifikuje macOS host service.

### 2026-10-22 — Remote Web v2 rejestracja tożsamości okna

Dodano niepodłączony do `App` modułowy worker dla v2: generuje tożsamość w
kanonicznym Rust/WASM, wykonuje cookie-only challenge/register przez
`remoteV2Request` i zachowuje klucz w pamięci workera do późniejszego handshake.
Main thread dostaje wyłącznie publiczne metadane i niecredentialowy identyfikator
sesji; zamknięcie jest ponawialne przy pełnej kolejce i zwalnia klucz workera.
Worker rezerwuje maksymalnie 64 próby przed operacjami asynchronicznymi, a proxy
ogranicza oczekujące RPC do 32.

Pięć testów (34 asercje), `bunx tsc --noEmit`, `bun run check` pod Node 22,
`bun run build` wraz z `check-static-output.mjs` oraz `git diff --check`
przeszły. Astro zgłasza jeden istniejący hint w `src/explorer.ts`; Vite zgłasza
istniejący limit dużego chunku. Statyczny output jest czysty, ale ta nieużywana
ścieżka workera nie jest jeszcze montowana przez aplikację. Nadal brak
tworzenia kanału, ticketu, Noise, grantu, terminala ani
odświeżenia/odwołania tożsamości. Serwerowy cleanup
challenge/window rows pozostaje nieustalony; limit per worker nie rozwiązuje
retencji między odświeżeniami ani kartami. To wyłącznie fundament E3, nie jego
odbiór.

## 2026-10-22 — Remote Web inventory v2, read-only

`remote-web` now mounts a detached, opt-in v2 inventory summary. It uses the
cookie-backed v2 request boundary, validates the generated `InventoryResult`
shape before rendering aggregate online-host, offline-host and published-
workspace counts, and contains its own disabled, loading, error and retry
states. It does not select a workspace, pair, start a channel, or mutate host
state, so a missing v2 endpoint remains isolated from v1 bootstrap.

The Remote Web API tests pass 7/7; auth-bootstrap browser coverage passes,
including disabled endpoint, valid response/refresh and malformed-response
retry; the general browser suite passes. `astro check` reports zero errors
and warnings (one existing hint). Independent review found no material issue.
This is a bounded read-only inventory surface, not the E3 browser terminal or
integrated v2 ticket/Noise/grant client. E3 and production qualification remain
open.

### 2026-10-22 — zapis preferencji trybu startu w TUI

`lomiremote setup` odczytuje Manual/Login/Boot z metadanych HostStore i zapisuje
wybór tylko po naciśnięciu `s`; zamknięcie porzuca niezapisany wybór. Brak wpisu
oznacza Manual, a uszkodzona wartość kończy odczyt błędem. Zapis przechodzi przez
Local IPC i SharedOwner. Nie instaluje ani nie uruchamia usługi i nie zmienia
udostępniania. Testy czterech dotkniętych pakietów, hostowy dispatch,
`generate-contracts --check` oraz formatowanie przeszły. Pełny bieżący zestaw
`lomi-host --lib` przeszedł 535/535 po poprawieniu współbieżnego fault-fixture:
testy ingress współdzieliły globalny rejestr z powtarzanymi ID, więc teraz
uruchamiają się w szeregu. Windows-only validator test dodano, ale jego target
nie został skompilowany: cross-build `ring` zatrzymuje się na brakującym
`assert.h`/nagłówkach MSVC. Usługi i rzeczywisty autostart nadal nie są
zakwalifikowane.

### 2026-10-22 — regresja bieżących źródeł na linuksowym laboratorium

Na Arch Linux x86_64, jako `test-user` bez instalacji systemowej, oba
archiwa źródłowe zweryfikowały się po transferze (SHA-256:
`99463f23e5616990e162dac061d835bb3be5b63030167e8c3090154b77337b2c` oraz
`21591a5c1cdf51666dc2f304f6b914acbf97846ce5a33e03a214e76308aa998a`).
Przeszły pakiety `lomi-host-store`, `lomi-remote-protocol`, `lomi-platform`
i `lomiremote`, kontrakt `generate-contracts --check`, Clippy dla nich wraz
z `lomi-host` oraz `cargo fmt --all -- --check`. Pełny Host suite: 535/535.
Przeniesiona kopia została odseparowana od wcześniejszych testów. Wynik nie
kwalifikuje Ubuntu/Debian, usług, rebootu ani pełnej ścieżki E1/E2.

Latest checkpoint (2026-10-21 Warsaw / 2026-10-20 UTC): corrected Source709/c8317209 passed check/strict Clippy10765, producer40615 (24 retained/nine selected), Native69624 (38 cases/114 copies), and listings72849 (675 names/five legacy exclusions/670 planned). Focused9233 executed all39 selected tests:38 passed/one existing real TLS terminal lifecycle test failed. All10 new move Store/planner tests and all28 rename regressions passed. Root audit verifies2 owners/six public evidence copies/one PTY worker/zero probes and positive cleanup. Static diagnostics locate stream.current-proof/Invalid with a pending stream; the exact cause remains unproven in this frozen result. Combined independent result review is CLOSED for these bounded passing scopes; full Host/full670/BUILD10/Stage/REQ remain denied. Source-only remote move kernel12588 is independently reviewed but unapplied/uncompiled; ingress activation and fixture repair remain staged work. No native job is active. Historical Source708 full660 remains659pass/onefail, for its own bytes. E0 acceptance, full E1/E2/S5/S6/S7 and E3-E7 remain open.

Focused E1 follow-up (2026-10-22): the previously failing TLS/Noise terminal
lifecycle case now passes on the current test source. Its fixture uses a 12×40
test PTY and a bounded queue of 8,192 current-peer responses; production
freshness, permission checks and frame limits are unchanged. Exact command:
`cargo test -p lomi-host --lib real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay -- --nocapture`
(1 passed, 0 failed, 3.17 s). The earlier 39-case and 660-case results remain
historical; the complete current Host suite and Linux run have not been repeated.

Cloud Worker follow-up (2026-10-22): an opt-in cross-language test is now wired
from the real `lomi-host::unix::cloud::Worker`, through `DataTransport` and
fixture TLS, to the actual `auth-app` Remote handler and private PostgreSQL
runtime. It asserts GET → heartbeat → publication and database sequence 4→5.
Default and `cloud-fixture` Rust test binaries both compile; formatting passes.
The PostgreSQL/TLS fixture was not run: this machine has Bun 1.3.14 rather than
the pinned 1.4.2 and no PostgreSQL binaries. Independent source review closed
the request ordering/configuration scope. This is not runtime evidence and does
not change the fail-closed rule or qualify Cloud/E2. The consumer admission
guard remains an unfrozen candidate; full S5 remains false, S6/S7 not run.

Additional E2 result (2026-10-22): the active host-credential integration test now
proves a database-backed runtime/publication survives credential refresh: the
old bearer is fenced, while the new bearer heartbeats the same binding and
advances publication sequence 1→2. A Rust `DataTransport` driver then calls
the same real Remote handler over fixture TLS with both current credentials,
denies the old bearer, heartbeats and publishes, and accepts seven requests.
The actual Remote app handler also served 20 HTTP requests on an ephemeral
`127.0.0.1` TCP port. Bun 1.4.2 / private PostgreSQL 18.6 passed 7 DB-backed
tests / 1,329 assertions, 913 regressions / 7,255 assertions with one existing
skip, Prisma validation, TypeScript, default-feature Rust `cargo check`, focused
formatting and fixture cleanup. The receipt confirms the TLS listener stopped,
PostgreSQL status 3 after shutdown, and unchanged Rust inputs. Evidence:
`artifacts/host-credentials-runtime-local/d65e5b19-fc2c-4a62-a2ed-7d788f809894/runtime-proof.json`
(SHA-256 `e9590f6a1f91a7ed4d18f96c12299223983a6fa55d14c899b10f91ecf14a4598`).
The earlier HTTP-only receipt remains preserved. This exercises Rust transport
against the real handler and database, not the Cloud Worker lifecycle, relay,
production trust configuration or complete E2; E2 stays in progress.

TUI workspace-consent follow-up (2026-10-22): `lomiremote` now has a first-
workspace wizard for adding an existing directory locally, then requesting
sharing only after an explicit `y`. Declining or escaping leaves it local; the
flow calls the existing typed host `WorkspaceAdd` and `Share` operations and
refreshes host state before displaying success. Input is byte-bounded, and
Ctrl-C reaches the dashboard close path. `cargo test -p lomiremote` passes all
37 tests, and `cargo fmt -p lomiremote -- --check` passes. This closes only the
TUI setup/consent slice, not consumer S5/S6/S7 or full E1/E2.

Remote-web v2 contract groundwork (2026-10-22): `remote-web` has an explicit
initialization boundary for the canonical Rust/WASM protocol codec, RPC
request/response correlation validation, and bounded WSS admission-frame
validation. The generated runtime snapshots now also include the canonical
Rust/WASM authority-crypto v3 package, with a strict file allowlist and byte
manifest. Snapshots are checked; authority package tests pass 38/38, remote-web
tests pass 54/54, and a clean-checkout frozen install/test/build passes. Astro
reports 0 errors, 0 warnings, and one existing `requestSeq` hint. Docker image
build was unavailable because Docker is not installed. The authority package
is not imported by the active browser app: live transport still uses v1, and
there is no integrated v2 relay/ticket/Noise/grant client. This remains
groundwork only, not E3 acceptance.

E3 consumer-authority audit (2026-10-22): the backend has same-origin Remote
cookie bridges for consumer-window registration, pairings, channel create/read,
admissions and ticket issuance. The private Auth resolver derives the direct
consumer assertion; browser code sends no Bearer. No active remote-web/mobile
client calls this lifecycle. The registered `ConsumerWindowIdentity` stores
public identity on the server. The server rejects a new challenge for an
already registered window ID; a registration retry is idempotent only for the
exact same consumed challenge and proof. Window and challenge rows still have
a 64-entry per-authorization limit.

The user selected persistent per-window browser identity. The foundation now
uses a stable tab scope plus an AES-GCM-encrypted seed in IndexedDB, bound to
the authoritative account, consumer authorization, and source-session tuple.
Refresh restores the local identity without re-registering; tuple changes,
expiry, and successful logout clear local records and worker sessions. Cleanup
aborts an in-flight WASM download and the download has a 10-second timeout.
The full Remote Web suite passes 76 tests / 485 assertions, TypeScript passes,
the package snapshot check passes, and `bun run build` passes static-output
integrity. Independent review found no remaining concrete issue in this
cleanup path. Astro reports 0 errors, 0 warnings, and one existing hint;
Vite reports a chunk above 500 kB.

This lifecycle is still not wired into the active browser app, whose live
terminal uses v1. Local cleanup does not revoke server window rows; there is
no server window status or revoke endpoint, and the 64-entry per-authorization
limit remains. These foundations do not provide the integrated v2
relay/ticket/Noise/grant client or satisfy E3.

Remote Web consumer-window bridge groundwork (2026-10-22): Remote now has
same-origin cookie POSTs for the existing v2 challenge/register operations.
They forward only the HttpOnly Remote session token and strict operation body
through the authenticated private Auth service. Auth resolves the exact live
browser source session and already-issued web authority under the shared lock
and database clock, then reuses the existing Rust proof, single-use challenge,
and exact replay path. Pairing gate remains independent of inventory. Focused
bridge tests pass 10/10 (102 assertions); related consumer/Remote tests pass
517/517 with one PostgreSQL-only suite skipped; TypeScript checking passes, and
independent security review found no material issue. The full Auth test command
was also attempted: 1,273 passed, 28 skipped, 99 failed, and one errored. Its
database-backed tests cannot reach the absent local PostgreSQL at
127.0.0.1:54329, so that full run is not a regression pass.

The authority WASM package now exports guarded ephemeral browser identity,
v3-handshake and channel wrappers. Rust release provenance and the synchronized
package snapshot check pass; Node and Bun each pass 40/40, strict TypeScript
declaration use passes, and Remote Web passes 54/54. The old v1 artifact and
build path remain unchanged. These are still foundations only: the active app
has not registered a browser window, created a v2 pairing/channel, or opened a
v2 relay terminal.

Remote Web pairing BFF step (2026-10-22): `POST /v2/remote/pairings` now also
accepts the HttpOnly Remote cookie under exact same-origin Origin, Fetch
Metadata, and CSRF-marker checks. The private Auth resolver derives the
consumer class; cookie requests must resolve to `web`, while the existing
Bearer path remains `desktop`. The pairing SQL receives the session-bound
assertion and rechecks it under the shared authorization lock. The focused
`remote-pairing` suite passes 110/110 (804 assertions), TypeScript checking
passes, and an independent review closed the lock-wait abort finding with a
regression test. This enables only the backend create operation: the active
browser does not call it, and v2 channel/ticket/relay integration and the
complete E3 Linux acceptance remain open.

Remote Web pairing peer BFF step (2026-10-22): v2 pairing reads and grant
revocation now accept the same guarded HttpOnly-cookie flow and require the
private Auth resolver to derive class `web`. SQL still rechecks the exact
session assertion under the shared lock. Both consumer and host revoke paths
now stop before mutation when a request was aborted while waiting for that
lock. `remote-pairing-peer` passes 164/164 (1,448 assertions), TypeScript
checking passes, and independent review closed the abort findings. The
browser client remains on v1; channel create/read, tickets, relay, and the
end-to-end E3 flow remain open.

Execution order revised at the user's request to minimize repeated work:

1. Finish the current failure audit, apply one coherent Rust correction batch,
   and reuse the reviewed build/ownership code. Review the actual delta once;
   run one compilation/Clippy pass, then discover and execute current tests.
2. Complete the shared owner/auth/publication path and E1/E2 blocking acceptance.
   Prepare real auth browser integration in parallel; serialize resource-heavy
   Cargo, PostgreSQL and browser jobs to avoid competing builds or unknown owners.
3. Once E1/E2 blockers close, prove the Linux host-to-reference-WWW vertical flow
   (E3): code login, explicit sharing, browser shell, reconnect and SSH detach.
4. Reuse that working protocol for desktop migration and File/Git services
   (E4/E5), then complete the client parity/canonical artifact matrix (E6).
5. Complete the remaining actual OS, installation/update, security, soak and
   cutover rehearsal gates (E7). Production publication needs separate operator
   authorization. None of the mandatory features or acceptance gates is dropped.

For unchanged wrappers, reuse reviewed code and verify concrete binding deltas;
create fresh result namespaces without cloning whole historical frameworks.
Batch compiler fixes and record concise milestone evidence in this ledger and
verification.json. Expand review/testing when a real source change or finding
requires it; historical passing results qualify only their original bytes.

Stage: **E1 / local host completion and bounded E2 foundations in progress; E3 client groundwork started**. Started 2026-10-19.
E0 feasibility evidence supports this bounded implementation; platform/release
qualification remains open and no production migration is accepted.

Latest bounded checkpoints record61 HostAuth,94 Store,102 host and31 HostHTTP
tests with their recorded focused checks, each for its own source snapshot.
These include consent epochs, complete acknowledged publication, pure peer
policy, durable exact pairing/channel decisions, typed peer reconciliation reads
and the guarded idle-turn handoff. Automatic owner-account pairing passes
normal Mac component checks; live TLS/WSS and client integration remain open. The frozen native
264-channel proof now passes both host-revoke and the actual global-lock stall,
with stable source/tool guards and positive cleanup. Earlier readiness failures
remain causally unresolved. The separately reviewed consumer
successor now passes S0–S4 on actual PostgreSQL, with exact independent reference
catalogs and positive cleanup. Root and independent result review close that
bounded fixture scope. Its sealing subset now passes202 checks, including120
additional owner denials beyond the accepted82; independent and root reviews
close that subset. Separate16-case operator and10-case predecessor fault
proofs are also accepted; full S5, remaining faults and business cases stay open. Pairing source review
closes recovery fairness, final-lock freshness and the stale-wall P2. The final
corrected snapshot passes19 focused and83 normal Host tests, docs, formatting
and strict all-target Clippy with stable guards and positive cleanup. The older
capacity failure remains causally unresolved; the new source-backed boundary
regression passes. Channel admission now passes19 focused cases and the prior102-test
Host suite; after an equivalent lint correction,19 focused tests, formatting and
strict all-target Clippy pass on final bytes. Root accepts only the Mac component
with scripted APIs/private Store. Trusted relay configuration and production
WSS/data-plane integration are next. The existing crypto path is
now a production host dependency, with unchanged lockfile. No full implementation
stage or complete requirement is accepted by these component results.

Execution constraint update: the user has ended the stream and explicitly
authorized intensive Mac work again. Local compilation, code generation and
database/native/load tests may resume when useful. The earlier Windows-only
restriction remains part of the evidence chronology; admitted Windows jobs
retain their original deadlines and scopes. Cross-platform requirements remain
open until their actual native environments pass; each result qualifies only
its recorded scope.
Technical owner: integrator; bounded probes delegated to project workers and
independently reviewed with the configured `gpt-6-astra` reviewer.

Remote Web v2 channel/ticket cookie bridge follow-up (2026-10-22): independent
review found that the five legacy no-window SQL entry points were still
executable by the Remote API role with `class=web`, bypassing the registered
window binding. Migration 012 now rejects non-desktop assertions in those
legacy overloads before their queries, and the gated database fixture covers
all five calls. The generated `ChannelGet` window header is now optional for
Bearer callers and documents its cookie-auth requirement. Focused channel and
transport tests pass 461/461 (3,630 assertions); Auth TypeScript checks pass;
the contract generator check, protocol crate tests, 61-schema contract check,
696 contract tests, contract typecheck, and Remote Web package sync check pass.
The channel SQL fixture remains unrun because `LOMI_E2_*` database URLs are
unset (one static schema test passed and two database tests skipped). The
active Remote Web app still uses v1 and has not opened a v2 channel or relay;
this closes only the backend cookie/contract slice, not E3 acceptance.

All five existing application repositories were clean on `main` at entry and
match the audit baseline in `remote-server/AUDYT.md`. The complete specification
(`README`, chapters 00–10, `AUDYT`, execution prompt), parent instructions and
project agent configurations were read before implementation. This new Git
repository was created before adding implementation files. No commits or remote
repository have been created.

| Gate | Status | Observed result / acceptance still required |
| --- | --- | --- |
| S0.1 Rust terminal | in_progress | Stock vt100 rejected. Patched Rust state + structured xterm adapter passes 26 groups / 246 projections / 82 attach boundaries and real Chromium input/rendering checks. Native macOS and Linux Vim each pass seven milestones / 39 projections / 13 attach boundaries. Wider CLI/profile/soak qualification remains |
| S0.2 Service boot | in_progress | Disposable Linux VM systemd user/linger with a dedicated nologin identity passes SSH detach, actual reboot and lost-descriptor lifecycle checks. The reviewed fixture passed a fresh 40-check SSH/reboot/cleanup lifecycle after seven native and nine driver tests. macOS LaunchAgent/private locked-Keychain proof passes 20 checks and independent review, including unchanged default/search lists and complete cleanup. Windows passes four policy and 16 native SCM/session-0/ConPTY/DPAPI/fault checks plus a separate three-phase actual SSH-disconnect proof with verified cleanup. Privileged macOS LaunchDaemon/boot remains not_run |
| S0.3 Domain/admission | in_progress | Six pure-domain and four real-process admission tests passed. Actual Tauri admission passes 39 checks plus retarget/exit/lost-reply faults and a 40-check zero-connection dev-server sentinel; all review findings closed. Native Workbench/CodeMirror dirty-editor and observer-window proof passes and all four findings are closed for its frozen input receipt; fresh controlled native rerun passes at run-17qwotlv before E1 contract extensions |
| S0.3a Git isolation | in_progress | Historical macOS/Linux candidates retain counterexamples. New Linux sealed-snapshot/namespace proof passes 18 native groups and 15 operations; four review findings closed and temporary policy removed. Portable gix/WASI packed-repo reads match native Git on macOS with 16 security/broker groups; two policy findings corrected and independently closed. Actual Windows Wasmtime passes 11 groups and Linux Wasmtime 12 groups, both with exact five-operation comparisons and closed runner reviews; production broker and broader Git semantics remain |
| S0.4 Enrollment/rotation | in_progress | Synthetic PoP/rotation/recovery passes 33 tests on real PG17. Actual pinned Better Auth binding, opaque session FK, two window keys, immutable first-login key commitment and account assignment pass 20 tests / 146 assertions with a limited role. Production hooks/routes, durable OS receipt and cross-enrollment ownership remain |
| S0.5 Contract | in_progress | Typed DTOs cover 39 RPC methods and 24 HTTP routes, independent IPC 1.0, strict identifiers, errors/receipts and streams. Frozen identity/admission integration passes all 20 commands against 210 retained public sources, including full signed identities, window possession, canonical grant/context wires, 38 Node + 38 Bun authority tests and 543 SDK cases. Independent evidence/package review is closed; separate RuntimeGet validation passes 29 native, 309 Node/Bun codec and 603 SDK tests, with 36 guarded supplemental inputs. Earlier Chromium/profile and 57-command aggregate receipts retain their exact historical scope. Actual baseline relay/global PG authorization lock passes 264-channel load, revoke and six-second-stall tests with reviewed failure reporting. Product client/relay integration and release qualification remain |
| S0.6 Provenance/release | in_progress | Canonical crypto extracted with original patched Snow/licenses; terminal vendor archives/patches pinned. Durable TUF wrapper passes 10 tests including process crash/FIFO rejection. Install/activation/signing/canonical client migration remain incomplete |
| E1 | in_progress | Product crates now implement native Unix ownership/IPC, SQLite coordination, PTY sessions and CLI/Ratatui. TUI can add an existing workspace locally and only share after explicit consent; `lomiremote` passes37 tests and fmt. Two actual IPC clients share one shell and exclusive control without input replay; real interactive CLI attach/interrupt/view-exit checks pass. Compact history, natural-exit persistence, Unix supervision and native Windows host/PTY proofs pass component tests; Linux service and macOS LaunchAgent acceptance passed within their recorded modes. Ubuntu 24.04.5 ARM64 disposable VM passed 821 product tests and a cold-boot service check; the non-pristine Ubuntu 24.04.5 x86_64 VPS passed a focused cold-boot service check, with fixture cleanup confirmed. Windows SCM runtime and service-management CLI lifecycle are reviewed; ordinary Windows10 LTSC stopped/running restarts pass in a frozen normal-product checkpoint; true Windows logon/console, Windows 11/Server, macOS full-descendant containment, and production service qualification remain |
| E2 | in_progress | Reviewed additive003 finalized host identity and default-off credential lifecycle pass three actual PostgreSQL tests / 789 assertions, 73 regressions / 552 assertions and one skip. Canonical identity/admission contracts and authority package have bounded reviewed proofs; HTTPS transport passes 22 Rust + 7 coverage tests, bundle3 HostAuth now passes42 native tests +7 coverage checks with independently closed scoped crypto evidence. Reviewed direct consumer/window004 passes five DB tests / 991 assertions and 76 regressions / 592 assertions, with one skip. The integrated Unix owner/store/protocol/CLI passes 180 native tests and 36 actual TLS-stall process checks. Host revoke passes six DB tests / 1,160 assertions; current-codec error acceptance and authority lock repair are reviewed. Runtime005/default-off HTTP passes seven DB tests / 1,304 assertions and 176 regressions / 1,147 assertions with reviewed role, race, overflow and error proofs. Private direct-consumer inventory006 passes nine DB tests / 1,437 assertions and 305 regressions / 2,245 assertions, with reviewed canonical success and 91-error proofs. Pairing creation007 passes eleven DB tests / 1,593 assertions and 404 regressions / 2,984 assertions, with reviewed canonical100-error evidence. Host polling/decisions008 pass thirteen DB tests / 1,983 assertions and 547 regressions / 4,019 assertions with reviewed canonical121-error evidence. Peer reads/grant revocation009 pass fifteen DB tests / 2,373 assertions and 692 regressions / 5,311 assertions on target PostgreSQL18.6, with reviewed canonical147-error evidence. Channel010 now passes18 database-stage tests/2,792 assertions and912 regressions/7,210 assertions, with reviewed canonical173-error evidence. 011 tickets/active relay now pass20 database-stage tests/3,963 assertions and1,189 unit tests/9,146 assertions, with reviewed183-error evidence. Dedicated native Noise over loopback relay passes617 assertions with independent review. The separate frozen264-channel proof passes both scenarios; consumer S0–S4 and82-check sealing subset pass. Current macOS actual-handler fixture also proves that central account revoke yields a real runtime GET 401, fences the shared HostAuth/SharedOwner, and closes two already-live TLS/Noise clients; runtime DB suite 7/7 and regressions 913/913 passed. This is a bounded no-relay fixture, not full E2 or consumer S5/S6/S7. Broader consumer scopes, product WSS and end-to-end integration remain |
| E3 | in_progress | Remote Web v2 includes pairing, persistent encrypted window identity, consumer registration, channel/ticket/Noise, terminal attach/control and Explorer. When the account API advertises an enabled v2 relay, the browser no longer starts the legacy v1 live worker; account-session bootstrap and sign-out HTTP remain v1 control-plane routes. The browser terminal profile is experimental. Clean Linux install, phone login/consent, live relay shell, reconnect/no-replay, unshare fencing and production Rust/WASM/mobile manifest acceptance remain |
| E4–E7 | not_started | Desktop owner migration, complete File/Git client integration, three-client parity, and signed release/OS/soak/cutover acceptance remain |

`blocked` here denotes a project dependency, not the status of an agent goal.
Passing a regression that reproduces a rejected candidate never passes its gate.

No REQ-01–REQ-17 is fully verified. Evidence and exact reproduction commands are
in [evidence.md](evidence.md); the remaining acceptance work is listed below.

| Requirement | State | Evidence / remaining work |
| --- | --- | --- |
| REQ-01 Rust/headless | in_progress | Product Rust daemon/IPC/CLI/TUI foundations compile and actual process tests pass; clean-machine and full boot acceptance remain |
| REQ-02 one domain/PTY owner | in_progress | Product SQLite domain, terminal RPC and actual two-client single-shell checks pass; existing desktop still owns its old PTYs |
| REQ-03 independent host authorization | in_progress | Synthetic rotation/recovery plus actual Better Auth server-owned enrollment/session/key/account binding and limited SQL role; reviewed default-off enrollment/session hooks; reviewed local default-off exchange/register/rotation and encrypted recovery pass actual PostgreSQL tests; private PostgreSQL 18.6 CloudWorker fixture now passes committed-publication TCP-drop recovery, restart/cursor reconciliation without repeat PUT, and two-client central revoke; deployed-relay lifecycle and native platform acceptance remain |
| REQ-04 shared consent | in_progress | Product local sharing/unshare commands and durable fences pass actual process/SQLite tests; offline logout and restart fences pass; CloudWorker publication/revoke, real loopback TLS/TCP lost-ACK, restart and multi-client revoke pass actual-handler fixtures; deployed relay integration remains |
| REQ-05 terminal/reconnect | in_progress | Structured Rust snapshots/live states pass pinned xterm projection oracle; Remote Web selects the v2 data plane when the server advertises the active v2 relay and has a terminal attach/control path, but its browser renderer remains experimental and clean-host relay/reconnect acceptance has not passed |
| REQ-06 terminal management | in_progress | Product PTY/control service, terminal management commands, durable receipts and local structured attachment pass focused tests; rename/move conflicts return ordinary error responses over real TLS/Noise; full platform/lifecycle acceptance remains |
| REQ-07 private views | in_progress | Actual isolated Workbench/CodeMirror proof preserves dirty text, selection and undo through mixed close/move; four findings closed against a genuine frozen-input receipt, fresh controlled native rerun passes; product migration pending |
| REQ-08 Explorer | in_progress | Root-confined `lomi-files` engine on macOS, Linux and Windows; remote list/stat/read/search/create/mkdir/rename/remove and invalidation-only `files.watch` over real TLS/Noise; opt-in Remote Web v2 Explorer can list, preview and mutate, but desktop/mobile Explorer, real-host relay acceptance and all-client parity remain open |
| REQ-09 Source Control | in_progress | Reviewed Linux namespace proof and portable macOS gix/WASI experiment; old candidates retain counterexamples. Windows and Linux WASI runtime proofs now pass; production broker and complete Git service remain |
| REQ-10 client parity | not_started | No application migration or method × client acceptance |
| REQ-11 new window / same shell | in_progress | Actual Better Auth proof preserves two independent window keys under one opaque session; live product browser/desktop workspace windows remain untested |
| REQ-12 lifecycle | in_progress | Actual Unix product PTYs and controlled daemon lifecycle tests pass; owner-crash containment, service adapters and all-OS acceptance pending |
| REQ-13 revoke / no replay | in_progress | Durable uncertain-writer quarantine tested; unshare and logout during a terminal or file effect, and recovery after a failed Store completion, are tested over real TLS/Noise on macOS; remaining methods (input, snapshot streams, Git) and Linux/Windows runs of the new race tests are not covered |
| REQ-14 E2EE/privacy | in_progress | Canonical audited crypto extracted; enrollment PoP, key-preserving account assignment, signed grant/context v3 and actual Chromium/WASM/native interop pass with independent review; production data plane remains |
| REQ-15 installation/update | in_progress | Durable TUF verification/restart/root rotation/process-fault tests pass; no installer activation or full OS qualification |
| REQ-16 safe migration | not_started | Existing remote clients/data unchanged; additive auth changes are local only; client import/recovery not implemented |
| REQ-17 canonical artifacts | in_progress | Draft generated schemas, source digests, canonical crypto and pinned patched terminal sources; shared client and duplicate WWW build remain unresolved |

Next acceptance: complete native product service and secret-provider checks,
qualify macOS descendant containment, then run the expanded aggregate. Reviewed private coalition fixtures cover admission, recovery and reparenting. The actual default-off per-PTY backend passes five native cases and 19 tests with independent review; controller-death, full-host and OS qualification remain open.
Compact-grid/browser parity, natural-exit persistence, retained-child ownership
and actual owner-crash/lost-descriptor tests are implemented and reviewed.
The fresh native mixed-view proof passed in `artifacts/desktop-e0/run-17qwotlv`;
its receipt freezes the exact pre-E1 inputs. Closing the actual TUI leaves the
same host/runtime alive. The product still needs full macOS descendant containment and platform
service/provider acceptance, alongside bounded E2 database preparation, followed by E3–E7. The Windows 10 LTSC Session 0
CLI/host/SQLite/PTY and independent SSH proof is complete and reviewed. Remote client checkouts remain unchanged; local E2 auth-app runtime and auth-frontend consent changes are under implementation. Windows 10 LTSC is feasibility evidence, not Windows
11 or Server qualification. See [e1.md](e1.md) for the current product boundary.

Production resources and remote client applications remain unchanged. E2 auth-app and auth-frontend changes are local only; see [e2.md](e2.md). A disposable
local Lima VM and synthetic guest user service are used for native qualification;
Homebrew Lima was installed on the development machine. The supplied Windows
test machine received fresh source-only snapshots and a side-by-side Rust 1.98.1
toolchain; its default toolchain was preserved. Nothing was committed,
pushed, deployed to production or published.

Owner-channel component acceptance closes with root receipt
`host-owner-channel-root-review/0622f2b7`. Actual `384fba63` passes19 channel,
19 pairing and102 normal Host tests plus docs/format; only a collapsible-if
Clippy lint fails. Frozen `800137a2` makes the equivalent parenthesized let-chain
change, preserving all four ordered mismatch checks and the error. Targeted
actual `88c7874d` then passes19 channel tests, six-file formatting and strict
all-target Clippy. The full102 tests were not repeated after that equivalent
lint delta. All196 current/frozen source inputs, eight tools, four mandatory
2GiB preflights and private cleanup pass. Independent semantic and counted
original-expiry fixture reviews are closed. The accepted scope is scripted
ChannelApi/PeerApi and private Store on Mac; live TLS/WSS, the data plane, client
integration and complete stage acceptance remain open.

Pristine-pre012 actual `ffb9a174` / runtime `4c20241b` passes all ten missing/
rename cases after the exact known-blank parser correction in frozen `548c7da2`.
Each unchanged012 attempt returns psql3/exact55000/message, complete ordered
markers and exactly one advisory-lock blank result. Independent measured review
checks the declared mutations,267 evidence hashes,164 SQL records,49 tools and
all30 raw same-database rollback pairs across27 sections. Each database receives
only the32-step prefix ending at approval-intent. Actual owned outer session27484
exits0 within a conservative51.794732s; positive stop/status3/PID/socket/private
cleanup passes. Root receipt `consumer-derivatives-v2-s5-pre012-root-review/b292f699`
accepts only these ten cases. Prior202/16 proofs remain separate and unchanged;
S3/S4 in this prefix fixture, full S5 and production/operator-pin admission remain
unqualified. New source work covers five external admission-negative cases and
18 further predecessor faults; four CTAS variants and business/lifecycle remain
open. Candidate reconstruction with COMMIT must use explicit clean rebuild
semantics; no cross-cluster raw-OID equality or invented operator SQLSTATE is
claimed.

Trusted relay-pin source `cfa9de51` has passed independent source review: a validated
canonical WSS endpoint type, optional backwards-compatible local configuration,
explicit CLI input, and independent first installation of the API/relay pins.
Installed pins remain immutable, including after logout. Nine Rust tests,46 shared
wire cases and a strict TypeScript case are authored; only source formatting has
run. Native behavior and generated WASM/SDK parity remain unverified. The proposed
controlled runner must rebuild both authority/protocol WASM provenance, regenerate
contracts/SDK/final compatibility manifests and pass drift/parity checks. Endpoint
reset/relogin and the specified public TOML configuration remain separate work.
No WSS or data-plane qualification follows from configuration source changes.


The relay-pin controller correction `21c58919` closes four independently
reviewed findings: child registration during cancellation, detached lifecycle
suite escape, ambient Bun configuration, and skipped/schema-only false passes.
Four focused native cohorts replace the escaping whole-Host runtime suite;
strict all-target Clippy still compiles the targets. All14 pure controller tests
pass. A fresh complete source/tool/output closure is being prepared before one
controlled native/WASM/SDK qualification; no such execution has occurred yet.

Consumer predecessor source `5c438c01` closes the zero-argument pg_proc JSON
vector correction (12 pure tests); five admission-negative cases `f1324c56`
close the default-ACL namespace JSON-string correction (10 pure tests).
Independent narrow reviews close both source changes. Runtime admission remains
closed because a separate P1 review found cancellation gaps in the frozen
process helper and its outer driver ownership. A new guardian must retain all
launch-capable children and foreground PostgreSQL, latch signals across launch
and cleanup, and prove shutdown within the original deadline. Existing normal
runs retain their observed positive cleanup evidence; historical helpers and
proofs are unchanged.

A new evidence recorder `ff8378ac` passes11 pure tests with the actual frozen
Fixture and fake execution. It preserves legacy-returned strings, shares exact
immutable outputs within each new private run, compresses large stdout with
strict decoding, and enforces a256MiB budget plus failure reserve. Independent
review, bounded derived-SQL byte output and successor integration remain open.
The11-call positive-authorization SQL plan `b303aa4a` passes12 source checks;
it still requires review and closed non-disclosing failure diagnostics before
execution. Neither preparation qualifies SQL behavior or full S5.


Relay-pin actual `9c214444` ends with owned outer exit1 during tool preflight:
Python/Node version checks pass; Bun1.4.2 with a spaced leading config argument
returns exit0 with no output, failing the exact version gate. No native product
test, build or generation runs. Source/tool guards and private cleanup pass.
Bounded owned probes reproduce this behavior and establish the attached
`--config=<owned-file>` syntax with both exact version and an actual test sentinel.
The controller correction will preserve all isolation and result requirements;
the failed attempt remains immutable.

Recorder review finds two P2s before integration: incomplete typed index checks
and first-eight cleanup retention losing a fifth cluster's failure evidence.
Corrections and a bounded raw-byte API are being implemented. Positive-auth SQL
review closes its source contract with no material SQL defect; credential-bearing
execution remains blocked on a separate client/server diagnostic path that
persists only a closed set of markers and fixed failure facts. No actual SQL
behavior or whole-stage acceptance follows from these source reviews.

Bun syntax correction `5955e7be` passes15 pure tests and independent narrow
source review; all four earlier safety fixes remain intact. Root verifies the
exact correction and all ten logs of the five owned probes. A new complete
closure is required before the full qualification; no product result is implied.


Relay-pin actual `c7abfd49` passes all eight tool versions, including corrected
Bun, then exits1 before compilation because offline Cargo lacks block-buffer0.10.4.
No native test or generation runs. Owned cleanup/source guards pass. Bounded
public-cache acquisition `bc51b133` exits0 and recovers295 archives, each checked
against Cargo.lock; no lock/source/tool/output change or build occurs. A fresh
qualification remains pending.

Canonical message framing is authored in staging with12 unexecuted tests:
32-byte encrypted internal header, bounded sequential1MiB messages,16KiB crypto
plaintext frames, nonsliding5s assembly deadline and permanent disposal on error.
Source review/native/WASM integration remain open, as do domain8MiB assembly,
host-wide quotas and effect authorization. Guardian source passes26 pure cases,
but review finds expired-budget cleanup, Darwin zombie-only signal handling and
cleanup-log failure gaps; no native PG execution is admitted.


Relay-pin `f055a08e` passes29 focused native tests and all eight versions;
authority-WASM linking then fails to load the installed LLVM library. The whole
run remains failed. Four owned loader probes and17 pure tests establish the
explicit pinned toolchain fallback; independent narrow review closes that
correction. The next combined controller `c5cad8a5` passes19 pure checks and
source review:32 commands,15 tools, five focused native cohorts, all13 framing
names and all ten framing cases independently required in Node/Bun. Fresh
complete closure and actual combined execution remain pending.

The reviewed canonical framing core now passes13 real standalone Rust tests
in1.301s, with owned outer exit0 and cleanup. Eight-file native/WASM integration
`f10ba3ce` passes source review, preserving core bytes except its comment/parser
visibility. Ten WASM cases are authored but not executed; generated bindings
remain unchanged. Canonical nonfinal16352-byte fragments cap1MiB messages at65
fragments. Semantic8MiB assembly, global quotas, AEAD/caller lifecycle and remote
effect gates remain open.

Recorder v2 review closes both P2s plus bounded byte output (16 pure tests).
The closed diagnostic parser's exact-boolean correction also closes review
(14 pure tests); private SQL execution and server settings remain unverified.
Guardian `493281a2` closes source review with43 pure tests, preserving the
original900s qualification and separate960s emergency ownership boundary.
Native cancellation probes are still unrun. Supervised18 source preserves its
SQL model and passes10 pure cases; review requires strict reader success,
stored-run/outer digest binding and a separate bounded raw-log policy before
admission. Those corrections are in progress; full S5 remains false.

## 2026-10-20 bounded checkpoint

Canonical root15763db0 closes independent result review. Final formatting,
strict all-target Clippy, both normal WASM builds, Rust generation and drift
check pass with outer58773 exit0. Only three predetermined provenance metadata
files change; the other136 outputs, including WASM material, remain exact.
The31 earlier successes are23+4+4 across three failed runs, whose failures stay
failed. Their42 focused native passes, Node/Bun codec365 each, authority38 each,
Node SDK696, isolated Bun SDK348+346 and strict TypeScript correlate through
immutable proofs and exactly two cfg(test) whitespace edits. This accepts the
Mac component only, without WSS/TLS/data-plane/Windows qualification.

Four native Guardian cancellation probes and actual32MiB inherited EFBIG
enforcement close result review. Accepted supervised18 rootbf15b98c verifies
54 same-DB raw27-section rollback pairs,980 evidence digests and normal actual
status0/stop0/status3 cleanup. Root exit upper494.192s is separate from pre-seal
manifest elapsed. Prior10/202 scopes were not rerun; no global TOAST/catalog or
wholeS5 claim follows.

Five-cluster actual4794 fails at original work840 (root upper844.134s): two
classifications finish, all three started clusters cleanly stop/reap,1706 indexed
files validate, and no completion receipt is published. Reviewed FD-relative
full audits preserve quotas and reduce repeated ancestor checks; only five-case
main opts in. Retry32919 is running with unchanged840/900/960 limits and has no
acceptance yet. Four CTAS cases keep recorder320 and remain source-reviewed,
unrun; their literal-False/hash-rebound0/0.0 regression is closed in source.

Six real benign private-pipe/GUC probes pass with outer15030 exit0 and root
upper28.919s; independent result review closes all six outcomes,12 retained
reaped/quiet children, six owned identities and24 empty logs. Invalid/trailing
output, cancellation, two-second EOF-with-live-child and effective PG privacy
settings are exercised. No credentials or eleven-call SQL ran. Its earlier
environment-only failure is preserved; retry supplies an exact UID-derived
macOS framework marker explicitly. Credential-bearing orchestration and verified
owned PG-data disposal remain source work; rollback WAL may retain credentials.

Public TOML recovery source is integrated across18 files after independent
review. SQLite NUL-marker bounds and platform migration-version P2s are closed
in source. All35 authored test functions, dependency resolution, build and
execution remain unverified. No live reload, Windows parity, readiness-notice
withdrawal or endpoint reset is claimed. Every product-stage gate stays false.


## 2026-10-20 five-case retry outcome and next admitted work

FD-recorder retry32919 exits1 at original work840; conservative root outer upper
857.342s. Independent partial audit proves four completed classifications,
all five started clusters' normal status0/stop0/status3 and retained-child reap,
owned identity/PID/socket cleanup, and2612 indexed evidence files. No completion
receipt or all-five qualification exists. Root receipt9e18f690 has SHA256
bab679938bb81e06ebd0dcc4ae44a13ba3cc13f1ea51b426f876d827c7e80c15.
The next journal proposal removes quadratic history rewrites while preserving
per-command persistence before raw-log retirement; it is source work only.

CTAS4 source/proof admission rehashes182 inputs, six proof files,49 PG/acquisition
files and separate Python/Node. Direct owned root25808 is running with recorder320
and unchanged840/900/960 limits. Prior18/5/S3/S4 are not rerun. Full private11
source review is closed at freeze1dd34862; its29 pure tests are bounded source
evidence, and real SQL, thirteen-notice envelopes and owned PG-data disposal
remain unexecuted. Product gates and complete requirements remain open.


## 2026-10-20 private11 result review remains open

Direct native private11 root96235 has a retained outer exit0 observation and a
candidate receipt reporting11 checks. The result is not accepted: `root-audit`
still says independent review is pending, while `root-check` says
`PASS_PENDING_INDEPENDENT_ROOT_RESULT_REVIEW` and
`rootOuterPrivateAbsent=false`. The enclosing receipt claims both checks passed
but hashes those contradictory files. No separate result-review artifact was
found. Keep the run as provisional evidence only; do not attach acceptance to
the receipt. S6/S7 and full S5 remain unqualified. The historical source and
test copies were restored to the exact pinned bytes; all 88 archived source
hashes verify. The active test-source candidate now requires a receipt chain
under `/private/var/db/lomi/consumer-private-eleven-root-admission`, with the
tree and files owned by OS UID 0; it also checks both companion proof hashes.
Its 15 pure tests pass, including rejection of caller-owned forged files. An
independent bounded review closes against the active controller and test hashes
recorded in verification.json. The existing UID 501 receipt cannot satisfy
this gate. There is no successor freeze or OS-root admission review/reissue;
native/PG execution was not run.
FullS5 is false; S6/S7 are NOT_RUN.

Public TOML dependency acquisition root3643 exits0 (18.892s controller,47.050s
root upper). Independent review closes root35a220fe receipt110f865b…: all373
old package identities/semantic edges remain, only platform→toml is added and
all7 new packages are in its closure.305 present public archives are hashed;
all7 new archives are present. Lock7c059b90… is durably published,540 inputs and
139 generated outputs stay unchanged, owned fetch child is reaped/group-quiet,
and private workspace/outer are gone. Explicit public-cache reuse is trusted,
not hermetic. The wrong initial CLI flag exits2 before controller/native entry
and stays a separate failure. Compilation and35 authored tests are still unrun.

First actual CTAS4 root25808 fails on repeated immutable ctas-results alias
publication after two independently verified rejections/three-DB rollbacks.
The partial root2b1beb03 proves physical indexed integrity with literalFalse
qualification and owned normal cleanup. A reviewed one-line save-after-loop
correction preserves18 test bodies and adds2 real-recorder fake integration
passes. Three source files are promoted; retry71489 is running under unchanged
840/900/960 limits with five-case807 factory. No previous failed run is promoted.
Journal orchestration source is reviewed; its complete dependency/test closure
still needs admission before any five-case retry. Every product gate stays off.


## 2026-10-20 CTAS4 and public-configuration typecheck accepted

CTAS retry71489 exits0 and independent result review closes root78a61419
receiptce7a63c3…: four exact owned-psql3/55000 rejections,12 same-database
whole27 rollback pairs,96 prefix SQL,706 indexed files/707 manifest hashes,
46,157,824 allocated evidence bytes and normal status0/stop0/status3 cleanup.
Root outer upper223.148s bounds controller pre-seal194.562s; owned identities,
PID absence and empty socket are rechecked and the root empty outer is removed.
This accepts b67/4c CTAS with the old807 factory only. A later dependency refresh
does not transfer that native result. First25808 remains a failed attempt.

Actual format32780 publishes16 selected outputs (13 byte changes) from private
copies, then fails whole-workspace format check on19 unchanged out-of-scope
crypto/vendor files. Root partial4f0164fb proves no other source/output writes,
two owned children reaped/group-quiet and private fixture removal. No compilation
occurs in that failed attempt. A new read-only continuation88205 passes
package-scoped formatting and offline locked all-targets checks for platform,
Store and Host. Independent review closes root80f9d15c receipt8bd379d0…:
540 source,139 generated,15 tools,7 archives,42 format proofs and all logs/maps
match. Controller73.521s/root upper175.624s<300; owned children and private/root
outer cleanup are proven. Test code is typechecked; tests and Clippy are unrun.

The first test-controller source is rejected before any execution because its
full-Host tests can create setsid PTY sessions outside the Cargo group. Focused
configuration/schema/auth tests and Clippy need a narrowed appointment. Full
Host runtime preservation remains required under a separately reviewed fixture
that owns those descendants. Historical unowned processes are never authority
for signaling or cleanup.

Journal production/helper source is reviewed and33 tests pass against the actual
new staged entrypoint. The installer still needs exact eight-file publication,
hard-pinned accepted CTAS prerequisite and receipt/rollback failure handling.
No new five-case native retry has run. The sealing crosswalk identifies three
unmeasured guard families;20 isolated guard-predicate supplements are source work.

Host ongoing-authority endpoint code has two reviewed P2 fixes: late expiry
permanently fences its channel, and post-commit cancellation suppresses output
without pretending committed state rolled back. A separate corrected contract
envelope preserves core6240 and19 unexecuted tests. No live endpoint, canonical
generation, SQL/TLS proof or remote effects follow. Store/core writer exclusion
and actual protected-handshake test integration remain open. All stage gates stay
false, requirementsFullyVerified remains empty, and nothing is published.

## 2026-10-20 — focused TOML tests and new five-case journal runtime

Actual51763 exits1 after all five selected test groups pass:10 platform,7 Store
configuration,6 schema,8 authorization and12 Host tests (43 total,0 ignored).
The passing crash-recovery parent asserts its child exit73; root does not claim
a separate observation of that exit. Strict Clippy101 reports a collapsible
platform Drop condition. Root partialc38b preserves that failed overall result,
all six retained-child reaps/group-quiet results and private-fixture removal.
An equivalent condition correction is applied with its original bytes saved.
Actual19040 then passes package formatting and all10 platform tests, but strict
Clippy101 reports another collapsible condition in Store. Its failed result
0ef13d15 and all three cleanups remain preserved. The equivalent Store correction
is saved; a fresh format/Store-test/Clippy appointment is pending. Full Host
runtime remains mandatory under a separately owned PTY fixture.

The journal installer now passes18 pure filesystem tests and independent review
closes exact-eight publication, accepted-CTAS pinning, receipt rollback and FIFO
blocking findings. Root installs the exact reviewed eight files, preserves all
preimages, verifies readback and both five/CTAS dependency closures. Post-install
ed217648 qualifies source integration only. Five entryb158 and lock6a2d are live;
the future CTAS lockf222 does not inherit old ce7 native qualification. Actual
five-case87413 is running, admitted by e1888e63, with unchanged840/900/960 limits.
There is no accepted new five-case result yet; both prior840 failures remain.

The20-case sealing supplement passes26 pure methods, but source review finds
missing six-table count evidence. A separate immutable correction is adding the
fixed typed all-zero baseline and full before/after vectors in all three DBs.
Native entry remains disabled pending reviewed runtime wiring and five closure.
The full Host fixture proposal has21 pure source/model checks and no native
fault harness or Rust execution; concrete ownership review findings are open.
No stage gate, whole-system qualification or publication is claimed.

## 2026-10-20 — corrected Clippy accepted; Noise qualification started

Actual19992 exits0: package-scoped format,7 Store configuration tests and strict
Clippy for platform/Store/Host all-targets pass. Root audit624b1c24 and independent
result review verify10 source files,540 inputs,139 generated files,15 tools,7
archives,240 historical references and all three owned-child/fixture cleanups.
Accepted receipt5e0b0c7d preserves both earlier Clippy failures. Historical43
focused passes and platform10 are separate runs; they are not43 tests rerun at
this corrected head. The original empty root outer is identity-checked/removed.

Journal five-case87413 exits1 at original work840: four classifications pass;
all five clusters have normal status0/stop0/status3, retained reaps and root
identity/marker/PID/socket checks. Partial3617166c validates2399 indexed files,
no completion receipt and no five-case qualification. Root upper856.898s is
recorded independently, and its empty outer is removed. Source optimization now
targets repeated namespace walks inside a single immutable save and the final
materialization operation; fresh retirement verification and all limits remain.

Root installs only the three reviewed private cfg(test) gate files, preserving
auth448 preimage. Source1fd9cbf1 contains25 original evaluator tests plus8 genuine
HostAuth/consumer Noise tests, including actual delayed direct-finish denial.
Actual32714 is running under a fresh542-input/252-Rust source view,554 frozen
runner files,542 read-only copies,139 generated files and fixed600/300/10 limits.
No test result, OS-provider/TLS/ongoing-authority or production effect is claimed.

The sealing20 count fix passes34 pure tests and its P2 source review closes;
native entry remains disabled. Local Store/Core lock-order source closes two
P2 findings with12 Rust tests still unrun. Owned fullHost fixture core fixes
are source-closed, while its29-case native harness needs outer-cancellation,
private-environment and exact test-inventory corrections. The fixed16 ongoing
authority installer has14 pure passes but a new-directory rollback finding;
normal notices/WASM/package/restricted-PG qualification remains unexecuted.
All stage gates remain false, requirementsFullyVerified empty, nothing published.


## 2026-10-20 — gate compilation failure preserved; installers reviewed

Actual32714 exits1 before executing any of the33 tests. Compiler101 reports
three helper API errors: InputSeq, bounded bytes construction and RequestId.
Root partial33dc6293 verifies554 frozen files,542 live inputs/read-only copies,
252 Rust files,139 generated files,15 tools,28 proofs and7 archives. The retained
compiler child is reaped with its group quiet; the private fixture is absent.
Root observed243.717s remains below the original600s bound. A fresh immutable
helper correction is pending; this failed attempt never qualifies the tests.

Owned fullHost harness successor4d4e3db9 passes36 pure tests, with source review
pending; all seven reviewed core files remain exact. Its29 native cases and
fullHost execution are still unrun. Authority installer5681a7dd passes20 pure
filesystem tests and independent source review closes uncertain-directory
rollback. Its original139 generated pins and16 payloads remain unchanged; one
additional profile input was already bound by the sealed compatibility manifest.
No authority payload is installed yet. Normal notices/WASM/package and actual
endpoint qualification remain pending. No stage or product gate is enabled.


## 2026-10-20 — actual33 pass; owned test source closure

Actual63618 exits0: build-only compilation and all33 focused gate tests pass
with zero ignored. Root audit372dd925 checks555 frozen files,542 live inputs
and read-only copies,252 Rust files,139 generated files,15 tools,58 proof
references,7 archives, before/final maps and actual logs. Both retained children
are reaped with quiet groups; private fixture is absent. Root observed64.993s
remains below600s. Independent RESULT review is pending. The old32714 compile
failure remains failed. A separate first-launch permission failure occurred
before any Popen; root preserved it, prepared only the mutable runs directory,
rehashed unchanged frozen bytes and used a fresh admission/deadline.

The33 comprise25 evaluator cases and8 actual HostAuth/consumer Noise cases.
Storage and current peer/owner facts remain synthetic. No physical provider,
TLS/ongoing authority endpoint, fullHost or production effect is qualified.

Owned harness53386d37 closes the remaining cancellation-I/O and late-cancel
status findings by source review;42 pure tests pass,29 native and4 Rust tests
remain unrun. Mechanical10-file Store/Core+owned-fixture merge review also
closes with no new material findings; no source application or build yet.
Build-only scoped formatting/compilation/Clippy preparation is underway.

The new recorder passes52 FS and37 actual staged-factory tests, but review
finds a new batch open can block on a FIFO replacement. An immutable correction
adds nonblocking open and guarded real-FIFO/no-publication tests. No optimization
is installed or timed on PostgreSQL yet; old87413 remains failed and all original
resource/deadline limits remain. Stage gates stay false; nothing is published.


## 2026-10-20 — Gate33 accepted; Core installed; composed-five running

Independent Gate33 RESULT review closes. Finala277641a accepts only the33
focused cases; both child reaps and absent private/root fixtures are verified.
This accepted source view precedes later Core installation and is preserved.

Root installs the exact10 reviewed Store/Core+owned-fixture source files,
preserving8 original preimages and checking2 new-file absences. Receipt7569e0b8
records source application only: formatting, compilation and runtime are unrun.
The e88d40ca build-only controller has38 pure passes and is under source review,
with544 inputs/254 Rust/139 generated, fixed37-file formatting scope and6 future
owned commands. It cannot run alongside current PostgreSQL work.

Recorder FIFO correctionb1fd6b56 passes53 FS and38 staged-factory tests; narrow
source review closes. Root publishes all8 exact canonical files, saves all old
bytes and successfully invokes canonical dependencies without Native actions.
Integration38c6539f does not qualify runtime. Actual63991 now runs all5 fixed
cases on c095/b95/d92, lock18ba, under root admission70621345 with78 source
inputs,49 PG/acquisition and2 Python/Node pins. Original840/900/960 and all caps
remain. No completion or accepted new five-case result exists yet.

PhaseA normal-generation bridge preserves normal algorithms but source review
requires retained-unknown ownership, original per-command deadline and late
cancellation fixes. It has no executable runtime closure or admission. Native
sealing20 adapter and the cloud provider/Store separation prerequisite remain
source work only. No stage qualification or publication is claimed.


Actual five-case run63991 exits0 within the conservative715.229266s outer
bound. All five classifications,701 immutable command journals,671 SQL joins
and normal status0/stop0/status3 cleanup records pass root audit `ae1f4270`.
Independent RESULT review remains pending; this is not complete S5 acceptance.
The initial root-audit comparison incorrectly mixed decoded streams with stored
gzip references. The corrected audit checks both representations independently;
all original evidence and the first audit failure are retained.

Scoped format/build run81085 exits1 with E0603: the fixture spawn helper has
parent-only visibility but is called from the crate root. Both format commands
passed; no test executable or discovery ran. Root partial result `8d751586`
verifies all544 source preimages and139 generated files, all eight formatting
rollbacks, three reaped/quiet process groups, and private/root fixture absence.
A one-function visibility correction and fresh source closure are being prepared.

Normal generation Phase A successor `c10426db` closes its three source findings
with25 pure tests; runtime closure, actual generation and Phase B remain open.
Cloud provider/Store successor `50214a43` closes source review, preserving
provider errors across stale post-I/O races; Rust execution and integration are
pending. PublicSetup file-I/O/Store splitting and the fresh twenty-case sealing
adapter remain source work. General owner-domain synchronization, ongoing
authority, production WSS/effects, full Host/runtime and E3–E7 remain open.
All complete-stage gates stay false; nothing is published.


Five admission cases are now independently accepted by root receipt `d8621f2a`.
The strict reader, all2,846 indexed hashes,701 command joins and671 SQL joins
pass, with five classifications, normal cleanup and owned root-directory removal.
Current evidence uses118,464,512 allocated bytes and2,853 entries within the
original limits. This accepts only those five faults; fullS5 and the twenty-case
sealing run remain open.

Root installed only the fixture spawn visibility correction `pub(crate)`;
integration receipt `adc284df` verifies all543 other inputs unchanged. Independent
source review closes the delta and fresh580-file runner. Actual scoped build
retry47757 is running with the same900/300-second limits; no application test or
discovery is admitted. Failed81085 remains unqualified and its rollback proof is
preserved. FullHost/PTY, general owner-domain and ongoing authority remain open.


Actual47757 stops at the original2GiB free-space floor; root partial `e6d2a9fd`
verifies complete rollback and owned cleanup. Recovery removes only3,997
single-link rebuildable files in target/debug/deps (845,352,960 allocated bytes);
all executables, dylibs, WASM, evidence, sources and five linked metadata files
are preserved. Fresh27930 then passes all three compilation commands, but strict
Clippy rejects six fixture-only legacy unused items and three collapsible ifs.
Root partial `41f31be8` verifies all544 preimages restored, six quiet/reaped groups,
private/root absence and six final binary hashes. A transient controller hash
from the preceding build was superseded by its later explicit build; its bytes
were not retained. The next runner must retain each command's binary copies.
No test/list ran and this build is not qualified.

Twenty-case source `790ceae9` closes independent all-three baseline replay,
exact initdb command-one and import-shadow findings;50 pure tests pass. Its first
actual direct invocation (chunk78c605) exits1 before Root/native execution or
runtime-directory creation: strict require(value is True) rejects the integer1
returned by valid Python flags. The no-Native diagnostic reproduces the actual
main-entry failure; root partial `7ce354bc` verifies unchanged386/79 inputs and
owned outer removal. No database or twenty-case scenario ran. A narrow flag
correction and entrypoint regression are pending.

PublicSetup successor `f8a9190c` closes source review after the explicit OperationId
test import; two-file integration and22 focused Rust tests remain unexecuted.
Full Host discovery/integration stays closed pending supervision of two direct
SQLite probe children. The independently mapped151 normal tests include that
test; none are skipped. A feature-only fixed subprocess broker is source work.
All stage gates and fullS5 remain false; nothing is published.


The seven-source actual build3644 exits1 within124.229660s. Root result
`terminal-owned-seven-root-integration/build-root-result.json` (`3873731c`)
checks all544 installed preimages after format rollback,139 generated files,
630 runner pins, six retired quiet/absent groups and both private cleanups. All
compiled executables were copied and verified before later commands. Three
remaining Clippy diagnostics require equivalent source corrections; no tests
or test discovery ran and this build is not qualified. Source-derived Host
inventory is now165, including four cloud and ten public-configuration tests.

Twenty-case actual12046 exits1 within40.794117s. Retained raw first-frame bytes
are3,363,515 versus the internal2,621,440 subcap. Root partial `c8567080`
preserves122 committed prefix commands, the uncommitted capture, stopped owned
PGDATA and raw logs. Recorded stop0/status3, absent PID file and empty socket
directory support normal shutdown, but the whole Guardian child ledger was not
persisted; it is not independently claimed. A stored/logical resource design
and durable failure-finalization evidence are required before retry. Original
256MiB allocated and other authoritative caps remain unchanged.

Broker successor `b2a57a2b` / `4bb695b2` closes both reviewed P2s: Host-only
crash occurs before probe cancellation, and root diagnostics cannot panic on
stderr errors while retaining children.74 pure checks pass; all nine new and
29 original native cases remain unrun. Current composition with the lint/Core
files requires separate review and a fresh545-input/255-Rust/38-format build.
The Terminal component proposal passes40 pure checks but keeps its execution
entry closed pending actual build/fault proofs and reviewed root bindings.


Broker/Clippy integration `ea5ef761` follows independent closure of the five-file
composition `6b40ada2`, BUILD7 source `faf54d09` (43 pure checks), and corrected
installer/atomic mechanics (21 filesystem checks). The original receipt-error
and incomplete-rollback findings are closed; publication additionally requires
caller-bound stable identity or explicit absence, including during rollback.
The prior implementations and failed reviews are retained. The new five files
are unformatted/uncompiled. Fresh build admission stopped before any Native
launch or outer-directory creation because free space fell to about1.4GB.
The user has been asked to free disk; this is a resource dependency, not a
source acceptance or permission to relax the original2GiB floor.

The source-only twenty-capture resource plan `e34de2a7` passed independent
design review. Its original allocated/raw/time caps remain unchanged; the
private codec and positive-owner failure ledger are under implementation and
pure validation. Native fit remains unproved. The frozen38-case driver `5cce3a53`
has22 pure passes and a deliberately closed entry, with ownership error paths
under correction before runtime admission. PhaseB emitter `55657f0e` has18
pure passes and independent source closure; actual archive/cache/resolver
qualification and production publication are still absent.


## 2026-10-22 — CloudWorker restart after expired runtime lease

The restart fixture now expires the private Remote runtime lease/freshness
before phase two and exercises first GET invalidation → second GET claim
admission → claim POST → final GET. Phase one committed publication sequence 8,
retained the pending intent across owner exit, and preserved the HostStore file
hash. Phase two reached every fixed stage through `final_get_reconciled` and
reported `action_online`, pending absent, outbox nonempty, ACK missing, and a
binding sequence outside the expected 7/8 values. The child then exited 101
before the exact route/state assertions completed.

The private SQL claim function resets `publicationSeq` to 0 and `workspaces` to
an empty array for a newly claimed runtime. Thus this fixture setup cannot both
claim an expired runtime and expect the old sequence-8 publication ACK and
workspace membership to remain locally acknowledged without another
publication. The sequence/route assertion was updated to the intended
GET/GET/claim/GET flow, but no additional correction or rerun was made. The
restart proof remains failed; production Cloud code and fail-closed behavior
were unchanged.

Formatting, `auth-app` TypeScript check, and the `cloud-fixture` test binary
compile passed. The guarded PostgreSQL 18.6 runtime suite reports 6 passed / 1
failed (784 assertions); cluster cleanup completed (stop exit 0, follow-up
status 3), and frozen source hashes remained stable. The listener observed 23
aggregate TLS requests. Restart-specific route counts were not finalized because
the child failed before the harness's route assertions. Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun27/18c8d420-9c37-4a82-95dc-394f8c75a70e/runtime-proof.json`.

Rerun28 completes that fixture-only recovery path. The restarted worker follows
GET (invalidate stale scope), GET (receive claim admission), claim POST, final
GET, heartbeat, and a new-generation publication PUT. The exact TLS route
sequence contains 9 requests: the original GET/heartbeat/PUT, then restart
GET/GET/claim/GET/heartbeat/PUT. The old-generation `(generation 1, sequence
8)` PUT was not repeated; the new generation acknowledged sequence 1, retained
the workspace, and cleared the local pending intent/outbox. HostStore bytes
were unchanged at the process handoff. The Cloud restart test itself passed.

The containing Auth runtime suite still ended 6 passed / 1 failed (790
assertions): a later, unrelated `claim-refresh-race` step uses hard-coded
`expectedGeneration: "1"` after the restart fixture has advanced the same
host row to generation 2, so its claim receives 409. This is a fixture ordering
assumption, not a restart recovery failure. No further run or correction was
made. Rust formatting, `cloud-fixture` test-binary compilation, and Auth
TypeScript check pass. The pinned PostgreSQL 18.6/Bun 1.4.2 run had stable
source hashes and completed private-cluster cleanup (stop exit 0; confirm
stopped exit 3). Receipt:
`../auth-app/artifacts/host-credentials-runtime-restart-worker-rerun28/959f74f5-9fd6-4fa8-85fa-929d19cab59d/runtime-proof.json`.

## 2026-10-21 — Host matrix green; remote terminal.move active

Environment: macOS arm64, Rust 1.98.1, `cargo test --offline --locked` through
`tools/test-host.sh` (umask 077, short private `TMPDIR`). No Windows/Linux run
in this checkpoint; no PostgreSQL, browser or production job ran. Nothing was
committed, pushed, deployed or published.

Resolved the one failing Host test
`real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay`.
The earlier `Invalid` was the fixture running out of scripted current-peer reads:
each 16 KiB snapshot fragment performs its own read and the default 80x24 grid
needed ~195 reads per connection (390 measured for attach + reconnect) against
a budget of 64. After that, unoptimized `curve25519`/JSON/hex validation made
two full snapshots outlive the real 5 s heartbeat freshness window under a loaded
parallel run (`Fatal::Stale`). Production code and contract values are unchanged
(5 s freshness, 30 s lease). Changes:

- fixture budget 64 -> 512 reads, with the measured need documented;
- the test pins a 12x40 PTY through a `#[cfg(test)]` setter, keeping a
  multi-fragment snapshot at ~1/4 of the cost;
- hang guard 4 s -> 20 s (it is not a performance assertion);
- workspace `[profile.dev] opt-level = 1`, dependencies `opt-level = 3`
  (debug assertions, overflow checks and debuginfo preserved).

Rejected approaches (recorded because they look natural): widening
`heartbeat.freshness_ms` or moving `request_started` in the fixture. Both break
pairing/channel admission because those wire values are compared against the
admitted handoff. Do not retry them.

Other test-only corrections found while running the full matrix:

- 87 Host tests failed with `INVALID_PROFILE` under a default umask: profile
  directories must be exactly 0700 and `tempfile::tempdir()` honors umask. Use
  `tools/test-host.sh` (the earlier controlled runner masked this dependency).
- `contended_other_workspace_startup_cannot_stop_after_close_or_restart_deadline`
  relied on child-exec latency, not on lock contention: startup of another
  workspace no longer holds the sessions map (lomi-terminal unchanged since
  checkpoint 708). The hook now crosses the 100 ms deadline deterministically at
  the destructive boundary, which is the property under test.
- `lomi-host-store/tests/durability.rs` expected schema version 3; unix/windows
  hosts are at 4 (public-configuration migration). The integration tests of
  `lomi-host-store` were not part of the earlier 675-name matrix.

Applied the two previously source-reviewed, never-compiled candidates
`terminal-move-owner-kernel` (7 paths) and `terminal-move-ingress`
(2 paths); both applied cleanly with `git apply`, then `cargo fmt -p lomi-host`.
Remote `terminal.move` is now part of the real TLS/Noise ingress: original wire
hash, duplicate-before-CAS replay, one durable receipt, one publication, and two
actual `/bin/sh` PTYs retained across move and reconnect (same-tab Before and
cross-tab After).

Results on these exact sources (orders of magnitude are per run, not summed):

| Check | Result |
| --- | --- |
| `lomi-host` | 491 passed, 0 failed, three consecutive full runs |
| whole workspace `--no-fail-fast` | 1136 passed, 0 failed |
| `clippy --workspace --all-targets -D warnings` | clean |
| `cargo fmt -p lomi-host --check` | clean (known out-of-scope crypto/vendor diffs untouched) |

Not verified: REQ-level acceptance, other OSes, full PostgreSQL/browser matrix,
remote create/split/close/restart, production Cloud HTTP publication. Remote
revoke/effect races remain open (REQ-13). A backup of the pre-change sources is in
`../.backups/` outside the repository.

## Remote terminal lifecycle (create / split / close / restart)

Remote `terminal.create`, `terminal.split`, `terminal.close` and
`terminal.restart` now run through the real TLS/Noise ingress on a workspace
channel with `workspace.read` + `terminal.observe` + `terminal.manage`.

Design (see `remote_terminal_lifecycle.rs`):

- One retained Shared announcement spans durable start -> physical effect ->
  completion. Domain and Store are released while the PTY effect runs; the
  effect is gated by a lock-free `effect_current` predicate, so a competing
  writer, revoke, unshare, cancellation or deadline stops the spawn/stop.
- Store `admit_start_external` atomically admits and starts the operation and
  yields exactly one permit. A duplicate returns the stored receipt and never a
  second permit.
- Only a Succeeded/Committed outcome is delivered. Any other final outcome is
  persisted but withheld; the connection is closed and the client reads the
  receipt back by exact duplicate lookup. A failed completion keeps its permit
  for persistence-only reconciliation (`DeferredCompletion`); an uncertain
  effect is recorded as unknown and never replayed.
- Close/Restart on a workspace channel treat `expected_session` as a CAS token
  validated by the plan, not as a live-target gate, so an exact retry after
  reconnect still reaches duplicate lookup. Terminal-scoped channels keep the
  strict live-target gate and cannot create or split.

New tests (all run, passing): Store atomic admit+start (2), real TLS/Noise
ingress for create, split, close, restart with real `/bin/sh` PTYs including
reconnect de-duplication and conflicting-hash withholding (4), a fault test where
a competing writer commits between start and effect (no PTY is spawned, no
receipt is delivered, maintenance settles Failed/None; confirmed to fail when the
predicate is disabled) for create, split, close and restart (4; close and restart
assert the real PTYs stay alive, nothing is spawned or stopped, and the durable
receipt settles Failed/None), and the `request_allowed` gate matrix (1).

| Check | Result |
| --- | --- |
| `lomi-host` | 502 passed, 0 failed |
| whole workspace `--no-fail-fast` | 1149 passed, 0 failed |
| `clippy --workspace --all-targets -D warnings` | clean |
| `cargo fmt -p lomi-host --check` | clean (pre-existing diff in `lomi-remote-crypto` untouched) |

Pre-effect rejections: a lifecycle request that fails planning (stale
`expected_session` -> `STALE_EPOCH`, unknown pane/tab -> `RESOURCE_NOT_FOUND`,
bad arguments -> `INVALID_ARGUMENT`) or is refused by the Store's revision CAS
without residue (`REVISION_CONFLICT`) is answered with an ordinary error response
(`Effect::None`, no receipt) over the still-usable connection. Only a small
whitelist (`rpc::pre_effect_rejection`) may be answered this way, only after the
authority was re-checked, and only when every owner turn is already dropped.
Idempotency conflicts and all post-journal failures still withhold and dispose.
Tests: stale revision for all four methods, stale session for close/restart;
both assert the error code, no state/journal/PTY change, and that the next
`workspace.get` on the same connection succeeds (they fail when the whitelist
is disabled).

Known limits: rename/move still close the connection on a stale tab or CAS
(their conflicts surface at Store commit); a pane whose session is no longer running cannot be
targeted by a request that carries a live `expected_session` on a terminal-scoped
channel; spawn failure (real exec error) and deferred-completion recovery after a
Store write failure are not yet covered by dedicated ingress tests. REQ-13 (revoke
races across all methods) stays open.

## Remote Explorer (files.list / stat / read / searchNames / create / mkdir / rename / remove)

`crates/lomi-files` is the root-confined engine; `unix/remote_files.rs` binds it
to the host; the read RPCs and the four mutations are served over the real
TLS/Noise connection.

Engine guarantees (Unix; every syscall is fd-relative from a pinned root fd):

- The root entry id is the workspace id. All other entry ids are host-minted
  UUIDs held in a registry and re-validated against the ancestor chain
  (device/inode) on every call, so a swapped directory invalidates the id
  instead of being followed.
- Revisions are salted hashes of identity, size and mtime; they never expose
  inode numbers.
- Symlinks are never followed (`O_NOFOLLOW`/`AT_SYMLINK_NOFOLLOW`); regular files
  with more than one link, `.git` entries and approved git dirs are
  `PROTECTED_PATH`. The host profile directory can neither be the root nor live
  inside it.
- Create makes an empty file, mkdir an empty directory, rename and create use
  `renameat2(RENAME_NOREPLACE)` / `renameatx_np(RENAME_EXCL)` and never overwrite,
  remove never recurses (`DIRECTORY_NOT_EMPTY`). Mutations are serialized per root.
- Non-UTF-8 names are preserved as raw bytes with a lossy display name and a
  base64url path id. Binary content is withheld; CRLF is reported.

Mutation pipeline (reuses the effect kernel of terminal create/split/close/restart):

- Store `admit_start_external_unversioned` is the atomic admit+start for file
  methods. Their preconditions are the file revisions in the request, checked
  by the engine at the syscall, not the workspace domain revision.
- `complete_external` journals the final receipt but queues no publication and
  rejects a projection for file methods (they never change workspace state).
- The syscall runs under the same lock-free `effect_current` fence as a PTY
  spawn. A known engine refusal is persisted as `Failed/None` and delivered to
  the client as an ordinary error (`FILE_CHANGED`, `PROTECTED_PATH`,
  `DIRECTORY_NOT_EMPTY`, `RESOURCE_NOT_FOUND`, `INVALID_ARGUMENT`) through the
  sealed delivery path, because the journal write itself invalidates the
  ordinary response proof. A syscall that fails after it may have started is
  `OutcomeUnknown/Unknown`, withheld, and never replayed.
- A retried operation id returns the stored receipt (`OperationResult::File`)
  without touching the disk.

Tests (real TLS/WebSocket/Noise, one connection each):

- `real_tls_noise_explorer_reads_are_root_confined_and_refusals_keep_the_connection`
  (list, stat, read with revision, search, symlink, hardlink, stale revision,
  unknown entry, binary file).
- `real_tls_noise_explorer_mutations_are_exact_idempotent_and_protected`
  (create, retry of the same operation returns the same receipt and does not
  replay, stale precondition, mkdir, rename incl. no-overwrite, remove, `.git`
  remove/rename, hard link, non-empty directory, connection survives all).
- Engine unit/race tests in `lomi-files` and `remote_files`.

Test hygiene: the TLS/PTY fixtures busy-wait cooperatively, so running more
test threads than cores produces spurious timeouts. `tools/test-host.sh` now
defaults to `RUST_TEST_THREADS=4`; `LOMI_ONLINE=1` allows a build on a machine
without a pre-populated cargo registry.

Not done: `files.watch` streams, GitService and every client UI. The
revoke-during-effect and failed-completion recovery tests for files are
described in the section below.

### Windows file engine (2026-10-21)

`crates/lomi-files/src/windows.rs` replaces the placeholder. Every operation is
relative to an open directory handle (`NtCreateFile` with `RootDirectory`,
`NtQueryDirectoryFile`, `NtSetInformationFile`), never to a text path after the
root has been opened:

- Reparse points (junctions, symlinks, mount points) are opened with
  `FILE_OPEN_REPARSE_POINT`, reported as `Symlink`, and never followed, listed
  into, read, or written through. Removing one removes only the link.
- Entries are identified by volume serial plus 128-bit file id; every call
  re-validates the ancestor chain, so a swapped ancestor is `FILE_CHANGED`.
- Component names that Win32 or NTFS would reinterpret are `INVALID_ARGUMENT`:
  separators, `:` (alternate data streams, `::$INDEX_ALLOCATION`), trailing dot
  or space, DOS device names with or without extension (`CON`, `NUL.txt`,
  `COM1`, `CONIN$`), wildcards, quotes, control characters, over-long names,
  and non-UTF-8 names. `.git` in any case and its `GIT~n` short-name aliases are
  `PROTECTED_PATH`. Case-insensitive collisions are `EXISTS`.
- Rename uses `FileRenameInformation[Ex]` without the replace flag and never
  overwrites. Delete uses POSIX delete semantics where available, clears the
  read-only attribute like `unlink`, and never recurses.
- Files with more than one hard link are `PROTECTED_PATH`.
- NTFS directory timestamps tick coarsely, so revisions include a per-entry
  generation counter that the engine bumps on every mutation it performs.
  Two engine mutations within one clock tick always change the parent revision.
  An *external* edit made within the same filesystem tick as a revision read
  can still go undetected (the same class of limit as coarse `ctime` on Linux).

Result on the Windows 10 lab machine: 25 engine tests (including concurrent
ancestor-swap and hard-link races, junction creation without privilege) and
`clippy -D warnings` pass. File symlinks need Developer Mode or elevation, so
the file-symlink half of one test is skipped on this standard-user account.
The host serves Explorer requests through the same engine; the Windows host
test target runs the shared (platform-independent) RPC tests, but the real
TLS/Noise Explorer tests are unix-only fixtures and were **not** run on Windows.

### Rename/move errors, revoke during effect, failed completion (2026-10-21)

- Terminal rename and move conflicts (stale or missing target, wrong
  revision) are persisted as `Failed/None` and delivered as an ordinary error
  response through the sealed path; the connection stays open. Only errors that
  occur before any journal write use the pre-effect whitelist
  (`ResourceExhausted` was added to it).
- New real TLS/Noise tests: unshare and logout while a terminal effect and
  while a file effect is in flight (the effect is fenced, nothing is delivered
  to the revoked client, the receipt is settled for recovery); a failed Store
  completion after the effect ran is recovered by the deferred-completion
  path without repeating the effect, for every terminal lifecycle method and
  for files. A `#[cfg(test)]` hook before `complete_effect` injects the failure.
- Linux `Fatal::Stale` in the terminal lifecycle stream test: the fixture has
  no heartbeat worker and peer proofs expire 5 s after creation, so a slow
  suite run saw an expired proof. The test now emulates the heartbeat worker.
  This was a fixture defect, not a stream-path defect.
- Intermittent `connect Invalid` in HTTP/relay fixtures: the process-wide DNS
  worker allows one lookup at a time and fails concurrent ones. IP literals now
  bypass it, and `localhost` resolves IPv4 first (Windows tried `::1` first).

### Cross-platform runs (2026-10-21, final)

Sources were copied (no `target/`) to the two lab machines; nothing was
installed system-wide (user-level rustup only). Earlier in the day the same
runs showed the failures listed under "Previously observed"; they are fixed
as described above.

| Machine | Scope | Result |
| --- | --- | --- |
| macOS (developer machine) | whole workspace, `tools/test-host.sh --workspace --no-fail-fast`; `fmt`; `clippy --workspace --all-targets -D warnings` | 1183 passed, 0 failed; clippy clean |
| Arch Linux x86_64 (rustc 1.98.1) | whole workspace (`LOMI_ONLINE=1`, serial) | 1160 passed, 0 failed |
| Arch Linux x86_64 | `lomi-host --lib` repeated 3 times | 515 passed, 0 failed in each of 3 runs (the complete suite passed once as well) |
| Windows 10 x86_64 (MSVC) | `lomi-host`, `lomi-host-store`, `lomi-platform`, `lomi-host-http`, `lomi-files` | `lomi-host` 287, `lomi-host-store` 18+10+8+12+15+17+27, `lomi-platform` 66 (2 ignored), `lomi-host-http` 60, `lomi-files` 25 passed; 0 failed |
| Windows 10 x86_64 | `clippy -p lomi-files --all-targets -D warnings` | clean |

Previously observed and now fixed: Linux `Fatal::Stale` in the terminal
lifecycle stream test; six `lomi-host-http` and one `lomi-platform` failure on
Windows; `lomi-host` and `lomi-host-store` test targets not compiling on
Windows (unix-only modules and a unix-only dev-dependency are now gated).
`lomi-platform`'s foreign-owner backup test skips when the token lacks the
privilege to assign a foreign owner (error 1307) instead of failing.

Not covered: the new revoke/failed-completion ingress tests are unix-only
fixtures; they ran on macOS and Linux only. Windows has no real TLS/Noise
Explorer or terminal RPC test. Windows `lomi-platform` and the host were run
under a standard, non-admin account only.

### files.watch, multi-client sync, exec failure, REQ-13 (2026-10-21)

- **`files.watch`** (`remote_files_watch.rs`, wired into `remote_ingress.rs`):
  invalidation only. One watch per connection; the host polls the watched
  directory once per second and compares a SHA-256 fingerprint over name,
  entry id, kind, size and revision. A change is sent as a
  `FileWatchFrame::Invalidated` naming the directory (never content), with a
  `watchSeq` and a cursor (the fingerprint of the state the client was told
  about). Resuming with a stale cursor is invalidated immediately, so a
  reconnecting client cannot miss a change. At most 8 frames may be
  unacknowledged; polling then pauses and the change coalesces. A directory
  over 1000 entries is refused at open (`HostBusy`) and, when it grows past that
  later, ends the watch with `ResyncRequired(WatchOverflow)`; a removed
  directory ends it with `ResyncRequired(StaleCursor)`. Client acks are accepted
  only for this connection's subscription and an already-sent sequence; any
  other watch frame from the client closes the connection. Frames use the same
  per-fragment current-peer proof as terminal frames.
  Limits: polling, not OS notifications. The fingerprint includes the watched
  directory's own revision (device, inode, mtime and ctime with nanoseconds,
  mode), so a child that is changed and reverted, or created and deleted,
  between two polls is still reported as long as the filesystem timestamps
  moved (unit tests cover both). What stays invisible is a change that leaves
  every timestamp the filesystem records identical, and anything inside a
  subdirectory (one directory level per watch). A content change is visible
  only through the file's revision (same tick limit as the engine).
- **Multi-client sync** (real TLS/Noise, two simultaneous connections):
  both attach to the same PTY, a command typed by one executes exactly once and
  its output is seen by the other, a rename by one is seen by the other as one
  newer workspace view, and the other's stale-revision edit is an ordinary
  `RevisionConflict` that keeps its connection. Finding: while a publication is
  committed but not yet acknowledged by the Cloud, every *other* connection's
  next current-peer read fails closed (`Fatal::Stale`) and that connection is
  closed. This is the existing fail-closed eligibility rule (`outbox` must be
  empty); it means a concurrent mutation by one client briefly disconnects the
  rest until they reconnect. At this checkpoint the second driver was held idle
  in that window; the follow-up proof below now makes it issue the read and
  observes the close before acknowledging the mutation.
- **Real exec failure**: a shell that really fails inside `execve` (EACCES) makes
  create/split a durable `Failed/None` receipt and restart (after the stop)
  `OutcomeUnknown`. For create/split the host now answers the request with an
  ordinary no-effect error (`HOST_BUSY`, effect `none`, carrying the
  operation id) and keeps nothing running; only a genuine spawn failure takes
  this path (a fence, revoke or competing writer still closes the connection
  without any answer). Restart after the stop stays withheld: the outcome is
  unknown, so the client reads the receipt by duplicate lookup after
  reconnecting. The earlier `Fatal::Stale` was the test client observing the
  closed connection, not a defect of delivering the error.
- **REQ-13** now has real-TLS tests for terminal `input` and terminal
  snapshot streams (unshare and logout; nothing reaches the PTY, the snapshot
  never completes). Git: there is no Git service (E5); a Git call is refused
  fail-closed (no response, connection closed) and a test asserts that no
  result can exist. Revocation while watching is covered by two real-TLS tests
  (unshare and logout after `files.watch` is established and acknowledged,
  then a change in the watched directory): no `FileWatchFrame` is delivered to
  the revoked client. Mutation-checked: skipping the revoke commit makes the
  test fail with "an invalidation was delivered after the workspace was
  revoked".
- Windows: the TLS/Noise fixtures now compile and run on the lab
  (`cfg(test)` instead of `cfg(all(test, unix))`). Private profile directories
  go through `OwnerLock` (a mode-0700 directory is rejected as
  `InvalidProfile` on Windows), the fixture auth provider is DPAPI there, and
  the real PTY is `cmd.exe`. `cmd.exe` ignores a verbatim `\\?\` working
  directory, so `lomi-windows-pty` hands it a plain drive path. A standard
  account cannot create a directory symlink; that assertion is skipped there.
  The elevated account can, and the same suite passed with the assertion
  included. See the Windows validation paragraph below.
- Clients: `remote-web` speaks the older v1 JSON relay protocol (`/v1/relay`,
  fragments) and a search of `lomi`, `lomi-web` and `mobile-app` finds no client of the
  v2 native RPC/Noise framing (`lomi` only has unrelated local MCP file tools), so an Explorer UI cannot be wired or verified yet. No client UI was
  added in `lomi-remote`.
  `remote-web` now has a transport-agnostic Explorer model
  (`src/explorer.ts`: listing with paging, `files.watch` subscription with
  ack-after-reload, resync handling, conditioned create/mkdir/rename/remove,
  unknown-outcome retry with the same operation id, revoked state) and a
  presentational `ExplorerView.tsx`. Both are tested only against a scripted
  in-memory host (12 `bun test` cases) and type-check with `tsc`; no page mounts
  them because no v2 browser transport (relay admission, ticket, Noise channel,
  grant flow) exists, so they have never talked to a real host.

Validation of this round: macOS whole workspace `tools/test-host.sh --workspace
--no-fail-fast` 1197 passed, 0 failed, 3 ignored; `cargo fmt --check` and
`clippy --workspace --all-targets -D warnings` clean. Windows 10 (standard
account): `lomi-host` 292 (was 287; the difference is the five `files.watch`
unit tests), `lomi-host-store`, `lomi-platform` 66 (2 ignored), `lomi-host-http`
60 and `lomi-files` 25 passed, 0 failed. Linux was **not** run: the lab machine
accepted the TCP connection and the pinned host key but never answered after the
password was sent, so the new revoke, exec-failure, multi-client and watch tests
ran on macOS only (the five watch unit tests also on Windows). A flaky
`lomiremote` `terminal_ipc` test (two tests in one process could create the
same timestamp-named directory) was fixed with a process-wide counter.

Follow-up validation (2026-10-21, later): macOS whole workspace
`tools/test-host.sh --workspace --no-fail-fast` 1199 passed, 2 failed,
`clippy --workspace --all-targets -D warnings` clean. The 2 failures
(`real_tls_noise_move_same_tab_before_...` and
`real_tls_noise_rename_delivers_...`) were `PolicyError::ClockRollback` during
fixture setup and passed on rerun. They are pre-existing: with the exec-failure
change reverted the same two tests still failed 1 run in 16. Cause, since fixed:
the channel worker built its `PolicyClock` from `live()` (whole seconds) and
a fresh `Instant::now()`, dropping the runtime anchor's fractional second.
`channel.rs` now uses `runtime.base` and `runtime.anchor`, which is what
`aligned_runtime_anchor_preserves_second_boundary_without_weakening_clock_guards`
already required. The two
revoke-while-watching tests, the two directory-revision watch tests and the
changed exec-failure test passed. `remote-web`: `bun test tests/explorer.test.ts`
12 passed; `tsc --noEmit` clean (`astro check` could not run: the machine has
Node 20, Astro needs >=22.12). Linux was not run.

Windows validation after the fixture port and the clock fix (2026-10-21):
standard account `test-user`, `cargo test --locked --no-fail-fast -p lomi-host
--lib -p lomi-windows-pty`: `lomi-host` 508 passed, 0 failed;
`lomi-windows-pty` 1 passed (the plain-cwd helper). The same `lomi-host` test
binary, run as `woro-server` at high integrity (`S-1-16-12288`), passed 508,
0 failed. An earlier standard-account run of `lomi-host-store`,
`lomi-platform` (66, 2 ignored), `lomi-host-http` (60), `lomi-files` (25) and
`lomi-terminal` was already green and was not repeated. macOS, after the
clock fix: the four tests that had been failing on `ClockRollback`, 20 runs,
0 failures. `clippy -p lomi-host -p lomi-windows-pty -p lomi-host-auth
--all-targets -D warnings` clean. The whole macOS workspace was not re-run
after this fix. A direct `mklink /D` on the standard account is refused
("You do not have sufficient privilege"); the same command as `woro-server`
creates the link.

## 2026-10-22 — Linux ARM64 product and service rerun

The disposable Ubuntu 24.04 ARM64 `lomi-e0` VM ran the frozen current source
through `tools/run_linux_product_host.py --run --with-service`. `lomi-host`
passed 533 tests; the selected Rust packages passed 796 tests with zero
failures and two intentional ignores. This includes the current real TLS/Noise
terminal and file revoke/effect, watch and multi-client tests. The product
systemd-user service passed prepare/verify (9 + 23 checks); cleanup removed the
owned unit, confirmed no fixture processes remained and removed all temporary
guest inputs. Report: `artifacts/product-linux/c75ceaff-22c2-46c3-b0de-d1c196060276/report.json`;
frozen source inventory digest: `95e91e71bfe690f55062bd5ed6b69a8ac4e90f729cbb7a0e2edf1672223e9aa7`.

The first attempt exposed a runner mismatch: it bypassed `tools/test-host.sh`,
so Linux's required private umask, short `TMPDIR` and single test thread were
not set. The runner now invokes that helper through `sh` and adds the guest
Cargo toolchain to `PATH`. The failed attempts retained separate reports and
confirmed cleanup. This bounded run does not qualify boot/reboot, clean
installation, Cloud/relay, or the full distribution and architecture matrix.

## 2026-10-22 — CloudWorker against the actual Remote handler

The opt-in `lomi-host/cloud-fixture` test ran inside the pinned runtime
harness against the real `createRemoteApp` handler, loopback TLS, and a private
PostgreSQL 18.6 cluster. After the first GET/heartbeat/publication ACK, the
fixture unshared its workspace. The same CloudWorker sent a second heartbeat
and publication, reconciling the database membership to empty and advancing
the cursor 4→5→6. Local ACK state records the empty membership at sequence 6,
with no retained publication intent or outbox. The server binding was
pre-established, so the Worker claim branch remains uncovered. The bounded
run passed 7 DB tests (1,329 assertions), 912 regressions plus one existing
skip, Prisma validation, TypeScript, offline Rust build, and cleanup. Receipt:
`artifacts/host-credentials-runtime-local/86f79b72-576c-4db4-9c72-1a176735f42d/runtime-proof.json`
(SHA-256 `a061c304661444ee4a45675ce25a2d415ddc30d9921ec0ed80ca00cecc85bbd8`).

This proves one-host publication and permission-refresh behavior. It does not
qualify production TLS, relay, global revoke, multiple-client fail-closed
coordination, restart recovery, full S5, S6, S7, or E2. The existing publish
ACK barrier and fail-closed rule were not changed. The harness's separate
`boundedPostgres186FixturePassed` stage flag remains false for this `runtime`
suite even though the runtime receipt and acceptance markers pass.

## 2026-10-22 — CloudWorker expired-lease claim against the actual handler

A follow-up fixture covers the separate expired-lease claim branch with the
real CloudWorker, DataTransport, fixture TLS, `createRemoteApp`, and private
PostgreSQL. It begins with server generation 2 / access epoch 3 and an expired
lease, then sends runtime GET → claim POST → runtime GET → heartbeat POST →
publication PUT. The replacement binding is generation 3 / epoch 4; its
publication cursor restarts at sequence 1. Rust assertions verify the
reconciled local binding, HostAuth epoch 4, acknowledged sequence 1, and no
pending intent or outbox. This does not exercise initial generation-0 claim.

The latest aggregate runtime receipt is
`artifacts/host-credentials-runtime-local/98667b87-00d6-4972-9905-9d684b2ba986/runtime-proof.json`
(SHA-256 `a78827fb1bca44e57570a19d31aad677ed7060f3b90c9305d2fd46d5cb20a5ff`).
It exited 0 and records 17 Rust TLS requests, including the explicit transport
race and both actual Worker paths; the claim Worker acceptance marker is true.
The receipt also records 7 DB tests / 1,329 assertions, 912 non-database
regressions with one existing skip, Prisma validation, TypeScript checking,
offline Rust build, and cleanup. `productionQualified`,
`productionPostgres186Qualified`, and `boundedPostgres186FixturePassed` remain
false. Global revoke, relay, multi-client fail-closed coordination, restart
recovery, and full E2/S5/S6/S7 remain unqualified; no fail-closed behavior was
changed.

## 2026-10-22 — CloudWorker publication recovery and central revoke

The actual-handler runtime fixture now simulates a lost/unknown ACK after the
real Remote handler commits publication sequence 7. It replaces the committed
HTTP success with canonical 409 `OUTCOME_UNKNOWN` plus `Cache-Control:
no-store`; this is not a socket-drop test. The Worker retains pending intent
and outbox, and the local binding cursor remains at sequence 6 before recovery.
For this exact unknown outcome, production code now prearms a GET instead of
retrying the PUT. The next GET reconciles the exact workspace at sequence 7.
The observed route sequence is GET → heartbeat → one publication PUT → GET.
Other error and fail-closed behavior are unchanged.

The next pinned runtime run adds central account-manager revoke through the
actual Better Auth handler, followed by the actual Rust CloudWorker and Remote
runtime handler. The central endpoint advances the host identity epoch and
revokes every host authorization family. The Worker's next runtime GET receives
401, fences local authority, and leaves `host_runtime` unchanged. The private
TLS server sees exactly one GET; it is stopped during cleanup.

The final pinned runtime run is
`artifacts/host-credentials-runtime-local/a1a04f67-6031-456d-aa2f-eda0ac1097e4/runtime-proof.json`
(SHA-256 `d7218cc86c7b63905ed068247a2877e5c9e35e453692e7d640175d3fddbfc7f6`).
It exited 0 with 21 Rust TLS requests, including the transport race,
publication/permission refresh, expired-lease claim, unknown-ACK recovery, and
the separate central revoke fixture. Runtime DB tests, non-database
regressions, Prisma validation, TypeScript checking, offline Rust builds, and
private fixture cleanup passed. The receipt's production qualification flags
and `boundedPostgres186FixturePassed` remain false; relay, multi-client
coordination, host restart, and full E2/S5/S6/S7 remain open.

## 2026-10-22 — Two-client publication fail-closed fence

The existing real TLS/Noise two-client test now checks the full ordering around
the publication barrier. Both clients attach to the same PTY; A's input runs
once and B observes it. A's first workspace rename is acknowledged, after
which B sees the new view and its stale-revision edit returns an ordinary
`RevisionConflict` without closing. A then commits a second rename. The fixture
asserts exactly one pending publication; before acknowledging it, B sends
`workspace.get` and receives `Delivery::Closed`. Only after that close does the
test acknowledge the outbox and release A. The fail-closed policy is unchanged.

Validation: `cargo test -p lomi-host
real_tls_noise_two_clients_share_one_pty_and_one_workspace_view -- --nocapture`
(1 passed) and `cargo fmt --all -- --check` passed. This host test uses a
controlled local publication acknowledgement; it is not a combined
CloudWorker/database/relay proof. Reconnect after the fail-closed close and
cross-client propagation of a real central revoke remain unqualified.

## 2026-10-22 — Host crate serial suite and HTTP fixture checks

The complete `lomi-host` library suite passes serially: 534 passed, 0 failed.
The earlier parallel and serial failures had the same fixture cause: Unix
`ready_test_fixture` created its profile directory with mode 0755, while the
production owner lock correctly requires a private profile. The test helper
now creates that temporary root with mode 0700; production lock behavior is
unchanged. A representative owner-lock test also passes after the correction.

`lomi-host-http` passes all 60 tests both without optional features and with
`test-fixtures`. The feature-specific error mapping now preserves transport
timeouts as `Timeout`, while assertions accept the fixture-only closed network
classifications. The production error mapping is unchanged. Formatting and
Clippy with `-D warnings` pass for the HTTP crate and fixture feature.

These are local Rust library results. They do not qualify Cloud multi-client
reconnect, all three clients, product services on every target OS, E3–E7, or
the production release matrix.

## 2026-10-22 — CloudWorker initial claim without a runtime row

The pinned actual-handler fixture deletes and verifies the absence of the
server `host_runtime` row, then exercises GET → claim POST → GET → heartbeat
POST → publication PUT through Rust DataTransport, loopback TLS, the real
Remote handler, and private PostgreSQL. The fixture uses an existing host
identity at access epoch 4, so this proves an absent-row claim but not
pristine-account enrollment. The server creates generation 1 / epoch 5 /
publication sequence 1. Rust verifies matching local binding and HostAuth,
one acknowledged workspace, empty pending intent/outbox, and no retained
operation. All five exact routes and the DB state assertion pass.

Receipt:
`artifacts/host-credentials-runtime-local/3967c452-82de-40d4-8dda-3805430e4a8d/runtime-proof.json`
(SHA-256 `04812532fa89883ac5100d713b54ed89735b4b96f833f0ab2683d47aa32c18b6`);
log SHA-256 `7ff8ad2868fbf68c1a0bb43e5f366827a3cc201d71a49b1473aaec4e2e73b3d4`;
frozen-input archive SHA-256
`9b7fbbb4b4650a1008120b43beb0dd2a32d276e39c4829fb281912fe6402db46`.
The aggregate run exited 0 with 26 TLS requests, seven DB tests / 1,338
assertions, legacy regressions, Prisma validation, TypeScript checking, offline
Rust build, and cleanup passed. Independent read-only review found no material
fixture or harness issue.

The full `lomi-host` serial library run after this addition passes 534/534;
workspace formatting and `cargo clippy --locked --offline -p lomi-host
--all-targets -- -D warnings` pass. This is bounded E2 evidence; production
Cloud, relay, client matrix, and the remaining E1–E7 gates are open.

## 2026-10-22 — bieżący zestaw `lomi-host` na Linuxie

Po wznowieniu dostępu testowego przesłano przypięte archiwum bieżących źródeł do osobnego katalogu na maszynie Arch Linux x86_64. Hash archiwum przed i po transferze jest zgodny; hash `cloud.rs`, testu dwóch klientów, `shared_owner.rs` i `Cargo.lock` na maszynie docelowej zgadza się z checkoutem źródłowym.

`cargo test --locked --offline -p lomi-host --lib -- --test-threads=1` zaliczył 534/534 testy. `cargo fmt --all -- --check` i `cargo clippy --locked --offline -p lomi-host --all-targets -- -D warnings` również przeszły. Stabilny rustfmt wypisał ostrzeżenia dla opcji wymagających nightly; nie zmienił źródeł.

Dowód wejścia i podsumowanie są w [archiwum źródeł](../../artifacts/linux-host-current-source/2026-10-22-arch-x86_64/source-input.tar.gz) i [raporcie przebiegu](../../artifacts/linux-host-current-source/2026-10-22-arch-x86_64/summary.json). To hostowy przebieg na Arch z domyślnymi features; opcjonalny `cloud-fixture` i rzeczywisty fixture PostgreSQL nie były tu uruchamiane. Nie zachowano osobnego logu testów. Nie kwalifikuje Ubuntu 22.04+/Debian 12+, czystego bootu usługi ani pełnego E1/E2; produkcja i etapy pozostają niezaliczone.

## 2026-10-22 — actual Cloud ACK after the two-client fail-closed close

The opt-in test uses the same two TLS/Noise channels, PTY, `HostStore`,
`SharedOwner`, and `HostAuth`. Before Cloud acknowledges the pending mutation,
client B receives `Delivery::Closed` for its workspace read. The real
CloudWorker then publishes via Rust `DataTransport`, fixture TLS, the actual
Remote handler, and private PostgreSQL. Server publication state advances,
and the test marker confirms the ACK followed B's close. The fail-closed rule
is unchanged.

Pinned runtime receipt
`artifacts/host-credentials-runtime-local/f35c6b32-2b60-4964-bf4a-cd195da9c57a/runtime-proof.json`
(SHA-256 `8a8bb86a689c32cf05c2729aa3c9e3698265410bf35e38b04769cca767a181a`)
exited 0. Runtime tests, regressions, Prisma, TypeScript, offline Rust build,
and cleanup passed. The run recorded 34 Rust TLS requests, including 8 for
the combined scenario. PostgreSQL used a private socket-only cluster and was
stopped; the TLS listener was also stopped. Frozen inputs SHA-256:
`3db3876841eff2acd53ddd6b38b337b12ab30e2944598a798bbef41fb2f005b1`.

The runner now checks `26 + sharedCloudRequests`; `actualCloudWorkerCombined`
is true for this bounded test. Reconnect after `Delivery::Closed`, central
revoke propagation to multiple clients, relay, full E2, S5/S6/S7, and the
remaining stages are not qualified. `productionQualified` remains false.

## 2026-10-22 — Linux `lomiremote` TUI tests on current source

The Linux SSH account already had Rust 1.98.1 installed under `~/.cargo/bin`;
that directory was absent from noninteractive `PATH`. An isolated source
snapshot was copied to a new test directory without replacing the prior source
or target cache. The tarball SHA-256 matched before extraction, and the TUI
source, integration test, and snapshot hashes matched the local checkout.

On Arch Linux x86_64 / kernel 7.2.11, `cargo test --locked --offline -p
lomiremote` compiled and passed **36/36** tests; the wizard consent, failure,
bounded-input and Ctrl-C cases all passed. `cargo fmt -p lomiremote -- --check`
also passed. Cargo used the previous nonconcurrent target cache, while all test
sources were from the new snapshot. Log and archive:
`artifacts/linux-lomiremote-ui-20261022/cargo-test.log` and
`artifacts/linux-lomiremote-ui-20261022/source-input.tar.gz`; the summary
records their hashes and limitations. This is not the complete Host suite,
Ubuntu/Debian release qualification, or a service boot test.

## 2026-10-22 — E3 consumer identity and credential blockers

Read-only tracing confirms `/v2/remote/channels` accepts a session Bearer
credential and the server derives a direct consumer assertion for each call.
The consumer-authorization endpoint returns session-bound context, not a
separate token. No remote-web or mobile v2 client currently implements this
lifecycle. Consumer-window registration also needs a signed persistent client
identity, but the shipped Rust/WASM `BrowserIdentity` is explicitly ephemeral
and has no secret import/export API. The authority crypto package snapshot is
now available to remote-web's build, but neither it nor the protocol boundary
is used by the active v1 worker. A safe session Bearer bridge and key lifecycle
are prerequisites to integrating the browser channel path; E3 stays open.

## 2026-10-22 — S5 private11 source successor

The stale 2026-10-20 freeze differed from the current candidate in `controller.py`
and `controller.test.py`. A separate successor now pins all 88 current source
files, 228 declared authority inputs, seven companion artifacts and an exact
88-member source archive. Its freeze SHA-256 is
`4da2afd5887621a06ff28ac798fbadf3fd78d74828a20fd4628f0420feec2c5c`; the
archive SHA-256 is `b2205aedb05fc86e119ae3b43858cb948911d4344e4b8f0ccca0193ebcb06d8c`.
Only `controller.py`, its pure test, and the plan path differ from the historical
freeze. The plan now points at the successor directory.

Both pure synthetic suites pass 15/15 (`controller.test.py` and
`disposal.test.py`). Default invocation reports `PREPARED_NOT_EXECUTED` with
zero calls and no child. Archive membership, every source pin, and all seven
companion hashes were rechecked. No PostgreSQL, Node, native pipe, SQL parser,
or credential-bearing call ran. A current runtime-input check stops because
the pinned Node executable is absent at the path in `tools.json`; the 49
runtime-tool and two local-stdlib pins are therefore recorded as unverified in
the fresh receipt. Independent review of this exact freeze found a high-severity
TOCTOU: the reviewed source tree is user-writable, `pinned()` hashes files
before a separate open/import or SQL use, and the entrypoint is already running
before its checks. A same-UID writer can substitute bytes during execution and
restore them before the final hash. The next source version needs a trusted
pre-launch root-owned staging closure and same-bytes module loading; until then
OS-root admission stays closed. Full S5 remains false.


## 2026-10-22 — Linux Arch current-source Host follow-up

After the lab SSH key was verified from the console and restored, a new isolated
source snapshot was transferred to Arch Linux x86_64. The archive SHA-256 is
`ad644d8edf5a5a08a89dfb8a739016424aa25f1d2d533cfe6d4258e786f4959d`; all 1245 extracted files matched the source
manifest. Reusing the prior nonconcurrent Cargo target cache, the complete
`lomi-host` library suite passed **534/534**. A focused run of real TLS/Noise
Host scenarios passed **38/38**, including two clients sharing one PTY,
workspace unshare during `files.watch`, watch acknowledgement/resume, and
uncertain/known exec-failure outcomes. `cargo fmt --all -- --check` and Linux
Clippy with `-D warnings` passed. Stable rustfmt printed only its existing
warnings about configured nightly-only options.

This closes the specific Arch rerun that had been blocked by SSH, not the
release matrix: Arch is not Ubuntu 22.04+ or Debian 12+, and the optional
Cloud-fixture/PostgreSQL tests, clean service boot/reboot, full Cloud actual
handler revoke, and E3–E7 remain unqualified. Evidence is under
`artifacts/linux-host-current-source/2026-10-22-arch-followup-revoke-watch-multiclient/`.

## 2026-10-22 — S5 successor2 source freeze prepared

The controller now checks that the runtime closure and loaded Python modules
come from a root-owned, non-writable tree; dynamic imports hash and execute the
same byte buffer. The fresh artifact
`artifacts/consumer-private-positive-controller/2026-10-22-eleven-source-only-successor2/`
pins 88 source files, 228 verified authority inputs, seven companion artifacts,
and exactly 88 archive members. Freeze SHA-256:
`0b64db4a29f4f3104353d13f321a75390e4d8de5f3e01bd80968fb3632623476`.
The exact frozen pure suites pass 17/17 and 15/15. Default invocation remains
`PREPARED_NOT_EXECUTED`, with zero positive calls. Node is still absent at the
pinned runtime path, leaving 49 runtime-tool and two stdlib pins unverified.
Independent static review of this exact successor is closed. The reviewer
confirmed the archive/source correspondence and that dynamic imports now hash
and execute the same bytes, closing the predecessor's module replacement
TOCTOU. A medium assurance gap remains: the controller entrypoint has already
started before its in-process ownership check. A trusted launcher must verify
and execute the exact entrypoint bytes and bind that digest to root admission.
The path-based ownership check also does not prove race resistance against a
privileged writer or unusual ACL grants. No native appointment or SQL ran;
root admission remains denied and S5 is not qualified.


## 2026-10-22 — Current-source Cloud runtime and central revoke rerun

The `auth-app` `runtime` fixture passed on macOS with pinned Bun 1.4.2,
PostgreSQL 18.6 over a private socket, and Rust 1.98.1. The current sources
built the Rust runtime driver and `cloud-fixture` test binary, applied
migrations and production roles/grants, then passed the actual Better Auth
handler runtime, regression suite, Prisma validation and typecheck. The actual
TLS CloudWorker checks passed publication and permission refresh, lost-ACK
reconciliation without repeating the PUT, and central host revoke. The manager
endpoint advanced the host epoch and revoked all authorization families; the
worker's real runtime GET was denied, local authority was fenced, and
`host_runtime` was not mutated. The listener and private database were stopped;
the runner exited 0.

This bounded fixture made 34 Rust TLS requests and 20 handler HTTP requests;
central revoke used a separate TLS handler and one GET. It does not prove
revoke propagation across multiple live client connections or relay behavior.
The fail-closed policy was unchanged. E2 and production qualification remain
open. Receipt and log: `../auth-app/artifacts/host-credentials-runtime-followup-20261022/8f1629e4-9d09-4dc4-9aa3-30cb476044a6/`;
receipt SHA-256 `b17505b8ee35753469cd0ce1be109eb73446bc94c75af70f56041f60577be1a6`.


## 2026-10-22 — Central revoke fences two live clients

The current-source `runtime` fixture exercises manager revoke while two real
TLS/Noise clients are attached to the same host owner. A Rust CloudWorker,
using the production auth supervisor and pinned TLS DataTransport, receives
HTTP 401 from the actual Remote runtime handler. The supervisor commits the
authority rejection on the same SharedOwner; the test then releases only
read-only workspace probes and requires both clients to receive
`Delivery::Closed` and both ingress drivers to disconnect. The runtime row
stays byte-for-byte unchanged, and no publication is pending. Manager revoke
advances the host epoch and revokes all authorization families. The fail-closed
policy was not changed.

The run used macOS, pinned Bun 1.4.2, private socket-only PostgreSQL 18.6,
Rust 1.98.1 and loopback TLS. It passed the Rust fixture build, 7/7 actual
handler DB tests, 913/913 legacy regressions, Prisma validation and TypeScript
checking. The isolated database and TLS listener were stopped. Receipt:
`../auth-app/artifacts/host-credentials-runtime-central-revoke-multiclient-rerun3-20261022/589b8d69-b4ff-44b5-8a2d-da453f1fbbb3/runtime-proof.json`
(SHA-256 `97ba916956c057abfe5f4c58b92c93023d819dcb6627e1195df3d6ebc03e5d8d`),
log SHA-256 `ae1291be6a6386669b0427a95cb55a61d895ae2403b94696531fafbe37d2e03d`,
and frozen-input archive SHA-256
`b942da37813ead630f9edaee04bd65c862a534578e0622aa0e9b9adf03ab06e1`.

This closes one bounded actual-handler propagation case. It uses two local
clients and does not exercise a deployed relay, cross-host fanout, reconnect,
restart recovery, the target Linux/Windows release matrix, full E2, or consumer
S5/S6/S7. Production qualification remains false.


## 2026-10-22 — S5 trusted-launcher prototype

Added a source-only launcher prototype for the private eleven-call S5
controller. It traverses the fixed root-owned tree without following symlinks,
reads the root admission, freeze and controller through one trusted directory
FD, binds the raw freeze hash to the exact controller digest, and executes the
admitted bytes in memory. A separate run admission binds both digests and the
controller's fixed native-admission path; without it the launcher prints the
fixed status `PREPARED_NOT_EXECUTED` and exits 0. Ten pure tests pass, including
schema/digest failures,
symlink and writable-ancestor rejection, the ordinary root `0755` base, and a
path replacement after admission. `plan.json` parses.

The launcher and complete project closure are not installed under the fixed
root-owned path. No controller, root, native pipe, PostgreSQL or Node operation
ran. Source and run admissions remain disabled; full S5 is false and S6/S7
remain unrun. Independent review found a high-severity pre-execution trust gap:
Python has already started executing `launcher.py` before its in-process digest
check. The digest is only an installed-file consistency check; it does not
authenticate the running entrypoint. A separately reviewed immutable install
boundary or a trusted bootstrap that verifies and executes the admitted bytes
is required before any root admission. Review also found a manifest schema
weakness, now closed by exact keys, strict integer schema version, and duplicate
JSON-key rejection. The review's launcher default-status finding was also
closed: the launcher reports the fixed status and a focused test covers it.
Installation and runtime remain outside review.

## 2026-10-22 — S5 deterministic source staging

Added a pinned manifest and `scripts/s5_source_stage.py` for the exact
successor2 closure: 88 frozen files, `freeze.json`, and the trusted launcher
(90 files). The checker rejects missing/extra paths, symlinks, nonregular
files, and hash drift, then stages only into a new user-owned directory. It
does not create admissions or perform root installation. Eight staging tests,
10 launcher tests, and the 90-file CLI verification pass. Independent review
found and closed three issues: the freeze was initially omitted from the copy,
non-object manifest JSON raised an uncaught exception, and root refusal came
after parent creation. No root runtime or controller operation ran; S5/S6/S7
remain open.

## 2026-10-22 — focused terminal reconnect rerun

The previously recorded real TLS/Noise terminal lifecycle test now passes on
the current worktree (1/1):

```sh
cargo test --locked -p lomi-host --lib real_tls_noise_terminal_lifecycle_streams_and_reconnect_keep_one_pty_without_input_replay -- --nocapture
```

It exercises a fresh channel/ticket/relay handshake and confirms the input is
not replayed. This does not reconcile the failure for the prior
frozen source or qualify aggregate Host/E2, production client reconnect,
S5/S6/S7, or release. The build emitted three warnings in the multi-client
fixture.

## 2026-10-22 — current Host library and lint gates

The current default-feature Host library suite passes 534/534 tests. The prior
test-fixture warnings were removed; Clippy passes without warnings:

```sh
cargo clippy --locked -p lomi-host --all-targets -- -D warnings
```

These checks do not
qualify the supported-OS service matrix, full E1/E2, consumer S5/S6/S7, or
release. Historical failures for prior frozen source bytes remain unchanged.

## 2026-10-22 — current-source Ubuntu ARM64 host and user-service rerun

The current 1,335-file source inventory (`59344b752ad54d8f43cadc038ffbf2c3504e444fe95edcf8ae095a121509e64a`)
was frozen and copied into a private run directory in the disposable Ubuntu
24.04 ARM64 Lima guest (Linux 6.8.0-147, Rust 1.98.1). `lomiremote` built,
and the selected product suites passed 810 tests with zero failures and two
ignored cases. Independent SSH phases confirmed one runtime and PTY continued
after disconnect. The temporary `systemd --user` service passed 9 prepare and
23 verify checks, including stop/restart/crash/uninstall behavior; cleanup
confirmed removal of the unit, all fixture processes, and owned files.

Receipt: `artifacts/product-linux/7bce419a-23ed-4837-a811-1e16acae34c3/report.json`
(SHA-256 `ef3b54d3f6d942a590e86df610afa923a5de85d5579d5eac8467756c0f7f7efe`);
frozen source archive SHA-256 `d84117087305d445eaa97e0a82fbfb9afbce9177882e0e4aa7a494d529fd7128`,
test log SHA-256 `2f2aeb502f2366cfdf8b3a8e02b20aa6aa862aa28b9423b8d48222ab33db8f3c`.
This remains one Ubuntu ARM64 VM/current-account service fixture: it does not
test reboot, system-level service, pristine installation, Cloud/relay, other
Linux architectures/distributions, or full E1/E2.

### 2026-10-22 — Remote Web v2 pairing request surface

The signed-in Remote Web app now offers an explicit v2 pairing request for an
online host and workspace. It shows the exact terminal capabilities being
requested and requires acknowledgement. The request body and operation ID are
stored per tab; a lost response is recovered with that exact idempotent request,
then status polling uses the returned pairing ID. The two-minute deadline
survives reloads. Terminal outcomes can be replaced only by another explicit
request. Passive page load resumes only a request tied to the current account
session and existing tab identity.

Browser identity persistence is encrypted in IndexedDB and used inside a
module worker. Unmount closes a registration that finishes after cancellation;
logout clears local identity and pairing metadata. Browsers without Web Locks
fail closed to avoid duplicated-tab identity reuse. The UI reports approval
without claiming that a terminal connection was established.

The signed-in Remote Web app also has the opt-in v2 workspace data path:
after a fresh approval it opens a relay ticket/channel, completes Noise,
validates the channel and authority, reads workspace/terminal state, and starts
a shell only after an explicit user action. A mutation with an uncertain result
is queried by its operation ID and is never replayed. Reconnect fetches the
current pairing and inventory again, comparing the auth tuple, window key,
workspace epoch, runtime binding and host signature before opening a channel.

On 2026-10-22, pairing lifecycle fencing was tightened: a registration carries
the auth tuple verified by the worker; a tuple rollover closes the old local
registration and discards its request/restoration state; aborted or superseded
polls cannot write late responses; and inventory from a prior account cannot
overwrite the mounted account's state. The account comparison ignores UUID
hyphen formatting only.

Current validation: `bun test` passes 137/137 tests across 25 files with 685
assertions. `astro check` reports 0 errors, 0 warnings and 4 existing hints;
static build and output-integrity checks pass. Vite emits the existing large
chunk warning. Pure pairing-state tests cover the poll/tuple guards; the
browser fixture uses v1 and does not exercise the v2 component lifecycle.

This remains opt-in, not full E3: clean Ubuntu/Debian install, phone device-code
login and consent, a deployed relay/host shell run, network-loss behavior and
unshare during real host mutation have not passed together. Expired, unused
consumer-window challenges now have an owner-checked database pruner; cleanup
of stale registered consumer-window identities still needs its own lifecycle
and capacity proof. E1/E2 and E3–E7 remain open.

### 2026-10-22 — CloudWorker lost-ACK restart fixture: first attempt failed

The first attempt did not complete the expired-lease claim sequence and did not
prove final cursor reconciliation. It is superseded by the completed follow-up
recorded later in this progress log; the failed attempt remains historical
evidence only.

### 2026-10-22 — E3 VPS target preflight

The user-provided VPS was reached over SSH after its ED25519 fingerprint was
verified against the provider console. Read-only inventory found Ubuntu
24.04.5 x86_64, 27 GiB free on `/`, passwordless sudo for the test user, and no
installed Lomi systemd units. No product files or services were installed.
The installation guide explicitly labels its `lomi.dev/server/install.*`
URLs as proposed interface examples, and the repository has no release
installer/artifact to run. This verifies a suitable target is available; it
does not pass the clean-install, device-code, shell, restart, or E3 acceptance.

### 2026-10-22 — lokalny instalator testowy Linux

Dodano `tools/install_linux_local.py` dla jawnie wskazanego, lokalnie
zbudowanego binarium. Weryfikuje podany SHA-256, kopiuje i ponownie hashuje
staging, przechowuje obiekt pod ścieżką content-addressed i atomowo przełącza
symlink `~/.local/bin/lomiremote`. Odrzuca niezgodne platformy, cudze pliki,
obce symlinki i katalogi zapisywalne przez inne konta. Testy pokrywają mismatch,
przerwaną zmianę wskaźnika, zmianę źródła między hashowaniem a kopią oraz brak
skutków logowania i konfiguracji usługi. `python3 -m unittest
tests/tools/test_linux_local_installer.py -v`: 10/10 lokalnie i 10/10 na
Ubuntu 24.04 ARM64 VM; kontrola trailing whitespace jest czysta. Przebieg
Ubuntu ujawnił wpływ `umask 002`; tworzone katalogi zostały ograniczone do
trybu 0700 niezależnie od umasku. Tymczasowe pliki testowe usunięto, VM
zatrzymano.

To narzędzie lokalne nie pobiera ani nie weryfikuje podpisu wydania. Nie
konfiguruje usługi, loginu, Cloud ani sharingu; nic nie zainstalowano na VPS.
Nie zamyka odbioru czystej instalacji E3 ani E7.

### 2026-10-22 — macOS S5 trusted-launcher prototype hardening

The source-only trusted bootstrap no longer signals a saved PID after an
ambiguous or terminal `waitpid` result. It rejects inherited SIGCHLD auto-reap
and custom handlers before spawning, launches the pinned interpreter
suspended, checks the child code signature by PID, and resumes only after
validation. Cleanup retries SIGKILL on EINTR and performs a blocking reap only
after successful signaling. Independent security review found no remaining
stale-PID kill path. Its only conditional cleanup limitation is an unexpected
non-EINTR SIGKILL failure, where the child may remain stopped while admission
rejects.

Validation: `python3
tests/consumer-private-positive-controller/trusted_bootstrap.test.py` passes
17/17; `clang -Wall -Wextra -Werror -fsyntax-only` passes; independent review
closed the stale-PID finding. This is still an uninstalled test prototype. It
does not provide root-owned admission, production operator pins, installer
integration, or full Consumer S5 acceptance.
### 2026-10-22 — bieżące bramki pakietów hosta

Na bieżącym checkoutcie przeszły zestawy `lomi-host-auth` (64 testy),
`lomi-host-http` (60) i `lomi-host-store` (127) oraz Clippy dla wszystkich
targetów tych trzech pakietów z `-D warnings`. Wraz z wcześniej zapisanym
wynikiem 534/534 dla biblioteki `lomi-host` potwierdza to te zakresy kodu.
Nie zamyka to E1/E2, testów usług na docelowych systemach, ścieżek konsumenta
ani macierzy wydania.

### 2026-10-22 — E2 transport Cloud, ponowna próba serialna

Runner agregatowych zestawów runtime został zmieniony tak, aby uruchamiał
pliki i przypadki Bun kolejno wobec współdzielonej bazy testowej; składnia
Python przechodzi. Ponowny przebieg `transport` z symulacją utraty TCP ACK
zatrzymał się przed testami przy budowie fixture'a Rust: linker zwrócił kod
69, ponieważ lokalnie zainstalowany Xcode wymaga jeszcze zaakceptowania
licencji. Runner zamknął i usunął własną tymczasową bazę; raport ma
`shutdownAndCleanupCompleted=true` i `productionQualified=false`. Nie ma
nowego wyniku dla Cloud, revoke ani wielu klientów.

Raport: `../../../auth-app/artifacts/e2-transport-runtime-macos-serial-clt-20261022/c663831a-c137-49ef-9d44-8d45d561a64e/runtime-proof.json`
(SHA-256 `0a1a01f4a6d6da09c61942469864268dd26d859ffac29b22467d73c06c9d8332`).
Xcode 27.1 jest zainstalowany, ale kompilacja wymagająca linkera oraz build
iOS pozostają zablokowane do lokalnej akceptacji licencji; nie wykonano jej
automatycznie.

### 2026-10-22 — E5 Remote Web Explorer: focused regression

Niezmienione modele Explorera i transport v2 w Remote Web przechodzą
`bun test tests/explorer.test.ts tests/remote-v2-explorer-transport.test.ts`:
16/16 testów, 55 asercji. Zakres obejmuje watch/ACK i resync, odrzucenie
zdarzeń z innego workspace po utracie kanału, paginację, kontrolę rewizji
mutacji, konflikt i stan nieznanego wyniku. To test jednostkowy z transportem
fixture; nie potwierdza hosta, desktopu, telefonu ani odbioru E5/E6.

### 2026-10-22 — Consumer revoke zachowuje tożsamość okna

Test runtime konsumenta zapisuje teraz stan sfinalizowanej tożsamości okna
przed wyścigiem revoke/rejestracja i sprawdza po nim zachowanie identyfikatora
operacji, podpisanej tożsamości, fingerprintu oraz znacznika `revoked=false`.
Istniejące asercje nadal wymagają odmowy późniejszego użycia po revoke.

`run_host_credentials_runtime.py --suite consumer` na prywatnym PostgreSQL
18.6 przeszedł: 7 testów runtime/schema w 7 plikach, 962 testy łącznie w
16 plikach, walidację Prisma i TypeScript. Baza socket-only została zatrzymana
i posprzątana. Raport ma `productionQualified=false`; to ograniczony dowód
cyklu Consumer i retencji tożsamości, nie pełny odbiór S5/S6/S7.

Raport: `../../../auth-app/artifacts/consumer-window-revoke-retention-rerun-20261022/5326616f-dea4-4ed4-9530-4829fc798a6f/runtime-proof.json`
(SHA-256 `8c4cb574edca300788e4d355e384dbcf46e7efd77d6b865b04774dd35b5a637f`).

### 2026-10-22 — E5 host watch code audit

Przegląd źródeł potwierdził, że Linux używa inotify, macOS kqueue, a Windows
`ReadDirectoryChangesW`; natywne zdarzenia obejmują katalog oraz ograniczoną
liczbę bezpośrednich plików, aby wykrywać także zapis z niezmienionym mtime.
Pięciosekundowa rekonsyliacja pozostaje jako zabezpieczenie zmian przodka i
ograniczeń backendu. Jednosekundowy fallback dotyczy pozostałych targetów Unix,
poza zadeklarowaną macierzą wydania. Ten przegląd źródeł nie uruchamia testów i
nie kwalifikuje odbioru E5 ani integracji Explorera w klientach.

### 2026-10-22 — Consumer S5: test źródłowy prywatnego kontrolera

`python3 -I -S -B controller.test.py` w
`tests/consumer-private-positive-controller` przeszedł 17/17. Test używa
syntetycznych zależności i tymczasowych plików; audyt w samym teście blokuje
procesy, sieć i natywne pipe'y. Wynik sprawdza zachowanie prototypu i sprzątanie
po błędach. Nie uruchamia PostgreSQL ani SQL, nie tworzy root admission i nie
zmienia planu: `SOURCE_ONLY_NOT_RUN`, `nativeAdmission: NOT_GRANTED`,
`fullS5Qualified: false`.

### 2026-10-22 — Remote Web: pełny fixture przeglądarkowy w trzech silnikach

`pnpm test:browser` przeszedł na Node 22.23.3 z `DEVELOPER_DIR` ustawionym na
lokalne Command Line Tools. Po dodaniu selektora silnika ten sam fixture
przeszedł w Chromium, Firefox i WebKit: automatyczne workspace,
odświeżenie/reconnect, dwa terminale, preemption, revoke, zmianę scope, klik
poza menu, Escape/Tab, wylogowanie i brak replayu wpisanego tekstu; CSP nie
zgłosiło naruszeń. To
lokalny test istniejącego klienta/protokołu v1, nie odbiór Remote Web v2,
czystego VPS-a ani wdrożonego relay/hosta, więc nie zamyka E3/E6.
`pnpm test:browser-identity` przeszedł również w Chromium, Firefox i WebKit;
każdy silnik odzyskał lokalną tożsamość IndexedDB po odświeżeniu.

Test WebKit pokazał, że `blur` przy klikaniu w menu „Sign out” usuwał element
przed `click`. Usunięto ogólne zamykanie menu przy blur; klik poza menu oraz
Escape/Tab nadal je zamykają. Po przebudowaniu `dist` wszystkie trzy testy
pełnego fixture'a przeszły. `pnpm test`: 140/140; `pnpm build`: typy i statyczne
wyjście poprawne, 0 błędów i 4 wskazówki.

### 2026-10-22 — Remote Web v2 i odtwarzalność Rust/WASM

Usunięto nieaktualny komentarz opisujący `remoteV2Request` jako transport
„dormant”; aktywna ścieżka v2 jest montowana po otrzymaniu `relayV2Url` przez
konto. Nie dodano testu przeglądarkowego v2 do istniejącego fixture'a, ponieważ
ten implementuje tylko v1. Wiarygodny test v2 potrzebuje prawdziwej podpisanej
tożsamości hosta, proof rejestracji okna konsumenta, admission Noise i relay
v2; fałszywe odpowiedzi API albo mock crypto pominęłyby kontrole produktu.
Test przejścia pairing → workspace pozostaje otwarty w E3/E6.

`node scripts/sync-remote-web-packages.mjs --check` potwierdził snapshoty.
Generator Rust przeszedł `--check`, a `packages/remote-contracts` sprawdził
61 schematów i przeszedł 696/696 testów. Buildy oraz kontrole odtwarzalności
release WASM dla protokołu i authority crypto przeszły; zestawy tych pakietów
mają wyniki 365/365 i 40/40. Wygenerowane manifesty pochodzenia oraz główny
compatibility manifest zsynchronizowano po dodaniu źródeł HTTP; sprawdzone
binaria WASM pozostały identyczne. Główny manifest nadal oznacza kontrakty jako
`draft-e0` / `productTarget: v1`, więc nie jest dowodem odbioru E3/E6 ani E7.

### 2026-10-22 — Cloud TCP-drop: lokalny build przez Command Line Tools

Runner `auth-app/test/run_host_credentials_runtime.py` obsługuje teraz jawny
`DEVELOPER_DIR` przekazany przez operatora i zapisuje tę ścieżkę w raporcie.
Pozwala to uruchamiać narzędzia Rust przez wskazane Command Line Tools bez
globalnej zmiany aktywnego Xcode ani akceptacji licencji w automatyzacji.
`python3 -m py_compile` przeszedł, a odpowiedni test Rust `lomi-host` z
feature `cloud-fixture` skompilował się z
`DEVELOPER_DIR=/Library/Developer/CommandLineTools` (`--no-run`, 1m08s).

Pełny runner Cloud nie ruszył: dostępny Bun ma wersję 1.3.14, a fixture
wymaga dokładnie 1.4.2. Zatrzymał się przed inicjalizacją PostgreSQL; raport
potwierdza zero listenerów i zakończone sprzątanie. Nie wykonano zerwania TCP,
restartu CloudWorkera ani nowego odbioru Cloud. Nie znaleziono lokalnego
binarium Bun 1.4.2. Ten fixture pozostaje niekwalifikujący produkcji.

GitService nadal nie ma bezpiecznego wycinka do wdrożenia bez decyzji o
host-owned odkrywaniu repozytoriów, stabilnych ID i mapowaniu ścieżek na
EntryId/FileRevision. Obecna autoryzacja przed dispatch odrzuca wszystkie
metody Git, a blokady są per workspace; nie włączono ani nie reklamowano RPC.

### 2026-10-23 — Consumer challenge-pruner readiness guard

The auth readiness check now fails closed unless the exact
`lomi_prune_expired_consumer_window_challenges(uuid)` function exists, is owned
by the non-login `lomi_consumer_challenge_pruner` role, is `SECURITY DEFINER`,
uses only `search_path=pg_catalog`, and is executable by the current runtime
role. Its ACL must contain exactly one non-owner `EXECUTE` grant, to
`lomi_runtime`, without grant option; PUBLIC and other-role grants fail
readiness. The owner role must have no memberships, elevated role attributes,
or `CREATE` on `public`. The operator schema inspector shares the role
predicate; its schema checks remain intact. Independent review found two gaps:
the pure validator accepted any function name, and readiness did not detect
broad `EXECUTE` grants. Both are now checked fail-closed.

Validation: `bun test test/remote-db-inspect-config.test.ts` passed (12 passed,
1 skipped, 0 failed; 454 assertions; Bun 1.3.14), `bun run check` passed, and
`git diff --check` passed. The opt-in
`test/consumer-pruner-inspection-runtime.test.ts` also passed against a
disposable local PostgreSQL fixture (1 passed); production readiness and the
test share the same static SQL, and the fixture read the actual routine,
owner, and ACL in a read-only transaction. The same query and production
mapping also passed through PrismaPg against a disposable cluster. A separate
throwaway SQL check confirmed PUBLIC and other-role grants are exposed for
rejection. No private PostgreSQL URL is present, and the full Consumer runner
requires Bun 1.4.2, so full S5–S7 qualification remains open. Full Xcode 27.1
is installed, but device tooling reports that the Apple license has not been
accepted; no license agreement or setting was changed and no mobile device run
is claimed.

### 2026-10-23 — Windows host read-only inventory

SSH access as both the administrative account and ordinary test account works.
The host reports Windows NT 10.0.19044.0 on 64-bit; a read-only service-name
query found no installed Lomi service. No service was installed and no lifecycle
test was performed. Windows 10 is outside the declared Windows 11 / Server
release matrix, so Windows service acceptance remains open.

### 2026-10-23 — CloudWorker lost ACK and restart: ordered acceptance

The restart harness now requires the exact lifecycle-stage sequence in both
child processes, including uniqueness and order. It no longer accepts a run
where the right markers merely appear somewhere in the output.

The pinned runtime runner passed with Bun 1.4.2, PostgreSQL 18.6, Rust 1.98.1,
the actual Better Auth handler and the real Rust CloudWorker. The fixture
committed publication sequence 8, dropped its TCP acknowledgement, retained
the durable intent across owner-process exit, reconciled after lease expiry,
then published sequence 1 in the new generation. It observed exactly nine
restart requests, the expected route order, no repeated publication PUT, and
an unchanged local store at the process handoff. The private PostgreSQL
cluster stopped and cleanup completed. This supersedes the earlier attempt
that stopped before PostgreSQL because the machine's default Bun was 1.3.14.

Evidence: [runtime proof](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/runtime-proof.json), [runtime log](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/runtime-proof.log), and [frozen inputs](../../../auth-app/artifacts/cloud-worker-restart-cursor-acceptance-20261023/f650369c-2009-4101-bce9-2cd41db157ec/frozen-inputs.tar.gz).

This is a bounded actual-handler/TLS fixture result, not proof of the
deployed Cloud relay, cross-host fan-out, Consumer S5–S7, or complete E2.

### 2026-10-23 — Consumer challenge-pruner runtime metadata

The full Consumer suite exposed that PostgreSQL's
`pg_get_function_identity_arguments` includes a declared parameter name.
Readiness now derives the canonical argument-type signature from
`oidvectortypes(p.proargtypes)`, matching the UUID identity used by
`to_regprocedure` while retaining the exact routine, owner, SECURITY DEFINER,
search-path and ACL checks.

Validation: the pinned `consumer` runner passed on PostgreSQL 18.6 with the
actual migrations, limited runtime roles and production grant scripts. Its
database runtime passed 7/7 tests, including the real challenge-pruner
metadata/ACL check; the non-database regression set passed 962 tests with one
existing skip, and Prisma validation and TypeScript typecheck passed. The
private cluster stopped and cleanup completed. This closes the readiness
metadata mismatch; it does not by itself complete Consumer S5–S7.

Evidence: [runtime proof](../../../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/runtime-proof.json), [runtime log](../../../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/runtime-proof.log), and [frozen inputs](../../../auth-app/artifacts/consumer-s5-s7-acceptance-20261023/e986852b-584b-478b-9ae3-fe79bc230320/frozen-inputs.tar.gz).

### 2026-10-23 — Consumer source-session logout cascade

The Consumer runtime suite now exercises Better Auth sign-out through the real
`/api/auth/sign-out` route after creating one finalized browser window and one
pending challenge. It verifies that deleting that source session cascades its
consumer authority, challenge rows, and finalized window, while a sibling
session and its authority on the same account remain live.

Validation: the pinned Consumer runner passed on Bun 1.4.2 and PostgreSQL
18.6. The database/runtime suite passed 7/7 tests; the non-database regression
suite passed 962 tests with one existing skip; Prisma validation and Auth
typecheck passed. The private cluster stopped and cleanup completed. This
closes the source-session sign-out cascade proof; per-window lifecycle and
broader Consumer S5–S7 acceptance remain open.

Evidence: [runtime proof](../../../auth-app/artifacts/consumer-logout-cascade-20261023/46085414-1d88-464c-aebb-4e75513f05eb/runtime-proof.json), [runtime log](../../../auth-app/artifacts/consumer-logout-cascade-20261023/46085414-1d88-464c-aebb-4e75513f05eb/runtime-proof.log), and [frozen inputs](../../../auth-app/artifacts/consumer-logout-cascade-20261023/46085414-1d88-464c-aebb-4e75513f05eb/frozen-inputs.tar.gz).

### 2026-10-23 — Remote Web selects v2 data plane when enabled

When the authenticated account response advertises the checked v2 relay URL,
Remote Web no longer starts its legacy v1 live worker in parallel. The v2
pairing surface remains explicit; no terminal is created before approval and a
separate user action. Account-session bootstrap and sign-out still use the v1
HTTP control-plane routes, so this is a data-plane migration step rather than a
complete protocol cutover.

Validation on Node 22.23.3: the browser bootstrap suite passed, including
cookie-only v2 inventory and a zero-live-worker assertion for v2 accounts;
`bun test tests` passed 140/140 tests (697 assertions); `pnpm check` reported
45 files, 0 errors, 0 warnings and 4 existing hints. `pnpm build` generated
static routes and passed output-integrity checks. Vite still reports the
existing minified chunk above 500 kB. `git diff --check` passed.

This uses mocked HTTP and does not exercise a live relay, device-code login,
browser shell, restart/reconnect, or no-replay acceptance. E3/E6 remain open.

### 2026-10-23 — CloudWorker recovers after an actual TLS/TCP ACK loss

With Command Line Tools selected for the local C compiler, the pinned Cloud
acceptance runner completed against a private PostgreSQL 18.6 cluster. The real
Better Auth handler committed publication sequence 7 and the loopback TLS
server destroyed the TCP socket before returning the ACK. The Rust CloudWorker
retained the uncertain intent, did not advance its acknowledged cursor, read
the committed state back, and issued no duplicate publication. A separate
worker restart fixture preserved its store and reconciled without repeating the
PUT. The same run verified central revoke against two live clients: both
connections closed, the shared owner was fenced, runtime GET returned 401, and
the stored runtime did not mutate.

The runner passed its Cloud handler, legacy regression, Prisma, typecheck and
cleanup checks. Its complete evidence is
[runtime-proof.json](../../../auth-app/artifacts/cloud-worker-restart-pg18-tcp-drop-clt-20261023/e82ef717-6afa-4550-b3f6-9875d2910405/runtime-proof.json).
This is a private handler/TLS fixture, not a deployed Cloud or relay fan-out
acceptance. Heartbeat/publication/revoke with reconnect across the deployed
relay, host OS service qualification, and production cutover remain open.

### 2026-10-23 — Remote Web v2 fences terminal input across page lifecycle

Remote Web now disables terminal control on `visibilitychange` and `pagehide`,
aborts a pending terminal open, closes its old channel, and resumes only after
the page is visible again. Resume attaches to the existing session, waits for a
fresh snapshot and a current-channel control claim, and does not create a shell
or replay buffered input. A page-hide transition also closes an exited
terminal's leftover channel. Late claim responses can change UI state only if
their channel and claim-fence ticket are still current.

Validation on Node 22.23.3: `bun test tests` passed 144 tests (711 assertions);
`pnpm build` passed Astro checks and static-output integrity (0 errors, 0
warnings, 4 existing hints); `pnpm test:browser-identity` passed in Chromium,
Firefox and WebKit for IndexedDB identity restoration and page-lifecycle input
fencing. The remote protocol browser acceptance suite also passed its current
mocked-host checks. Vite still reports the existing minified chunk above 500
kB. These checks do not exercise a live v2 relay, real device backgrounding,
or the complete E3 browser-shell acceptance.

### 2026-10-23 — Initial native transport rebind attempt (superseded)

The first rebind run stopped before native transport proof. Its source-map and
copy guards passed, but the pinned helper had been built without its required
`test-fixtures` feature, so it exited without answering the first `init`
command. That build and run are retained as historical evidence:
[runtime proof](../../../auth-app/artifacts/channel-transport-native-runtime-rebind-20261023/e73f8e98-332c-4fe5-85af-ec505c9aa7b4/runtime-proof.json).

### 2026-10-23 — Current-tree native Noise transport over the real loopback relay

The current 713-path source map and its before/copy/after guards were retained.
The helper build receipt is now pinned alongside the helper binary. All 725
mapped and explicit native inputs pass before/copy/after hash audits; the prior
map and receipts remain unchanged. The focused actual-handler transport test passed on Bun 1.4.2 and
PostgreSQL 18.6: one end-to-end test, 615 assertions, 212 native-helper
commands, and all 15 native acceptance markers. It exercised native identity
and enrollment proofs, canonical grant/context equality, two real loopback
WebSocket peers, three Noise messages, bidirectional encrypted traffic,
authority fencing, expiry/late-finish rejection, and slot disposal. The helper
closed cleanly; all mapped and copied inputs matched after the run; the private
database stopped.

The fixture's Remote v2 config now supplies the required relay v2 URL. This is
a local current-tree SQL/loopback-`ws` proof; it does not qualify deployed
Cloud, WSS/TLS, production host data workers, cross-platform services, the
separate 264-channel load run, or E6.

Evidence: [runtime proof](../../../auth-app/artifacts/channel-transport-native-runtime-final-20261023/0d935716-d062-4bcb-9781-af6be30fa03f/runtime-proof.json), [runtime log](../../../auth-app/artifacts/channel-transport-native-runtime-final-20261023/0d935716-d062-4bcb-9781-af6be30fa03f/runtime-proof.log), [current source map](../../artifacts/channel-transport-native-current-source/e05da707-bc55-4c77-ba56-352fe2dfc02d/original-hash-guards.json), and [feature-enabled helper build receipt](../../artifacts/channel-transport-native-current-source/transport-authority-feature-enabled-20261023/build-receipt.json).

### 2026-10-23 — Serial 264-channel native Noise load

After two load fixtures were accidentally started concurrently and competed
for machine resources, the exact pinned input set was rerun serially with Bun
1.4.2 and PostgreSQL 18.6. Both 264-channel scenarios passed with
real Noise traffic and AEAD: 792 messages, 528 finishes and 528 initial
encrypted directions per scenario. The host-revoke case closed 512 peers;
the global-lock-stall case observed a blocked owner renewal and fenced 132
queued freshness channels. Both helper pairs and listeners closed, all 725
native inputs passed before/copy/after audit, and the private database stopped.

This is local native/SQL fixture evidence, not deployed Cloud/WSS, host OS
matrix, real consumer reconnect or production qualification. The runner keeps
`productionQualified=false` for this bounded load-only scope.

Evidence: [runtime proof](../../../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/runtime-proof.json), [runtime log](../../../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/runtime-proof.log), [host-revoke markers](../../../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/native-load-host-revoke-markers.json), and [global-lock markers](../../../auth-app/artifacts/channel-transport-native-load-serial-bun142-20261023/5542b9b6-7aae-4e86-aebb-66276776e933/native-load-global-lock-stall-markers.json).

### 2026-10-23 — Mobile Explorer architecture audit

The mobile client currently uses its v1 terminal/metadata channel. It has no
generic Remote v2 RPC channel, approved workspace authority context, files
watch transport, or Explorer screen. Host v2 `files.*` methods already exist,
but a screen cannot safely invoke them until mobile can open the same scoped,
approved v2 workspace channel. The smallest safe sequence is that channel,
then bounded read-only list/navigation/text preview, then watch and mutations
with their own lifecycle and uncertain-outcome handling. No mobile source was
changed; E5/E6 mobile acceptance remains open.

### 2026-10-23 — Desktop publisher filters AI terminals

The desktop remote-workspace projection now excludes staged Lomi agent
terminals, agent-controlled panes, and panes identified as supported AI CLI
terminals. Mixed split layouts are pruned; AI-only tabs are omitted. The same
classification gates shell startup and shared-terminal capacity accounting.
Context polling applies all control and CLI classifications before emitting a
single lifecycle notification, so a publisher cannot observe a partially
updated sample.

Validation on Node 22.23.3: full `pnpm test` passed 308 desktop tests and 45
AI-runtime tests; `pnpm check` passed; `pnpm build` passed. The build retains
the existing 1,089.88 kB Workbench chunk and dynamic-import warnings. The
focused workspace suite passed 9/9 on Node 22.14.0, the terminal-context
Playwright test passed 1/1, and Prettier checks passed. Externally launched CLI
detection and agent-control classification still depend on the existing
one-second `terminal_contexts` poll. This change does not remove that
recognition window or qualify E4 desktop A/B integration and privacy
acceptance.

### 2026-10-23 — files.watch replacement closes the prior subscription

A `files.watch` request now drops the connection's existing subscription
before attempting to open its replacement. If the new request is rejected, the
old watch cannot continue emitting invalidations after the error response.
Successful replacement still installs exactly one watch on that connection.

Validation: Rust format check passed; on macOS, `lomi-host` watch unit tests
passed 12/12 and the real TLS/Noise watch acknowledgement/resume ingress test
passed 1/1. On the Ubuntu 24.04 VPS, `lomi-files` Linux/inotify tests passed
26/26. The same watch replacement change was applied to its temporary test
checkout; Linux `lomi-host` watch tests passed 16/16 and its real TLS/Noise
watch ingress test passed 1/1. The VPS has no installed product host, and this
does not qualify E3 installation. This fixes the single-slot replacement
lifecycle only; it does not complete recursive watch coverage, release
qualification, or Explorer integration across clients.

### 2026-10-23 — nested `files.watch` same-mtime regression

Added a host-level regression test that opens `files.watch` on a listed nested
directory, edits a child without changing its size, restores its original mtime,
and requires an invalidation. This covers a path that was previously tested at
the file backend level on Windows and at the remote watch level only for the
workspace root.

Validation: Rust format check passed; the entire macOS `remote_files_watch`
module passed 13/13, including the focused nested test. Windows target
execution remains open; this test adds coverage and does not claim that watch
qualification or Explorer integration is complete.

On a fresh Ubuntu 24.04.5 ARM64 VM, the focused nested test passed 1/1, the full
`remote_files_watch` module passed 17/17, and the real TLS/Noise watch ingress
test passed 1/1. Logs, environment details, and the source snapshot digest are
in `artifacts/linux-files-watch/2026-10-23/ubuntu-24.04.5-arm64/`. This is
local component evidence; it does not qualify the installed product, a VPS
lifecycle, or Explorer integration across clients.

### 2026-10-23 — Linux TUF-verified local activation primitive

Added `TrustStore::update_and_activate` and an `activate` CLI command. The
activation path accepts only bytes returned by the existing TUF verifier,
stages them as a SHA-256-named read-only object, and atomically replaces a
relative `active` symlink. Directory components reject symlinks, untrusted
owners, and writable non-sticky ancestors. Trust metadata is durably committed
before activation; if the pointer swap fails, the old target remains active
and retrying the same verified metadata is supported.

An independent security review found no remaining path-replacement blocker for
the stated other-UID threat model; same-UID and root interference are outside
that boundary. Rust format check and macOS all-targets `cargo check` passed.
The durable suite passed 10/10 on macOS. On a local Ubuntu 24.04.5 ARM64 VM,
the Linux-enabled durable suite passed 13/13, including all three activation
tests. The test fixture now creates its temporary trust root with mode 0700,
matching the runtime's private-directory contract. A Linux x86_64 cross-check
still stops before this crate because `x86_64-linux-gnu-gcc` is not installed.
Service startup, installer integration, signing pipeline, and release
qualification remain open. This is a local activation primitive, not a
production installer.

### 2026-10-23 — Cloud lost-ACK restart fencing fixture

Extended the isolated Auth-handler/Rust-DataTransport runtime fixture with two
restart outcomes. If the predecessor runtime still has a live lease, the new
runtime fences and invalidates the old binding and pending intent, preserves
the exact outbox, does not ACK the predecessor cursor, and sends no second
publication. After the lease expires, the existing path admits a fresh claim,
reconciles by GET, and publishes under the new runtime generation. Production
Cloud behavior was not changed.

The final private PostgreSQL 18.6 / Bun 1.4.2 runner exited 0: 7 runtime tests
passed, `auth-app-typecheck` passed, all six explicit valid-lease markers
matched, and all 47 Rust DataTransport requests matched the fixture's expected
counts and routes. The relay and Auth server were loopback/private fixtures;
this does not qualify a deployed Cloud relay, production multi-client fan-out,
or E1/E2 as a whole. Evidence: [runtime proof](../../../auth-app/artifacts/cloud-worker-predecessor-valid-lease-fencing-final/7872194c-436d-4a58-b652-c30446b7984a/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/cloud-worker-predecessor-valid-lease-fencing-final/7872194c-436d-4a58-b652-c30446b7984a/runtime-proof.log).

### 2026-10-23 — Remote Web local browser matrix

The Remote Web unit suite passed 144/144. Astro check under Node 22.23.3
reported 0 errors, 0 warnings, and 4 hints. The persistent IndexedDB identity
and page-lifecycle input fence passed in Chromium, Firefox, and WebKit. The
full local terminal browser fixture also passed in all three engines, covering
refresh/reconnect, one-shot input, control, concurrent panes, metadata privacy,
revocation/race handling, and CSP. The static production build and output
integrity check passed; Vite still reports a JavaScript chunk over 500 kB.

This remains browser fixture evidence only: no deployed relay/host, GitService,
physical mobile device, or full v1 method matrix was exercised. It does not
complete E6 or production release qualification. Detailed record:
`../../../remote-web/docs/implementation/browser-matrix-2026-10-23.md`.

### 2026-10-23 — Consumer runner executes the Remote Web bridge suite

Added `remote-web-consumer-bridge` to the pinned Auth runtime runner's unit
suite, so the source-integrity snapshot and test execution now cover the same
bridge file. Also preserved Auth's `409 OUTCOME_UNKNOWN` through the Remote Web
BFF instead of converting it to `503 effect: none`. The focused Bun suite
passed 11/11. The full Consumer runner passed against its private PostgreSQL
18.6 cluster: the real Consumer authority runtime passed, the legacy suite
passed 973 tests with one existing skip, Prisma validation and Auth typecheck
passed, and cleanup completed.

Evidence: [runtime proof](../../../auth-app/artifacts/consumer-bridge-uncertain-20261023/2e88df5a-be21-4c54-891a-6b5c26a6560a/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/consumer-bridge-uncertain-20261023/2e88df5a-be21-4c54-891a-6b5c26a6560a/runtime-proof.log).
The proof is local fixture evidence (`productionQualified: false`); Cloud relay,
production deployment, cross-host lifecycle, and Consumer S5–S7 acceptance
remain open.

### 2026-10-23 — S5 trusted-entrypoint source review

An independent read-only review of `trusted_bootstrap.c` and
`trusted_launcher.py` confirms the earlier controller-entrypoint TOCTOU is
closed at source level, conditional on a trusted installation. The native
bootstrap checks the root-owned admission, freeze, controller and launcher
before starting Python, binds their digests, then executes the already-open
launcher descriptor. The launcher rechecks and executes the same in-memory
controller bytes. The controller's own ownership checks happen later, but its
entrypoint bytes are already bound to the admission.

The source-only suites passed: launcher 10/10, controller 17/17 and disposal
15/15. `trusted_bootstrap.test.py` could not compile its test binary because
Apple Clang exited 69 while the Xcode license is pending; no license or global
Xcode setting was changed. The bootstrap is still not installed under
`/Library`, its own binary provenance depends on an unverified installation
boundary, the current Python framework fails strict signature validation, and
no root admission, controller, PostgreSQL or SQL was run. Therefore this closes
only the source-level finding; S5 and E1/E2 remain unqualified.

### 2026-10-23 — Consumer per-window revoke runtime

Added an authenticated per-window revoke through Auth and the signed Remote
Web private exchange. The handler holds the global authorization lock, requires
live account-management authority, scopes the target to that account, and only
sets the existing irreversible `revoked` flag. The focused PostgreSQL runtime
test passed same-account revoke, cross-account denial, idempotence, immutable
identity retention, and sibling-window isolation. The bounded Consumer runner
passed all 8 database runtime tests and 974 legacy regression tests; Prisma
validation, Auth typecheck, and private-cluster cleanup passed.

This is local current-source fixture evidence, not deployed Cloud or full
Consumer S5–S7 acceptance. At this checkpoint the Remote Web route was covered
by bridge and transport tests but had no user-facing revoke action; that
integration remains open. Evidence: [runtime proof](../../../auth-app/artifacts/consumer-window-revoke-runtime-20261023/dc9f6e2b-34e0-4ce2-abdc-b22dcc8bfa43/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/consumer-window-revoke-runtime-20261023/dc9f6e2b-34e0-4ce2-abdc-b22dcc8bfa43/runtime-proof.log).

### 2026-10-23 — Remote Web current-window revoke interaction

The Remote v2 panel now offers an inline-confirmed revoke action for the
registered browser window. It disconnects the matching workspace before the
bodyless revoke request, closes the worker session and deletes only that
account/window's local identity after a validated server acknowledgement. A
failed or uncertain response keeps the same registration and encrypted key so
the user can continue or retry the idempotent revoke. If server confirmation
arrives but local cleanup fails, retry closes/cleans locally without sending a
second revoke request. Pairing and refresh controls are disabled while the
request is in flight.

An independent read-only review found no remaining issue in the revoke/retry
flow. The full Remote Web unit suite passed 149 tests; Astro reported 0 errors
and 0 warnings (4 existing hints); the static production build and output
integrity check passed. Vite still reports a JavaScript chunk over 500 kB.
This is local browser-client evidence; it does not qualify live Cloud/relay,
Consumer S5–S7, physical mobile, or E6/E7.

### 2026-10-23 — Inventory commitment contract and full local transport rerun

The inventory boundary now validates the persisted signed host commitment in
its actual descriptor-plus-signature shape, including byte widths and binding
the descriptor host ID to the inventory host ID. The typed Rust protocol,
canonical contracts, WASM codec, compatibility manifest, and Remote Web
snapshots were regenerated. The restricted inventory database role now has
the two read grants required for those persisted commitment columns.

The full current-source transport runner passed on a private, socket-only
PostgreSQL 18.6 fixture: all 21 database/runtime tests passed (4,151
assertions), the legacy suite passed 1,256 tests with one existing skip,
Prisma validation passed, and Auth typecheck passed. Actual handler fixtures
covered inventory, pairing, channel lifecycle and v2 transport; the Rust
CloudWorker fixture covered publication/permission refresh, injected lost-ACK
uncertainty with GET reconciliation and no repeated PUT, and restart recovery.
The runner stopped the private database and loopback listeners. Evidence:
[runtime proof](../../../auth-app/artifacts/transport-inventory-channel-fix-20261023/5e5b82dd-5557-49d2-adae-1344de21ee30/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/transport-inventory-channel-fix-20261023/5e5b82dd-5557-49d2-adae-1344de21ee30/runtime-proof.log).

This is local fixture evidence only (`productionQualified: false`): it does
not qualify a deployed Cloud relay, release-target service lifecycle, clean
VPS install, or E1/E2 as a whole. The channel failure found during diagnosis
was a test attempting to reverse an intentionally irreversible window revoke;
the test now preserves the database's one-way revoke rule.

### 2026-10-23 — VPS target read-only inspection

SSH access to the supplied VPS was recovered using the credentials the user
provided. Read-only inspection reports Ubuntu 24.04.5 LTS x86_64, with no
`lomiremote` executable or running Lomi service. The account home contains a
manifest from earlier test work, so this is not a pristine filesystem. No
installation or service changes were made. E3 still lacks a production
installer, deployed relay and full login-code-to-shell acceptance.

### 2026-10-23 — Remote Git confinement and snapshot review

Read-only review compared the host `FilesTarget`/`FileRoot` API, the Git WASI
experiment and the existing desktop Git reader. Remote host RPC still has no
Git executor. `FileRoot` safely pins individual operations, but paginated
directory walks and per-file reads do not produce an atomic repository
snapshot; a second scan can detect ordinary races but cannot prove a coherent
HEAD/index/worktree state. The desktop reader's strict helper/network/write
isolation is macOS-specific and depends on Tauri approval paths, so it cannot
be wired directly into host RPC. No Git methods were enabled. A production
slice needs a repository-scoped host lock, an OS-qualified runner or snapshot
boundary, stable preconditions, revocation checks and bounded result mapping.

### 2026-10-23 — Consumer PostgreSQL guardian cancellation probes

Corrected the native-probe controller's admission and evidence checks after an
independent source review found that incomplete child evidence could still
produce a pass. The controller now requires exact admission types and values,
stable log identities before and after reads, and the precise expected
collision evidence for case C. Current source and pins were reviewed with no
blocking regression.

The root-admitted macOS run passed all four bounded cases: cancellation before
startup, cancellation during foreground PostgreSQL cleanup, the expected
single log-name collision fallback, and logical deadline expiry. All 11 child
processes were reaped and quiet; PostgreSQL PID files and socket directories
were absent/empty. The independent result review checked all 25 proof hashes,
the 49 pinned runtime tools, admission/source hashes, case evidence, and
cleanup with no discrepancy. Evidence:
[root receipt](../../artifacts/consumer-pg-guardian-native-root-result/0a6bcb07-46d2-41b6-a78e-6ff21230bca8/receipt.json).

This only accepts the macOS guardian cancellation harness. It does not execute
product SQL or qualify Consumer S5; Windows, deployed Cloud/relay, and release
qualification remain open. The deadline case injects a 901-second logical
offset rather than waiting 901 seconds, and this run did not exercise the raw
log hardcap or its alternate SIGXFSZ termination branch. The historical
guardian record's `nativeProbesExecuted: false` remains accurate for that
older source freeze.

### 2026-10-23 — Ubuntu 24.04 current-source host tests

Copied a source-only archive to a dedicated temporary directory on the
Ubuntu 24.04.5 x86_64 VPS and verified its SHA-256 before extraction. With
Rust 1.98.1, `cargo test --locked -p lomi-host --lib` passed 545/545 tests.
The supporting packages `lomi-host-auth`, `lomi-host-http`, `lomi-host-store`,
`lomi-remote-protocol`, `lomi-platform`, and `lomiremote` passed 442 tests
across 41 test binaries; two existing tests were ignored. Both raw logs were
downloaded and matched their recorded hashes. The host suite includes real
TLS/Noise, two-client, terminal reconnect/no-input-replay, Explorer watch and
unshare checks.

The VPS already contains artifacts from earlier work and is not a clean host.
No service was installed or started, so clean-install, boot, logon and
systemd-service lifecycle gates remain open. The host suite also explicitly
confirms Git RPCs are still fail-closed as unsupported. Evidence:
[test summary](../../artifacts/ubuntu24-current-source-rust/2026-10-23/e1e2-ubuntu24-rust-34f18bb2-ff79-42ca-bfa3-654fc5c1d867/summary.json)
and the captured logs in that directory.

### 2026-10-23 — Ubuntu corrected-source full package rerun

Fixed the Linux `CStr` construction and direct inotify return that strict
Clippy flagged, and applied the pinned stable rustfmt output to the protocol
DTO and identity test. An independent source review found no concrete issues.
On the corrected source archive, all seven host/support packages passed
987 tests across 43 test-result blocks, with zero failures and two ignored
tests. The run used `CARGO_INCREMENTAL=0` and
`CARGO_PROFILE_TEST_DEBUG=0`; the earlier disk-full link attempt was
superseded. Workspace format and strict all-target Clippy also passed.

The VPS is still not pristine, and the `lomiremote` service was inactive
before and after the run. No install, boot, service recovery, Cloud/relay
cycle, or Consumer S5–S7 acceptance was performed. This remains bounded
source-test evidence, not production qualification. The temporary test tree
was removed and VPS free space returned to 9.2 GB. Evidence and hashes:
[corrected-source summary](../../artifacts/ubuntu24-current-source-rust/2026-10-23/e1e2-ubuntu24-fixed-622bd149-c121-45c9-ac80-b4a9bd538e4d/summary.json).

The direct `cloud-fixture` package invocation was also attempted on that VPS,
but all six selected CloudWorker tests are intentionally ignored unless the
private auth-app TLS handler and fixture token are supplied. It executed zero
tests and adds no Cloud acceptance. Its log and receipt are retained in the
same artifact directory; the dedicated local handler-runner result above is
separate evidence.

### 2026-10-23 — macOS host tests and portable PTY fixture

On the arm64 developer Mac, `lomi-files` passed 23/23 and the complete
`lomi-host --lib` suite passed 541/541; strict all-target Clippy and workspace
format checks passed. The first host run exposed an environmental test problem:
`/usr/bin/python3` displayed the pending Xcode license inside the controlled
PTY instead of running the test program. Replaced that fixture with `/bin/sh`,
`stty`, and `printf`; the full host suite then passed on macOS and passed 545/545
again on the Ubuntu VPS with the same source. Evidence:
[macOS summary](../../artifacts/macos-current-source-rust/2026-10-23/mac-files-4f12c8ad-0fc9-45f2-8874-ec311df9385f/summary.json)
and [Ubuntu rerun](../../artifacts/ubuntu24-current-source-rust/2026-10-23/e1e2-ubuntu24-pty-test-fix-f44d0e83-f633-4998-bae8-7beccff7e83b/summary.json).

These are source-test results on macOS 27 and a non-pristine Ubuntu VPS. The
Xcode license remains unaccepted; no LaunchDaemon, FileVault, Keychain, clean
boot, or production service lifecycle was qualified.

### 2026-10-23 — Remote Web preview race and mobile source checks

Fenced Explorer file previews by request generation, current directory
generation, and workspace context. Closing a preview, navigating, disposing
the Explorer, or opening a newer preview now prevents an older `files.read`
response from publishing stale content. The regression cases cover close,
navigation, overlapping previews, disposal, and previewing a recursive search
result. The complete Remote Web suite passed 154 tests across 28 files; the
static Astro production build and output-integrity check passed. Astro reported
four existing hints and Vite reported a JavaScript chunk above 500 kB. The full
local browser scenario also passed in Chromium, Firefox, and WebKit; each run
reported four accepted inputs, zero rejected input frames, and no CSP violations.

On Node 22.23.3, the mobile `pnpm check` passed lint, both TypeScript checks,
289 tests, renderer provenance/CSP, crypto provenance, and configuration
policy. Its final release check stopped because full Xcode is installed but its
Apple license is not accepted (`xcodebuild` exit 69); no license was accepted.
Current USB discovery reports no Android device and no iPhone. Native mobile
builds and physical-device E6 acceptance therefore remain open. These are
local source checks only and do not qualify deployed Cloud/relay, Consumer
S5–S7, or production release.

### 2026-10-23 — Consumer abort fence and runtime snapshot consistency

Consumer authority endpoints now check request cancellation after entering the
global authorization transaction and before effectful SQL. An aborted request
queued behind the advisory lock rolls back with the canonical retryable 503
(`effect: none`); challenge pruning, insertion, revoke, issue, and window
registration writes are fenced before they begin. The regression holds the
real PostgreSQL advisory lock, confirms the lomi_runtime backend is queued,
aborts the request, releases the lock, and verifies both the response and an
unchanged challenge count. Disabled Consumer authority still returns 404
before cancellation is considered.

The Cloud runtime snapshot parser now rejects inconsistent database output when
`freshnessRemainingMs` exceeds `leaseRemainingMs`, even if each value is within
its independent bound. This is defense in depth for the SQL contract; it is not
a finding against the current migration.

The pinned Bun 1.4.2 / PostgreSQL 18.6 Consumer runner passed: 8 database tests
and 1,296 assertions, 977 legacy regressions and 7,968 assertions, Prisma
validation, TypeScript, and owned-cluster cleanup. The runtime boundary suite
passed 106/106 tests. Evidence is in
`../../auth-app/artifacts/consumer-abort-fence-20261023/e2e359c2-1d68-4ec8-b78b-3b342245418b/`.
A first rerun with the machine's default Bun 1.3.14 stopped at version preflight
before initializing PostgreSQL; it is not a product test failure. These local
fixtures still do not qualify deployed Cloud/relay, cross-host fan-out, full
Consumer S5–S7, or production release.

### 2026-10-23 — CloudWorker restart proof in the transport diagnostic

The dedicated Auth transport diagnostic now runs the existing real-handler
CloudWorker restart fixture alongside the active-relay unshare test. Its private
HTTPS callback awaits the actual PostgreSQL-backed publication handler, then
drops only the successful PUT response. A second Rust worker process opens the
same durable HostStore and reconciles through GET; the fixture verifies the
committed cursor, store handoff, route order, and no replay of the old
generation's publication. The live-lease restart case also verifies GET with
no second PUT while preserving the outbox under fail-closed fencing.

Pinned Bun 1.4.2 / PostgreSQL 18.6 transport diagnostic passed with 1,150
assertions. Cleanup completed and PostgreSQL TCP listener count was zero. This
is diagnostic-only local TLS/PostgreSQL evidence; it does not qualify deployed
Cloud, relay fan-out, or production operation. Evidence:
[runtime proof](../../../auth-app/artifacts/cloud-unshare-relay-worker-restart-20261023/db7fa4f1-2639-4447-9163-434042f928d0/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/cloud-unshare-relay-worker-restart-20261023/db7fa4f1-2639-4447-9163-434042f928d0/runtime-proof.log).

### 2026-10-23 — Remote Web v2 vertical handshake rerun

The isolated end-to-end consumer-window v2 channel harness passed on Bun
1.4.2: 1 test, 3 assertions, zero failures. This covers the harness's
pairing/grant/admission/ticket/relay/Noise/transport success path. It remains
source-fixture evidence; it does not establish a deployed relay, a clean VPS,
physical-device acceptance, browser method parity, or E3/E6 release gates.

### 2026-10-23 — Consumer S5 source drift recovery and admission hardening

The current generated candidate had changed four files relative to the
accepted S4 input lock. It rewrote the file labeled `old-source` to add
`signedHostKey` and `initialCommitment`, so refreshing hashes would have
broken the S4 baseline and made the operator's replacement disagree with the
captured reference. The unadmitted four-file state was preserved under
`artifacts/consumer-derivatives-v2-unadmitted-source-drift/a8200e6c-82c9-45ac-9b62-3a88b26d512a/`;
the exact S4-reviewed candidate inputs were restored and all 19 staged hashes
matched the frozen lock.

Hardened the source-only S5 constructor to require each predecessor snapshot
and operator root literal to match the accepted S4 transition manifest, then
record those correlations in the derived fixture manifest. It also cross-checks
the predecessor hashes and migration paths against the catalog contract. Added
mutation tests for changed baseline source, changed operator literal, and
broken manifest/contract links. The fresh constructor completed at
`artifacts/consumer-derivatives-v2-sealing-derived/97e6d7a4-69d0-4ea0-8916-9f299bc1e1ad/`;
`sealing.test.py` passed 22/22. No SQL or PostgreSQL ran. This is source
admission evidence only; S5 runtime remains NOT_RUN pending independent review
of the fresh owned outer controller and a separate runtime gate. The legacy
staging validator was also run after restoration and fails its first check
because it compares the frozen old-source snapshot with the mutable current
migration. That validator needs a separately reviewed immutable-baseline
input before it can be an acceptance check; the failed run was not treated as
candidate or product acceptance.

### 2026-10-23 — Consumer S5 bounded subset execution and root review

The independently reviewed one-shot controller completed with actual exit 0;
the root-observed conservative elapsed upper bound was 84 seconds against the
900-second limit. The owned PostgreSQL 18.6 fixture reported S0–S4 PASS and
S5 SUBSET_PASS, with clean cluster/socket and private HOME/TMP cleanup. Root
verification checked all 576 evidence hashes, the matching manifest/receipt,
all 82 recorded cases, all 76 owner denials as SQLSTATE 42501, unchanged
catalog/metadata after each denial, final catalog and canonical metadata
equality with reference-new, and the 49-file toolchain before/after.

Evidence: [outer controller result](../../artifacts/consumer-derivatives-v2-sealing-controller/6e031d26-f23c-4db3-b6f7-4a265aa452af/outer-tool-result.json),
[runtime manifest](../../artifacts/consumer-derivatives-v2-sealing-runtime/66f47fbd-069c-4808-bbbd-69c0cb439f99/transition-manifest.json),
and [root subset review](../../artifacts/consumer-derivatives-v2-s5-subset-root-review/dbcc50a3-0675-4f08-9aed-8f600cc7b641/receipt.json).
An independent read-only review also verified all 576 hashes, all 82 passing
case rows, 76 denial transcripts, the final state and the outer/cleanup chain.
This only accepts the bounded S5 subset: full S5, S6/S7, HTTP, Better Auth,
UI, Prisma 012, and production qualification remain false or not run.

### 2026-10-23 — Consumer v3 Prisma candidate mapping

The Auth Prisma schema now models the staged v3 approval, proof, derivative
consent, and exact owner relations, including the parent-binding key change in
candidate 012. Prisma validation and the focused `remote-db-inspect-config`
source suite passed (12 passed, 1 skipped). A source review caught and the
schema update corrected the stale three-column parent-binding relation and
added the candidate composite FK relations. It does not add a redundant
`(approvalIntentId,birthXid)` unique absent from candidate SQL. Prisma requires
some inverse relations to be arrays because it cannot infer their at-most-one
cardinality from a unique subset of the composite FK; the SQL unique/FK
constraints still enforce the real cardinality.

This is schema preparation only. The v3 migration remains staged and
unapplied; its catalog and ACL pins are still NULL. No PostgreSQL, SQL,
migration, generated client, or runtime flow was changed or run. The
derivative-consent endpoint remains absent, so this does not qualify Consumer
S5–S7 or production.

### 2026-10-23 — Consumer v3 account-delete cascade source correction

Independent review found that account deletion cascaded to the new approval
intent while its exact service/web/mobile rows referenced the intent with
`ON DELETE NO ACTION`. The v3 source successor now uses `ON DELETE CASCADE` on
those three exact ownership FKs, and the approval-flow contract describes the
complete account-only cleanup chain. The Prisma relation actions now match.
The reviewer found no additional SQL-source blocker and considers a fresh,
bounded disposable PostgreSQL 18.6 qualification appointment source-admissible;
this is not production qualification.

The v3 pure validator passed 167 checks and its focused static suite passed
5/5. Prisma validation passed and the focused source suite passed 12 tests with
1 skip. No SQL or database was run; operator catalog/ACL pins remain NULL and
the runtime integration is still absent.

### 2026-10-23 — Consumer v3 qualification source bundle

Added a separate source-only v3 qualification preparation package. Its
57-file lock includes the current Auth schema (with the reviewed cascade
actions), frozen Auth migrations/ops, candidate contracts and candidate hash
closure. The regenerated bundle has manifest SHA-256
`97ba9d087c31db39798e6c40532a55c503d3bafb39906d5c18a4c879eced01aa`.
Independent review found no remaining prep-package blockers after adding
symlink containment, exact bundle-tree closure, plan-state validation and
bytecode exclusion.

`python3 -B tests/consumer-derivatives-v3-qualification/test_prepare.py`
passed 10/10. The bundle is still `PREPARED_NOT_EXECUTED`; admission is unset,
all S0–S5 stages are `NOT_RUN`, all SQL/PG/tool-version counters are zero, and
catalog/ACL pins remain NULL. No SQL or PostgreSQL command was run. This bundle
is not a database receipt, product migration, or release qualification.

The planned v3 SQL runner is not implemented or admitted. A read-only source
trace found that the candidate defaults new objects to deny, while the exact
role-specific fixture/production grants for browser approval, web exchange,
mobile exchange, inventory and typed API calls are incomplete. Existing v2
fixture grants cannot be reused as v3 authority. The current route code still
emits only the direct `remote:account:read` scope and contains no v3
marker/intent/proof/consent writes. No runner or ACL script was created from
inferred privileges; exact grants must be derived and reviewed against
implemented SQL call paths before a disposable S0–S5 appointment.

### 2026-10-23 — Consumer runtime ACL inspection

Extended the read-only production/staging database inspector to include the
`lomi_runtime` role's effective Consumer capabilities: row-lock prerequisites
for the four `FOR SHARE` relations, immutable binding reads, and EXECUTE on
`lomi_consumer_require_live`. The receipt is now
`lomi_remote_schema_inspection_v2`; validation still happens in a read-only
transaction and emits no identity rows. A review caught that supported
bootstraps set the role to `INHERIT`; the validator now permits that only with
zero memberships in either direction, while continuing to reject elevated
role attributes or missing capabilities. The operator bootstrap and inspector
share a pure role-attribute validator; bootstrap checks that boundary before
migrations, revokes schema `CREATE` from `lomi_runtime`, and checks the
effective privilege before committing its ACL transaction.

The focused source suite passed 16 tests (1 database test skipped without its
fixture), TypeScript checking passed, and the disposable Consumer runtime
fixture passed with PostgreSQL 18.6 and Bun 1.4.2. It applied both grant files
twice and its staging inspection database executed the catalog query and
verified the role capability fields with `INHERIT` and zero memberships; the
runner shut down and removed its private cluster. Evidence:
[private runtime proof](../../../auth-app/artifacts/consumer-runtime-lock-privilege-rerun-20261023/final-acl-boundary-proof.json/2c7df45c-0d23-41e0-8a09-b9e5b913ef4b/runtime-proof.json).
This remains isolated Consumer/runtime evidence: `productionQualified=false`,
and it does not qualify v3 S5–S7 or deployed production ACLs.

### 2026-10-23 — Cloud TCP-drop rerun against current Rust source

Repeated the pinned E2 runtime fixture after the Cloud source changed. The
current-source hash was stable through the build. With Bun 1.4.2,
PostgreSQL 18.6, and Command Line Tools selected, the actual Better Auth
handler committed the publication before a TLS/TCP acknowledgement drop; the
worker retained the intent, reconciled the cursor by GET, and sent no second
publication. The owner-process restart path also preserved its store, matched
the expected nine-request sequence, reconciled the committed cursor, and did
not repeat the PUT. The same run passed central revoke, Prisma validation,
TypeScript checking, and the 981-test regression set (one existing skip).
The private cluster stopped and its status check confirmed it was down.

Evidence: [current-source runtime proof](../../../auth-app/artifacts/cloud-runtime-current-source-rerun1-20261023/be86aef1-b084-4cd2-a96d-29aa2e497c1e/runtime-proof.json)
and [runtime log](../../../auth-app/artifacts/cloud-runtime-current-source-rerun1-20261023/be86aef1-b084-4cd2-a96d-29aa2e497c1e/runtime-proof.log).
This is a private handler/TLS fixture; `productionQualified=false`. Deployed
Cloud and relay fan-out, OS target services, and the full Consumer S5–S7 gate
remain open.

### 2026-10-23 — TUI device-code login entry point

The `lomiremote` dashboard now exposes the existing host login IPC flow. Starting
login requires an explicit key; status refresh does not retrieve the code; the
verification URL and short code appear only after the user presses the reveal
key, and leaving the panel clears the displayed code. The view reports the
time-limited code expiry and points unconfigured hosts to `lomiremote auth
configure`. Closing the panel does not stop the host.

Validation: focused TUI tests passed 14/14, including `TestBackend` checks that
the code is absent before reveal, present only after reveal, and absent again
after leaving the panel; `cargo fmt --all -- --check` and `git diff --check`
passed. This exercises synthetic IPC responses only. It does not qualify the
real device-code/Cloud/OS-service cycle or the supported OS release matrix.

### 2026-10-23 — Remote Web Explorer text encodings

Explorer previews now decode the host's declared UTF-8, UTF-16LE, and UTF-16BE
encodings. Binary, unknown, malformed, and over-64-KiB replies stay unpreviewed;
the existing generation and workspace checks still discard late replies. Added
coverage for Unicode, BOMs, invalid byte sequences, and the response bound.

Validation: `bun test tests/explorer.test.ts
tests/remote-v2-explorer-transport.test.ts` passed 40/40, and `bun --bun run
check` reported 0 errors, 0 warnings, and 4 existing hints. This closes a
browser preview defect only; Explorer is still not integrated into mobile or
the desktop app, and this is not deployed v2/production acceptance.

### 2026-10-23 — Consumer product issuance and typed API source integration

Added the gated product source for fresh web/mobile derivative login, visible
consent, approval intents, atomic source/proof/service/session/consent exchange,
fixed-deadline renewal, actual-credential authentication, C discovery/issuance,
and terminal revocation. Private versioned assertions share one validator and
SQL composite builder. The API uses typed wrappers and retains the browser
window binding; a private mobile policy digest detects differing Auth/API
configuration without disclosing user IDs. The gate defaults closed, requires
relay v2, and rejects the unsupported optional push combination.

Independent source review found and the integration corrected an enrollment
bypass through public Auth, ambiguous window-response failures reported as no
effect, and Prisma generation against unapplied columns. The full Prisma v3
mapping is now in `auth-app/prisma/schema.consumer-v3.candidate.prisma`; the
active schema matches the existing migrations and was freshly generated.
The private compatibility run passed 44 actual-handler/database tests with no
skips, 1016 source regressions, Prisma validation and type checking, then
stopped and removed its cluster. Evidence:
[compatibility receipt](../../../auth-app/artifacts/consumer-v3-source-legacy-compat-20261023/ec87cde2-d228-43ee-b344-77de56178eaa/runtime-proof.json).
Later focused gate/assertion tests passed 54/54; bridge uncertainty and typed
API tests passed 33/33 with type checking.

Current migration 202610220012 added web-window overloads after the frozen
candidate. A separate review-only product overlay preserves those overloads
and adds mobile to the five non-window class guards; its eight static mutation
tests passed. No candidate SQL, operator, new grants, or production deployment
ran. New v3 PostgreSQL issuance, deferred rollback/races, exact effective ACLs,
and the complete S5–S7 qualification still require a fresh admitted fixture;
catalog/ACL pins remain unset. The compatibility receipt proves the existing
schema path, not execution of the new derivative branch.

### 2026-10-23 — Local iOS toolchain and compile evidence

Xcode 27.1 license and first-launch setup completed, and `devicectl` detected
the paired physical iPhone. With an isolated checksum-verified Node 22.23.4,
the mobile checks passed 289 tests plus lint/type, renderer, crypto, config and
release source checks. The existing iOS workspace compiled successfully for
an arm64 iPhone 17 Pro simulator (zero errors, 511 warnings). The temporary
machine-local Node override was restored byte-for-byte and the owned build
directory was removed. Evidence:
[local validation summary](../../../mobile-app/artifacts/local-ios-validation-20261023/validation-summary.txt).
No app was installed or launched; physical iPhone runtime acceptance, Android,
the new mobile v2 data plane and the E6 method matrix remain open.

### 2026-10-23 — Consumer compatibility and product SQL access review

The current gate-off compatibility fixture passed 44 real handler/database
tests and 1028 source regressions with no failures, plus Prisma validation
and type checking. All 242 frozen source files remained unchanged during
the run; the owned PostgreSQL 18.6 cluster stopped and cleanup completed.
Evidence: [compatibility receipt](../../../auth-app/artifacts/consumer-v3-final-legacy-compat-20261023/eab1c1a4-4725-4d7c-8091-5b64a91c60e1/runtime-proof.json).
This tests the existing active schema, not execution of derivative v3 SQL.

Once the v3 assertion type is installed, disabling the v3 admission flag
cannot restore the legacy Remote-cookie bridge to the full Better Auth
parent. The catalog-presence fence and its regression test fail closed;
direct full-account management remains its own authenticated path.

The separate [product SQL source successor](../../staging/consumer-derivatives-v3-product-successor/README.md)
preserves the frozen candidate, adds the five current typed window overloads,
and guards replacement of exactly five scalar channel/ticket functions.
Independent source review identified missing Exchange parent reads, surviving
PUBLIC column grants, global defaults outside schema-only revokes, and
retained API grant options. The source delta now addresses those findings;
its validator and ten mutation tests pass. Catalog and ACL pins are still
NULL, and no candidate SQL or operator has executed.

The new actual-handler test source covers web/mobile issuance, retained
approval ceilings, rollback and response-loss behavior, private inventory,
mobile self-revoke, role identity, fifteen typed-wrapper privileges and
fifteen scalar API denials. It checks proof cleanup by retained intent IDs
without joining deleted parents. Type checking passes; with its opt-in
runtime flag unset, its single database test is skipped and opens no database.
Its successful pairing/channel/ticket transaction coverage and populated S7
plans are still absent. A fresh independently reviewed private controller is
being prepared; these source results do not close Consumer S5–S7 or authorize
production activation.

### 2026-10-23 — Signed iPhone build and physical launch smoke

The generic iPhoneOS Release build completed with zero errors and 535 warnings.
The preserved arm64 app passed strict code-signature verification; its signer,
embedded development profile and connected device matched. The release JS
bundle and native crypto marker are present. After confirming that the bundle
was absent, installation of `dev.lomi.mobile` 1.0.0 build 3 and one launch
succeeded on the physical iPhone 15 Pro Max running iOS 27.0.1. A read-only
process check confirmed the installed executable was still running. The app
remains installed. Evidence:
[device build receipt](../../../mobile-app/artifacts/local-ios-device-compile-20261023/949780bc-0c67-4973-a814-6991c8c21a5c/validation-summary.txt)
and [physical smoke receipt](../../../mobile-app/artifacts/local-ios-device-compile-20261023/949780bc-0c67-4973-a814-6991c8c21a5c/smoke-test-receipt.txt).

The temporary Node override was restored and the owned DerivedData removed.
Xcode also left a new inactive device-symbol copy cache; only that current-test
temporary tree was removed after checking ownership, creation time and absent
open files. The app and receipts were retained, and free disk space recovered
to about 6.4 GiB. See the [cache cleanup receipt](../../../mobile-app/artifacts/local-ios-device-compile-20261023/949780bc-0c67-4973-a814-6991c8c21a5c/temporary-symbol-cache-cleanup.json).
No authentication/account operation, device console collection or publication
occurred. This does not qualify native crypto interoperability, the E6 method
matrix, terminal/Explorer/Git, background/reconnect behavior or Android.

### 2026-10-23 — Private Consumer v3 execution and first product failures

The admitted socket-only PostgreSQL 18.6 controller now passes S0–S4: actual
pinned Prisma migration deployment in three private databases, candidate SQL
installation, independent raw catalog/ACL measurement, and helper/three-root/
channel operator all-old, all-new, mixed-state and ACL-drift checks. Source
catalog/ACL pins remain NULL; measured values exist only in private copies.
The effective-role ACL subset and eleven real permission-denied probes also
passed. Exact host and parent relation preservation permits only the nine
reviewed nongrantable Exchange SELECT column grants.

The actual new Auth/Exchange/API handler branch reached 309 assertions before
the first derivative C issue failed closed. A bounded rollback diagnostic
identified SQLSTATE 42703 during insertion: parent record `p` collided with
the consumed-proof table alias in the invoker principal guard. See the
[diagnostic run](../../artifacts/consumer-derivatives-v3-product-run-d5705a9a-693b-4500-b2d3-2c037821f05a/run-report.json).
Every completed attempt stopped and removed its owned cluster, with status 3,
no postmaster PID and an empty socket directory after cleanup.

The product successor now generates a count-checked reversible proof-alias
correction while retaining frozen inputs. Its helper contract/operator rebind
only the corrected source digest, preserving NULL catalog/ACL pins and the
owner-only seal. Fifteen static package tests pass. Auth's canonical guard
query now returns a Boolean instead of unsupported PostgreSQL void; ten
focused tests pass and type checking passes. Independent reviews found no
material issues in these source deltas. Corrected PostgreSQL execution is
still pending.

The controller also integrates eighty source-defined sealed-helper denial
attempts with real Runtime/API/Exchange/Migrator logins, bound 42501 and
rollback transcripts, and complete catalog/role preservation. These attempts
have not executed yet. Full S5, S6 and populated S7 remain unqualified; this
private work does not authorize production activation or publication.

### 2026-10-23 — Windows lab reconnected

Read-only SSH checks confirm Windows 10 Enterprise LTSC 10.0.19044 x64 and no
currently installed Lomi service. Existing passing private service, DPAPI,
SCM and PTY receipts remain Windows 10 evidence. The user confirmed that no
Windows 11 or Windows Server host is available, so those release targets
remain untested. No service installation, reboot or repeated native test was
performed during this reconnect check.

### 2026-10-23 — Corrected Consumer v3 handler subset passed

The independently admitted corrected private fixture completed with no
failure: S0–S4 passed, all eighty real-login sealed-helper denial attempts
returned 42501 with rollback acknowledgement and unchanged complete catalogs,
and the actual handler S6 subset passed one test with 801 assertions. This
executes the corrected proof JOIN and Prisma Boolean guard projection against
PostgreSQL, rather than relying on source inspection or mocks. Evidence:
[private run report](../../artifacts/consumer-derivatives-v3-product-run-8dc0b27f-63e1-4d1a-8840-aab3eaf058ac/run-report.json).

The fourteen acceptance markers cover fresh/legacy web and mobile issuance,
consent insertion rollback and same-ID retry, concurrent one-use exchange,
lost exchange ACK without reissue, post-commit private ACK uncertainty,
credential-hash/two-account inventory isolation, mobile refresh/replay/policy,
mobile self-revoke and ownership, mobile window gates, typed-wrapper ACLs,
actual role identities, listener shutdown and fixture cleanup. All 245 source
hashes match before/after; tool hashes and the preserved S6 log hashes match.
Cleanup independently confirmed PostgreSQL status 3, no PID, an empty socket
directory and removal of the owned work tree.

The controller deliberately reports `SUBSET_RUN_NOT_QUALIFIED` and exits 1:
full S5 owner-state operator rejection checks and populated S7 plans remain
NOT_RUN, and successful Pairing/Channel/Ticket transactions remain excluded
from S6. This is a private fixture result, not production migration-history,
cross-client acceptance or authorization to publish. The pinned pg 8 driver
also emitted a deprecation warning about overlapping queries on one client;
the test passed, but this does not establish pg 9 compatibility.

### 2026-10-23 — Private Consumer sealing and owner boundary S5 passed

The next admitted private PostgreSQL run passed S0–S5 and repeated the actual
S6 issuance/lifecycle/inventory/ACL subset without failure. It executed all
eighty nonoperator helper denials and twenty-eight owner-state operator
rejections. The latter run immediately after each real positive control at
its measured sealing phase, before the later product-access ACL transition.
Fourteen partial outcomes cannot qualify the merged matrix. The probes cover
missing owner name, excessive role attributes/config, schema CREATE and
memberships in both directions, including ADMIN OPTION.

Both helper/root operators also rejected a real authentication-bypassing
replacement of a void function body. The exact P0001 guard reason, unchanged
owner/ACL/security/config, unchanged modified catalog after rejection, and
complete catalog restoration before positive controls were verified.
Evidence: [private S5 report](../../artifacts/consumer-derivatives-v3-product-run-7c2fbf38-8c72-4c4b-b22b-0eae1122e01f/run-report.json).
All 247 source hashes and tool hashes match before/after; S6 log hashes match.
The owned cluster stopped with status 3 and its marked work tree was removed.

The result remains `SUBSET_RUN_NOT_QUALIFIED`: successful derivative
Pairing/Channel/Ticket transactions, populated S7, production migration-history
qualification and the wider E1/E2 host/Cloud acceptance remain open. This
private S5 proof does not authorize deployment or publication.

### 2026-10-23 — Private Consumer S6 signed transaction flows passed

The admitted expanded fixture passed S0–S6 with no failure. Both actual
derivative kinds completed signed window registration, real device-code host
enrollment and signed registration, runtime claim/publication, Pairing and
host-approved signed grant, Channel admission, Ticket issuance and grant
revoke through the real Auth/Remote handlers. The forwarding observer verified
all fifteen typed SQL overloads, including the five web-window variants.
Evidence: [expanded S6 private report](../../artifacts/consumer-derivatives-v3-product-run-94dbb4f9-aaca-4ee8-90c6-d8641959748f/run-report.json).

Lost commit acknowledgement tests prove a durable row exists before exact
Pairing/Channel/revoke retries, then verify recovery and uniqueness. Lost
Ticket acknowledgement exposes no raw token, leaves exactly one additional
32-byte hash-only row, and is not retried. Evidence-only observers use the
existing owner pool; handlers retain their Runtime/API clients. The real
signed heartbeat activity aborts and drains original requests before cleanup;
five pure deferred-request tests cover that ownership behavior.

The mobile host metadata parser now recognizes the mobile recipient class
and requires its account-management flag to be false. Existing exact peer
context binding remains. Host/peer boundary suites pass 316 tests and 2516
assertions, with type checking. The actual private S6 test passes 875 Bun
assertions plus the positive driver's checked protocol and durability facts.
All eighteen acceptance flags, 249 before/after source hashes, tool hashes
and S6 log hashes verify. Retained-key cleanup directly checks twenty-five
input/authority families after parent deletion, including unowned device codes
and ACK-loss operation IDs; the marked PostgreSQL cluster then stopped and
was removed with status 3.

S7 remains NOT_RUN. This private handler proof does not qualify deployed
Cloud/relay, browser/desktop/physical mobile behavior, host services or the
production migration ledger, and does not authorize publication.

### 2026-10-23 — First populated Consumer S7 run rejected safely

The source-bound S0–S7 fixture repeated S0–S6 successfully, including all
eighteen signed-transaction acceptance flags. S7 then failed during its
short-expiry exchange/authority setup, before producing population or query
plans. The complete private run took 47.495 seconds; the S7 Bun test failed
after 165.88 ms, so the ten-second parent deadline does not explain it.
Evidence: [first S7 runtime report](../../artifacts/consumer-derivatives-v3-product-run-c480aa37-7707-42eb-b15b-4e0058de491f/run-report.json).

S7 is FAILED, not qualified. All fifteen direct cleanup counts were zero.
The controller independently confirmed PostgreSQL status 3, absent PID/socket
and removal of its marked work tree. A separate post-failure verification
confirmed all 259 frozen source entries, tool/dependency hashes and command
log hashes: [source verification](../../artifacts/consumer-derivatives-v3-product-run-c480aa37-7707-42eb-b15b-4e0058de491f/post-failure-source-verification.json).

Before admission, 101 pure controller/evidence tests, fifteen pure cleanup
tests (38 assertions) and TypeScript checking passed. Independent review
closed duplicate growth observations, false-zero/malformed count acceptance,
PostgreSQL alias casing, owner UTC, real logout header/admission cleanup,
seed identity binding, actual socket-directory validation, and selective
index-work validation. These source checks do not replace the failed runtime
gate. The next run needs fixed-step, allowlisted error diagnostics to locate
the exchange/authority failure without logging credentials or database rows.

The diagnostic rerun identified `42501` during mobile exchange. The driver
incorrectly used the web Exchange role for mobile, whose real endpoint uses
Runtime. The fixture now follows those production role boundaries; no ACL was
broadened. Subsequent runs completed both 512/4096 growth stages, ten cascade
deletes and two source-TTL deletes, with no missing driver cases and complete
cleanup, but the full S7 postvalidator rejected them. Evidence:
[first complete driver capture](../../artifacts/consumer-derivatives-v3-product-run-6f1e9ec1-c66b-4478-8e2f-5e20c32d158d/run-report.json),
[direct-probe capture](../../artifacts/consumer-derivatives-v3-product-run-6326466a-6843-4a23-98ba-d5482711189d/run-report.json).

The probes now reproduce the frozen PL/pgSQL guard's standalone parameterized
principal lookup, rather than adding an outer intent relation. Validation
recognizes its reviewed globally unique ID access paths and retains strict
selectivity/work limits; DELETE plans retain normal-planner scan/timing
observations while exact cascade effects and rollback remain mandatory.
At 512 accounts the web/mobile tables contained only 131 actual rows, for which
PostgreSQL chose a five/six-page sequential scan. At 4096 the same direct probes
used indexes. Both archived runs remain FAILED. The next source-bound fixture
uses 2048/4096 accounts to measure two populated distributions, with the same
4096 cap, deadlines, connection limits, and strict probe criteria.

### 2026-10-23 — Private Consumer S0–S7 qualification passed

The fresh admitted 2048/4096-account fixture passed every stage S0–S7 in
81.822 seconds. S7 validated all seven cascade child lookup plans and three
reserved-principal absence plans at both populated sizes, selective indexed
access with no executed principal sequential scans, and ten logical-key work
comparisons with no unrelated-row work growth. The source-matching direct
probes accept only reviewed PK/unique ID access paths, without planner forcing.
Evidence: [private S0–S7 report](../../artifacts/consumer-derivatives-v3-product-run-3c08ee32-54b1-461c-8c30-36a5fbf57a75/run-report.json).

All ten actual cascade DELETE plans retained RI-trigger measurements and
verified intended authority removal, unrelated web/mobile canonical liveness,
and exact rollback restoration. Both naturally expired consumed-source deletes
observed source counts 1/0/1 across before/inside/rollback, retained proof,
consent and C, and executed the canonical live-principal guard. Row-derived
private seed receipts preserve approval/consumption XIDs and original ceilings;
expired, idle-expired, actually revoked and tombstoned categories all validate.

The root independently verified all 259 before/after source hashes, unchanged
tool/dependency hashes, every command log hash, and the retained S7 output hash.
All direct cleanup counts were zero; PostgreSQL stopped with status 3, no PID
or socket remained, and the marked tree was removed. The final source checks
also passed 109 pure controller/evidence tests, twenty pure cleanup/diagnostic
tests (56 assertions), and TypeScript checking. Archived 512-stage failures
remain failed and do not form part of the successful population claim.

This closes the private Consumer S5/S6/S7 proof for this exact source bundle.
`productionQualified` and `deploymentAuthorized` remain false. Real deployed
Cloud/relay and browser/desktop/physical mobile acceptance, host lifecycle and
production migration-ledger qualification remain separate E1/E2/E3 gates.


### 2026-10-23 — Historical host revocation proof ACK passed private runtime

A committed rotation whose response is lost leaves the host holding its old
access and refresh credentials. Global revoke then rejects exact refresh
recovery, while the old access credential cannot identify the rotated family
for the ordinary revoke ACK. The new native proof-only revocation ACK route
accepts the retained refresh hash only for an already-revoked matching family,
under the global authorization lock. It returns the current monotonic host
epoch without issuing credentials or changing host/family authority. Generic
HTTP authorization rejects this surface; only the specialized revoked-proof
contract can produce its ACK. The Rust transport and actor preserve the exact
pending generation and secret-first/SQLite-second completion order.

The admitted private PostgreSQL 18.6 run passed 44 real-handler tests (2231
assertions), 1037 non-database regressions (8395 assertions), Prisma validation
and TypeScript checking. The revoke case uses an actual committed rotation,
the identical saved retry request, actual account-wide session revoke, and an
expired consumed historical refresh with its exact confirmed recovery receipt
removed. It verifies wrong-proof rejection, unchanged complete authority state
across proof ACK, and a later new enrollment unaffected by the old-family ACK.
Expiry is bounded fixture fault injection, not a natural ninety-day TTL claim.
Evidence: [host ACK runtime report](../../../auth-app/artifacts/host-revocation-ack-current-source-20261023/dc5e6180-9df2-41b6-b07d-e5179ee45f29/runtime-proof.json),
[post-run source/tool verification](../../../auth-app/artifacts/host-revocation-ack-current-source-20261023/dc5e6180-9df2-41b6-b07d-e5179ee45f29/post-run-verification.json).

All 253 Auth, 507 Rust and six codec source entries remained unchanged, as did
the independently audited PostgreSQL/Bun/dependency closure. The private
cluster stopped with status 3 and its marked tree was removed. Earlier failed
runs remain failed: diagnostics located test assumptions about bootstrap
retention after registration and an epoch absent from the public context DTO.
The final test follows the actual cascade and checks the issued row's epoch;
no production schema, response field or role grant was relaxed for those fixes.

Independent source review and focused Rust tests passed; protocol/transport
suites passed 34/61 tests, HostAuth lifecycle 49, and host library 544 before
the final two focused reopen/failure regressions. These component checks plus
the real-handler run do not yet prove the joined native TLS/process lifecycle.
That is the next private acceptance gate. Installed services, protected native
keyrings, real relay/clients and production remain unqualified; publication is
not authorized. Only Windows 10 and an iPhone are currently available; Windows
11/Server and a physical Android remain absent from the required host/client
matrix.


### 2026-10-23 — Native HostAuth HTTPS/process cycle passed privately

The admitted `host-auth-cycle` suite passed its real native acceptance in
5.814 seconds: one HostAuth-generated identity enrolled over private HTTPS,
received actual device approval, exchanged and registered, durably prepared a
rotation, and lost the committed response when the server destroyed its socket
before writing response bytes. The actual account-wide revoke handler then
fenced that same account/family. A third process reopened the same ProtectedFile
bundle, rejected ordinary rotation at `prepared_at + 301`, received typed
AuthRequired for the retained old access token, and completed the historical
proof ACK. A further provider reopen verified durable Revoked state.

The server independently observed all seven exact routes/statuses, old access
and refresh hashes, family/epoch binding, the committed replacement credential
rows, and exactly one response drop. The complete authority snapshot was
unchanged across the revoke/proof-ACK requests. Three children exited and were
reaped; the actual TLS close callback, zero sockets/requests, removed profile,
and deleted fixture user were required before the success marker.
Evidence: [native HostAuth runtime report](../../../auth-app/artifacts/host-auth-native-cycle-current-source-20261023/d3b775fd-a992-48fe-9f75-c62d628bd271/runtime-proof.json),
[root post-run verification](../../../auth-app/artifacts/host-auth-native-cycle-current-source-20261023/d3b775fd-a992-48fe-9f75-c62d628bd271/post-run-verification.json).

The run also passed 1046 regressions (8445 assertions), Prisma validation and
TypeScript checking. One optional PostgreSQL metadata-inspection test was
skipped because this targeted suite has no staging-inspection database; its
separate Consumer-suite acceptance is retained above. Ten pure evidence guards
and three pure target-URL tests passed before execution. Both bounded pools
have at most two connections and explicit statement/lock/connect/query limits.
The controller reserves cleanup time, stops its owned PostgreSQL before archive
work, verifies every retained Rust/binary archive member against the build
inputs, and fails the targeted claim on missing markers, cleanup or deadlines.

All 257 Auth, 508 Rust and six codec sources remained unchanged, as did the
separately audited PostgreSQL/Bun/dependency closure. Root repeated the source,
log, archive-member, tool and removed-tree checks after the run. The private
cluster stopped with status 3 and its marked work tree was removed. Source
review closed ambiguous database URL overrides, final credential-observation
binding, listener-close evidence, private-file races, archive races and the
Unix-only fixture gate. No publication or production migration was performed.

`hostAuthNativeCyclePassed=true` qualifies this bounded private seam only.
The provider is explicitly ProtectedFile with OS permissions, the five-minute
rotation expiry is a local clock simulation, and browser approval is driven
by the private real-handler fixture. Installed daemon/SQLite actor recovery,
native Keychain/DPAPI/Secret Service, physical phone approval, full boot and
real relay/client acceptance remain separate gates. In particular, the product
still needs explicit login recovery after credential AuthRequired without
re-verifying the rejected retained bundle forever.

### 2026-10-23 — Deferred login recovery and enrollment retirement proof

The host now fences rejected retained credentials against the exact selected
configuration and authorization generation. Passive rejection does not start
a new login. An explicit LoginStart preserves its operation as a deferred
intent while the old authority is retired. A typed revoke acknowledgement is
durable in SecretStorage before SQLite clears pending revoke and promotes the
deferred intent; the promoted generation remains locked and unverified, with
sharing consent cleared. Reopening the terminal secret state can repair the
second write without repeating a mutation. Expired rotation/enrollment intents
retain their original proof and use a bounded five-second reprobe wait; they
do not manufacture a fresh rotation or refresh an expired request.

The read-only enrollment retirement endpoint covers ExchangePrepared and
Unconfirmed recovery, where registration/access credentials may never have
reached the host. It returns either an exact revoked-family acknowledgement or
a distinct no-family result for an approved, revoked, unconsumed enrollment
with no family. The latter carries no fabricated family or epoch. Both paths
verify the retained canonical proof and account/key/operation bindings under
the global authorization lock. Historical verification is confined to this
retirement surface; it does not admit a principal, restore sharing, or relax
ordinary exchange/register expiry.

The integrated locked/offline Rust run passed all tests and doctests in
lomi-host, lomi-host-auth, lomi-host-store, lomi-remote-protocol and
lomi-host-http, including 568 host unit tests. The cloud-fixture test build
also passed after adding explicit diagnostic branches for the two new expiry
errors. Independent source review found no material actor-integration issue.
These remain component checks, rather than installed-service acceptance.

Two fresh private PostgreSQL 18.6/Bun 1.4.2 runs passed the actual Auth handlers:

- [Core retirement report](../../../auth-app/artifacts/enrollment-retirement-current-source-20261023/70d4b5b3-9b98-4c4c-9cec-9913a65c31aa/runtime-proof.json):
  45 database tests, 2287 assertions, 79.707 seconds; 1050 regression tests,
  8505 assertions; Prisma validation and TypeScript checking passed.
- [Natural-expiry retirement report](../../../auth-app/artifacts/enrollment-retirement-current-source-20261023/6ec2b19e-ccf3-49f5-baa0-59c84bb4434b/runtime-proof.json):
  45 database tests, 2298 assertions, 674.138 seconds; the same 1050 regressions
  and 8505 assertions, Prisma and TypeScript checks passed. Both revoked-family
  and no-family proofs were accepted after actual database challenge expiry,
  without advancing the client clock or changing proof-bound timestamps.

Both runs require all fifteen core markers: closed live/wrong-proof/wrong-
binding denials, suspended/stale-account retirement, unchanged newer family,
unchanged authority/catalog, serialized revoke race, receipt/bootstrap
independence, consumed-without-family denial and verified fixture cleanup.
The consumed-row case is explicit exact-row operator attenuation; it is not
a normal product transition. The natural run additionally requires both
expiry markers. The endpoint itself makes no authority writes.

Root post-run source/tool and artifact receipts passed in each report folder.
All 260 Auth, 508 Rust and six codec inputs remained unchanged; the audited
PostgreSQL/Bun/dependency closure also matched. Every one of 1469 regular
archive members matched its declared hash, with only 132 parent directory
entries, and log/public-error capture hashes matched. Owned PostgreSQL stopped
with status 3 and its private work tree was removed within the bounded run.

Earlier failed runs remain failed. Finer diagnostics located the failure in
the later enrollment rather than global revoke. The fixture now uses its own
valid documentation IPv6 source and cleans only its exact rate-limit keys,
instead of inheriting the aggregate suite's fallback source bucket. The old
HTTP status was not captured, so rate limiting is a likely cause, not a
confirmed 429. No production permission, lifecycle predicate or rate limit
was loosened to obtain the passing results.

This qualifies the bounded backend retirement seam, not the complete E1/E2
product cycle. The next native qualification joins the actual auth actor,
SQLite, ProtectedFile and HTTPS across natural rotation expiry and restart
between the two durable acknowledgements. Installed daemons/native keyrings,
real relay and clients, physical phone approval, full boot and the required
release OS matrix remain open. No publication or cutover was performed.

### 2026-10-24 — Remote Web uses the active v2 workspace entrypoint

When the account advertises relayV2Url, the primary Shared workspaces navigation
now contains the existing v2 workspace selection and access request panel.
Previously the primary navigation read the disabled legacy worker's empty
workspace list, while the usable v2 controls appeared separately below it.
The v2 empty view now directs the user to the real selector, and does not show
the legacy No shared workspaces state or its permanently disabled Refresh
button. Access requests retain the same explicit acknowledgement, pairing
validation, identity and host approval requirements.

The existing browser bootstrap suite passed all 24 checks, including valid and
disabled v2 inventory, retry, session expiry, sign-out and keyboard account
navigation. Its v2 checks now require the access panel inside the primary
navigation and reject the stale legacy empty state/button. Astro checking
passed with zero errors and warnings and four existing async-conversion hints.
These are UI checks with local API/worker mocks; they do not qualify deployed
relay/Noise/host operation, a physical client, or the complete E3 acceptance.

The collapsed sidebar keeps the v2 panel mounted but hidden, preserving its
window identity and local request state. A keyboard-accessible folder button
expands it and moves focus into its controls. The existing valid-inventory
browser check now verifies collapse/expand and that the local acknowledgement
is retained. Final serial bootstrap checking passed all 24 cases and Astro
checking again passed with zero errors/warnings. One concurrent cold-start
attempt timed out before the initial sign-in redirect; its cause was not
confirmed, and the passing rerun did not change authentication behavior or
loosen a timeout.

### 2026-10-24 — LoginStart contention and macOS XPC lifetime experiment

LoginStart now retries typed Busy from its two pre-admission owner reads under
the original operation and deadline. It restarts the read pair, releases owner
guards before waiting, and retains the exact configuration/generation fences
at the single writer admission. The commit and wake flow is unchanged. Tests
cover real owner-lock contention, second-read contention, cancellation, expiry,
non-Busy failures, and one persisted intent/wake through the real local handler.
The current-tree cloud-fixture host suite passed 575 tests with eight private
fixtures ignored; the production locked/offline cargo check also passed.

The subsequent [private actor attempt](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/1beb1869-0e5b-45f0-9b66-bfbe681a4581/runtime-proof.json)
remains failed: enrollment presented a public code, but the child did not reach
Ready before its 45-second process deadline. Its source/tool and complete
1981-file archive audits passed; owned PostgreSQL stopped and its private tree
was removed. These audits establish evidence integrity, not runtime success.
Closed status/route diagnostics are being added to identify the stalled stage
without disclosing credentials or relaxing the Ready predicate or deadline.

The [macOS bundled-XPC lifetime experiment](../../artifacts/macos-public-xpc-20261024/8aff1883-4301-4052-a7e8-022d0a48cf49/report.json)
started two distinct services. Killing or terminating each owned controller
removed its service, but known same-session and escaped descendants remained
alive beyond both five-second deadlines. A natural leader exit also left its
detached leaf running. This is evidence against using this XPC arrangement
alone for descendant containment. It is an exploratory, forced-nonpass run:
unresolved unrelated processes prevent complete preflight inventory, and the
SDK marks its libproc observation interfaces private and subject to change.
No such inspection dependency or private containment SPI was added to product
code. The post-run audit archived all 234 events, verified the 29 reviewed
inputs and 13 prior evidence hashes, and found every known controlled identity
absent after the helpers' bounded self-expiry. This does not qualify the
release OS matrix or macOS default containment; both remain open.

### 2026-10-24 — Actual auth actor recovery across four processes

The [current private actor cycle](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/95f74430-02ba-4fa1-9bd8-cc0d438b7b69/runtime-proof.json)
passed in 547.601 seconds. It used four fresh, real auth workers with the same
SQLite identity and explicit ProtectedFile provider, actual Auth handlers,
private HTTPS and owned PostgreSQL 18.6. It waited naturally for refresh and
the local 300-second rotation-intent expiry. The server committed refresh and
dropped its response; the next process retained that rotation. Global account
revoke then denied stale access, accepted the historical registered-family
acknowledgement, and left authority unchanged. The third process stopped after
durable secret acknowledgement but before SQLite handoff. Passive reopening
completed that handoff and promoted the same explicit login operation while
remaining locked/unverified and issuing fresh enrollment.

All 25 acceptance facts passed with four processes, eight HTTPS requests and
zero pending polls. There was no old-refresh replay or repeated revoke/ACK.
The separate regression step reported 1049 passes, one skip and 8491 assertions;
Prisma validation and TypeScript checking passed. Post-run audits verified all
264 Auth, 509 Rust and six codec inputs, the pinned tool closure, all 1983
regular archive members and binary/log hashes. The listener and children were
closed, PostgreSQL stopped with status 3, and the owned private tree was removed.
Independent review found no material acceptance or stale-marker issue.

This is one bounded cycle, not a stability or full E1/E2 acceptance. The prior
45-second Ready timeout used the same production source; its cause remains
unexplained. The successful follow-up added only closed status/route telemetry,
without changing the Ready predicate or timeouts. Immediate fixture approval
produced no authorization_pending poll, so the delayed-approval path still
needs a dedicated actual-handler check. Installed services/native keyrings,
physical phone approval, deployed relay/multiple clients and the release OS
matrix remain separate requirements. No publication or cutover was performed.

### 2026-10-24 — Native-parsed pending approval evidence

The delayed-approval [actor attempt](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/eecf43a2-fd76-49ed-927d-29dc0f3d5660/runtime-proof.json)
remains failed. Its bridge observed a pending poll, then rewrote another real
OAuth 400 response to HTTP 500. The actor reported storage_unavailable and did
not reach Ready. Source/tool and all 1983 archive-member audits passed, and the
owned database and worktree were cleaned. The original error code was not
captured, so that run does not prove which non-pending OAuth error occurred.

The integrated follow-up forwards poll statuses and bodies unchanged. A private,
test-only observer records the actual Rust transport parser outcome with a
contiguous ordinal and a closed label; it is disabled outside the auth-only
fixture and retains no response bodies, credentials or error text. Approval
requires a finished server response paired with the same native pending ordinal.
Final acceptance requires exact ordered native/server correspondence, bounded
waits, one final approved poll, and counts derived from native outcomes. Malformed,
unknown, overflow, out-of-phase and EOF-truncated records fail closed. No second
OAuth body parser was introduced in TypeScript.

Independent integrated-source review found no material issue. The current host
cloud-fixture suite passed 580 tests with eight private fixtures ignored. Python
evidence tests passed 21 cases; Bun diagnostics passed eight cases with 51
assertions; TypeScript and formatting checks passed. Actual delayed-approval
runtime qualification remains pending a fresh admission and complete post-run
audits. These changes do not close E1/E2, installed-service, relay or phone gates.


The [native-parsed delayed-approval run](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/f50cd11b-1acd-4faa-a60e-69fcd4ab28b5/runtime-proof.json)
failed at actor-ready after the unchanged 45-second child deadline. Its actual
Rust outcomes were authorization_pending, slow_down and approved, in the same
order as three finished HTTP responses (400, 400, 200). The host then reported
storage_unavailable before sending any exchange request. This disproves the
bridge's former HTTP-rewrite explanation as the complete cause of the Ready
failure; the remaining failure lies after parsing the approved response or in
the following local transition. An enrollment/challenge deadline mismatch is a
hypothesis under investigation, not an established diagnosis.

Both independent post-run audits passed: all 264 Auth, 509 Rust and six codec
inputs and the pinned tool closure were unchanged; all 1983 archive members,
log and binary hashes matched. PostgreSQL stopped (status 3), children/listener
were closed and the private worktree was removed. Runtime acceptance remains
false; source freeze was released only after these checks. No runtime timeout,
Ready predicate, OAuth forwarding or fail-closed behavior was relaxed.


### 2026-10-24 — Independent enrollment and canonical challenge deadlines

A deterministic HostAuth case reproduced rejection of a valid canonical server
challenge: the conservative pre-request deadline was 700, while issuance across
one second produced a server challenge expiring at 701. This source-level bug
is established separately from the still-unattributed failed actor run above.
The original specification requires the exact server challenge and expiring
client use; it does not require the server deadline to precede the client's
conservative estimate.

The reviewed product correction preserves the canonical challenge and explicitly
enforces the earlier exclusive deadline at approval, both exchange preparation
branches, request emission and first response acceptance. Persisted preparation
must precede both deadlines; the separate original 300-second intent remains
unchanged. No signed expiry is clamped. Existing origin/account/key/enrollment/
audience checks and proof-only historical retirement access are retained.

Integrated verification passed all 79 HostAuth tests (four library, 60 lifecycle
and 15 peer-policy tests). Coverage includes shorter/equal/later server expiry,
exclusive boundaries before and after reopen, delayed responses, exact retained
proof bytes, original intent expiry and no state publication on rejection.
Independent review verified the three-file patch and exact source hashes.
The library SHA-256 is
`4a5fa38b8b6e11fb43c75f4f4e6758ee6678116d8c9ce47fefa431d86427292b`.
The clock-floor correction remains separate work: the first draft failed review
because its test stopped before registration/Ready and recovery paths still
resampled raw time. No such incomplete clock draft was integrated. A fresh
actual actor cycle and complete E1/E2 acceptance remain outstanding.


### 2026-10-24 — Clock handoff and canonical RPC object validation

The integrated clock correction carries a trusted durable floor through approval,
exchange, registration and verified Ready. Forward observations calibrate a new
monotonic projection for fresh work; they do not freeze time until an older
projection catches up. Recovery after expired approval and credential rejection
uses nondecreasing trusted time. Existing operation identities, absolute budgets,
retained-effect checkpoints and fail-closed publication rules remain intact.
The complete current host suite passed 583 tests with eight private fixtures
ignored, including actual-loop Ready, elapsed-time, expiry and exact retirement
regressions. Production cargo check passed.

Native RPC decoding previously accepted positional arrays at the root, params,
call and shared context positions despite object-only generated schemas. Actual
negative tests reproduced those forms through native and nested local RPC.
The reviewed correction uses one map-only adapter without an intermediate Value
copy, preserves serialization/schema output, and applies the shared original-byte
UTF-8/size/duplicate/trailing check at remote RPC ingress. The complete protocol
suite passed 112 tests plus one doctest; browser-feature and generated-contract
checks passed. Local IPC raw duplicate acceptance remains unproven and was not
changed. An earlier worker edited active protocol files contrary to its scratch
scope; exact candidates were preserved and verified archive preimages restored
before the independently reviewed replacement was integrated. No admitted runtime
was active during that incident.

The canonical protocol WASM was rebuilt and all 366 tests passed, including
rejection of the same positional requests by the actual WASM artifact. Authority
WASM was rebuilt and its 40 tests passed. Current dependency notices were refreshed
because their lock digest referred to an older Cargo.lock; their 91-package set
was unchanged. Controlled packing produced archive
`20b81d817f2ba9f8fd9d614b3495878a1bf3e5b98e56ca8eea54e86cbe5751dc`.
The installed Auth package matches all ten archive members; only nine authority
package files changed in the complete dependency tree, with unrelated dependencies
unchanged. Twelve existing test digest checks now name the new protocol WASM;
historical evidence was left unchanged. Canonical schemas/validators and generated
Remote Web snapshots were refreshed. Auth TypeScript and snapshot checks passed.

The independently reviewed relay fixture now covers host-specific and account-wide
revoke with two active pairs and unused tickets. It requires unauthenticated,
unconsumed denied tickets and closure before all original freshness/expiry bounds.
Those new relay scenarios and the corrected four-process auth actor still need
actual private runtime execution and complete post-run audits. Mobile vendor/build
provenance and full deployed/product acceptance remain separate open requirements.
No publication, cutover or release qualification occurred.


The corrected-source [actor attempt](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/99585a48-2105-457e-92a6-5a5c25fa0ec1/runtime-proof.json)
remains failed. Native pending/slow_down/approved matched finished HTTP 400/400/200,
and exchange returned 200. The worker reached registering (Unconfirmed) but sent
no registration request before the unchanged 45-second child limit. The private
approval/preparation failure diagnostic was empty; it does not cover Ready.
Thus this run narrows the failure beyond the repaired approval/exchange path,
without identifying the remaining Ready handoff failure. System TLS is not used
by the fixture's registration send branch, which uses its injected test-root
transport; construction or earlier handoff failures remain under investigation.

Both post-run audits passed: exact 265 Auth, 510 Rust and six codec inputs,
updated tool closure 31ca6dea7fc6d1f397ba1fa17100972e4988fa7cc2753c841c133f65c8cd14d1,
all 1985 regular archive members and log/binary hashes. The private tree was
removed, owned children/listener reaped and PostgreSQL stopped with status 3.
The new tool-only lock preserves prior PostgreSQL/Bun/Prisma/alias pins and
accounts explicitly for the nine-file authority-package update; historical
locks and results remain unchanged. Independent review admitted only that one
private attempt. Source freeze was released after both terminal audits; no
runtime acceptance, stability, service, phone or deployed relay claim follows.

### 2026-10-24 — Current-source four-process auth cycle passes

A test-only Ready trace now reports bounded, closed stage/outcome labels through
factory, admission, preparation, HTTP, clock, acceptance and publication. Its
64-record cap, deduplication and parser reject malformed or truncated records;
valid error labels remain advisory. It uses the existing private fixture opt-in
and changes no production authorization, operation budget, retry or error rule.
The integrated host suite passed 586 tests with eight private fixtures ignored;
production cargo check, 15 parent diagnostic tests with 433 assertions, 21 pure
evidence tests and Auth TypeScript checking passed.

The fresh, independently admitted [actual actor cycle](../../../auth-app/artifacts/host-actor-native-cycle-current-source-20261024/c04361e3-0df2-4969-85ce-d6d7a4cfd5c6/runtime-proof.json)
passed on the current source and rebuilt canonical WASM dependencies. It exercised
native authorization_pending before browser-handler approval, verified Ready,
natural refresh, committed rotation with a dropped response, retained rotation,
natural expiry checked against the database clock, account-global revoke and
denied stale access. It stopped after durable secret retirement acknowledgement
but before the SQLite handoff; a fourth passive process repaired the same host
and operation without LoginStart or replaying refresh, revoke or acknowledgement.
All 26 boolean facts and exact counts passed: one pending poll, nine requests
and four processes. The actor step took 552.372 seconds. The additional regression
suite passed 1049 tests with one skip; Prisma validation and TypeScript passed.

Both post-run audits passed: unchanged 265 Auth, 510 Rust and six codec inputs,
tool closure `31ca6dea7fc6d1f397ba1fa17100972e4988fa7cc2753c841c133f65c8cd14d1`,
all 1985 regular archive members and log/binary hashes. PostgreSQL stopped with
status 3, children/listener were reaped and the owned private tree was removed.
Source freeze was released only after both audits. The previous registering
failure remains unexplained; this successful bounded run does not establish
stability or complete E1/E2. Installed services, native keyrings, physical phone,
deployed relay and full production acceptance remain open. No release occurred.

### 2026-10-24 — Host and account revoke through the private relay

The first current-source relay attempt failed at the account-global helper. Source
review found an impossible fixture invariant: deleting every account session
cascades through consumer authorization, consumer-created proposals and tickets,
but the shared helper required unchanged ticket rows. The correction uses an
explicit lifecycle expectation: host revoke retains the exact unused tickets;
account revoke requires both known proposals and ticket sets to be absent.
Prestate checks bind the deleted proposals to the expected consumer authority.
Both branches still require no authentication/Ready on denied reconnects, closure
within five seconds and before freshness, context and ticket expiry. Closed
subphase/status/closure diagnostics retain no credentials or response payloads.
Independent review confirmed the cascade contract and correction. An intervening
diagnostic-only admission was superseded before any execution. The first failed
run's precise failing predicate remains unobserved; no result was overwritten.

The fresh [corrected relay diagnostic](../../../auth-app/artifacts/relay-central-revoke-current-source-20261024/26e331f7-d036-490a-92d5-ededc6a2c29a/runtime-proof.json)
passed both runtime tests with 1277 assertions in 49.146 seconds. Its exact
15-fact record passed: host-specific and account-global revoke each closed two
active pairs and denied two unused tickets; epochs/families advanced or revoked,
account sessions/consumer authorities disappeared, stale heartbeat/publication
were denied and runtime rows stayed unchanged. A separate actual Rust CloudWorker
HTTPS probe fenced after host revoke. The accompanying 47-request TLS control-plane
cycle confirmed permissions refresh, committed publication with a dropped ACK,
valid/expired-lease restart reconciliation and no repeated PUT.

Both post-run audits passed: unchanged 265 Auth, 510 Rust and six codec inputs,
the current 31ca6dea tool closure, all 1474 archived Auth/codec/library members and
log hash. PostgreSQL stopped with status 3 and the private tree was removed.
Rust executable evidence here is build/hash and source inventory; executables were
not archived. This diagnostic uses synthetic opaque loopback WebSocket payloads,
not canonical Noise traffic, installed host service or deployed relay acceptance.
Aggregate fixture and production flags remain false. Source freeze is released.

Consumer integration also remains open: the earlier private S0-S7 receipt applied
composed candidate SQL and operator transitions, while active Prisma migrations
stop at 013 and omit the derivative intent/proof/consent integration. The current
product overlay was not applied as one artifact. Its private S7 plan probes used
2048/4096 account targets, which do not establish the governing 1000/10000 unrelated
principal/approval cases. Preserve that private receipt's exact scope; the next
product change is an append-only migration/schema integration and clean/013-upgrade
qualification, followed by the required growth cases and real client acceptance.

### 2026-10-24 — Foundation DDL install, upgrade and rollback pass

The append-only Consumer foundation remains a frozen, unintegrated proposal.
Its independently admitted [local schema qualification](../../artifacts/consumer-foundation-schema-20261024/162e9267-9dd9-46aa-adb3-0dfaf1783df8/report.json)
passed all three cases on a fresh private socket-only PostgreSQL 18.6 cluster:
all 27 Prisma migrations on a clean database; the exact 26 predecessors plus
valid synthetic legacy rows upgraded to 27 without changing legacy data; and
an injected PZ001 before COMMIT leaving the original ledger, data and raw
predecessor DDL unchanged with no candidate objects remaining. Default-deny
checks and the absence of implicit approval or consent backfill passed.

Clean and upgraded catalogs match after normalization of generated internal
foreign-key trigger names. That normalization requires the linked FK identity,
system function and flags; it preserves definitions, arguments, multiplicity
and every other catalog section. Raw and canonical captures remain separate.
The earlier failed name comparison is preserved, rather than reclassified.

The [post-run audit](../../artifacts/consumer-foundation-schema-20261024/162e9267-9dd9-46aa-adb3-0dfaf1783df8/root-post-verification.json)
passed all 31 frozen inputs, the complete 31ca6dea tool closure and all 38 public
source archive members. PostgreSQL stopped with status 3, its PID was absent
and the owned cluster was deleted before the source freeze was released. This
qualifies only the tested schema DDL proposal. Coordinated ACL installation,
legacy Auth lifecycle behavior, API privileges and deployment remain open.

### 2026-10-24 — Required S7 growth recipe prepared; runtime held

The independently reviewed per-kind growth recipe is integrated with plan
version 2. It requires 1000 and 10000 unrelated issued principals of each
derivative kind, excluding eight dedicated control fixtures, and checks actual
principal, approval, proof, consent and service row counts. The canonical
liveness guard remains evaluated without treating its VOID result as NULL.
Controller tests passed 52 cases, evidence tests passed 22, and Auth TypeScript
checking passed. A fresh exact source/dependency bundle was prepared.

Its independent runtime admission is held: a final lifecycle query could resolve
after the 360-second driver deadline and still produce successful completion
after cleanup. The completion gate needs a final deadline/abort check without
skipping cleanup or extending any budget. The prepared bundle has not run;
full S7 and production qualification remain false. A separate reviewed ACL
bootstrap proposal fixes qualified type capture and reapplies the fixed ACL
delta on terminal replay, but actual install/recovery/replay qualification is
still required before integrating that proposal.

### 2026-10-24 — Required private S7 population and full fixture pass

The final completion gate now rechecks deadline and abort after unconditional
cleanup, preserving an earlier failure. Independent review approved the change;
23 completion/diagnostic/cleanup tests, 52 controller tests and full Auth
TypeScript checking passed. A first admission attempt rejected the root's
incorrect receipt modes before SQL. Its source, receipts and post-audit remain
preserved; a fresh bundle used the required modes and validated both receipts
before executing.

The independently admitted [fresh private S0-S7 run](../../artifacts/consumer-derivatives-v3-product-run-344ffd2d-1985-41be-8d9a-202a04755f3e/run-report.json)
passed every stage in 266.193 seconds. S7 measured 1000 and 10000 unrelated live
principals of each derivative kind, excluding the eight dedicated fixtures.
At the larger target it observed 10000 web and 10000 mobile principals and
20000 unrelated approvals, proofs, consents and service authorizations. The ten
rollback cascade measurements, two source-TTL delete measurements, canonical
liveness, control observations and raw-plan validation passed without missing
cases. Retained S7 evidence is 283808 bytes, below the unchanged 32 MiB ceiling.

The [root post-run verification](../../artifacts/consumer-derivatives-v3-product-run-344ffd2d-1985-41be-8d9a-202a04755f3e/root-post-verification.json)
passed 247 active source pins, 263 bundled source files, full tool closure
31ca6dea, 746 command logs, 160 catalog captures, all 268 public source archive
members and the pure S7 postvalidator. PostgreSQL stopped with status 3, the
postmaster PID and sockets were absent, and the marked tree was removed before
the source freeze was released.

This qualifies the exact private fixture and its required growth recipe. It
still applies the active 26-migration ledger followed by literal candidate SQL
and fixture operator transitions. The separate foundation DDL proof does not
turn it into a product ACL/bootstrap installation result. Actual coordinated
rollout, legacy Auth lifecycle, installed services and real relay/client
acceptance remain open; production and deployment flags stay false.

### 2026-10-24 — Product ACL catalog controls pass; installation remains open

The next independently admitted [ACL qualification run](../../artifacts/consumer-acl-foundation-20261024/584a3149-435e-42ba-b097-5cc10eac9440/report.json)
applied all 27 migrations and passed its read-only ACL representation controls.
PostgreSQL rejected the zero-dimensional empty ACL literal with SQLSTATE 22023;
a NULL ACL produced zero rows. Explicit ACL values preserved grantor, grantee,
privilege and grantability. The sequence default used the lowercase `s` kind
and returned SELECT, UPDATE and USAGE without grant options. These probes
constructed ACL values and did not grant database privileges.

The run then stopped during post-migration catalog capture with SQLSTATE 42601.
It did not reach guarded permission installation or terminal replay. A separate
source inspection found and corrected an unbalanced migration-ledger aggregate
query in a new, unintegrated proposal. Its 29 pure tests and 210 assertions pass;
the failed run did not record a query identifier, so that correction does not
establish the exact runtime failure's cause. A fresh qualification will retain
bounded query identifiers without SQL text or parameters.

The [post-run audit](../../artifacts/consumer-acl-foundation-20261024/584a3149-435e-42ba-b097-5cc10eac9440/root-post-verification.json)
passed 66 source inputs, full tool closure 31ca6dea and all 71 public source
archive members. The postmaster PID was absent, PostgreSQL returned stopped
status 3 and the marked cluster was deleted before releasing the source freeze.
The command journal is retained; raw command output logs are not archived in
this proof. This is partial catalog evidence, not accepted product ACL
installation, legacy Auth lifecycle or production qualification.

Independent source review then found that the new balance test scanned a
captured constant name rather than its SQL body. The corrected extraction is
covered by a malformed-ledger negative control through the same helper. That
fixture is self-contained: 30 tests and 212 assertions pass both in the
proposal and an isolated copy without sibling revisions. The final source
review is clean, and the production ACL stage is unchanged by these test fixes.

The subsequent A1 source admission remains held and that prepared revision
has not run. Review found that its Python module loader could execute existing
bytecode caches despite `-B`, which prevents cache writes rather than reads.
The next revision must verify source bytes and compile/execute that same buffer;
root audit loaders need the same correction. Existing source-hash checks do
not, by themselves, prove that cached modules executed those source bytes.

### 2026-10-24 — Clean ACL reference installation and replay pass

The new source-only Python loader verifies a required digest, then compiles and
executes that same buffer. Its 27 tests pass, including timestamp-valid stale
bytecode and digest-mismatch controls; inert Bun assertions and strict
TypeScript checking also pass. The preceding source revision remains
unexecuted. An independent source review admitted the corrected revision once.

That [fresh A1 reference run](../../artifacts/consumer-acl-foundation-20261024/d8529259-8f74-4a09-add8-36b7f535b722/report.json)
passed all 27 migrations, read-only ACL controls and the actual 14-attribute
assertion type catalog. The complete catalog after rolling back the measurement
savepoint matched its premeasurement hash. Actual guarded owner transfer,
helper sealing, three roots, ACL delta and product channels matched all five
measured boundaries. Reapplying the baselines and fixed ACL delta produced
exactly the same terminal catalog, including routine metadata and role graph.

The [post-run verification](../../artifacts/consumer-acl-foundation-20261024/d8529259-8f74-4a09-add8-36b7f535b722/root-post-verification.json)
passed 121 frozen inputs, full tool closure 31ca6dea, all 126 public source
archive members, all five run artifacts and the 14 matching command-journal
records. The postmaster PID was absent, PostgreSQL reported stopped status 3
and the marked runtime was deleted before releasing the source freeze. Ten
run/admission artifacts have verified durable copies. Raw command output logs
are not archived; the retained catalog and generated SQL evidence are explicit.

Independent artifact review found no material issues and accepted the run as
bounded reference evidence for a separately reviewed A2 binding. The
[root acceptance receipt](../../artifacts/consumer-acl-foundation-20261024/d8529259-8f74-4a09-add8-36b7f535b722/bounded-reference-acceptance.json)
binds the exact source, PostgreSQL binary and proof hashes. The original outputs
keep their `UNREVIEWED_REFERENCE_OUTPUTS` label. This measures the clean
reference installer, not the actual bootstrap's reviewed-bundle admission.
Populated upgrades, ACL-pending recovery, all 12 profiles, real handlers,
native device-code behavior and product deployment remain open. The foundation
and ACL proposals are still unintegrated; A2 runtime has not been admitted.

### 2026-10-24 — Actual Auth handlers pass under the candidate terminal ACL

The isolated Auth source copy now uses a client generated from the exact
46-model foundation schema, rather than the active 43-model client. The 54
generated files, input schema/config and generation command are pinned; active
sources and dependencies stayed unchanged. Full strict ESNext checking passes.
The adapter's final identity check explicitly rejects a missing or empty
server identity. Eighteen inert parent tests and four profile tests pass.
Privacy regressions require malformed markers and summary-shaped secrets to
remain absent from receipts; only stream hashes and byte lengths are retained.

The separately admitted [fresh A2 handler run](../../artifacts/consumer-bootstrap-handler-20261024/828c5aac-08e2-4b3c-b7b6-84c47b370ae2/a2-run-receipt.json)
passed after a fresh 27-migration install and guarded terminal ACL replay on
private PostgreSQL. Its single successful handler command produced exactly
the required 18 true marker fields, including actual role checks, all 15 typed
overloads, issuance/consent rollback, concurrent one-use behavior, lost-response
durability, account inventory, mobile refresh/revoke policy and fixture cleanup.
The test also executes the legacy web/mobile and custom desktop PKCE handler
branches with derivative issuance disabled. It uses the existing application
handlers and copied candidate client, without fixture permission grants.

The [post-run verification](../../artifacts/consumer-bootstrap-handler-20261024/828c5aac-08e2-4b3c-b7b6-84c47b370ae2/root-post-verification.json)
passed all 374 source inputs, full tool closure 31ca6dea, all 380 public source
archive members, six run artifacts and 15 matching journal records. It also
rechecked the reference's five guarded boundaries, rollback and terminal
equality. The postmaster PID was absent, PostgreSQL reported stopped status 3
and the owned runtime was deleted before releasing the source freeze. Eleven
run/admission artifacts have verified durable copies; raw command output is
not archived.

Independent artifact review found no material issues and accepted the
[bounded handler proof](../../artifacts/consumer-bootstrap-handler-20261024/828c5aac-08e2-4b3c-b7b6-84c47b370ae2/bounded-handler-acceptance.json).
Original outputs keep their unreviewed-reference labels. This qualifies the
tested clean reference/handler path, not actual bootstrap admission, all 12
profiles, native device-code, installed services, relay/clients or deployment.
The foundation and ACL proposals remain unintegrated. Native device-code
qualification is the next separate A3 run and has not been admitted.

### 2026-10-24 — Native A3 attempt fails; cleanup and source capture pass

The separately admitted [A3 attempt](../../artifacts/consumer-native-lifecycle-20261024/e791d74c-e657-42a9-89ed-7edb8ad512ff/a3-run-receipt.json)
completed a fresh 27-migration reference install, ACL controls, type catalog
checks and terminal replay. TLS fixture preparation also passed. The native
Bun test then exited with code 1 after 996 ms, without an accepted result
marker. A3 remains failed; this attempt does not qualify device-code login,
rotation recovery or global revoke.

The parent discarded the completed child's command streams before recording
their hashes or safe failure phase, so the exact cause is unknown. Its actor
entry also retained the intermediate `RUNNING` label inside the failed receipt.
A separate source revision will preserve bounded diagnostic metadata on failure;
the frozen failed revision will not be rerun.

The [post-run audit](../../artifacts/consumer-native-lifecycle-20261024/e791d74c-e657-42a9-89ed-7edb8ad512ff/root-post-verification.json)
passed 1,075 source inputs, two artifact hashes, four extra OpenSSL/OS inputs,
both tool closures, 1,081 regular archive members and 24 matching journal
records. PostgreSQL reported stopped status 3, its PID was absent, and both
owned PostgreSQL and actor directories were deleted. Eleven public run and
admission artifacts have verified durable copies; private TLS files and raw
command streams are excluded. Independent [failure-capture review](../../artifacts/consumer-native-lifecycle-20261024/e791d74c-e657-42a9-89ed-7edb8ad512ff/failure-capture-review.json)
found no material issues and released the freeze for source-only work. Actual
bootstrap, all profiles, services, physical clients and production remain open.

### 2026-10-24 — Native fixture path mismatch diagnosed

The diagnostic revision's [separate A3 attempt](../../artifacts/consumer-native-lifecycle-20261024/c48c2312-dd4e-433b-8f68-af1372203b7f/a3-run-receipt.json)
failed at `actor-enroll` after 985 ms. It now records native status `FAILED`,
complete byte-stream hashes and lengths, and a bounded phase/source hint;
raw streams remain excluded. The pinned Rust fixture accepts only
`lomi-e2-<UUID>` run roots, while the A3 adapter supplied
`lomi-consumer-native-a3-actor-<UUID>`. Its strict path check rejects that
input before profile creation. A source-only adapter/parent revision aligns
the actor root with the existing Rust contract and retains the separate
PostgreSQL directory, A3 owner marker and exclusive creation checks.

The [post-run audit](../../artifacts/consumer-native-lifecycle-20261024/c48c2312-dd4e-433b-8f68-af1372203b7f/root-post-verification.json)
passed 1,079 source bindings, both tool closures, 1,085 regular archive members,
24 matching journal records and verified removal of both runtime directories.
A summary-variable error in the first audit formatter was corrected; the
existing completed archive and all inputs were reverified without rerunning
the native job. Independent [failure-capture review](../../artifacts/consumer-native-lifecycle-20261024/c48c2312-dd4e-433b-8f68-af1372203b7f/failure-capture-review.json)
confirmed the evidence and static mismatch. Native qualification remains open.

The namespace-aligned [next attempt](../../artifacts/consumer-native-lifecycle-20261024/0aa2f5da-8e38-4b9e-9508-fb24aad1609e/a3-run-receipt.json)
passed public initialization, a confirmed pending poll and HTTP 200 browser
approval, then failed at `actor-ready` after 45.28 seconds. It did not reach
the accepted native result marker. The parent retained phase and stream
hashes but dropped the producer's route/native diagnostics, so the precise
Ready failure is still unknown. The next source revision will retain only
strictly validated closed status fields and bounded route progress.

Its [post-run audit](../../artifacts/consumer-native-lifecycle-20261024/0aa2f5da-8e38-4b9e-9508-fb24aad1609e/root-post-verification.json)
passed 1,087 source bindings, 1,093 regular archive members, both tool closures,
24 journal records and cleanup of both actual receipt paths, including the
new `lomi-e2-` actor directory. Independent failure-capture review is clean.
The 45-second child limit and the requirement to reach verified Ready remain
unchanged; this partial native progress does not qualify the complete cycle.

### 2026-10-24 — SCRAM bootstrap source contract prepared

The isolated [A4 source contract](../../artifacts/consumer-bootstrap-scram-contract-20261024/48b8980b-73a4-4c24-813b-690d5386c7b8/proof-manifest.json)
plans a UUID-bound Unix-socket target, SCRAM-only initialization, distinct
private credentials, a closed candidate environment and an externally pinned
reviewed bundle. The candidate entry, its imports and all 27 migrations are
bound to an ordinary 55-file source copy. Ten pure tests and source/hash
checks pass; independent review found no material source-contract issue.
The public source archive contains 64 verified regular files.

The entry remains disabled. A deletion owner still needs creation-time
device/inode, link-count and content bindings plus current no-follow identity
checks. Dependency closure, reviewed reference profiles, actual bootstrap,
SCRAM authentication, supervision, cleanup and the private production branch
remain unimplemented or unqualified. This is preparation for the actual
bootstrap gate, not runtime or production evidence.

### 2026-10-24 — Native cycle passes on the candidate terminal ACL

The separately admitted [native A3 run](../../artifacts/consumer-native-lifecycle-20261024/1b6244c7-e24a-43be-89ef-1813d2fe782b/a3-run-receipt.json)
passed on a fresh 27-migration private cluster. Four native Rust processes
completed device-code approval, verified Ready, natural refresh, a response
lost after rotation committed, retained rotation state, natural expiry,
global revoke, stale-revoke denial, historical ACK and passive repair.
All 26 required markers are true. Ten requests include one pending poll and
one slow-down response. The native command exited 0 after 562.53 seconds.

The [post-run audit](../../artifacts/consumer-native-lifecycle-20261024/1b6244c7-e24a-43be-89ef-1813d2fe782b/root-post-verification.json)
passed all 1,089 source bindings, two artifact hashes, four extra tool/OS
inputs, both tool closures, 1,095 regular archive members and 24 journal
records. PostgreSQL reported stopped status 3, its PID was absent, and both
actual runtime paths were deleted. Eleven public artifacts have verified
durable copies; private TLS material and raw streams remain excluded.
Independent review accepted the [bounded native reference](../../artifacts/consumer-native-lifecycle-20261024/1b6244c7-e24a-43be-89ef-1813d2fe782b/bounded-native-reference-acceptance.json)
for continued qualification. Original outputs retain their unreviewed labels.

The earlier 45.28-second Ready timeout remains unexplained. This pass changes
no application, ACL, native binary or adapter behavior relative to that failed
attempt and does not establish a stability fix. Actual bootstrap, all 12
profiles, installed services, deployed relay, physical clients, full Consumer
acceptance and production remain open; the foundation/ACL proposals are still
unintegrated.

### 2026-10-24 — Private SCRAM fixture passes on the pinned Bun runtime

The temporary A4 owner/coordinator drafts were unavailable after the environment
reset. The 64-file source contract was recovered from its verified durable
archive into [persistent staging](../../staging/consumer-scram/README.md).
A new Python owner supervises PostgreSQL as its direct child, binds private
filesystem identities and handles startup, interrupted launches and cleanup.
The probe imports the pinned application driver and candidate snapshot helper
only after checking project sources, dependencies and the private owner context.

The first installed-Bun-1.3.14 [attempt](../../staging/consumer-scram/runs/60fb9046-7121-4adf-b833-e8c07b9e4cfe/failed-run.json)
timed out after server readiness and a logged wrong-password rejection. Its
runtime was removed; the exact hang phase and child exit receipt were not
retained. The second [attempt](../../staging/consumer-scram/runs/ab493742-84b8-4baf-a819-18facfbd43c6/post-verification.json)
reported `CLIENT_CLOSE_FAILED` with the other five checks true, verified owner
cleanup and PostgreSQL exit 0. Both attempts remain failed. Client closure now
observes end events before calling the driver and has its own five-second limit;
the owner caps the probe at 90 seconds and preserves failure cleanup receipts.

The original Bun 1.4.2 binary was recovered from the official release and its
raw bytes matched the archived `35d20dd0` tool pin. The global installation was
unchanged. On that runtime the fresh [preflight](../../staging/consumer-scram/runs/a4ce7a2b-16c3-46ad-9453-22a4840ebd33/result.json)
passed all six checks: observed SCRAM authentication, incorrect-password
SQLSTATE `28P01`, exact socket-only server identity, absent managed roles,
read-only catalog capture and client closure. The command exited 0 in 1.11
seconds. This runtime comparison does not prove the exact cause of the earlier
timeout.

The [owner receipt](../../staging/consumer-scram/runs/a4ce7a2b-16c3-46ad-9453-22a4840ebd33/owner-result.json)
records reaped PostgreSQL PID 47072 with exit 0 and verified runtime removal.
The [post-run audit](../../staging/consumer-scram/runs/a4ce7a2b-16c3-46ad-9453-22a4840ebd33/post-verification.json)
reverified 70 current source files, 70 regular archive members and the canonical
catalog digest. Separate filesystem-only postchecks also passed the 55-file
candidate tree, 14-package/143-file driver closure and executable pins. The
focused owner suite has 24 passing tests; the probe has 16 passing tests in
Node and in Bun 1.4.2. Original results retain their unreviewed fixture labels.
Independent [bounded result review](../../staging/consumer-scram/runs/a4ce7a2b-16c3-46ad-9453-22a4840ebd33/bounded-acceptance.json)
accepted this fixture for continued reference collection after checking the
source/archive/result bindings and independently observing the absent PID and
runtime directory.

This proves the private SCRAM fixture only. It creates the test database but
does not run migrations, create application roles, execute the actual bootstrap
or supply a reviewed bundle. All 12 clean/populated/recovery reference profiles,
actual bootstrap, active application integration and the remaining E1–E7 gates
remain open. No remote laboratory machine, deployment or publication was used.

### 2026-10-24 — Independent reference matrix captured for actual bootstrap

The [reference collector](../../staging/consumer-scram/reference_capture.ts)
now covers clean install, populated migration-013 upgrade and both ACL-pending
recovery selectors on the owned SCRAM fixture. A separate 26-migration project
contains the original schema and permission baselines; the candidate retains
all 27 source-pinned migrations. Populated scenarios insert synthetic legacy
user/session/account/binding rows and check that migration and permission
operations preserve them. The collector checks the complete migration inventory
and checksums; the pinned permission snapshot itself records only the 013/014
boundary ledger entries.

Four future qualification targets were reserved before reference capture and
remain uninitialized and unobserved. The owner and collector reject their UUIDs
and target identities for reference work. Source checks cover both exact project
inventories, their two declared dependency links, the complete dependency tree,
Prisma CLI/schema engine and recovered source-bound operator plans. Ten owner,
six source-contract and fourteen collector tests pass. Independent source review
resolved the populated-selector, asynchronous client-error, bounded-read and
parent source-bookend findings before execution.

The first eight reference commands exited 0 and produced matching catalogs,
but [independent result review](../../staging/consumer-scram/reference-runs/matrix-ce0c10fd-2e83-412d-a1d4-6ae38fd9717f/review-finding.json)
found that the recorded operator SQL hashes could not be regenerated after
canonical JSON persistence reordered nested pin keys. That matrix is not
admitted for a bootstrap bundle. Its first owner stdout was also truncated by
the tool output limit; the partial receipt is preserved and was not rebuilt.

The corrected collector canonicalizes pins before generating SQL and persists
that same object. The regression reverses nested key order, saves/reloads the
pins and rebuilds the four operators through the actual pinned stage. Eight
fresh [corrected captures](../../staging/consumer-scram/reference-runs/canonical-adf827a2-ac52-4905-8c3d-7cdc01a60dcb/matrix.json)
exited 0 across two independent series. All 12 corresponding profiles match,
giving 24 matching snapshots; operator pins, operator hashes and terminal
catalogs also agree across all eight clusters. The [separate audit](../../staging/consumer-scram/reference-runs/canonical-adf827a2-ac52-4905-8c3d-7cdc01a60dcb/operator-roundtrip-verification.json)
reproduced all 32 SQL hashes directly from persisted results. All eight original
owner receipts are complete and report PostgreSQL exit 0 and verified removal.
The root postcheck reverified 170 current/archive source files, every snapshot
digest, all absent postmaster PIDs/runtime directories and qualification-target
separation. Independent catalog/operator and source/cleanup reviewers
[accepted the corrected reference matrix](../../staging/consumer-scram/reference-runs/canonical-adf827a2-ac52-4905-8c3d-7cdc01a60dcb/bounded-acceptance.json)
for private bootstrap preparation only, verifying all 32 regenerated hashes
and all eight complete 113-pin receipts. The rejected first matrix is not used.

These are reference captures, not execution of the candidate bootstrap. Runtime
evidence binding, a reviewed target-specific bundle, actual bootstrap runs,
active integration and the remaining E1–E7 acceptance gates remain open. No
publication, deployment or cutover was performed.

### 2026-10-24 — Three explicit handler gates pass on canonical SCRAM

The [fresh handler run](../../staging/consumer-scram/runtime-runs/8b3da2af-d34e-44f9-b7e5-70200043e231/result.json)
passed `typedResolver`, `legacyAuthLifecycle` and
`rawScalarApiFallbackExcluded` on a newly owned canonical clean-install SCRAM
reference. It preserved all 18 original A2 handler assertions. A genuine typed
inventory request succeeded; a legacy assertion was rejected before SQL. A
real typed-function permission revocation produced PostgreSQL `42501` and a
closed API response with zero scalar retries. Readiness controls passed before
the fault and after restoration; readiness failed during the fault. The legacy
API comparison preserved valid required feature flags. The catalog was restored
exactly before successful fixture cleanup and marker emission.

The recovered 119-file A2 project is unchanged. Three test-only overlay files
make the separate runtime gates explicit; all 56 implementation files match the
active auth service. The parent checks the full dependency closure and pins
364 source/tool entries. Independent source reviews resolved configuration,
readiness-control, client-release, output-collision and evidence-binding issues
before this run. Source-only validation passed 16 Python, 7 Node and 6 Bun tests.

The command and owner exited 0. The [postcheck](../../staging/consumer-scram/runtime-runs/8b3da2af-d34e-44f9-b7e5-70200043e231/post-verification.json)
verified all 475 current/archive source files, the complete 364-pin receipt,
three canonical reference snapshots and gate/marker hashes. PostgreSQL exited
0; its PID and owned runtime directory are absent. Raw command streams remain
excluded; their bounded byte counts and hashes are retained. Independent
source/cleanup and runtime-evidence reviews
[accepted the three runtime gates](../../staging/consumer-scram/runtime-runs/8b3da2af-d34e-44f9-b7e5-70200043e231/bounded-acceptance.json)
for private bootstrap preparation. All original results retain their
unreviewed labels.

No reserved qualification target was initialized or observed. The reviewed
target-specific bundle, stop-and-drain attestation, actual candidate bootstrap,
active foundation/ACL integration and full E1–E7 acceptance remain open. No
remote laboratory host, deployment or publication was used.

### 2026-10-24 — Actual private bootstrap passes four selectors and replay

The [actual bootstrap matrix](../../staging/consumer-scram/bootstrap-runs/qualification-fc1f9a3c-718b-46f0-b2cc-c4a48d5e242f/matrix.json)
records four fresh owned SCRAM targets selected before independent reference
capture. Every target ran the actual candidate bootstrap and then ran it again
at the terminal catalog. Clean install, populated migration-013 upgrade and
both post-migration/ACL-pending recoveries passed. All eight candidate commands
exited 0; all eleven checks passed per target. Synthetic legacy data survived,
the temporary migration role was retired, and all terminal/replay catalogs
matched the independently reviewed reference exactly.

Before target initialization, separate source and input reviews accepted the
owner, coordinator and external bundles. The four target-specific bundles bind
the accepted 12 reference profiles, canonical operators, three handler runtime
gates and an explicit fresh-private-fixture maintenance attestation. They do
not attest production service drainage. The coordinator independently rechecks
application-role drainage and starts no application service. No target supplied
its own trusted reference. A first offline validation failed on a historical
file-mode assumption; the error is preserved, and full validation passed after
the new loader was corrected. Source-only tests pass 21 owner, 8 admission and
11 coordinator cases.

The archive contains 510 ordinary source/evidence input files. Root postchecks
verified current/archive hashes, all four complete 386-pin owner receipts,
external admission/bundle/catalog/command bindings, PostgreSQL exit 0 and absent
PIDs/runtime directories. A final 380-pin source check matches the corresponding
preflight subset; the other six pins bind the external admission inputs. An
actual operator invocation with the wrong external admission digest exited 1
before runtime initialization. This proves that specific admission rejection;
arbitrary live-catalog drift rejection remains a separate scenario.

Independent source/cleanup and runtime/catalog reviews
[accepted the four private selectors and terminal replay](../../staging/consumer-scram/bootstrap-runs/qualification-fc1f9a3c-718b-46f0-b2cc-c4a48d5e242f/bounded-acceptance.json).
Original outputs retain unreviewed labels. These are private
`APP_ENV=development` runs. The private production
branch, active schema/generated-client/operator integration, Consumer S5–S7
product integration and the remaining E1–E7 gates remain open. The separate
required private S7 growth pass above remains accepted within its own scope.
No production database,
remote laboratory host, deployment, cutover or publication was used.

### 2026-10-25 — Active Consumer source integrated; eight Linux images pass

The active auth service now contains the qualified 46-model Prisma schema and
an append-only 27th migration. All 26 earlier migrations remain byte-identical.
The regenerated 54-file Prisma client matches the accepted private handler
runtime copy. The canonical bootstrap and ACL stage preserve the qualified
reference, maintenance, source and catalog guards; deployment aliases enter
through `--no-env-file`. The operator requires an explicitly reviewed external
bundle and drained services. Existing local Compose migration wiring still
needs those new operator inputs and is documented as incomplete.

Independent source review found and resolved mismatches between URL identity
validation and the pinned PostgreSQL driver's actual connection settings. The
target helper now requires an explicit port, a closed unique query allowlist,
production TLS verification and the exact owned development socket exception.
It rejects unsafe inherited TLS/PG settings, startup-message NUL injection and
ambiguous URL encodings. Driver and startup-wire regression checks pass. The
schema inspector now requires the full promoted catalog and performs the
shared owner/access postflight inside its read-only transaction. Source tests
also cover JSON object-key ordering without weakening ordered type attributes.

All eight final Linux/amd64 images built on the Ubuntu VPS: auth, both migration
variants, API, identity, relay, operations and push worker. Their isolated
network-disabled, read-only container contracts passed with Bun 1.4.2 and a
non-root user. The [root image postcheck](../../../auth-app/artifacts/consumer-product-integration-20261024/8ea76f3b-fd1d-4de4-8f18-f3a1878265a4/final-build/root-post-verification.json)
verified all 143 source files and original build/contract receipts, exact
generated-client hashes where packaged, the packaged WASM identity operation,
and exclusion of a synthetic operator-input sentinel and known credential
environment keys. The earlier seven-image baseline predates target-helper
hardening and is retained separately. Independent review
[accepted packaging, ABI and configuration smoke only](../../../auth-app/artifacts/consumer-product-integration-20261024/8ea76f3b-fd1d-4de4-8f18-f3a1878265a4/final-build/bounded-image-acceptance.json).
The retained build driver and container-check script match their remote copies
after the build. Original receipts did not pin these scripts before execution;
the postcheck supplies no retroactive pre-execution attestation. This installed
container build tools on the VPS but deployed no Lomi
application and connected to no database. Windows and the Arch laboratory host
were not used.

The [active test/typecheck receipt](../../../auth-app/artifacts/consumer-product-integration-20261024/8ea76f3b-fd1d-4de4-8f18-f3a1878265a4/root-pure-check-results.json)
records 1,441 passing tests, 31 skips and 11 import errors in database-required
files when run with database settings absent. The full test command exited 1;
type checking passed. The required database lane and active guarded-install
Consumer bridge remain open, along with the private production branch and all
remaining E1–E7 gates. No production qualification, cutover or publication is
claimed.

### 2026-10-25 — Cloud restart audit preserves process fencing

A read-only audit of the [retained actual-handler Cloud receipt](../../../auth-app/artifacts/cloud-runtime-current-source-rerun1-20261023/be86aef1-b084-4cd2-a96d-29aa2e497c1e/runtime-proof.json)
and its matching archive/log distinguishes three already executed private
cases. A live Worker reconciles a committed publication with a lost ACK by GET,
without a second PUT. A new owner while the predecessor lease is live rejects
the predecessor binding and intent, preserves the outbox, and acknowledges or
publishes nothing. After lease expiry, a new owner claims a fresh generation
and publishes sequence 1; it does not retry the predecessor generation's
sequence-8 PUT.

That fresh-generation snapshot is required reclaim behavior, consistent with
the [process-bound runtime architecture](../../../remote-server/02-architektura.md)
and [startup fence protocol](../../../remote-server/04-protokol-workspace.md).
It must not be treated as an impermissible duplicate or repaired by retaining
the old process's admission. The narrower case of recreating only the Worker
object while retaining the same owner and live lease is not proved by those
receipts; it is distinct from owner-process restart. This audit executed no
runtime command and changes no Cloud or fail-closed behavior. The existing
private receipt does not close deployed relay, canonical Noise integration,
multi-client product acceptance or E2.

### 2026-10-25 — Active guarded operator passes; core SQL exposes logout faults

The [first active product SQL run](../../staging/consumer-scram/product-sql-runs/qualification-dad2c790-6afe-4f15-bdd7-184a6a36dce0/result.json)
finished in 88.884 seconds with exit 1: 119 tests passed, two failed and four
optional restricted-role cases were skipped. Its [source admission](../../staging/consumer-scram/product-sql-runs/qualification-dad2c790-6afe-4f15-bdd7-184a6a36dce0/source-acceptance.json)
binds 823 ordinary source/input/controller files and 392 source/external-input
pins. Two independent source reviews and 7 Python/13 pinned Bun helper tests
resolved diagnostic UTF-8 truncation, real Bun summary grammar, failed clone
teardown reporting and bounded PostgreSQL client closure before execution.
The inherited 240-second work and 60-second cleanup limits are unchanged.

The accepted reference bootstrap/replay passed, followed by the active canonical
operator's terminal replay and full active schema inspector. Each of the eleven
required SQL test files received its own fresh `lomi_auth_test` clone, and all
eleven clones were removed. The final canonical A6 catalog, global role graph
and source inventory remained unchanged. PostgreSQL exited 0; the
[root postcheck](../../staging/consumer-scram/product-sql-runs/qualification-dad2c790-6afe-4f15-bdd7-184a6a36dce0/post-verification.json)
verified complete original receipts, all 823 current source files before
releasing the freeze, the 392-pin input receipt, absent PID 30085 and removal of
the owned runtime. This proves active terminal replay/inspection within this
private run; it does not prove active cold installation or a passing SQL suite.

Both failures were in `remote-auth.test.ts`. Repeating logout rewrote terminal
revocation timestamps and correctly hit the new SQL guard, returning 503. A
second fixture tried to change an issued service authorization's version, which
the new immutable-birth guard correctly forbids. The handler now revokes only
nonterminal rows while retaining related-row cleanup. Tests retain and compare
terminal stamps, reject in-place version changes, and exercise account recovery
and fresh same-user authorization without reviving the old cookie. The push
role test also now checks the complete installed guarded ACL read-only instead
of reapplying a partial permission baseline; all 28 push tests passed in this
run. Type checking passed after the logout changes; the corrected logout tests
have not yet run against SQL.

Independent review
[accepted the failed capture and bounded active terminal replay/inspection](../../staging/consumer-scram/product-sql-runs/qualification-dad2c790-6afe-4f15-bdd7-184a6a36dce0/bounded-failure-acceptance.json).
The actual run remains failed. The original result and redacted diagnostics
are preserved. The next
run must distinguish the historical handler reference from changed active
product source; the old fixture's active-source equality check must not freeze
product development or be bypassed by editing accepted evidence. The earlier
Linux image acceptance also predates this logout fix and is not a build of its
new source. Active Consumer S5–S7, required restricted-role coverage, the private
production branch, full E1–E7 acceptance and production qualification remain
open. No deployment or publication was performed.

### 2026-10-25 — Active core SQL passes after the logout fix

The [corrected core SQL run](../../staging/consumer-scram/product-sql-runs/qualification-a0b354f9-d25e-4542-90fd-c253395c0be0/result.json)
exited 0 in 83.545 seconds: 121 tests passed, none failed and four optional
restricted-role cases were skipped. All eleven fresh clone cycles completed.
The logout retry, terminal timestamp preservation, immutable authorization
version, account recovery and fresh same-user authorization checks passed.
The intervening [failed rerun](../../staging/consumer-scram/product-sql-runs/qualification-c1e9ba89-46fd-4d99-a73d-871d12f546b9/bounded-failure-acceptance.json)
remains failed with 120 passes, one failure and four skips: its last failure
was Bun's matcher rejecting a lazy Prisma promise. The corrected test converts
it to a native promise before checking the rejection.

The product owner now validates the frozen historical handler separately from
the 307-file current product inventory. A small wrapper supplies that historical
verifier at both qualification admission gates through explicit dependencies;
the default verifier and public CLI still require current handler equality.
The complete reference, maintenance, four-bundle and operator checks remain in
force. Historical accepted archives and evidence are unchanged. Source checks
passed 10 Python, 25 pinned Bun and eight Node tests before the run; the small
promise/manifest follow-up passed type checking and the focused owner/SQL tests.

The [postcheck](../../staging/consumer-scram/product-sql-runs/qualification-a0b354f9-d25e-4542-90fd-c253395c0be0/post-verification.json)
verified 828 ordinary source/input/controller files and all 394 receipt pins,
complete report bindings, exact final A6/global roles and closed clients.
PostgreSQL exited 0; PID 13888 and the owned runtime are absent. Independent review
[accepted this bounded core result](../../staging/consumer-scram/product-sql-runs/qualification-a0b354f9-d25e-4542-90fd-c253395c0be0/bounded-core-acceptance.json).
This is private core SQL acceptance with
four role cases excluded. The next increment must use real API/exchange
credentials for those cases and real identity-runtime credentials for health,
without adding grants to force success. Active cold installation, full Consumer
S5–S7 and the remaining E1–E7 product/release gates remain open.

### 2026-10-25 — Genuine-role SQL passes all 125 cases

The [genuine-role run](../../staging/consumer-scram/product-sql-runs/qualification-af0cc238-2bb0-4973-a716-4834082b84dc/result.json)
exited 0 in 70.745 seconds: all 125 tests passed with no skips or failures.
The three formerly skipped Remote API cases use the actual `lomi_remote_api`
login, and the exchange case uses `lomi_remote_exchange`. The health test now
uses the actual `lomi_runtime` login. Each role authenticated on the relevant
fresh clone; a read-only probe checked exact session/current identity, login,
privilege flags, inheritance, zero memberships and denied schema creation before
the test child started. No grant or `SET ROLE` was added to manufacture login
evidence. Ten ordinary fixture files retain the admin connection for setup.

The [postcheck](../../staging/consumer-scram/product-sql-runs/qualification-af0cc238-2bb0-4973-a716-4834082b84dc/post-verification.json)
verified all 828 source/input/controller files, the complete 394-pin receipt,
report and marker bindings, all eleven created/dropped clones, exact final A6
and global role graph, stable source and closed clients. PostgreSQL exited 0;
PID 48452 and the owned runtime are absent. Independent review
[accepted this bounded private core/role result](../../staging/consumer-scram/product-sql-runs/qualification-af0cc238-2bb0-4973-a716-4834082b84dc/bounded-role-acceptance.json).
Original producer labels and all prior failed
captures remain unchanged.

This closes the four skipped cases from the earlier core run and adds genuine
runtime-role readiness. It does not qualify current active cold installation,
complete Consumer S5–S7, Cloud/relay integration or production. The next Consumer
runtime phase must exercise the current applications and all eighteen issuance,
lifecycle and signed-transaction markers on an actual guarded clone, preserving
the separately accepted historical S7 population evidence.

### 2026-10-25 — Current private Consumer S6 passes

The [current S6 run](../../staging/consumer-scram/product-sql-runs/consumer-a5aa3471-90e1-40f5-a4e1-d0a35bbfb58e/result.json)
exited 0 in 178.673 seconds. Its dedicated suite ran exactly one test with no
failures, errors or skips. All eighteen markers passed, including all fifteen
typed overloads, active web/mobile issuance and lifecycle, signed Pairing,
Channel and Ticket transactions, revoke, transaction rollback and lost-response
outcomes. Read-only probes authenticated the real API, exchange and runtime
roles with their restricted attributes. The unchanged 240-second work and
60-second cleanup limits were retained; the core SQL suite remains a separately
accepted run.

The [root postcheck](../../staging/consumer-scram/product-sql-runs/consumer-a5aa3471-90e1-40f5-a4e1-d0a35bbfb58e/post-verification.json)
verified all 830 captured source/input/controller files and 394 input pins,
complete report and marker bindings, stable canonical A6/global roles, closed
clients and the created/dropped clone. PostgreSQL exited 0; PID 18788 and the
owned runtime are absent. Independent review reconstructed the complete
771-byte consumer stdout and verified its command hash, source/archive/input
bindings and cleanup, with no material findings. The separate
[bounded S6 acceptance](../../staging/consumer-scram/product-sql-runs/consumer-a5aa3471-90e1-40f5-a4e1-d0a35bbfb58e/bounded-s6-acceptance.json)
preserves all original producer labels and historical/current distinctions.

This closes current private S6 runtime qualification. The historical candidate
still performed cold installation before active canonical terminal replay.
Actual current cold installation, live catalog/owner drift rejection, full
S5/S7 and all remaining E1–E7 product/release gates stay open. Windows and the
Arch laboratory host were not used. No deployment, cutover or publication was
performed.

### 2026-10-25 — Current canonical development cold install passes

The [current cold-install run](../../staging/consumer-scram/product-sql-runs/cold-install-11bb02ab-d746-43c9-9782-1cb51be2e7c8/result.json)
exited 0 in 79.946 seconds. The first command now executes the current active
`auth-app/ops/remote-db-bootstrap.ts` against the independently reviewed empty
development profile. It reached exact canonical A6 and replayed without catalog
drift. A third active replay, the full inspector, all 125 core SQL tests and
eleven fresh clone cycles passed without errors, failures or skips. Real API,
exchange and runtime login probes retained their restricted attributes.

The product-only `--bootstrap-source current-canonical` mode preserves the
historical default and standalone CLI. Source checks run before connection,
before and after both bootstrap commands, and before report persistence. The
raw version-2 bootstrap report retains historical `referenceSource` separately
from the current manifest/tree/entry/stage/target `executionSource`. Validators
check that extension before passing only the reference invariants through the
unchanged historical validator; the original raw report and SHA remain intact.
The current cold-install claim requires the complete empty-to-terminal and
stable replay evidence. Source validation passed 37 pinned Bun and 16 Python
tests plus a syntax compile. A full staging typecheck still reports existing
historical/staging typing diagnostics; it is not claimed as passed.

The [postcheck](../../staging/consumer-scram/product-sql-runs/cold-install-11bb02ab-d746-43c9-9782-1cb51be2e7c8/post-verification.json)
verified all 831 archived/current files, 395 source/input pins, original complete
owner/report bindings and all three success-marker hashes. PostgreSQL exited 0;
PID 78563 and the owned runtime are absent. Root and independent review
[accepted only current private development clean installation, replay and core SQL](../../staging/consumer-scram/product-sql-runs/cold-install-11bb02ab-d746-43c9-9782-1cb51be2e7c8/bounded-cold-install-acceptance.json).
Source-preparation count/alias corrections are retained separately and started
no runtime. All producer labels and historical evidence remain unchanged.

A separate [bounded source/routine comparison](../../staging/consumer-scram/product-sql-bridges/source-1217e318-1436-4f41-b8b1-069fc5fa1538/bounded-comparison-acceptance.json)
verified all seven unchanged S7 recipe sources and 122 matching routine
owners/ACLs/security settings in the historical and independent canonical
catalogs. Of their definitions, 102 hash identically and 20 differ only in
composite argument-type qualification in the rendered header. This establishes
no relation/index/constraint/trigger parity and transfers no S7 runtime pass.
The historical S7 test itself took 219.53 seconds; 266.193 seconds was the whole
S0–S7 run. A complete current S7 invocation's fit within the unchanged owner
budget remains unmeasured.

Full phase-bound S5 and current S7, other active installation profiles, the
private production branch and all remaining E1–E7 product/release gates stay
open. Windows and the Arch laboratory host were not used. No deployment,
cutover or publication was performed.

### 2026-10-25 — Namespace ownership bypass corrected; full S5 stays open

The current product S5 run reached the helper denial matrix but failed on
migrator `DROP FUNCTION` after five successful denials. All earlier phase
controls, eleven bootstrap checks, eleven negative ACL probes, and host/parent
preservation had passed. Its original failure is retained and postverified;
it does not qualify S5.

The product bootstrap had assigned `public` to `lomi_migrator`, allowing
namespace ownership to bypass the sealed function owner. Bootstrap now retains
the administrative owner and grants the migrator explicit `USAGE, CREATE`.
A catalog guard rejects direct, inherited, assumable, or implicit database
ownership before creating the temporary migration login, after its grant, and
at postflight. The inspector checks the same boundary read-only. Independent
source review found no material issues; 35 focused Auth tests passed, one
existing guarded PostgreSQL test was skipped, and Auth TypeScript passed.

A separate native regression reproduced the old direct-CASCADE bypass and
passed all 80 direct helper/actor/operation denials (`42501`) with unchanged
rollback captures under the corrected policy. It also rejected five unsafe
ownership/login states. Root verified 172 full captures, ten archived sources,
client closure and absence of PostgreSQL PID 77349 and its private runtime.
Its helper bodies are synthetic signature-equivalent fixtures, so this is
neither a full product install nor full S5 qualification.

The [namespace policy evidence and next gate](../../staging/consumer-scram/namespace-policy-next.md)
records both failed product S5 runs, the native regression, the 313-file source
manifest successor, and the remaining independent reference/admission work.
Old canonical A6, historical reference/admission data, and prior cold/S6
acceptance retain their original source and namespace policy. No owner/ACL
fields are ignored and no historical result is relabeled to admit this fix.
Current S5/S7 and remaining E1–E7 product/release gates stay open. Windows 10
LTSC and the Arch laboratory host may remain off until advance notice. No
deployment, cutover or publication occurred.

### 2026-10-25 — Namespace S7 integration runs but does not pass

The new namespace S7 owner/coordinator and root controller passed source review;
the owner passed eleven focused tests. The native run in
`namespace-s7-runs/61e079c1-ffe4-4547-b866-e09d7667e0da/` completed with a failed
result after 485.877741 seconds. Current bootstrap passed, but the consumer
driver aborted during `exchange-batch`. It completed the 1,000-principal growth
point and did not complete the required 10,000 point or later lifecycle cases.
The existing inner 360-second deadline and 420-second test limit are unchanged.

Clone removal, all fifteen fixture cleanup counts, terminal catalog and role
graph preservation, 752 source pins, five retained output receipts and owned
PostgreSQL teardown passed. The strict postcheck preserves the failed outcome
(`6f7a5038…`); it does not qualify S7. The [native result](../../staging/consumer-scram/namespace-s7-runs/61e079c1-ffe4-4547-b866-e09d7667e0da/result.json)
is `02c46850…`, and its [runtime evidence](../../staging/consumer-scram/namespace-s7-runs/61e079c1-ffe4-4547-b866-e09d7667e0da/result.json.s7.json.evidence.json)
is `3c8bc267…`. The earlier Python 3.9 startup failure remains separate; the
new controller guards its interpreter version and used Python 3.14.7.

Current S6/S7, core SQL, Cloud/relay and all later production gates remain open.
No Windows/Arch access, deployment, cutover or publication occurred.

### 2026-10-25 — Independent namespace reference matrix passes

All eight [namespace reference runs](../../staging/consumer-scram/namespace-reference-runs/cohort-98320787-df83-4980-8506-f3d228677966/matrix.json)
passed: two independent series across all four clean/populated/ACL-recovery
selectors. Root and independent artifact review verified 432 archived/current
sources, eight 440-pin receipts, all 24 complete snapshot digests, all twelve
corresponding cross-series phase profiles, and reproduction of all 32 operator
hashes. All PostgreSQL children exited zero; their PIDs and private runtime
directories are absent. The new terminal is `faff08c9…`; full catalog changes
from the predecessor are limited to schema ownership/ACLs.

The separate [bounded reference acceptance](../../staging/consumer-scram/namespace-reference-runs/cohort-98320787-df83-4980-8506-f3d228677966/bounded-reference-acceptance.json)
permits private admission preparation only. It does not transfer bootstrap,
current handler runtime, full S5/S7 or production acceptance. The preceding
PATH-rejected run remains failed and postverified; its correction has an
actual Python-environment/JavaScript-validator regression.

Current runtime gates are being prepared using a complete 313-file copy of
the active Auth inputs plus three fixed SCRAM test fixtures. This keeps the
current generated client and logout fix while preserving all frozen evidence.
The current S6 marker alone does not prove the named typed-resolver, legacy
desktop-lifecycle and no-scalar-fallback gates. The
[namespace evidence note](../../staging/consumer-scram/namespace-policy-next.md)
also records repaired S5 failure diagnostics and S7 report/evidence handling.
S7 still needs an explicit supported lifecycle budget; no S7 native run or
production acceptance is claimed.

### 2026-10-25 — Current namespace API runtime gates pass

The fresh [namespace runtime run](../../staging/consumer-scram/namespace-runtime-runs/runtime-44fbf55b-7a7c-4670-8f5c-18c2da62f8d9/result.json)
passed all three named API gates and eighteen original assertions on real
owned PostgreSQL in 29.98 seconds. It used all 313 current Auth input files
plus three frozen SCRAM fixtures, including the current generated client and
idempotent logout fix. Typed queries were observed twice; scalar queries were
never observed. All seventeen coordinator checks and three cleanup checks
passed; before/after/seed terminal catalogs match the new namespace reference.

Root postverification and independent artifact review checked 762 archived and
current sources, all 771 owner pins, all raw evidence and marker reconstruction.
PostgreSQL PID 83706 exited zero and is absent; the private runtime is absent.
The separate [bounded runtime acceptance](../../staging/consumer-scram/namespace-runtime-runs/runtime-44fbf55b-7a7c-4670-8f5c-18c2da62f8d9/bounded-runtime-acceptance.json)
permits preparation of private bootstrap inputs only. Original raw labels stay
unreviewed. Actual canonical bootstrap, full S5, current S7 and production are
not qualified by this result. The private namespace bundle/admission producer
and loader are under review; preparation has not started a qualification target.

Windows 10 LTSC and the Arch laboratory machine remain unnecessary for the
nearest Mac-based checks and may remain off until advance notice. Neither was
accessed. No app deployment, cutover or publication occurred.

### 2026-10-25 — Private namespace bootstrap inputs prepared

Independent source review accepted the producer and loader. The producer checks
all eight full reference results, all 24 physical execution/owner/postcheck
receipts and their source vectors, the fixed reference source snapshot, and
the fresh runtime gate evidence. The loader binds all four target-specific
bundles to those exact profiles, pins, operators, runtime gates, source and
maintenance records. Fourteen focused Bun tests passed with 123 assertions;
the scoped TypeScript check passed.

The new private admission is
`namespace-bootstrap-admissions/d0e66818-2c84-4b5e-b944-2f35eee9b01a/admission.json`
(`f172d760…`). Actual filesystem admission passed for all four selectors.
The separate loader verification (`b924a3bc…`) confirms seven private canonical
files and absence of all four planned qualification runtimes. It retains a
preceding controller failure caused by an incorrect eight-file expectation;
the exact seven-file schema was verified without changing producer inputs.
Independent artifact review reproduced all seven producer buffers and checked
all sixteen operator hashes, accepting private-input readiness only. The
separate bounded decision requires a reviewed runtime owner and coordinator
before execution. No actual canonical bootstrap, full S5/S7 or production
acceptance is claimed.

### 2026-10-25 — Current canonical profile matrix and selected full S5 pass

The actual current canonical CLI and replay passed on all four private
development profiles in
`namespace-product-runs/69ae6313-1e60-489a-ac86-e43d7f335f31/`. Each result passed
all eleven bootstrap and eleven postcheck flags. Independent review verified
1,190 source/archive files, every 737-pin receipt, actual command marker hashes,
exact admitted catalogs and preserved legacy fixture fingerprints. All four
PostgreSQL children exited zero; their PIDs and runtime directories are absent.

The ACL-pending-clean run also passed the full current S5 phase and final ACL:
28 owner-state rejections/controls, 80 helper denials, eleven negative ACL
checks, rollback and role/table/column/host preservation. The helper/ACL denials
returned `42501`; twenty helper checks used a genuine migration login/current
migrator. All 251 raw captures (397,322,877 bytes) and referenced function
definitions were independently validated. Final/replay catalogs match
`faff08c9…`. The failed predecessor runs remain failed.

The [canonical profile matrix acceptance](../../staging/consumer-scram/namespace-product-runs/69ae6313-1e60-489a-ac86-e43d7f335f31/bounded-profile-matrix-acceptance.json)
(`2f99f875…`) covers the four private-development canonical profiles. The
[selected S5 acceptance](../../staging/consumer-scram/namespace-product-runs/69ae6313-1e60-489a-ac86-e43d7f335f31/s5-aclPendingCleanInstall/bounded-s5-acceptance.json)
(`cb66b1cb…`) covers its current phase/final ACL. Neither result qualifies
current full core-SQL clone tests, S6/S7, private production mode, Cloud/relay,
host services or production release. Original producer labels stay unreviewed.

A separate versioned lifecycle helper passed source review and five focused
tests for the proposed S7 work/cleanup policy (720/60 seconds, coordinator660,
driver420). Its verified loader fixes a forged-module identity gap; the pinned
supervisor's original 240/60 defaults and clocks remain unchanged. S7 now needs
the completed namespace bootstrap candidate, same-live-target driver integration
and measured native qualification. Windows/Arch were not accessed, and no
deployment, cutover or publication occurred.


### 2026-10-25 — Current namespace consumer S6 accepted; S7 remains failed

The actual consumer S6 lane passed after a completed clean namespace bootstrap
in `namespace-s6-runs/3e55148a-cafc-4f17-8e19-3fb6ec657ffb/`: one test, 875
assertions, all eighteen acceptance-marker fields and three genuine restricted
role probes. All sixteen coordinator, seven owner and eleven bootstrap checks
passed. The clone was created and dropped once, catalog/roles stayed stable,
and PostgreSQL PID 52853 exited zero with PID/runtime absent. The owned run took
30.460405 seconds. Independent review verified 1,199 source/archive files, 744
pins and both retained output receipts. The bounded acceptance is `681a1b22…`;
its scope is the private current clean-install consumer S6 lane. It does not
qualify core SQL, S7, host services, clients or production. Original producer
labels and broader flags remain unchanged.

The new S6 Node/Python integration passed source review, nine Bun tests with
106 assertions and thirteen Python tests with real Node-emitted consumer/core
fixtures. Partial clone/admission/role failures, genuine Bun error-count
overlap, wrapped and whole-fixture timeouts, and persistent output drift are
covered. It retains the original 240/60 supervisor and 230-second coordinator
cap. An actual eleven-file core run is separate and not yet accepted here.

S7 CPU diagnostic `ad3e8ebe…` remained failed; its 6,304 samples and long sample
gaps do not establish per-function CPU cost or a failure cause. The subsequent
normal, non-profiler run `3712bf12…` reached both 1,000/10,000 growth points, ten
delete-plan observations, two source-TTL observations, private seed receipts
and populated lifecycle evidence, with no missing cases. It still failed the
post-cleanup completion check with an abort after 447.480499 seconds overall.
The exact abort time relative to cleanup was not captured. Independent review
verified 1,213 files, 752 pins, five outputs and full cleanup; PG 65403/runtime
are absent. Failed evidence review `eeee46a4…` preserves the failed outcome.

At the authorized QEMU stop recheck, both identified processes were already
absent; no signals were sent. No QEMU process was observed in later checks.
A catalog audit identifies possible unindexed cascade lookups but does not
prove their timing impact. The new bounded three-query cleanup observer and
private preload integration passed independent source review and seventeen
Bun tests with 123 assertions. Native measurement still needs the additional
root receipt/source pins. No deadlines, workload, foreign keys or triggers
were relaxed. No Windows/Arch access, deployment, publication or cutover took
place.


### 2026-10-25 — Current namespace core SQL suite accepted

The actual exported eleven-file core SQL suite passed after the current clean
namespace bootstrap in `namespace-s6-runs/3f4203e9-afba-43d7-852c-d8be55c62ff7/`:
125 tests and 3,020 assertions, zero failures/skips/errors, eleven fresh clones
created and dropped. Sixteen coordinator, seven owner and eleven bootstrap
checks passed. Catalog/global roles stayed stable; PostgreSQL PID 86328 exited
zero and its PID/runtime are absent. The owned run took 37.516389 seconds.

Independent review verified 1,199 current/archive files, 744 pins, all eleven
command/summary receipts and both original output files. Restricted-role
evidence covers the three required API/exchange/runtime probes; it does not
claim all 125 tests ran under restricted roles. Bounded core acceptance is
`78e38efacb1e5f1a626d933edab687936adaa8fd3f4ba6d41356c28f4037c5f9`.
Original producer labels and wider flags remain false. This result qualifies
only the current private core SQL lane; S7, full E1/E2, host/client integration
and production gates remain open. No deployment/publication/cutover occurred.

### 2026-10-27 — Real browser snapshots and current Cloud ACK recovery

The host now implements grant-limited `workspace.capabilities`, admits terminal
channels using live owner membership, and drains queued output across idle
siblings without an idle wait between fragments. Idle-only connections retain
the 250 ms wait. Original operations, deadlines, priority work and every
fragment's authorization checks remain in place. Native build
`namespace-joined-cloud-builds/e664f94e-4823-4a51-b037-acc8b4a3860a/` passed all
51 selected ingress regressions, including real TLS/Noise 80×24 snapshots with
two busy clients and an idle workspace sibling. Its 512-file build closure
still excludes CLI source contents; these tests do not qualify whole-actor
performance or release targets.

Remote Web initializes snapshot assembly from the metadata returned by
`terminal.attach`, before consuming chunk frames. Frozen Web build
`namespace-remote-web-builds/terminal-attach-metadata-4d4b8014-8166-4bc4-8620-8d527146df2e/`
passed 55 tests and its build checks. Actual integration
`namespace-current-cloud-runs/772ea0a8-b60f-499d-b989-c793feb847a1/` rendered both
real terminal grids and granted the first window input control, but failed at
`INPUT_FAILED`. All 1,210 source bookends matched and cleanup completed, with
PostgreSQL exit zero. Worker lease renewal, bounded ordered input buffering and
typed error handling are subsequent changes under implementation and test;
the frozen build's pass does not qualify those changes.

Fresh actual Cloud ACK run
`namespace-current-cloud-ack-runs/9fac44af-f989-4768-b27e-d981d0518287/` passed
on the new native build: one test, 14 checks, three real role probes, 74 strict
marker fields and 51 correlated requests. The real TCP response drop,
worker recreation and owner restart reconciled publication state without
repeating the PUT. Independent review verified 1,220 stable inputs, retained
captures and full cleanup, including the absent canonical runtime. This is
bounded ACK-cycle evidence; it does not qualify Joined, real-relay recovery,
full S5/S7, E1/E2 or production.

New source preparation
`namespace-current-consumer-sources/a89b09ba-c5e6-41a0-a1c5-853ec682a69b/`
independently verifies 318 live/copied backend files, the exact two-file change
and one-test addition, all 28 unchanged migrations, and the physical dependency
tree from 18,189 files and 22 approved links plus separate Prisma tools. Its
manifest is `0c5623a4…`, tree `d7eab939…` and receipt `2d16d1ae…`. Dependencies
were verified but not copied; optional native evidence was not supplied.
Source bookends cover copying and manifest verification, with the dependency
scan and receipt write following them. Fresh admission must recheck its inputs.
All admission, runtime and S5/S6/S7 qualification flags remain false. Earlier
317-source results are preserved and are not transferred to the changed code.

### 2026-10-27 — Control lifecycle and current catalog equivalence

Remote Web now renews worker-private terminal control leases and serializes
bounded input/resize queues. It preserves typed host errors, expires control
conservatively and never replays an uncertain mutation. Frozen Web build
`namespace-remote-web-builds/terminal-input-diagnostics-b199a8e7-128e-4e6f-a5c4-5e7cd88435d6/`
passed 114 tests, Astro and static/package checks; independent review verified
222 source inputs, 18,933 dependency entries and 22 assets. The protocol WASM
remains one copy. Forty focused diagnostic tests, strict staging TypeScript
and seven asset-loader tests also passed.

Actual Joined run
`namespace-current-cloud-runs/b27fb7fd-9a56-44a4-871f-fa894c7b7b05/`
still failed at `INPUT_FAILED`. Both grids opened, and the first window
initially acquired control. Its new input receipt establishes that control
was already lost with `OUTCOME_UNKNOWN` before typing: bringing the page to
the front completed, focusing the controlled terminal timed out, and neither
typing nor Enter started. The failing RPC and host scheduling cause remain
unproven. All 1,210 source bookends matched; owned resources were cleaned,
PostgreSQL exited zero and the canonical runtime is absent. This run does not
qualify input delivery, no-replay, unshare, or E1/E2.

Pure catalog-equivalence preparation completed and passed independent review:
`namespace-current-consumer-catalog-equivalence/1a08e432-91b5-4c8b-94bf-d8d226967b2d/`
contains certificate `f66be0da…`, bound to producer `a9e96618…` and actual
execution receipt `ebcb3870…`. Ten unit tests and strict TypeScript passed.
The preparation keeps the original 317-file catalog provenance separate from
the current 318-file execution source, verifies the exact 315 unchanged plus
two changed and one added files, and reproduces all 32 operator comparisons.
All eight original reference results, their 24 receipts, physical dependencies,
raw locks, reference assets and tools were rechecked before and after operator
compilation. Earlier rejected preparation attempts remain retained.

This accepts source/catalog equivalence preparation only. Fresh current
runtime gates, versioned admission and full Consumer S5/S6/S7 remain required.
No historical runtime or qualification pass transfers to the changed product.
No deployment, publication or cutover occurred.

### 2026-10-27 — Renewal timeout attribution and runtime source preparation

Fresh actual Joined run
`namespace-current-cloud-runs/cb9460cb-3102-4fd8-b18e-f59c6a0f1ea4/`
identifies the first window's failure as `RENEWAL_TIMEOUT`: the client timer
for the validated `terminal.renew` request expired and input control was disabled.
Input observations begin with that failure already latched. Focus never
completed and neither typing nor Enter started. This establishes the failing
request, not the native phase responsible for its delay. Both terminal grids
opened. All 1,210 source bookends matched, cleanup completed and PostgreSQL
exited zero. Input, no-replay, unshare and full E1/E2 remain unqualified.

The run used independently reviewed Web build
`namespace-remote-web-builds/terminal-timeout-map-91d93430-36b2-446c-b95d-1a66d58abaf2/`
(`2b646748…`), with 116 tests and 481 Bun assertions passing. Forty-nine
focused tests, strict staging TypeScript and seven loader tests passed. The
review found and closed a diagnostic prototype-key lookup issue before the
actual run; its negative cases cover inherited keys and getters. Timeouts,
lease TTL, fail-closed behavior and one-shot requests were not relaxed.
All 18,902 dependency file copies have separate inodes and single links;
APFS cloning saves disk space while every byte hash remains checked.

New runtime source cohort
`namespace-current-consumer-runtime-sources/eab04a78-0880-4034-9a18-ff60df418d0e/`
passed independent source-closure review: 321 exact private files combine
the current 318-file source with three pinned frozen gate fixtures. Manifest
`97a10cc3…`, tree `24f283e1…` and receipt `b5cffa9b…` bind the sole separately
declared dependency link. Eleven focused tests passed. The producer exited
zero; the root launcher's incorrect postcheck field and its first supplemental
argument error remain retained as failures. A successful supplemental check
(`526d8e40…`) reverified the physical source and dependencies without repeating
the producer. This is source preparation, not an executed runtime gate.

The catalog helper now exports its existing pure verifier without changing
its behavior. The new revalidator `61b86907…` reproduced the exact original
271,699-byte certificate `f66be0da…`, with no new certificate created; ten tests
and strict TypeScript passed. Independent review preserves the distinction
between original producer `a9e96618…` and the new revalidator. A new versioned
runtime contract and coordinator are under implementation; fresh runtime
gates, admission and Consumer S5/S6/S7 are still required.

### 2026-10-27 — Handler timings and a bounded TCP candidate

Actual run `namespace-current-cloud-runs/5a294bcb-e5c9-4e03-af32-4ebeb6917c3d/`
again failed with `RENEWAL_TIMEOUT` before input. New bounded handler timings
record 392 Pairing GETs: 958 ms total, 2.44 ms mean and 18 ms maximum until
the handler produced its response. These observations exclude listener queueing,
DNS, connect/TLS, socket delivery and native owner work; they do not establish
the phase responsible for the renewal timeout. All 1,210 source bookends and
cleanup checks passed, with PostgreSQL exit zero.

`lomi-host-http` now sets TCP_NODELAY before handing a connected socket to
TLS/HTTP/WebSocket code, preserving the original operation checks and deadlines.
Build `namespace-joined-cloud-builds/c3a2881b-3a73-429d-a3e4-9197afee8d72/`
has 512 stable source inputs, with only `budget.rs` changed from `e664…`.
All 64 HTTP tests and 51 selected TLS/Noise ingress regressions passed. The
CLI source contents and full tool/dependency closure remain outside this
bounded source claim.

The comparison run
`namespace-current-cloud-runs/d58cbe02-9772-4822-9740-a7a5361876b1/`
failed earlier at `BROWSER_CONSUMERS_FAILED`: the first grid never appeared,
and the terminal connection stopped before any input attempt. The run proves
no latency improvement or successful consumer path. All resources were cleaned,
PostgreSQL exited zero and the source bookends matched. Bounded test-only native
failure diagnostics are being added to identify that earlier failure.

Review found that the historical native build/verification recipes could delete
scratch after an unconfirmed command-cleanup exception. Their recorded successful
captures remain unchanged. New private templates under
`namespace-joined-cloud-runner-templates/bf34aa3e840fb20f653eea5b9650c4bd/`
latch uncertain termination, refuse further commands and retain scratch unless
termination and directory identity are verified. No-process fault tests passed
with stable source bookends (`9e65433a…`). Future native runs use these guarded
templates; earlier recipes remain as execution provenance.

The new Consumer runtime contract and coordinator passed 21 focused tests,
183 assertions, strict TypeScript and full pure-source preflight against the
current 318/321-file closures (`6896a463…`). The preflight uses an explicitly
synthetic context and creates no runtime or database. Independent review closed
legacy JSON, predecessor reservation, receipt-write and context-rejection-latch
defects. The real runtime owner and actual three-gate execution remain pending;
all admission and qualification claims stay false.

### 2026-10-27 — Native first-frame refresh failure localized

Test-only native ingress diagnostics now retain at most 64 closed-schema
records while hashing every original stdout/stderr byte. Records contain
fixed categories, bounded counters and booleans, without identities, keys,
leases, input or error text. Eleven focused tests and strict TypeScript passed
(`37fdb931…`); the earlier rejected test-typing attempt remains preserved.
Independent review accepted this bounded diagnostic scope.

Guarded build `namespace-joined-cloud-builds/2e50bf35-603f-4f1a-bfeb-e6db3baf3086/`
completed with 512 stable source inputs, 64 HTTP passes and 51 selected
TLS/Noise ingress passes. Independent review verified captures, binaries,
source bookends and confirmed scratch removal after terminal commands.

Actual run `namespace-current-cloud-runs/2ae03d0c-82f5-4277-9eab-4928326a5df2/`
still failed before the first terminal grid. Its native diagnostic identifies
`CONNECTION_TURN_ESTABLISHED`, `INVALID`, at `remote_ingress.rs:1636`, the
`refresh_peer` call before frame opening or RPC dispatch. The connection had
processed zero requests and had existed for 2,425 ms. This localizes the
refresh wrapper; it does not yet establish which authority, clock or terminal
membership predicate rejected it. Further test-only origin attribution is
being verified without relaxing the security checks.

The actual run's 1,210 source bookends matched. Native exit was zero and
all owned cleanup checks passed, PostgreSQL exited zero, and the canonical
runtime is absent. Joined receipt `18655f46…` and owner receipt `2f137c54…`
remain failed integration evidence. Input, no-replay, unshare, full E1/E2,
Consumer S5/S6/S7 and production acceptance remain open.

### 2026-10-27 — Parallel product integration and bounded verification

The host now dispatches `git.repositories`, `git.status`, `git.diff`, `git.log`
and `git.show` through an owned two-worker executor. Jobs retain their original
deadline, cancel when their channel is discarded, and pass the ordinary current
owner/peer gate before results and each response fragment. Oversized escaped
JSON produces a bounded resource error instead of closing the connection.
All five reads, a subsequent workspace request, denial without GitRead,
pending-read unshare and unshare after the first diff fragment passed real
TLS/Noise tests in the existing ingress fixture.

The first combined host scope retained its failed result: HTTP 64/64, connection
gates 52/52 and ingress 53/54. The terminal-purpose test waited beyond its
five-second control lease while its sibling streamed a snapshot. After the
fixture ordering correction, the fresh combined
[host result](../../artifacts/scoped-checks/host-c115a778-2d07-44c0-b9b6-f126c1160337/report.json)
passed all 175 tests: 64 HTTP, 52 connection, 54 ingress, one original-deadline
and four Git executor cases. Production lease and freshness limits stay
unchanged. Full current Cloud/relay/browser acceptance remains open.

Current Consumer S5 has a separate fresh ACL-pending reference capture with
passing migration, namespace, catalog and replay checks. Its historical catalog
reference and current execution source remain distinct. Full target-bound S5
qualification, S6 and S7 are still required.

Mobile native identity persistence and authenticated channel verification pass
Rust/bridge checks and compile for Android and iOS simulator. Normal iOS builds
use source-built Expo modules with the installed compiler. Backend mobile-window
channel/ticket support, active v2 wiring and device acceptance remain open.

`tools/check.py --scope host|consumer|web|git` keeps the existing owned command
lifecycle and one private report per invocation. Implementers run focused checks
before integration. Git stage/unstage reached a working engine checkpoint;
independent publication findings are being fixed before RPC activation. No
complete E1–E7 or production claim follows from these component results.
