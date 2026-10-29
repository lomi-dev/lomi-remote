# Consumer derivative PostgreSQL qualification preparation

**PREPARED, NOT EXECUTED.** This directory contains an input verifier, fixture-only
SQL, staged acceptance recipe and static checks. It has no PostgreSQL runner.
Root must explicitly admit a fresh owned PostgreSQL appointment after the current
appointment is released. Even `postgres --version`, `psql --version`, initdb or a
read-only SQL connection is prohibited before that admission. An argument, file
or local boolean is not a substitute for root admission.

The frozen reviewed candidate and all NULL pins are unchanged. This task does
not add a live migration012, TS/Prisma/UI code or evidence of SQL/HTTP/BetterAuth
integration. Future fixture SQL acceptance cannot establish those integrations.

## Current permitted commands

From the Lomi workspace:

```sh
python3 lomi-remote/tests/consumer-derivatives/validate.py
python3 lomi-remote/tests/consumer-derivatives/prepare.py --check-inputs
python3 lomi-remote/tests/consumer-derivatives/prepare.py
```

These commands use only Python standard-library AST, hashes, JSON and named
public tar members. They do not import the existing runtime harness, invoke
executables, read operator .env/configuration/credentials, connect to SQL, run
Bun/Cargo, or rewrite staging. Preparation creates a **new** UUID directory under
`artifacts/consumer-derivatives-plan`, marked PREPARED_NOT_EXECUTED with zero PG
invocations. It copies only the28 named frozen SQL/harness members,14 reviewed
candidate source files, explicit NULL pin files, and its own named public recipe
sources, plus the separately hash-pinned named public owned_process.py support
source. Existing evidence directories are never destinations.

## Frozen inputs and process boundary

`inputs.lock.json` pins the closed FC66 receipt
`channel-transport-runtime/fc66ad64-9dc2-4285-8895-72d4d1a436d8/runtime-proof.json`,
its frozen tar, reviewed candidate manifest and two NULL-pin files, and final
`a1fd0260-718f-4a18-85f7-9005097277f1` toolchain guard sidecar. Preparation hashes
all39 core files and8 default-initdb scripts plus acquisition receipt/summary;
it does not query executable versions. The sidecar's four recorded version
strings are evidence of that earlier run, not fresh version validation.

The read frozen harness is exactly `test/run_host_credentials_runtime.py` inside
the FC66 tar. Its approved pattern is private marked socket-only cluster,
synthetic e2_owner, C locale/trust, frozen migrations, real test roles, and three
frozen ops scripts reapplied twice. This recipe uses those exact public migration
and ops SQL bytes. It does **not** run the original aggregate harness: that would
run Bun/Prisma/HTTP tests outside this bounded SQL-only appointment. Direct SQL
replay does not establish Prisma migration-ledger behavior.

After admission, the future runner must use approved owned_process ownership
(SIGCHLD initialized before children, unreaped direct-child/group identity),
plus the dedicated marked pg_ctl lifecycle because PG starts a separate session.
Do not import/execute that runner during preparation. No borrowed current cluster,
shared socket, running app, production URL, service connection or operator config.
Use a private HOME/TMPDIR, an explicit env allowlist, no inherited PG* or DATABASE_URL,
umask077, core dumps0,2GiB minimum free space,900s outer budget,60s ordinary child
budget and at most two owned client connections. No HTTP/native/Cargo child.
Long stages require a new bounded appointment, not an unbounded timeout increase.

The eventual owned command templates, **not commands authorized now**, are:

```text
<pg>/postgres --version; <pg>/initdb --version; <pg>/pg_ctl --version; <pg>/psql --version
<pg>/initdb -D <owned>/data -U e2_owner --auth=trust --no-locale -E UTF8
<pg>/pg_ctl -D <owned>/data -l <owned>/postgres.log -o "-h '' -k <owned>/socket -p <owned-port>" -w start
<pg>/psql -X --no-password -h <owned>/socket -p <owned-port> -U e2_owner -v ON_ERROR_STOP=1 -d <fixture-db> -f <named-public.sql>
<pg>/pg_ctl -D <owned>/data -m immediate -w stop
<pg>/pg_ctl -D <owned>/data status  # require exit3, prove owned listeners/clients closed
```

Create target, reference-old and reference-new databases in this one owned
cluster. Roles are cluster-global, which keeps expanded ACL role OIDs/order
consistent; do not compare unstable OIDs across independently provisioned clusters.
Use exact18.6 and exact toolchain closure before/after. PG logs/output may contain
only synthetic data; do not archive private bearer/code/verifier values or private
absolute session logs in public evidence. On failure stop only the owned marked
cluster and clients; never use pkill/shared-service stops or guessed PID cleanup.

## Concrete stage and fixture sources

`acceptance.json` defines S0–S8 admission, install/reference/seal, lifecycle,
concurrency/plans and finally-cleanup gates plus14 required positive/negative case
recipes. Case status is deliberately recipe-not-yet-executed. S6/S7 SQL driver and
synthetic row builders are a later bounded implementation step after root reviews
this recipe; this preparation does not pretend descriptions are executed tests.
Do not mark later stages passed when only install/sealing was admitted/run.

The first SQL appointment should stop after S5 unless root separately admits the
reviewed S6/S7 case implementation. This limits initial risk and makes missing
ownership/ACL/SQL assumptions visible before lifecycle work.

- `fixture-ownership-bootstrap.sql` transfers only24 named candidate prerequisite
  functions once, reconciling FC66's operator-owned migration setup with intended
  initial migrator/inventory/pairing owners. It uses the frozen ops pattern of a
  transaction-local temporary schema CREATE grant then explicit REVOKE; there is
  no role membership. It changes no function body and does not touch the three
  existing sealed roots. **Never reapply it after helper sealing.** Reapplication
  would defeat the owner boundary and must be rejected by the stage runner.
- `fixture-ops.sql` gives only explicit new table/column/type/function access,
  retires exact scalar API roots, and preserves separate host APIs. Apply it after
  each frozen three-ops pass, twice. It deliberately does not create/normalize
  unknown roles/default privileges or broaden membership. Its own grants must be
  independently reviewed and measured; source text does not prove sufficiency.
- `catalog-discovery.sql` records raw definition UTF8 hex, SHA256, exact owners,
  security/config, expanded function ACL and role/default/column/type metadata.
  It reads no user/session/token rows or role passwords. Some rows reference new
  functions, so run it after candidate install in each reference/target DB; for
  predecessor roots additionally compare the frozen-only pre-install snapshot.

No test bootstrap change is made to frozen Auth migration/ops/harness source.
If ALTER OWNER requires privileges the exact candidate operator does not retain,
or the new invoker/deferred guards need an unreviewed permission, **stop and report
that failure**. Do not patch reviewed bodies, temporarily add membership, use a
more privileged runtime, silently grant schema CREATE, or bless its new catalog.
The helper operator's role/ownership behavior is an actual S5 proof obligation.

## Source-proven pin discovery, never target blessing

1. Verify frozen receipt/tar/candidate hashes. Verify each candidate old-source
   snapshot byte-for-byte equals the function extracted from frozen006/007/008.
   Verified public source, not mutable target state, chooses which roots exist.
2. Construct reference-old independently from those exact frozen migration/ops
   bytes. Install the reviewed candidate source for helpers/prerequisites in the
   specified initial ownership state; preserve its complete source transcript.
3. Construct reference-new independently from the same inputs. Install the three
   new root definitions by extracting only the **three literal EXECUTE bodies**
   in the reviewed operator and compare their source hashes to the candidate
   root manifest. For helpers, use only the explicit literal owner/revoke/grant
   post-state statements in the reviewed helper operator. Do not execute either
   NULL-pin operator, copy a target body, or transform pg_get_functiondef text.
4. In each reference collect exact raw definitions, owners and expanded ACL after
   the intended state transition. Separately measure target-before. Every target
   predecessor must equal its independently source-admitted reference. Any body,
   owner, ACL/config/security, role/default or column-grant drift rejects admission.
5. Build a transition manifest with all source/archive/toolchain hashes, reference
   SQL transcript hashes, raw old/new definitions, exact owner/ACL maps, target-old
   equality records, and derived-copy diffs. The root reviews this concrete
   manifest before approving a measured operator run. A discovered target hash
   alone never supplies an expected pin; no catalog whitespace/substitution rule.
6. Only then fill NULL `old_catalog_sha256`, `new_catalog_sha256`, `old_acl`,
   `new_acl` and prerequisite `catalog_sha256`/`acl` **in separate private RAM/owned
   fixture copies**. Keep signatures, owner constants, source hashes and every
   literal SQL body identical. Replace only the bounded `$pins$`, `$deps$`,
   `$helper_pins$` JSON literal data fields. Record exact before/after SHA and JSON
   field deltas. Original staging/public review copies stay byte-identical/NULL.
7. Run derived helper seal then derived three-root seal; rerun for idempotency.
   Mutate one helper/root/ACL in an isolated rollback branch to demonstrate mixed
   state rejection. Repeat grant reapplication and verify no owner capability
   remains. Failures are evidence of a failed fixture gate, not permission to
   adjust expected hashes until it passes.

The reference-new state constructor is an essential separately reviewed part of
the future SQL driver. It is **not implemented as a discovery auto-acceptor** here.
That deliberate gate prevents an unsafe generic “read target then fill NULLs”
workflow. Reference setup itself is operator-only synthetic fixture work; it does
not authorize production application or provide deployment qualification.

## Required evidence and limits

Actual migrator CREATE OR REPLACE/ALTER/DROP/SET ROLE denials require SQLSTATE42501
and unchanged catalogs, not merely duplicate/syntax/dependency errors. Test owner
role membership/schema privileges, grants reapplied twice, and an unexpected-role
SELECT default/column grant: admission must reject that branch, never silently
remove it and accept a new baseline. Synthetic unknown-role tests do not require
reading account secrets or accepting arbitrary operator roles.

Lifecycle cases require real original source rows at approval/consume/proof and
through same-transaction deferred commit; partial/fake receipts rollback. Only
an earlier committed proof releases short source retention. Ordinary TTL cleanup
must delete the original plaintext verifier/request without shortening valid C.
No legacy request/service upgrade, consent resampling, post-revoke remint, old
renew/refresh lifetime extension, parent-ID fake credential hash or mobile parent
reclassification is allowed. Test parent/account/actual/global revocation and
unrelated-control liveness. Short mobile access expiry differs from established
principal/grant liveness. Verify response-loss/retry semantics without reissuing
consumed credential flows.

Plan proof uses populated fixtures at1000/10000 unrelated rows, ANALYZE, ordinary
unforced `EXPLAIN (ANALYZE, BUFFERS, VERBOSE)`, real RI-trigger cascade measurements,
affected-row counts and growth comparisons. No planner overrides, tiny-table
index forcing, or standalone-lookalike SELECT as a substitute for actual cascade
cost. Two-client races must have bounded barriers and owned process identities.

A future receipt must distinguish static source validation, actual SQL stages,
and NOT_RUN stages, and preserve HTTP/BetterAuth/UI/Prisma012/production=false.
This preparation reports only hashes/AST/allowlist/recipe checks and zero PG work.
