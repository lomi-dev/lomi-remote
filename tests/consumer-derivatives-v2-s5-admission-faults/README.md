# Admission-negative fixture preparation: source only

This new eight-file test successor prepares five admission-negative cases.
No PostgreSQL, Node, operator, version probe or runtime has executed in this
slice. Root's accepted pre012 result b292f699 and operator result278a53d1 are
bound by exact receipt/source/evidence hashes. All earlier sources,548 files,
196 original inputs, recursive603/1206 guards, candidates, NULL contracts,
derived copies and executed proofs remain unchanged. Four root implementation
documents remain owned by root and are not modified here.

The five declared cases are:

| Case | Setup | Required admission category/message |
|---|---|---|
| unknown-role | Synthetic fixture_unexpected only | UNKNOWN_ROLE / unknown fixture role |
| unknown-default | SELECT table default to fixture_unexpected before candidate creation | UNKNOWN_DEFAULT_PRINCIPAL / unknown default privilege |
| unknown-column | UPDATE(originId) to fixture_unexpected after fixture ops | UNKNOWN_COLUMN_PRINCIPAL / unknown object privilege |
| known-default | Same default to known lomi_migrator | Full original guard PASS; KNOWN_DEFAULT_REFERENCE_DRIFT / metadata differs from admitted independent reference |
| known-column | Same column grant to known lomi_remote_api | Full original guard PASS; KNOWN_COLUMN_REFERENCE_DRIFT / metadata differs from admitted independent reference |

These categories describe Python ValueError admission, not operator SQLSTATE.
SQL setup must exit0. No fault branch accepts pins, invokes the derived-pin
constructor, or runs a measured sealing operator. `pinsAccepted=false`,
`derivationAttempted=false`, `measuredOperatorsExecuted=false` remain mandatory.
The previously accepted S4 independent references are source authority only;
fault captures never supply expected definitions, owners, ACLs or pin values.

`baseline.py` is a narrow separately pinned successor of the accepted548 prefix.
Its only execution-schedule change is stopping BEFORE old[30], not after the
approval-intent file. It replays24 frozen migrations, the same empty ledger
fixture, then frozen3 ops twice in all3 databases. Constructor-selected old[30]
through old[35] are unchanged approval-intent,012,core,typed,one-time ownership
bootstrap and fixture ops. They are appended only after the default injection
in the fault branch. Every candidate work item is wrapped with before/after
current_user/session_user markers in the same psql session; exact original SQL
bytes/source hashes are retained. All creators must be e2_owner. Bootstrap
transfers function ownership, not table ownership. Correct injection is:

```sql
ALTER DEFAULT PRIVILEGES FOR ROLE e2_owner IN SCHEMA public
GRANT SELECT ON TABLES TO fixture_unexpected;
```

The candidate default-deny lists exclude fixture_unexpected and lomi_migrator.
Thus these grants survive unchanged candidate execution. Default propagation
must be evidenced on actual newly created consumer_approval_intent,
consumer_approval_consumed_proof and consumer_derivative_consent tables, with
exact e2_owner grantor/owner, grantee and SELECT privilege. Column injection
occurs AFTER old[35]; no ops/revoke may intervene before capture/admission.

Pristine old/new controls are built independently in the two reference DBs,
compared to admitted independent S4 references, and captured BEFORE introducing
an unexpected global role in the fault branch. The pure JS source reference
selector is reused; this is not the derived-pin constructor. Literal reference
new-state construction uses the same admitted S4 transaction, not measured
operators or target-discovered expectations.

Full raw27 snapshots, function definition UTF8hex/SHA, expanded table/column/
default ACLs, roles, schema authority and stable catalog/metadata are retained
unchanged. Admission phases run the ORIGINAL authority guard over explicit
DEFAULT_ACL, COLUMN_ACL and ROLE subsets, recorded as full-capture SHA plus exact
raw row indices. No principal/ACL/OID/definition value is normalized. Full
original-order guard outcomes on catalog and metadata are also recorded:
unknown roles appear first in discovery's role group, while metadata's object/
column ACL SELECTs precede its roles. The targeted phase proves the intended
branch even when the original full-order diagnostic reports another unknown
principal first. Known-role cases must pass both full original guards before
exact independent metadata comparison rejects the extra privilege.

Declared-delta validation starts with pristine independent references. It
requires only source-specified extra role/default/table/column records and exact
predicted protected raw ACL-array changes, retaining existing array order and
function bytes. No extra function/owner/schema/privilege change is accepted.
The separate public namespace query supplies its stable identity; a fault
ACL never selects that identity or an expected pin.

Candidate scripts contain COMMIT, so this harness does not promise an outer
rollback across reconstruction. Each case has a NEW private3DB cluster, run
sequentially under ONE original900-second outer /840-second normal-work budget
with60-second final cleanup reserve. At most one cluster exists at a time; SQL
clients are sequential/max2 connections, each child60 seconds, socket-only
PG18.6,2GiB preflight before every cluster, core0, controlled private HOME/TMP,
owned SIGCHLD helper and dedicated marked pg_ctl lifecycle. Positive stop,
status3, absent PID/socket and private-directory removal are required between
cases. Logging/evidence failures cannot precede or skip mandatory owned stop.
Failure stops the appointment; no retry, role deletion/revoke-and-bless, repair,
or reuse of a faulted cluster is allowed.

Every fresh rebuild retains raw27 baseline/control/setup snapshots and proves
source replay, absence of previous unknown role/default/column additions,
positive original guard and exact independent reference comparison. Raw OIDs
are NOT compared across fresh clusters and no captured OID bytes are rewritten.
Destroy/rebuild is explicitly distinct from same-database transactional rollback.

Completion requires all five exact admission categories, positive cleanup for
five clusters and private directories, stable sources/49 tools, matching atomic
manifest/receipt and independently retained owned outer exit0 under900 seconds.
Manifest or receipt alone never admits success. S5 remains SUBSET_PASS,
fullS5Qualified false; all lifecycle/business/HTTP/Prisma/production gates remain
unqualified. No raw invalid/NULL-principal call is claimed as business success.

Later inner invocation, ONLY after independent review and root runtime/resource
admission, from the repository root:

```sh
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2-s5-admission-faults/s5.py --appointment ROOT-ADMISSION --node /Users/woro/.hermes/node/bin/node
```

Evidence goes only to
`artifacts/consumer-derivatives-v2-s5-admission-faults-runtime/UUID`, with separate
case subdirectories. No derived fixture copy or --derived input is used.

Pure regression command:

```sh
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2-s5-admission-faults/admission.test.py
```

Pure tests use synthetic copies of admitted references and no child on import.
They establish deterministic source/phase/delta/gate properties, not actual SQL
parsing, default propagation, privilege behavior or owned cleanup execution.
