# Operator mixed/drift rollback subset: source only

This new source prepares16 operator-negative cases. It has not run SQL,
PostgreSQL, Node, operators, version probes, or permission tests. Existing
candidates, original NULL pins, derived copies,196 inputs,603 previous
dependencies, snapshots and proofs remain unchanged. The root-accepted202-check
owner subset is bound through receipt c0efa78c-6969-4157-873a-cfb4dab78724 (SHA
`6e19748b6cbc7ea5de7601c4b4c5752a88faba8c8c9e83b5e6fc5fb40975121d`).
This group retains that proof independently; it does not rerun sealing before
faults and thereby destroy the all-old helper baseline.

The driver reuses the reviewed S0–S4 constructor, source/tool/owned lifecycle,
unchanged exact derived helper/root operator bytes, and captured independent
old/new references. It reconstructs all three DBs, then asserts exact pristine
catalog and metadata equality before every fault. Baselines are explicit:

- Target-old: one principal helper changed to exact independent new owner/ACL
  (the other remains exact old); helper body/config/owner/expanded-ACL drift on
  principal helper. These are5 cases against the unchanged helper operator.
- Reference-new: inventory remains exact new while assertion and recipient
  roots become exact old (helpers remain exact new); inventory root body/
  config/owner/expanded-ACL drift. These are5 cases against the root operator.
- Reference-new: body-owner schema CREATE and membership in each direction,
  tested against both operators. These are6 cases.

This is one choice of helper/root for each drift, not every branch permutation.
Other helper/root choices, SECURITY/role-attribute/missing-owner variants,
unknown role/default/column admission, pristine-pre012 mutations/reapply,
positive business calls and S6+ remain NOT_RUN in `excluded.json`. S5 is only
SUBSET_PASS with fullS5Qualified false; no downstream S6 admission follows.

Each case uses one marked owned psql with ON_ERROR_STOP and VERBOSITY verbose.
The SQL is an outer BEGIN, ordinary legal setup DDL, four complete catalog/
metadata begin/end markers, OPERATOR_BEGIN, and the **UNCHANGED full derived
operator**, including its BEGIN/DO/COMMIT. A final UNEXPECTED_ACCEPTANCE marker
follows the operator. No operator statement, body, pin, BEGIN or COMMIT is stripped
or rewritten. No direct system-catalog writes occur.

Expected psql exit is3 and the sole ERROR must be P0001 with the exact frozen
guard message. The source-recorded nested-BEGIN warning is neither evidence of
success nor an accepted error substitute. Missing/incomplete/out-of-order
snapshot markers, unexpected setup output/error, wrong code/message, or reaching
UNEXPECTED_ACCEPTANCE fails the entire appointment. Psql error stops before the
inner COMMIT and the owned connection closes. Only after its child is reaped do
fresh captures verify ALL3 DB catalogs/metadata, including global role membership
rows, exactly equal pristine references. Unexpected operator acceptance can
reach COMMIT: immediately stop, discard qualification for the entire private
appointment, and clean up its owned PG; never repair/continue or reuse it.
Failure artifacts/private working directory follow the prior retained-evidence
policy and are never used as a new baseline.

The setup snapshot must match the exact declared fault independently of the
error. Mixed function rows come from accepted independent references. Hostile
body setup has a labeled immediate return and unchanged signature/header; it
never changes authoritative sources. Config setup predicts one exact PG18.6
work_mem clause and config element. Owner setup uses ordinary ALTER and its
known ACL owner substitution; ACL setup adds a single exact EXECUTE grant.
A separately captured, closed role-name/OID map generates expected expanded-ACL
ordering exactly as the pinned discovery orders it. Captured ACL values/order
are never sorted, normalized or repaired. Schema/membership setup changes only
the declared authority row. Every raw definition SHA remains consistent. Any
unexpected PG rendering or authority effect fails conservatively, not a repair.

[PostgreSQL18 error documentation](https://www.postgresql.org/docs/18/plpgsql-errors-and-messages.html)
assigns P0001 to RAISE EXCEPTION without ERRCODE. Frozen helper/root guard
messages are checked in pure tests; their full source remains unchanged.
[GRANT documentation](https://www.postgresql.org/docs/18/sql-grant.html) documents
superuser grants as the object owner and membership defaults. Both tested
membership recipients are NOINHERIT, yielding INHERIT false, SET true and ADMIN
false. No principal data rows or credentials are fabricated.

Runtime retains the same private PG18.6 socket-only cluster,3 DBs,max2 clients,
60-second children,840-second normal work plus cleanup reserve inside original
900 seconds,2GiB immediate free floor, core0, closed environment/private HOME/TMP,
owned SIGCHLD identities and dedicated marked pg_ctl stop/status3/PID/socket
cleanup. Atomic completion receipt plus an independent owned outer exit0 under
900 seconds remains mandatory. Manifest/receipt alone never admit success.
The new gate additionally requires operatorFaultsCompleted true/count16 and
fullS5Qualified false/boundedSubsetCompleted true/S5 SUBSET_PASS.

Later inner invocation, ONLY after source review, disk/resource admission and
an independently owned outer controller:

```sh
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2-s5-operator-faults/s5.py --appointment ROOT-ADMISSION --node /Users/woro/.hermes/node/bin/node --derived ABSOLUTE-FROZEN-DERIVED-DIRECTORY
```

Runtime evidence uses only
`artifacts/consumer-derivatives-v2-s5-operator-faults-runtime/UUID`.

Pure validation command:

```sh
/Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2-s5-operator-faults/operator-faults.test.py
```

Pure tests validate source shapes, exact declared expected changes, error and
snapshot-marker admission, unchanged operator embedding, role identity closure,
and subset gate. They do NOT prove SQL parsing, nested transaction semantics,
actual P0001 messages or runtime atomic rollback. Those need separate admitted
execution. All business/lifecycle/HTTP/Prisma/production claims remain unqualified.
