# Supervised18 successor — source only

This new executable runs the frozen18 SQL/case sequence in the guardian main
process. No old controller, child fixture driver, legacy outer kill, or frozen
owned-process helper is executed or modified. Runtime remains blocked pending
independent source review and separate root admission.

`run_s5` is an AST-checked copy with one prefix-module substitution. `prefix.py`
preserves the exact32-step SQL schedule and replaces detached `pg_ctl start`
with a real foreground `start_postgres` / `wait_startup` call. The real argv
and retained handle PID are recorded. The adapter uses explicit guardian tool
methods and returns their bounded public text result to the unchanged Fixture;
psql statuses0 and3 remain actual statuses, checked by the original caller.

One new256MiB EvidenceStore records the entire run. Exact derived SQL bytes
use `save_bytes`; the strict format-v2 reader verifies index closure and raw
aliases. Event counts are informational. Eighteen actual unique case results,
completion, hashes and the full reader are mandatory. SQL capture, raw same-DB
checks and separate-commit LAST reapply remain unchanged.

The work directory is registered before any launch. Fixture cleanup delegates
to the guardian independently of recorder success. The outermost finally
always calls `finish_owner`; UNKNOWN ownership retains the sole owner and
private work. The original840 work budget and900 qualification deadline never
renew. Emergency cleanup until960 cannot qualify a late result. All work is
retained on success and failure.

Candidate receipts declare `driverInProcess=true` and require independently
observed actual executable exit0 within original900. They never invent a child
driver exit. External source freeze and root review remain necessary. Full S5
is false, S3/S4 are NOT_RUN, and four CTAS cases remain open. Original NULL pins,
model admission and catalog policies remain unchanged.

Pure validation uses pinned Python3.14 `-I -S -B`, private HOME/TMP and a Python
audit hook that rejects every child/process launch. It exercises no PostgreSQL,
Node, probes, or controller. `inputs.lock.json` closes the new source allowlist
and pins dependencies; external freeze must pin that lock itself.

The raw-log budget is separate from compact evidence and PG data. Before any
child, the guardian installs an inherited32MiB soft/hard `RLIMIT_FSIZE`. This
also restricts every individual PG data and evidence file. Before foreground
PG starts, initialized files must fit that cap and actual initialized WAL
segments must be exactly16MiB; later larger files fail closed. The frozen
fixture remains a small DDL workload, with no large data-file qualification.

Raw stdout/stderr reserve64MiB per child pair under a512MiB logical ceiling,
including128MiB reserved for cleanup. Existing allocated bytes are checked at
admission; this is not a filesystem-wide quota or a bound on filesystem
metadata/PG data. Only known reaped ordinary logs may be retired, after exact
unsanitized legacy text is saved through the compact store and both original
raw-file hashes/inodes are verified. Generic raw-result records use public
`reader.stdout` for each stream; `commands.json` keeps its original cleaned
strings. Retirement or recording failure retains charges and disqualifies the
run. Log-budget failure cannot block actual cleanup: the guardian can run its
pinned stop/status clients through the preopened discard sink, unqualified.

Admission requires `reader.validate() is True`, canonical UUID run binding to
the evidence directory, supplied manifest bytes equal the actual stored
manifest, canonical receipt bytes equal the actual stored receipt, and exact
closed typed outer observations binding run ID, manifest hash and index hash.
Missing stored exclusions, false reader results, rebound metadata and a late
outer exit cannot qualify.

The sole Python owner must already ignore SIGXFSZ before installing the hard
file cap, and that disposition is rechecked at raw-log admission. The policy
changes no signal handler. Default or custom SIGXFSZ dispositions fail before
setting the cap or launching a child. Passing resource metadata requires the
actual installed cap, verified ignored disposition and initialized-file/WAL
admission; constants alone do not establish qualification.
