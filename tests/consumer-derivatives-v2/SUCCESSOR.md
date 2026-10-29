# Consumer derivatives v2: source successor, not executed

The explicit successor delta is candidate012 strict predecessor guarding, one
syntax-only CASE grouping in authority-core, and its deterministic helper source
identity field updates. No other SQL body, owner or ACL transition changes. The old
candidate, FC66 archive, eight preparation sources, pure constructor, source
pins and every executed failure remain immutable. The v2 candidate manifest and
new preparation manifest are separately admitted by a copied pure constructor
and copied bounded S0–S4 driver. There is no generic version selector or fallback.

The actual failure was SQLSTATE42704 at the old incorrect generated name. All
three immutable a393 baseline captures independently record the two-column
originId/accountSessionId CHECK as `consumer_authorization_check`. The successor
requires the exact four predecessor CHECKs and the exact class-equality FK before
any DDL. Names, raw definition text, ordered referenced columns, type, validation,
enforcement, deferral, locality/inheritance/parent and period state must match.
FK target schema/relation/ordered columns/actions/match and referenced index
identity/state must also match. Unknown additional CHECKs touching the protected
columns reject. The transition-binding FK guard selects every FK to
remote_session_binding, every FK touching originKind/originId/clientClass/
canManageAccount, and set-equal permutations
of the protected class-binding triple regardless of target. Any unadmitted
selected FK rejects, including duplicate equivalent constraints. This is a
transition-binding guard, not a blanket rejection of all account-column FKs. The
actual frozen accountId/userId FK to remote_account_identity and
accountSessionId/userId FK to session remain preserved and outside this transition-column
selection. An unrelated frozen epoch CHECK is preserved.

The existing BEGIN/global Auth lock remains first. Relation locks keep admitted
catalog state stable through the transition. The correct CHECK and exact guarded
FK are dropped. Apart from the two authority-core CASE grouping parentheses and
its derived helper source-identity JSON fields, remaining post-transition
statements/bodies retain their original bytes. There is no IF EXISTS, compatibility rename, privilege repair,
sealing operator execution or original NULL-pin filling. A repeat application is
expected to reject the missing old constraint state before new DDL.

`predecessor-contract.json` binds FC66 migration004 and all three exact baseline
capture hashes. Its definitions/validation/deferral were actually measured in
those old captures; additional state expectations are derived from frozen SQL
and PostgreSQL18.6 semantics and remain unexecuted v2 gates. CHECK referenced
column order follows first occurrence in the frozen expression, as implemented
by [StoreRelCheck in PostgreSQL18.6](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/catalog/heap.c);
therefore the origin CHECK records originId then accountSessionId. In particular,
[PostgreSQL18.6 addFkConstraint source](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/backend/commands/tablecmds.c)
sets an ordinary-table local FK to no-inherit, unlike ordinary CHECK constraints.
`successor-provenance.json` fixes the allowed source delta and model hash. Both
files are explicitly hash-admitted by the successor lock/driver and included in
qualification source closure, even though outside the fourteen-file manifest.

The eight-name preparation copy retains seven exact historical bytes and changes
only its input lock. Copied historical `prepare.py`, `validate.py`, `README.md`,
and candidate `build_candidate.py`/`validate_candidate.py` are PROVENANCE ONLY.
Do not execute them as v2 tools; some still name historical destinations. Runtime
uses only the separately reviewed v2 driver/bridge and pinned pure constructor.

Python-only validation under controlled environment (no PG/Node invocation):

```sh
env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2/successor.test.py
env -i PATH=/usr/bin:/bin LANG=C LC_ALL=C TZ=UTC /Library/Frameworks/Python.framework/Versions/3.14/bin/python3.14 -I -S -B tests/consumer-derivatives-v2/pg-s0-s4.test.py
```

These tests verify source hashes, immutable capture correlation, deterministic
SQL delta and synthetic predecessor-model rejections. They do not execute or
parse SQL in PostgreSQL, run Node, prove transaction rollback, or prove grants.
The independently hash-pinned pure JS constructor has not run in this slice.

## Planned real SQL fault cases — NOT RUN

After separate source review and explicit root appointment, use only the owned
fixture to verify clean predecessor success; each missing/renamed/wrong-expression
CHECK; unvalidated/not-enforced/inherited variants; wrong FK target/column order/
actions/match/deferral/validation/index state; and duplicate equivalent CHECK/FK.
For each applicable branch retain actual SQLSTATE55000 and before/after full
schema catalogs proving atomic rejection and no retained DDL. Confirm unmodified
post-transition semantics and repeated-apply rejection. Never manufacture invalid
system-catalog states through direct catalog writes. Cases requiring a state PG
cannot legally construct should be reported as such, not faked as executed.

A later actual S0–S4 execution must use a fresh reviewed outer wrapper, private
socket-only three-DB PG18.6 fixture, original900/840/60-second bounds, two-client
limit, empty ledger support, positive cleanup, unchanged source/tool hashes and
independent completion receipt plus actual controller exit0. S4 stops for root's
measured-manifest review. S5, HTTP, app/Prisma engine and production remain false.


## Source review correction: additional class-binding FKs

The first frozen v2 review is preserved as unexecuted historical source in its
original dfc controller snapshot and 9f6299cf preparation, plus a complete named
candidate snapshot at `artifacts/consumer-derivatives-v2-source-history/e9224eec-1e54-400d-8223-408cccb584db`.
The corrected selection additionally rejects an extra clientClass-only FK to
another table and a reordered three-column FK to another table. The exact
expected FK still compares its original ordered columns; set selection never
normalizes or broadens the admitted FK record.

Planned legal PostgreSQL negative branches (NOT RUN): on an independently
admitted disposable fixture, create a synthetic text-key fixture_client_classes
and add a clientClass-only FK from the empty consumer_authorization table; then
try the v2 candidate and require SQLSTATE55000/unchanged schema after rollback.
In a separate clean branch create fixture_class_triples with a unique
(clientClass text, accountId uuid, sessionId text) key and add the permuted FK
(clientClass, accountId, accountSessionId) targeting that key. Require the same
rejection and rollback proof. Keep both original account/session FKs intact in
these cases. Each branch and positive preservation case needs separate explicit
root admission before any real SQL execution.

The relevant FK overlap includes all four transitioned columns: originKind,
originId, clientClass and canManageAccount. The real-SQL plan also includes a
separate legal branch creating fixture_origin_ids(value text PRIMARY KEY), then
adding an originId-only FK to it on the empty predecessor table. Require
SQLSTATE55000 and unchanged catalogs after rollback; this branch is NOT RUN.
The ordinary account/session identity FKs without those four columns stay
preserved. No generic whole-catalog FK classifier is introduced.


## Authority-core CASE grouping after measured SQLSTATE42601

The actual v2 trial2699 reached target authority-core after the strict012 guard
and transition succeeded, then failed with SQLSTATE42601 at its line28 IF CASE.
The entire prechange6eb candidate closure, authority JSONs and source model are
preserved in `artifacts/consumer-derivatives-v2-source-history/1cdbae82-1ad6-4c96-aa52-f4f8e01672a5`.
The c629 review preparation and2699 actual receipts remain immutable.

[PostgreSQL18.6 PL/pgSQL grammar](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/pl/plpgsql/src/pl_gram.y)
defines expr_until_then through read_sql_expression(K_THEN). Its SQL expression
reader stops on that terminator at parenthesis depth0 and tracks parentheses
and brackets. The bare CASE's THEN can therefore terminate the IF expression.
The correction wraps that complete existing CASE in parentheses: exactly two
added bytes, with identical operands, WHEN/THEN/ELSE branches and END. The other
two CASE expressions in the same file's IF conditions were already grouped;
no other bare IF/WHILE CASE occurrence was found or changed.

The changed first helper's existing NON-NULL source_sha256 is recomputed in the
v2 helper pending contract and matching embedded helper-operator JSON. These
are deterministic source identity updates only. Every old/new catalog hash and
ACL placeholder remains NULL; signatures, owners, transition statements and the
second helper's source identity stay unchanged. V1 copies are untouched.

Pure tests correlate the actual42601 receipt, compare the old failed fragment
to the new grouped fragment, prove the complete core-file delta is exactly those
two bytes, and verify only the derived source SHA value changes in the helper
contract/operator. This is source evidence, not proof of SQL parsing or runtime
acceptance. A fresh separately admitted PG trial is required for that claim.
