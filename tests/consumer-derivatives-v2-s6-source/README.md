# S6 pending web source fixture

This directory contains a pure Python SQL-text builder and static tests for a
synthetic pending web approval fixture. The builder emits a disposable
transaction that creates only synthetic rows, marks the exact web attempt as
`consumerV3Requested=true`, inserts its matching code and unconsumed approval
intent under `lomi_runtime`, forces `approval_intent_complete_v2`, checks that
proof, service, web actual, and consent rows are absent, then commits.
Source rows are seeded first under `e2_owner`; no consumer authorization is
seeded.

The mismatch variant inserts a deliberately changed client binding under
`lomi_runtime`. It catches exactly SQLSTATE `23514` from the immediate source
guard, verifies that no intent or authority row remains, then explicitly rolls
back the disposable transaction. The positive variant reaches and forces the
named deferred pending-intent constraint before committing.

A second negative variant consumes the synthetic request and code but leaves
the intent unconsumed and inserts no proof or authority. It forces the source
deferred guard, checks the expected diagnostic and partial state, then rolls
back the disposable transaction.

A third negative variant seeds an unmarked legacy request. It attempts to set
the V3 marker and then create an approval intent from the unchanged source. It
checks the immutable-marker and exact-source diagnostics, verifies no intent or
authority was created, and rolls back the disposable transaction.

A fourth negative variant attempts independent updates to all 33 approval
snapshot fields that are not terminal-consumption fields. Each update must
raise SQLSTATE `23514` with the exact immutable-snapshot diagnostic. The
fixture then compares the complete row, confirms it remains pending with no
proof or authority, and rolls back the disposable transaction.

The tests inspect generated text only. They do not execute SQL, connect to
PostgreSQL, or qualify any behavior. Everything remains unqualified: this is
source-only preparation, with no S6 execution or acceptance claim. The
candidate hash pin is checked by the Python test before SQL text is generated.

Run the pure Python checks with:

```sh
python3 tests/consumer-derivatives-v2-s6-source/pending_web.test.py
```
