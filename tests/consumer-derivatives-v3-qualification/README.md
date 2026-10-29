# Consumer derivatives v3 qualification preparation

This package prepares a source-only review bundle for a possible bounded
PostgreSQL 18.6 S0–S5 appointment. The bundle status is
`PREPARED_NOT_EXECUTED`; it is not an admission, qualification receipt, or
authorization to run database work. A separate explicit appointment and review
of the concrete bundle are required before any PostgreSQL work.

The input allowlist pins the staged v3 candidate, its pending NULL catalog/ACL
contracts, the current Auth Prisma schema and source migrations, relevant
permission scripts, and the focused source test. `prepare.py` only verifies
those bytes and copies them into a new source bundle with a plan and digest
manifest. It does not build candidate SQL, query tool versions, or invoke
processes, PostgreSQL, SQL, Bun, Cargo, HTTP, or network access.

All catalog and ACL pins must remain NULL. Candidate admission and runtime gates
remain closed. Every S0–S5 step is recorded as `NOT_RUN`; the stage descriptions
are preparation notes, not completed checks. The frozen v2 package is not
modified or copied into this package.

Run the static package checks with:

```text
python3 -B tests/consumer-derivatives-v3-qualification/test_prepare.py
```

To create the source-only bundle, run `prepare.py` from this directory. It
creates a new directory under `artifacts/consumer-derivatives-v3-qualification-prep/`
and refuses to overwrite an existing bundle. This operation only reads pinned
source files and writes copies, `plan.json`, and `bundle-manifest.json`.
