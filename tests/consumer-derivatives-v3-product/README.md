# Consumer v3 private product controller

This directory contains a source-only preparer and an admission-gated private
fixture controller. The controller pins the current Auth source, active
migrations and operations, the exact Consumer v3 successor package, PostgreSQL
18.6, Bun 1.4.2, and the installed Auth dependency tree. It has no production
target option.

Importing `controller.py` is inert. The preparer creates a new mode-0700
artifact bundle and runs only source and file-hash checks. It does not invoke
PostgreSQL, SQL, Bun, or candidate operators. Runtime requires two distinct
source-bound documents in the prepared bundle's `admission/` directory:

- `independent-review.json`
- `root-admission.json`

Both receipts bind the exact controller and bundle-manifest SHA-256 values.
The command flag selects execution but cannot replace those receipts.

After root and independent review admit that exact source bundle, run:

```sh
python3 -I -S -B /Users/woro/Documents/Lomi/lomi-remote/artifacts/consumer-derivatives-v3-product-<uuid>/controller.py --run
```

The controller starts one marked socket-only PostgreSQL 18.6 cluster with
three isolated databases. It uses a fresh UUID data directory, socket, HOME,
TMPDIR, four explicit local role URLs, four max-2 pools, a 16-connection
server limit, bounded child output, and one original 900-second deadline.
Process startup and shutdown use the pinned owned-process helper.

Every run writes a private `run-report.json`. `productionQualified` stays
false. S5 implements effective ACL checks and 80 sealed-helper denial attempts
using actual Runtime/API/Exchange/Migrator logins. Every attempt must return
42501, acknowledge rollback and preserve the complete catalog and role state.
Twenty-eight operator owner-state attempts run at their exact measured phases,
after genuine positive controls and before later ACL transitions. Each requires
the expected source rejection and complete rollback; fourteen partial outcomes
cannot qualify the full matrix. Each helper/root transition also rejects a
real catalog body replaced by an authentication-bypassing void body. Exact
P0001 reason, preserved owner/ACL/config, and complete restoration are required
before its positive controls. S5 passes only after these probes, both matrices
and all role checks complete. S6 runs actual issuance, lifecycle, inventory,
ACL and signed Host/Pairing/Channel/Ticket handler transactions for both web
and mobile derivatives. It requires all fifteen typed overloads, lost-ACK
outcomes and direct descendant cleanup evidence. This does not establish real
relay or physical client acceptance. S7 uses a separate bounded driver with
1,000 and 10,000 unrelated issued principals per derivative kind, using the
production flow primitives. Shared relations have twice that population.
Eight dedicated fixtures are excluded from those counts. It retains unforced
lookup plans, actual rollback DELETE plans and
RI-trigger timings, source-TTL retention probes, and row-derived seed receipts
in private files. A Python postvalidator checks observed counts, canonical
liveness guards, rollback restoration and raw-plan digests before stage PASS.
Source or test preparation alone does not qualify S7. The private fixture is
not a production or Prisma-ledger qualification.
