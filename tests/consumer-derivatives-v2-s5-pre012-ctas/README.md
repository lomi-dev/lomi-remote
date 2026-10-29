Four CTAS cases: SOURCE ONLY, actual executions0, fullS5false.

`cases.py` builds three extra selected FKs and one replacement class-FK target.
Each target is CTAS WITH NO DATA with an explicit named UNIQUE. All FKs use
explicit ON DELETE CASCADE and unchanged no-action update semantics, binding to
independently captured pre-fault builtin identities. The replacement retains the
original FK name/source/actions while changing only the typed target.

The independent full-row expectation covers the existing27 raw public catalog
sections. Only ten declared fresh OID scalar values may come from a fault
capture; every other field, crosslink, name, definition, array position, order,
cardinality and ACL row is predicted from pristine templates and declared DDL.
Raw captured data is never rewritten. Public-projection scope excludes TOAST
and dependency/global-catalog proof. See primary-sources.json for reviewed
PostgreSQL REL_18_6 sources and explicit prediction/actual-acceptance boundary.

`protocol.py` renders an outer transaction containing legal setup, raw capture,
the unchanged actual metadata SQL, and the entire unchanged012. It requires
ownedpsql3, exact55000 message, ordered unique markers and one advisory blank.
The metadata kind rows separately reach the original authority guard; passing
raw envelopes to that guard is explicitly rejected. Its returned pass record
must be saved by a future executor together with actual metadata. Exact raw
rollback comparisons require all three DBs and strict five predecessor rows.

There is no Guardian/process harness or executable native entrypoint here.
Future integration, source review, recursive source/tool admission and root
heavy-window admission remain necessary. Any actual PG/model mismatch stops
without automatic expectation updates or retries. Prior10/18 source/evidence
are unchanged and not reexecuted. No business/lifecycle/S3/S4/S6 claim.
