# Baseline authorization-lock load proof

This measures the existing relay scheduler and actual global PostgreSQL advisory
lock at the audited `auth-app` revision. It does not implement new authority
routes or qualify the new protocol. The sibling application remains unchanged.
`source.json` pins the imported relay, transaction helper, database factory,
generated Prisma sources and package/lock manifests. A changed pin fails before
starting any database. The Bun process imports those modules directly, never
the application entrypoint, and uses `--no-env-file`.

```sh
python3 tools/run_authority_lock_spike.py \
  --pg-bin /path/to/postgresql17/bin \
  --output artifacts/authority-lock/evidence.json
```

The runner starts a unique socket-only PostgreSQL 17 cluster with fsync enabled.
The runtime role has no superuser, database/role creation or schema creation
rights; it can only read/update one synthetic authority row. The real
`withGlobalAuthorizationLock` supplies its actual two-second lock timeout,
seven-second statement timeout and nine-second interactive transaction budget.
No existing database, app `.env`, credential or account is used. Current failure
evidence is written before prerequisites, and success requires Bun cleanup,
PostgreSQL stop and private-cluster removal. An uncertain stop preserves files.

The actual Bun WebSocket relay listens only on loopback. The candidate budget is
eight views of 32 terminals plus one workspace channel each: **264 channels /
528 connections**, with 64 authority slots. This is an experiment, not a shipped
quota. The four scenarios check exclusive owner claim, multiple validation
cycles and binary delivery across the full budget, committed revoke, and an
actual six-second SQL lock holder while eight bounded admission-churn workers
make at most 80 fresh one-time-ticket attempts. Busy attachment admissions may
retry with new tickets under a five-second deadline. Application frames and old
tickets are never retried; admission refusal counts remain visible.

The freshness experiment attempts synthetic frames on any still-open peers after
the five-second deadline, records the actual attempt count and requires zero
forwarding. Zero attempts means the peers had already closed; that run does not
claim an exercised stale-frame rejection. It separately records socket-close time
(a 100 ms scheduler cadence and a 300 ms observation budget). Socket resource
cleanup latency is not presented as the exact writer effect deadline. All
authority requests retain their bounded slots until the actual request settles;
the fixture waits for them and closes every owned socket, server and DB pool.
SQL reads after the committed revoke and successful results delivered after it
are separate counters. A valid point-in-time read can be delivered later; the
fixture does not claim that serialization forbids such delivery. `lifecycle.mjs`
observes delivery after the transaction promise resolves. Its deadline aborts
new fixture operations, waits a bounded time for in-flight work, attempts every
cleanup step independently and writes failed evidence even after an earlier
cleanup fails. Pure lifecycle fault regressions run without PostgreSQL:

```sh
node --test tests/authority-lock/lifecycle.test.mjs
```

Reports contain only counts/timings, dependency pins, exact command arguments,
exit codes and input digests. Tickets, URLs with tokens, terminal/file contents,
SQL error bodies and environment values are not retained. New host/consumer
authority routes, end-to-end writer effect fences, production traffic,
multi-host scale and deployment remain unqualified. In particular, a passing
overload test proves fail-closed behavior and does not qualify availability
under a six-second global lock stall.
