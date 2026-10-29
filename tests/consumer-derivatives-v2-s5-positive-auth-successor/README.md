# Consumer S5 positive-auth successor: source only

This namespace pins the existing `positive-auth.sql`, case plan and closed
byte-diagnostic parser. The SQL remains source only and has not been parsed or
run. `SOURCE_ONLY_NOT_RUN` applies to SQL; full S5 remains false, and S6/S7
remain `NOT_RUN`.

`adapter.py` is a pure integration boundary for bounded, fakeable anonymous
pipe captures. It cannot start processes, execute SQL, connect to PostgreSQL,
or admit runtime execution. Its runtime entrypoint is closed by default. The
adapter returns only sanitized fixed evidence and requires exact EOF on both
pipes, a normal zero child exit, successful reap, quiet process group, completed
cleanup, complete ownership facts, and observations within one original
monotonic start/deadline window. Any missing, malformed, partial, oversized,
unknown, diagnostic-bearing, timed out, cancelled, or contradictory input
collapses to generic failure without preserving raw bytes or exception text.

The pure fake integration suite is the only validation in this namespace:

```sh
python3 -I -S -B tests/consumer-derivatives-v2-s5-positive-auth-successor/recorder.test.py
```

Passing these source-only tests does not authorize runtime admission. A new
independent appointment, source/tool gates, reviewed credential-safe execution,
rollback comparison, and positive owned-resource cleanup would still be
required before any runtime qualification.
