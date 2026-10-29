# Private PostgreSQL diagnostic protocol (source only)

This pure module does not launch PostgreSQL, psql, a build, or a network client.
Its fake-stream tests do not establish runtime admission or effective server
configuration. The frozen positive-auth fixture remains unchanged and NOT_RUN.

## Guardian integration contract

Load `diagnostics.py` by an explicit trusted path. Create one `DiagnosticParser`
per child. Pump both pipes concurrently as bounded byte chunks through
`feed_stdout(bytes)` and `feed_stderr(bytes)`. Never decode, print, log, capture,
persist, interpolate, or attach those chunks to an exception. Keep the pump's
read size bounded independently (for example 256 bytes); the parser cannot bound
a chunk already allocated by its caller. This module has no raw output buffer:
it matches each byte against a closed protocol and retains only candidate
positions and ASCII SQLSTATE characters. Non-ASCII bytes fail immediately;
therefore every accepted stream is strict UTF-8. stdout must be empty.

Budgets are 1,024 stdout bytes, 8,192 stderr bytes, 8,192 combined bytes, and
256 bytes per line. Unexpected bytes fail before those ceilings where possible.
After rejection the parser clears candidates/state characters and discards
further input. The guardian must still drain or close pipes, enforce its deadline,
terminate/reap its owned process, and positively clean its private resources.
It must never divert rejected bytes into a raw-output fallback.

After both pipes close and the child is reaped, call
`finish(actual_exit_code, deadline=bool, cancelled=bool)` exactly once. Persist
only the returned `Result.evidence()` dictionary. The six fields are `stage`,
`state`, `marker_ids`, `count`, `exit`, and `deadline`. Exit is normalized to
0/nonzero(1)/unavailable(null); cancellation yields generic failure. The complete
stage requires all thirteen unique ordered NOTICE lines, empty stdout, actual
exit zero, and no deadline/cancellation. It does not establish the independent
catalog/count/connection/cleanup postconditions required by the fixture.

Only exact psql envelopes for `positive-auth.sql` and its frozen DO closing line
numbers are accepted, with LF terminators and two spaces after NOTICE:/ERROR:.
Use a private cwd and `--file positive-auth.sql` with the separately hash-checked
fixture. An absolute filename, changed line number, CRLF, extra DETAIL/HINT/
CONTEXT, result row, malformed state, reordered marker, or unknown diagnostic
fails closed. An error envelope is allowed only at its matching stage in the
marker sequence; only a validated fixed stage and canonical five-character
uppercase alphanumeric SQLSTATE outside successful class 00 can survive, and
only with nonzero exit. Nonzero exit after all markers is generic failure.

## Required launch policy, not yet runtime-verified

The guardian must pin the psql/postgres binaries and fixture separately.
Append `CLIENT_FLAGS` exactly to the pinned psql executable, then explicit
socket/database/user/file arguments. These flags require `-X --no-password
-qAt`, ON_ERROR_STOP=1, VERBOSITY=terse, SHOW_CONTEXT=never, ECHO=none, and
ECHO_HIDDEN=off. Start with an empty environment, add `PRIVATE_ENV_FIXED`, and
set only `PRIVATE_ENV_REQUIRED` to controlled private HOME/socket/port/database/
user values. Do not inherit PGOPTIONS, PGPASSWORD, PGSERVICE, startup files,
history, arbitrary locale variables, or shell configuration. HOME and temporary
directories must be private. No credentials belong in argv, env, commands,
persisted results, debug output, or evidence.

Launch the pinned `postgres` directly in the foreground with its owned private
data directory and `SERVER_FLAGS`; route both server stdout and stderr to
DEVNULL from process creation. Do not use pg_ctl or create postgres.log. The
explicit settings are log_destination=stderr, logging_collector=off,
log_statement=none, log_min_error_statement=panic, log_min_messages=panic,
log_error_verbosity=terse, log_min_duration_statement=-1,
log_min_duration_sample=-1, log_transaction_sample_rate=0,
log_parameter_max_length=0, and log_parameter_max_length_on_error=0.

Before any token generation, the guardian must verify the effective settings
against this exact policy through a separately closed credential-free settings
probe, including actual binary/version and server output routing. This module
defines policy only; it does not claim that any process has applied it. Keep
server diagnostics discarded for the entire lifetime, including startup,
shutdown, cancellation and faults. Client pipes must always use this private
parser, including unsuccessful launches and connection errors.

Policy references: [psql](https://www.postgresql.org/docs/18/app-psql.html) and
[server logging](https://www.postgresql.org/docs/18/runtime-config-logging.html).
These are reviewed policy references, not a claim of a PostgreSQL 18 execution.

## Pure validation

Run `diagnostics.test.py` using the separately pinned Python 3.14.7 interpreter
with `-I -S -B`, empty inherited environment, and private HOME/TMPDIR. The suite
installs an audit hook rejecting child creation and sockets. It tests canary
MESSAGE/DETAIL/HINT/CONTEXT/query/row leakage, invalid UTF-8, oversized input,
every split boundary, one-byte chunks, exact error envelopes, wrong prefixes,
missing/duplicate/reordered markers, cancellation/deadline, nonzero exits,
repr and artifact serialization, fixture hash, and zero child/network attempts.
No production driver, process manager, frozen fixture, or original input pin is
modified. The artifact directory
`artifacts/consumer-private-diagnostics/2026-10-19-pure-parser/` contains
`source-pins.json`, a source freeze, additions diff and `pure-test-receipt.json`
recording this bounded validation only. Guardian integration needs its own tests
and independent review before any credential-bearing fixture is admitted.
