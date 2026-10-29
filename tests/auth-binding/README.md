# Real handler and PostgreSQL binding tests

Run `tools/run_auth_binding_spike.py` as documented in
`packages/auth-binding-spike/README.md`. The runner executes actual Better Auth
1.7.6 handlers and real SQL in a new private PG17 cluster; it does not import an
application config, start a network listener or use an existing account/database.

`binding.test.ts` covers ordinary device flow, concurrent single redemption,
rollback after session creation, immutable host/device/bootstrap ownership,
canonical Rust proof admission, typed consumer FKs, server-owned class assignment,
independent window refresh, actual Better Auth sign-out, SQL window-limit races,
global revoke/suspend/reactivation and runtime database privileges.

The fixture uses opaque text Better Auth user/session IDs alongside separate UUID
Remote account/bootstrap/consumer/window IDs. Public client IDs are deliberately
reused in negative tests to prove they do not grant the host class. All identity
material and session cookies are synthetic. Test failure output is not retained
by the runner; evidence contains only bounded metadata and totals.

Passing these tests demonstrates the isolated binding mechanism. Production
routes, actual device enrollment UI, mobile login, KMS/credential recovery,
per-window key generation/Noise/grants and deployment remain `not_run`.

First-login regressions use the canonical account-independent host commitment:
init has no account, actual browser approval derives the bound fingerprint from
stored keys, and PoP verifies against that exact account. Valid foreign-account
proofs, key substitutions, immutable-record rebinding and consumed bootstrap reuse
are rejected. The same pending seed can be recreated; the durable record supplies
the one-time approved-account boundary.

`test_runner_shutdown.py` runs real PG17 lifecycle failure cases when the explicit
`AUTH_BINDING_TEST_PG_BIN` is set. It verifies timeout/interrupt after a successful
suite cannot write success evidence. It then reaps the preserved test cluster.
