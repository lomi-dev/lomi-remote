# Synthetic PostgreSQL enrollment checks

Run the private-cluster runner documented in
`packages/enrollment-spike/README.md`. `evidence.json` records sanitized outcomes
and exact PostgreSQL version for the most recent local run. This is development
evidence, not a signed release attestation or Better Auth integration result.

The suite tests immutable bindings/limited privileges, canonical Rust proof
rejection, concurrent exchange/refresh, secured response equality, AEAD context
binding, plaintext absence from DB rows, replay revocation, bounded expired
receipt removal, global revoke/reactivation and process-exit recovery. Child
process requests use stdin, not argv; successful workers emit no token values.
The PG fixture contains only public test identity material and synthetic tokens.

The fixture CLI intentionally enables crypto's `test-fixtures` feature and must
never be included in release builds; the crypto crate rejects that feature in
release mode. No platform service or application endpoint is started by the test.

`after_receipt` means the worker received an in-memory result and exits before
any OS credential write. Atomic keychain/DPAPI/protected-file receipt storage,
Better Auth hooks, consumer FK/window lifecycle, production route integration,
clock authority, KMS, power-loss testing and deployments remain `not_run`.
