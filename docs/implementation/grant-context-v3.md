# Grant/context 3 format

Grant/context v3 uses the existing host identity keys, Ed25519 signatures, and
Snow Noise XX profile. It introduces no legacy permission conversion and does
not expand `permissions: control`. Historical compatibility constants refer
only to the imported implementation.

Remote API major 2, application major 2, grant/context version 3 and the terminal
profile are independent axes. V3 validation requires the first three exact
values. Terminal admission currently accepts only the existing unqualified
`lomi-rust-grid-v1-experimental` profile from
`contracts/terminal-profile-experimental.json`; this does not add it to production
negotiation or claim a production support matrix.

## Canonical bytes

Canonical encoding is definite-length positional CBOR, with shortest unsigned
integer encoding, byte strings for fixed binary IDs/keys and text for domain,
capability names and account session/profile identifiers. JSON is only a transport
representation. All u64 JSON values are canonical decimal strings (no numeric
JSON, signs, whitespace, leading zeroes, exponent or overflow). Structs reject
unknown and duplicate fields. `from_json` methods enforce the 128 KiB input cap
and semantic validation before returning. Raw serde deserialization is not an
admission; signing, canonicalization and verification all revalidate semantics.

The 23-entry grant array is, in order:

1. `"lomi-remote-grant-v3"`
2. version `3`
3. API major `2`
4. application major `2`
5. account ID (16 bytes)
6. host ID (16 bytes)
7. host complete public-bundle fingerprint (32 bytes)
8. host authorization ID (16 bytes)
9. host access epoch (u64)
10. consumer authorization ID (16 bytes)
11. account session ID (1..128 ASCII alphanumeric, underscore or hyphen)
12. consumer window identity subject ID (16 bytes)
13. consumer complete public-bundle fingerprint (32 bytes)
14. grant ID (16 bytes)
15. grant revision (u64)
16. workspace ID (16 bytes)
17. workspace epoch (16 bytes)
18. runtime ID (16 bytes)
19. runtime generation (u64)
20. capability names (array, lexicographically sorted by wire name)
21. nonce (32 bytes)
22. grant expiry (Unix seconds, u64)
23. purpose `"workspace"`

IDs, fingerprints and nonce must be nonzero. Epoch counters, revision and expiry
must be positive. The actual protocol `CapabilitySet` validates registry names,
duplicates and dependency closure; v3 additionally requires `workspace.read`.
Input capability order does not affect canonical bytes or signature semantics.
Account session IDs remain text because upstream account sessions are not UUIDs;
they are distinct from Remote authorization IDs and ephemeral window identities.

The grant authorizes a dynamic workspace, including future terminal members when
its capabilities permit. It carries no session list. A terminal target is bound
at admission and must match independently read current membership.

The 10-entry channel context array is:

1. `"lomi-remote-channel-context-v3"`
2. context version `3`
3. complete canonical grant bytes (CBOR byte string)
4. channel ID (16 nonzero bytes)
5. initiator role `"device"`
6. responder role `"host"`
7. purpose (`"workspace"` or `"terminal"`)
8. null for workspace, or `[pane ID, session ID, session epoch, terminal profile]`
9. admission issued-at (Unix seconds, u64)
10. admission expiry (Unix seconds, u64)

Terminal IDs/epoch must be nonzero; terminal admission requires
`terminal.observe`. A workspace context cannot contain a terminal target and a
terminal context cannot omit one. The issued-at must be positive; expiry must be
later, at most 30 seconds after issued-at, and no later than grant expiry. This
30-second limit is an explicit E0 proof limit, not a production freshness SLA.

## Verification and channel construction

`Identity::sign_grant_v3` and `sign_channel_admission_v3` reuse the existing
identity signing key without exporting secret bytes. Signing binds the account,
host subject, complete host fingerprint and host role. A signed grant contains
`{grant, signature}`; a signed admission contains `{context, signature}`. Signature
bytes are exactly Ed25519 over each complete canonical array, without hashing a
JSON representation or introducing another signature scheme.

Verification requires independently trusted expected grant/context, both complete
bundle pins, the host and consumer signed bundles, trusted current authority state
and trusted current Unix time. Both bundles must verify against their pins;
account, subjects, roles and fingerprints must match. Complete expected-state
equality, signature verification and the current host/consumer authorization,
account session, access epoch, grant revision, workspace epoch and runtime
ID/generation checks are all required. Grant expiry rejects `now >= expiresAt`.
Admission additionally rejects `now < issuedAt` or `now >= expiresAt`, and terminal
membership must equal the separately supplied current target. An embedded signed
value or its self-derived fingerprint is never an independent expected value/pin.

Only successful verification creates the private-field
`VerifiedChannelContextV3`. `Handshake::new_v3` consumes it, verifies the endpoint
bundles and roles again, and rechecks its time boundary. The Noise prologue is
exactly this four-entry array:

`["lomi-remote-noise-prologue-v3", canonical context bytes, consumer fingerprint, host fingerprint]`

Thus the prologue includes every signed grant/context field. Endpoint role swaps,
workspace/terminal confusion and context mismatches cannot complete authenticated
Noise XX. There is no public raw-prologue constructor. A small private shared
builder in the historical channel module reuses the same Snow handshake,
authenticated static-key check, transport, frame limits, counters and zeroization.
No Snow source or old vector is adapted.

The consumed token is a point-in-time proof, not a freshness lease or storage
transaction. Callers must read fresh, non-revoked authority/membership state,
atomically consume nonce/channel admission where required, enforce unique channel
IDs, and recheck freshness, membership, capabilities and fences on every operation
and before effects. A second independent verification can intentionally recreate
an admission token; replay prevention requires authoritative storage. Disconnect
requires a fresh handshake/admission. This proof does not implement storage,
control leases, revocation delivery, dispatch authorization or production policy.

## Caller responsibilities

A verified token is a point-in-time proof, not a freshness lease or storage
transaction. Callers must read current, non-revoked authority and membership
state, atomically consume nonce/channel admission where required, enforce unique
channel IDs, and recheck freshness, membership, capabilities, and fences before
each operation and effect. Replay prevention requires authoritative storage.
Disconnect requires a fresh handshake. This format does not implement storage,
control leases, revocation delivery, dispatch authorization, or production policy.
