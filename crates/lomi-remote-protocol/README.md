# Protocol foundation (E0)

This crate supplies strict primitives, independent version axes and the typed
39-method logical registry for the next S0.5 contract slice. It is not the frozen
S0.5 contract, full method parameter contract, HTTP OpenAPI or an admission
implementation. `DraftContract` and its three command DTOs remain representative
scaffolding. No cryptographic signing bytes are defined or changed here.

UUID types are distinct per identity/epoch domain. JSON accepts only canonical
lowercase hyphenated UUID text and rejects nil. `from_bytes`/`to_bytes` preserve
all 16 bytes, with no UUID version restriction or conversion of opaque account
sessions into UUIDs. Existing crypto CBOR IDs remain independently validated
binary values; this foundation does not replace crypto verification.

Foundation opaque tokens accept 1..N ASCII letters, digits, underscore or hyphen:
request IDs and account session IDs have N=128, event cursors N=1024, and file
revision/repository state tokens N=256. These are explicit E0 bounds, not a
production retention or encoding guarantee. Opaque revisions/cursors are never
parsed as counters. Numeric revisions/sequences/offsets use `DecimalU64`, which
rejects numeric JSON, signs, leading zeroes and overflow. All request/context DTO objects reject
unknown fields; the generated catalog is a schema catalog, not a wire envelope.

Remote API 2, application 2, grant/context 3, local IPC 1.0 and terminal profile
`lomi-rust-grid-v1-experimental` are independent axes. IPC rejects any other
major and negotiates the smaller supported minor. The profile is unqualified;
accepting its exact identifier does not advertise production support.

`Method::rights` distinguishes static capabilities from `StoredOperationRights`.
The existing `CapabilitySet::authorize` continues to refuse operation status and
cancel. `authorize_operation` requires an independently authenticated principal
authorization, workspace and requested operation ID plus an independently read
trusted storage record.
The record has private fields and no request deserializer. Its constructor
requires the complete original method rights and actual rights used at admission,
including `git.execute` when repository-controlled execution occurred. Pass the
rights actually required, not the entire granted capability set. Current rights
must still contain every recorded right. Missing/foreign principal/workspace or mismatched operation ID
records all return `NotFound` before disclosing receipts or tombstones. Request
IDs may change across transports; they do not participate in this binding.
Caller code remains responsible for fresh authority, signatures, epochs,
membership, effects/fences and an atomic storage lookup. These helpers neither
read storage nor reveal operation state. They do not establish trusted actor
class from any client field. Git read isolation and local execution consent
remain independent requirements.

Run `cargo run -p lomi-remote-protocol --bin generate-contracts` to regenerate the
draft schema, foundation schema catalog and compatibility manifest. Add
`-- --check` to reject drift. The manifest hashes exact generated schema bytes
and the existing experimental profile bytes with SHA-256. `foundation-e0` does
not claim complete parameters, an HTTP API, a frozen contract, production
admission or terminal qualification.
