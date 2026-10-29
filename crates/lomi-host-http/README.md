`lomi-host-http` is a blocking native HTTPS transport for the existing host
credential and host-access data DTOs. It does not implement a CLI, IPC, lifecycle transitions, durable
storage, polling cadence, retry policy or the trusted clock. Its caller
must run it on a dedicated bounded host worker, outside the PTY/runtime actor.
Each method makes one request attempt; the caller retains the original durable
exchange/rotation request and operation identity after an ambiguous response.

`Transport::new` revalidates `lomi_host_auth::Config`, including values built
through its public deserializer, before creating the resolver or any request. Endpoints derive
from its canonical HTTPS origin and fixed paths. Polling uses the configured
public client ID and fixed OAuth device-code grant fields. It requires Better
Auth 1.7.6's actual success fields (`access_token`, `token_type`, integer
`expires_in`, `scope`) plus required `host_enrollment` context. The latter and all
credential DTOs reject unknown fields. Registration sends the unconfirmed access
credential returned with that registration request. Revocation sends a host
access credential and an expected epoch to a path containing a typed host UUID;
an already revoked family's credential can receive an acknowledgement without
regaining authority. The lifecycle caller validates the returned host and epoch.
Cookies, ambient proxies, environment-selected certificate roots and
response-provided URLs are not transport configuration inputs. Production trust
uses WebPKI roots and explicit rustls/ring certificate and hostname validation;
root injection is private and exercised only by crate unit tests.

Auth deploys identity and Remote API as distinct listeners. `Transport` sends
only enrollment, OAuth device polling, exchange, refresh, registration and
revocation to the identity origin in `lomi_host_auth::Config`. Its origin also
serves the identity credential audiences and must retain that meaning.
`DataTransport` owns the nine host data methods and a separate `RemoteApiOrigin`.
Construct both from independently trusted deployment configuration:

```rust,ignore
let identity = Transport::new(&identity_config)?;
let remote_origin = RemoteApiOrigin::new(&identity_config, pinned_remote_origin)?;
let remote = DataTransport::new(remote_origin)?;
```

`pinned_remote_origin` must be the canonical HTTPS origin of the public Remote
API listener (`REMOTE_PUBLIC_ORIGIN`), supplied by the caller's trusted
configuration. The transport does not discover or approve this pin, persist it,
or infer it from credential responses. `RemoteApiOrigin::new` validates the
identity configuration, rejects an equal identity/remote origin, and uses the
same narrow canonical DNS/IPv4 authority rules as HostAuth Config. Paths,
queries, fragments, user information, IPv6, uppercase/ambiguous host forms,
explicit default port 443, noncanonical ports and numeric host aliases fail.
The type has private fields and no deserializer or mutation API. Data methods
cannot be called on the identity `Transport`; neither transport has a public
per-request origin, URL, header, root-certificate or proxy override. Both use the
same private TLS/resolver/deadline policy. This is a library boundary and local
fixture qualification, with no product wiring or deployment integration claim.

ureq is pinned to 3.4.2 with default features disabled and `rustls` enabled. The
agent enforces HTTPS, disables proxy selection and redirects, limits headers to
16 KiB, and retains no idle connections. Total/per-call timeouts are 15 seconds,
DNS 3 seconds, connect including TLS 5 seconds, request/body sends 2 seconds each,
and response headers/body 5 seconds each. DNS uses one lazy process-wide worker,
a one-slot queue, a busy gate and request-specific one-slot result channels. A
native lookup cannot be cancelled: after a timeout, subsequent resolutions fail
fast until that worker returns. New transport instances cannot create additional
DNS workers. No new thread is spawned per request or timeout. DNS receives only
public hostnames and ports. This is a resource bound, not cancellation of the
platform resolver. Tests use a separate injected lookup worker for deterministic
stall coverage.

Request serialization writes through a 16 KiB bounded zeroizing writer, checking
the limit during each write. Responses use one fixed-capacity zeroizing 32 KiB +
one byte allocation; declared length and streaming limits reject overflow while
accepting exactly 32 KiB. Truncated bodies fail closed. Responses require one `application/json`
Content-Type, optionally with a UTF-8 charset parameter, and forbid any
Content-Encoding header. Object/scalar response schemas reject positional
arrays at every depth; literal brackets inside JSON strings remain valid. The accepted native host response contract rejects non-ASCII and backslash
escapes in successful secret-bearing JSON before parsing; this is a transport
restriction, not a general claim about all public protocol DTOs. Errors expose only
closed static codes, never raw library errors, body text, OAuth descriptions,
headers, URLs, redirects or credentials. Poll results carry no Debug implementation.

Zeroization covers application-owned request/response and bearer formatting
buffers. Existing protocol wrappers and ureq, HTTP, TLS, serde and operating
system internals can allocate ordinary copies; this library does not claim to
erase all credential memory. Product logging must disable ureq/ureq-proto/http
TRACE/DEBUG output before transport use: ureq internally traces redirect Location
values even when redirects are disabled. The transport does not install a global
logger or claim control over its embedding application's logging policy.

TLS uses rustls with ring's native C/assembly cryptographic implementation; this
is distinct from protocol canonical encoding/signature ownership in the existing
Rust crypto crate. No TLS primitives or canonical crypto algorithms are replaced.
Tests generate CA/server keys only in RAM and use owned loopback ports; private
keys, tokens and seeds are never written as test evidence. There are no real
account requests or production auth/policy changes.

Primary API/source references: [ureq 3.4.2 configuration](https://github.com/algesten/ureq/blob/3.4.2/src/config.rs),
[resolver trait](https://github.com/algesten/ureq/blob/3.4.2/src/unversioned/resolver.rs),
[body reader](https://github.com/algesten/ureq/blob/3.4.2/src/body/mod.rs), and
[rcgen 0.14.7](https://github.com/rustls/rcgen/blob/v0.14.7/rcgen/Cargo.toml).

Credential endpoints preserve five canonical failures as the closed `HostFailure`
enum: invalid argument, authentication required, resource not found, unknown
outcome and service unavailable. Status, canonical message, effect, retryability
and empty details must agree exactly; extra fields, operation lookups, duplicate
fields or malformed responses stay an ambiguous `HttpStatus` error. No response
text is retained. Polling accepts the enrollment gate's exact HTTP 403
`access_denied` response as denial, without accepting pending/slow-down on 403.

`python3.14 -B crates/lomi-host-http/tools/validate.py` retains a new read-only
UUID receipt and copies of explicit public inputs before running bounded checks.
An inventory guard rejects omitted Rust files or symlinks under the known local
transport/auth/platform/protocol/crypto/snow source roots, including other OS and
WASM modules. Compilation uses the shared live workspace and target directory;
before/after hashes do not constitute an isolated build or proof of executable
hashes. The validator creates a fresh private HOME and retains it; neither its
removal nor its final contents are certified by the receipt. Earlier receipts retain
their original input coverage and are historical, not updated qualifications.

The nine `DataTransport` host data methods are `runtime_get`, `runtime_claim`, `heartbeat`,
`publication`, `pairing_pending`, `pairing_decision`, `channel_pending`,
`channel_admission` and `channel_ticket`. They use typed host/pairing/channel
IDs, canonical protocol DTOs and only a supplied `HostAccessCredential` bearer.
GETs carry no body. Paths follow the actual Auth v2 handlers: runtime and claim
use `/runtime` and `/runtime/claim`; heartbeat and publication are directly under
`/hosts/{hostId}`. No method selects a URL, query, cookie or caller header.

Data requests have private endpoint budgets: runtime claim, heartbeat and
publication allow 1 MiB; pairing decision, channel admission and ticket allow
16 KiB. Runtime and ticket results allow 32 KiB, pairing decision results
128 KiB, and pending/admission results 1 MiB. Both declared and streamed response
lengths are bounded. Data responses additionally require the actual Auth
`Cache-Control: no-store` header. Credential limits and header behavior remain
16 KiB requests and 32 KiB responses.

The separate data decoder directly deserializes canonical typed DTOs from the
zeroizing raw buffer, requiring a root object and rejecting backslashes and
non-ASCII before parsing. Canonical nested DTO map visitors reject positional
struct arrays while genuine bounded publication/pending lists remain accepted.
No intermediate JSON tree or second typed parse is used. Protocol wrappers own
ordinary strings; this is not an absolute zero-copy or memory-erasure guarantee.

`DataFailure` preserves only exact canonical status, code, message, retryability,
effect and empty details. Runtime admits `HOST_BUSY`; pairing/channel admit
`IDEMPOTENCY_CONFLICT` and `RESOURCE_EXHAUSTED` instead. Malformed or unknown
errors remain ambiguous `HttpStatus` failures. Pending GETs can commit stale-row
tombstones and return `OUTCOME_UNKNOWN`; a GET failure never proves no effect.
The caller retains freshness, generation, signing, consent and runtime semantic
policy. Ticket replies require `expiresInMs` in 1..5000; the caller keeps the
original observation time and deadline. The transport adds no orchestration,
retry or body replay.

## Original operation budget proposal

`Transport::with_budget` and `DataTransport::with_budget` bind fixed DTO methods
to the original absolute `Instant` and a borrowed authoritative operation check.
The owner must map its existing private `Operation::check()` into `BudgetStop`;
it must pass that same operation's deadline and must not create a fresh operation
or replacement latch for HTTP. The callback performs only that authority check.

Each named call owns a terminal-only bridge and one scoped watcher, joined before
return or unwind. DNS continues using the single process-wide native lookup
worker. Network work remains on the caller's bounded HTTP worker. A private
nonblocking TCP transport enforces absolute deadlines beneath the stock rustls
connector, including the full TCP/TLS connect stage and partial socket writes.
The existing TLS roots, certificate, hostname and signature checks are retained.
Relative ureq timeouts are additional caps, with zero rejected before sending.

This is unintegrated source, not a claim that existing callers carry their
original operation budget. Direct legacy methods retain transport-local caps.
Cancellation ends local waiting and does not prove rollback of a remote effect.
A transient external cancellation reset is observed only if the actual operation
check has seen it; the existing Operation makes observed cancellation sticky.

The socket2 dependency is already present in Cargo.lock, but the new direct
dependency edge must be generated by Cargo offline after composition. The copied
lockfile is deliberately unchanged. Rust compilation, tests, source validation
across the full graph, runtime timing and cross-platform socket behavior are
unrun in this source-only phase.
