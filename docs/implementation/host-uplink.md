# Host uplink (plan 1.0, P2.1 / P2.14 / P2.15)

One WebSocket from the Host to the relay (`wss://<relay>/relay`) that replaces
the periodic HTTP traffic of an idle Host: the heartbeat and the two pending
polls. It also carries `publication.put` and `token.update`. Code:
`crates/lomi-host-http/src/uplink.rs`. Frames come from `lomi-remote-core`
(`frame`); there is no second codec.

## Switch

Off unless `LOMI_REMOTE_UPLINK=<64 lowercase hex>` (the relay's
`REMOTE_RELAY_CONTRACT_HASH`) is set in the Host's environment. Off means the
module is never initialised: every hook returns "use HTTP" and the Host behaves
exactly as before. The relay URL is not configured separately: it is the
configured `--relay-endpoint` with `/v2/relay` replaced by `/relay`. A persistent
configuration field and a build-time contract hash are open (see Risks).

## Design: the uplink is subordinate to the actor

The Host's runtime/publication state machine (fence, gate, publication
barrier, peer cutoff) is unchanged. It still calls the same four
`DataTransport` methods with its own token and runtime binding:

| Call | Uplink off, down, stale or not matching the binding | Uplink admitted for this runtime |
| --- | --- | --- |
| `heartbeat` | HTTP | answered locally: same runtime, `lease_ms` 15000, `freshness_ms` 5000 |
| `runtime_get` | HTTP | answered locally from the admitted runtime and the publication sequence this link knows |
| `publication` | HTTP | chunked `publication.put` CALLs, same single-attempt rule |
| `pairing_pending`, `channel_pending` | HTTP | "nothing pending" without a request, unless a wake hint is set |

Consequences:

- The actor, not the uplink thread, decides everything that is security
  relevant. A synthesized heartbeat is the same `HeartbeatResult` the HTTP route
  returns, so lease, freshness and the peer cutoff are computed by the existing
  code from the existing observation.
- The actor owns the token. Every heartbeat call carries the current access
  token and runtime binding; that call is the only thing that keeps the link
  alive (`OFFER_TTL`, 10 s). A paused, gated, logged-out or blocked actor stops
  calling and the link closes by itself; the Host is then offline exactly as
  when the HTTP heartbeat stops.
- The first runtime GET and claim stay HTTP (once per start or re-claim). The
  AUTH claim is the idempotent form of that claim: same `runtimeId`,
  `expectedGeneration = runtimeGeneration - 1`. READY must echo exactly the
  binding the actor holds (host, runtime id, generation, epoch), else the link
  is not used. `STALE_EPOCH` or `HOST_BUSY` on AUTH leave the link down and the
  heartbeat on HTTP, where the actor's existing recovery (re-read, re-claim)
  runs; a changed binding reconnects at once.

### Freshness

`authority.fresh` arrives every 2 s while the relay's authorization feed is
confirmed. A heartbeat is answered from the link only if the last one is at most
3 s old, and then grants 5 s (the HTTP value): at most 8 s after relay
confirmation, the plan's bound. When the feed lapses or the link drops, the
next heartbeat is a normal HTTP heartbeat with the server's own freshness.

### Runtime reads

The actor re-reads the runtime whenever a worker unit rotates (every ~15 s, even
idle), which would be the last periodic request of an idle Host. While the link
is admitted for the binding the actor last used, fresh, and its publication
sequence known, that read is answered locally: READY gives the sequence, our own
acknowledged publications advance it, an uncertain publication clears it, and
any real HTTP runtime read restores it. A cleared sequence sends the read to
HTTP, where the actor's existing reconciliation runs.

`lease_ms` is a fixed 15 s, not READY's `leaseMs` (the lease remaining at that
moment): the relay renews the 30 s lease at least every 15 s while the link
lives, so 15 s is always true and the actor's rolling `lease_until` never lapses.

### Peer activity keeps heartbeats on HTTP (until P3)

Pairing and channel routes (pending, get, decision, admission, ticket) still
require the server's 5 s freshness, and the relay's batched availability write
leaves gaps in it (it only covers 5 s of every `REMOTE_RELAY_PRESENCE_WRITE_MS`).
So, from a wake hint or any peer-scope HTTP call until 30 s after the last one,
heartbeats and runtime reads go to HTTP again, and a hinted pending read waits
(its hint is kept) until an HTTP heartbeat has succeeded in the last 3 s. An idle
Host never enters this mode; an active one behaves as before. Removing it is part
of P3 (channels over the link).

### Pending reads (wake hints)

`channel.pending` / `pairing.pending` set a flag. The next pending read hits
HTTP once (and again until the server answers an empty list, so a proposal that
was fetched but not yet handled is never forgotten); with no flag the read
returns an empty list locally. Both flags are set on every connect. The actor's
own cadence (500 ms) is unchanged, so discovery latency is the same as today;
only the requests are gone.

### Publication

`PublicationParams` is split into chunks of at most ~60 KB of JSON (relay rule:
a workspace may continue as the first entry of the next chunk), sent one CALL
at a time. Outcomes map to what the HTTP route gives the actor: `STALE_EPOCH`
-> `StaleEpoch`, `AUTH_FAILED` -> `AuthRequired`, `INVALID_ARGUMENT` ->
`InvalidArgument`; an uncertain final write (`UNAVAILABLE`/`TIMEOUT` on the last
chunk, wrong sequence in the reply, link lost after the last chunk was sent,
caller gave up after sending it) -> `OutcomeUnknown`, which the actor reconciles
with a fresh GET exactly as for HTTP. Nothing is replayed. While a
`token.update` is pending the publication goes to HTTP (the relay would still
check the old token hash).

### Token rotation (P2.15)

Rotation stays in the actor (HTTP, durable). Right after `accept_rotation`
succeeds, the actor calls `uplink::offer_token`; the uplink sends `token.update`
on the live link (the relay re-times the link and replaces its stored hash; the
old hash is tolerated for 20 s). The link is not closed. If the update is
refused, the link closes and reconnects with the new token. The next heartbeat
carries the token too, so a missed hand-off self-heals within a second.

### Threading and waits

One thread `lomi-uplink` (blocking `tungstenite` over the Host's rustls
client, including `LOMI_REMOTE_DEV_EXTRA_CA` in debug builds). The socket is
`RelayConnection` from `relay.rs` (`RelayTransport::connect_link`), so the
existing budget, resolver and TLS code is reused. Waits are `poll(2)` on the
socket plus a wake pipe (publication job, token hand-off); no `sleep` or
`recv_timeout` stretching. Reconnect: 0.5 s doubling to 30 s, 50-100 % jitter,
reset after a link that lived 10 s. Other HTTP paths keep their single-attempt
rule; only this thread retries.

## Windows (P2.16)

The module has no Windows-only code: the wake pipe and `poll(2)` are
`cfg(unix)`; elsewhere the thread waits in 10 ms slices (as `wait_ready`
already does on Windows). `ring` needs a C toolchain, which a Mac does not
have for MSVC, but its build script can be stubbed for a type check:

```sh
cargo check -p lomi-host-http --target x86_64-pc-windows-msvc \
  --config 'target.x86_64-pc-windows-msvc.ring_core_0_17_14_.rustc-link-search=[]'
```

`lomi-host` (which holds the actor-side hooks in `unix/cloud.rs` and
`unix/shared_owner.rs`, compiled on Windows too) cannot be checked this way:
`wasmtime-internal-fiber` compiles `windows.c` against `<windows.h>`. Those two
edits only call `uplink::enabled`, `set_endpoint` and `offer_token`; the full
check stays with desktop CI.

## Not changed / not covered

- Channels, tickets and admission stay HTTP and relay data channels (P3).
- `device.revoked`, `devices.changed` and `circuit.*` events are ignored; the
  Host still learns of device revocation through the existing pairing reads
  (P3 moves that onto the uplink). `host.revoked` closes the link; the next
  heartbeat is HTTP and hits the existing revocation handling.
- Legacy readers of the server's freshness (web inventory "online") see an
  uplink Host as live for 5 s of every `REMOTE_RELAY_PRESENCE_WRITE_MS`; the local
  stack was run with 5000 so the e2e does not hit a gap. Clients move to
  `presence` events in P2.17-P2.19.
- The actor's own wake-ups (heartbeat tick, 500 ms peer cadence) still run
  locally; they no longer make requests.

## Risks

- Contract hash and relay URL derivation are a development switch, not a
  shipped configuration.
- `lomi-remote-core` enables `serde_json/preserve_order` for the whole Host
  build (key order of `json!` audit lines changes from sorted to insertion).
- Idle CPU wake-ups of the actor were not reduced.
