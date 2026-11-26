# Debug Host against a local HTTPS/WSS stack

Debug builds of `lomiremote` (never release builds) can trust one extra local
CA, such as the Caddy `tls internal` root, for every Host TLS client (identity
and Remote API HTTP, relay WebSocket). The code is behind
`cfg(debug_assertions)`; a release binary contains neither the variable name
nor the loader. Certificate and hostname verification stay on.

- `LOMI_REMOTE_DEV_EXTRA_CA` must be an absolute path to a PEM file. If it is
  set but unreadable, relative, empty or not valid PEM, the Host refuses to
  start TLS (fail closed).
- Limit: when set, the HTTP clients (ureq) trust only this CA, not the
  built-in WebPki roots; the relay client trusts WebPki plus this CA.
- Existing origin rules already allow `localhost` and `127.0.0.1` with an
  explicit port other than 443. The identity origin and the Remote API origin
  must differ, so use different ports.

```sh
export PATH=$HOME/.cargo/bin:/opt/homebrew/bin:$PATH
export LOMI_REMOTE_DEV_EXTRA_CA="$HOME/Library/Application Support/Caddy/pki/authorities/local/root.crt"
PROFILE=$(mktemp -d)/profile

cargo build -p lomiremote   # debug profile, required
BIN=target/debug/lomiremote

"$BIN" --profile-dir "$PROFILE" auth configure --confirm \
  --origin https://localhost:8443 \
  --remote-api-origin https://localhost:8444 \
  --relay-endpoint wss://localhost:8445/v2/relay \
  --client-id <public-client-id> \
  --provider protected-file --ack-os-permissions-only

"$BIN" --profile-dir "$PROFILE" daemon run
```

Ports are examples; use the ones your Caddyfile serves. Run the Host with the
same exported variable in its environment.
