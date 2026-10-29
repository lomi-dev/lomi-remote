# lomiremote

The native Rust CLI and Ratatui dashboard are clients of the same local host.
The foreground daemon delegates to `lomi-host`; the dashboard contains no host
store, process coordinator, terminal emulator or cloud authorization logic.

From the repository root:

```sh
cargo run --locked -p lomiremote -- --help
cargo run --locked -p lomiremote -- daemon run --profile-dir /private/host-profile
cargo run --locked -p lomiremote -- status --json --profile-dir /private/host-profile
cargo run --locked -p lomiremote -- workspace add --name Build --path .
cargo run --locked -p lomiremote
```

With no command, the dashboard opens only when both stdin and stdout are terminals.
Otherwise it writes plain help to stderr and exits with code 2. `--help`,
`--version`, `version`, and JSON status/doctor output work with redirection.
An absent host produces a versioned JSON error and exit code 4; diagnostics do
not create a profile or start a daemon implicitly.

The dashboard supports selection, details, refresh, keyboard help and q/Ctrl-C.
Closing it restores raw mode, alternate screen and cursor state independently;
it never sends a host stop command. Untrusted labels have control characters
replaced and their displayed length bounded. No shell output is interpreted by
Ratatui. The dashboard uses Ratatui and does not interpret shell output as UI content.

`setup` loads and can save a local manual/login/boot start preference. Saving it
does not install or start an OS service, enroll an account, or share a workspace;
those actions remain unavailable. Unsupported commands return an error instead
of reporting success.
Workspace removal and sharing changes require `--confirm` and pass through local
IPC admission. Removing a registration never requests deletion of project files.


Terminal commands inspect the current workspace context and domain revision
before each explicit mutation. The configured `default` profile starts the
operator's OS shell; the CLI accepts no command, environment or content argument.

```sh
lomiremote terminal list --workspace WORKSPACE_UUID --json
lomiremote terminal create --workspace WORKSPACE_UUID --name Build --json
lomiremote terminal split --workspace WORKSPACE_UUID --pane PANE_UUID --axis vertical
lomiremote terminal rename --workspace WORKSPACE_UUID --tab TAB_UUID --name Logs
lomiremote terminal move --workspace WORKSPACE_UUID --pane PANE_UUID --target-pane OTHER_PANE_UUID
lomiremote terminal close --workspace WORKSPACE_UUID --pane PANE_UUID --confirm
lomiremote terminal restart --workspace WORKSPACE_UUID --pane PANE_UUID --confirm
lomiremote terminal attach --workspace WORKSPACE_UUID --pane PANE_UUID
lomiremote terminal attach --workspace WORKSPACE_UUID --pane PANE_UUID --control
```

List and attach never restart stopped or lost panes. Close and restart compare
the current persisted descriptor, including an absent session. Every mutation
uses a fresh operation ID; uncertain replies report that ID and exit 7, without
retrying. JSON mutation output contains the canonical operation receipt.

Attach initially observes. `--control` requests exclusive control only after the
full structured snapshot is validated, rendered and acknowledged. The view draws
canonical grid cells through Ratatui, including wide characters, colors and the
alternate buffer. It never reparses PTY bytes. Snapshot and delta assemblies have
an 8 MiB limit and a ten-second deadline. Invalid, missing or out-of-order frames
close the view and require an explicit new attach.

F10 or Ctrl-] closes only the local view. While controlled, Ctrl-C is a PTY input
byte. Focus loss or lease expiry drops control. Input writes are bounded to
16 KiB and use the server's next input/resize counters; uncertain or partial
input is never replayed. Large paste is rejected before sending. Available key
presses are coalesced into one bounded write to reduce output backpressure.
Closing a view does not stop the host or shell, and the host continues reading
output without an attached view. A view does not automatically reclaim control
after revocation. Windows defaults to `%USERPROFILE%\.lomiRemote`.
