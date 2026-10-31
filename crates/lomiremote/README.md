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

The dashboard keeps a workspace list in the left 25% and the current view in
the right 75%, including forms and operation pages. Selecting a workspace
loads a workspace-bound view immediately; Enter does not open a separate
workspace view. The right panel has Open tabs, Logs and Settings sections.
Open tabs describes the shared terminal projection and its pane states; private
desktop editor, browser and chat panels are not part of that projection.
Diagnostic logs are explicitly labeled Host-wide. Workspace settings reuse the
existing rename, sharing and removal confirmation flows.
The dashboard supports selection, refresh, keyboard help and q/Ctrl-C.
`?` opens a modal shortcut reference over the current view. Close it with
`Esc` or `?`; scrolling and resize stay inside the dialog without changing
the selected workspace or executing the displayed actions.
Click workspace rows and footer actions, or use Tab/Shift+Tab to focus a
control and Enter to activate it. The mouse wheel scrolls the list or panel
under the pointer. Dialogs capture both input methods until closed. Service,
access, profiles, diagnostics, settings and interactive setup use the same
keyboard and pointer actions; selecting a row never starts a terminal.
Arrow keys also move between panes, tabs, lists and actions. From the workspace
sidebar, Right focuses the tab strip; Left returns to the sidebar. Down moves
into tab content, Up returns to the strip, and reaching the content's bottom
can move focus to footer actions. Text fields retain their cursor controls;
arrows move focus without confirming changes.
Supported terminal emulators show an arrow over the canvas and a hand over
visible, enabled controls. Hover never activates a control. OSC 22 output is
deduplicated, updates after redraws, and restores the terminal's default mouse
pointer on exit. Input carets are independent of the mouse pointer.

Automatic pointer-shape support recognizes Kitty, Ghostty, foot, iTerm2 3.5+
and xterm 367+. Unknown emulators retain their native pointer; there is no
portable way for a TUI to force this feature. See the
[OSC 22 compatibility table](https://ghostty.org/docs/vt/osc/22).
`LOMI_REMOTE_POINTER=off` disables shape changes; `css` or `x11` can explicitly
select a dialect when an SSH session does not advertise the emulator. Automatic
shape changes are disabled under tmux and Screen. An explicit dialect under
tmux uses passthrough and requires the owner's `allow-passthrough` setting;
Lomi does not change terminal or multiplexer configuration. Non-terminal
output and Screen never receive pointer sequences. No terminal
queries or input probes are sent.

The footer shows `a Add workspace`, `s Share` for an Offline workspace and
`s Unshare` for a shared workspace. The other workspace actions are listed
in `? Shortcuts`. Adding opens a centered name field and a Select directory
button. The directory picker supports mouse and keyboard navigation, reads
directory entries only, and preserves the form when cancelled. Creating a
workspace registers the existing directory without creating or moving files;
sharing still requires separate confirmation.
Changing sharing opens a confirmation dialog with Cancel selected. Use Tab
or Left/Right to choose, Enter to accept the selection, or Esc to cancel.
Closing the dashboard restores mouse capture, raw mode, alternate screen and
cursor state independently; it never sends a host stop command.
Untrusted labels have control characters
replaced and their displayed length bounded. No shell output is interpreted by
Ratatui. The dashboard uses Ratatui and does not interpret shell output as UI content.

The dashboard and setup screens use a fixed dark palette from the built-in
Lomi desktop theme. Shared colors and text treatments live in `src/ui/theme.rs`.
RGB terminals use the original values; Apple's Terminal uses the nearest stable
256-color equivalents. The theme does not follow the OS light/dark preference.

For appearance-only work, run the existing dashboard with in-memory sample data:

```sh
cargo run --locked -p lomiremote --example ui_preview
```

This debug example uses the real renderer and keyboard navigation. It never
connects to a Host, starts services, reads credentials or changes configuration;
all backend actions are disabled. Build without `LOMI_HOST_*` release pins.
Use the normal page shortcuts and press `q` or `Ctrl-C` to close the preview.

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
