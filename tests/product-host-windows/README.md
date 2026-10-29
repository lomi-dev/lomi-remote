# Native Windows product host proof

Run `python3 tests/product-host-windows/run_native.py` from the workspace.
The runner uses the pinned Windows SSH host and archives exact product sources,
vendored parsers, tool sources, native binary digests and bounded receipts under
`artifacts/product-host-windows/<UUID>.*`. Its isolated workspace stages the
complete manifest-derived workspace path dependency closure. The original
workspace manifest and checked-in lock are staged unchanged, hashed in the
report, and enforced by remote Cargo commands using `--locked`.

The native MSVC build exercises the real CLI, manual daemon, private profile,
SQLite store, authenticated IPC, terminal service and ConPTY backend in Session 0.
The synthetic workspace checks status/doctor, workspace and terminal lifecycle,
two independent observers, control ownership, duplicate input receipts, native
resize, Ctrl+C in the default command interpreter, native exit, terminal restart,
close, daemon stop and persistent workspace identity after owner restart. Stream
updates are validated and applied while replies arrive; snapshots use the Rust
terminal model. Profile/database/WAL/SHM checks verify current-user ownership and
private access before and after restart; absent SHM is allowed for SQLite's
exclusive WAL mode.

Two subsequent independent SSH connections start and then authenticate the same
runtime before stopping it. An intermediate connection verifies its exact owned
executable and Session 0. This checks the configured OpenSSH Job permits the
launcher's explicit breakaway; a forbidden breakaway fails without a fallback.

Inputs and profiles use fresh UUID names directly under USERPROFILE. No SCM,
autostart, reboot, logoff or account configuration changes occur. Captures contain
closed diagnostics, public synthetic identifiers and hashes. Cleanup requires
zero processes with an executable inside the exact owned source directory and
checks the profile name and reparse status. Failed or uncertain runs preserve
their inputs and profile. Never kill or adopt processes using reported numeric
PIDs. The recorded Windows build is the qualification scope.
