# Native Windows product PTY proof

Run `python3 tests/product-pty-windows/run_native.py` from the workspace.
The runner uses the existing passwordless SSH target and pinned
`artifacts/windows/known_hosts`; it never installs a service or changes SCM,
autostart, logon, user data, or credentials.

Each run archives exact inputs and SHA-256 provenance under
`artifacts/product-pty-windows/<UUID>.*`. A side-by-side UUID directory contains
an isolated four-crate workspace, the unchanged vendored parser sources, and an
offline-derived dependency lock. Every subset dependency must match the real
workspace's version, registry source and checksum. MSVC builds run on the native
Windows 10 LTSC machine. Evidence records the exact OS build and Rust toolchain;
this is not qualification of other Windows versions.

`pty-proof` runs only its own synthetic console child and descendant. It checks
Session 0, explicit input, resize, Ctrl+C, normal exit, direct-child wait and
Job active-process-zero cleanup. An abrupt owner exit bypasses Rust destructors,
exercising kill-on-final-Job-handle-close; a separately owned same-account child
must remain alive. Feature-gated synthetic faults reject authorization, fail
suspended setup, fail executable creation, and fail closer-thread creation;
the last must retain HPCON ownership and complete on retry. Authorization is
checked after suspended creation and Job assignment, immediately before resume;
a rejected fence proves the child startup marker never ran. Resize pressure,
cancellation before a delayed syscall, retained resources after timeout and the
global admission bound are also exercised.

The terminal example uses `TerminalService::new()` with the native backend and
its independent reader. It checks two observers, one controller, rejected
observer input, input receipts and duplicate suppression, native resize and Rust
model dimensions, parsed output, Ctrl+C, native exit publication, and shutdown.
Cleanup faults must remain unavailable for normal durable exit publication. A
barrier forces a pending read to succeed after its deadline and before
cancellation; an immediate-exit child emits at least 17 KiB and its final marker
must survive the bounded natural-exit drain into the final snapshot.
The real Rust terminal parser is used throughout; there is no GUI or Node host.

Output logs contain fixed synthetic diagnostics only. Transfers have bounded
capture and deadlines. Remote cleanup requires the exact UUID directory name
and zero remaining processes whose executable belongs to that directory. A
failed or uncertain run preserves its directory and evidence for inspection;
never kill or adopt processes by an emitted numeric PID. Successful runs remove
only their own directory and input archive.
