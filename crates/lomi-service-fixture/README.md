# Persistent synthetic native PTY owner

This is an E0.2 qualification fixture, not a product daemon. It owns one
controlled `/bin/sh -f -c` process, a native PTY, bounded Rust model counters,
private same-UID Unix IPC and an exclusive owner lock. It has no cloud, auth,
sharing, TUI, GUI, arbitrary input/exec, install or production snapshot API.

```sh
cargo test -p lomi-service-fixture
cargo clippy -p lomi-service-fixture --all-targets -- -D warnings
lomi-service-fixture owner /ABSOLUTE/PRIVATE/STATE
lomi-service-fixture client /ABSOLUTE/PRIVATE/STATE start
lomi-service-fixture client /ABSOLUTE/PRIVATE/STATE status
```

Client requests are limited to `status`, `start`, `resize` (37 rows, 101 columns),
`after-detach`, `ctrl-c` and `exit`. Each CLI invocation is a separate client
process. The owner survives client exit. Its shell has an empty environment
with only synthetic HOME, fixed PATH/locale/TERM and private temporary CWD.
A synthetic OSC 7 frame is detected by the host without a renderer. PTY bytes
never appear on stdout or in evidence. Status exposes counters, booleans,
epochs and numeric fixture PIDs only.

The read queue is bounded to 32 chunks of 2 KiB, the detection tail to 4 KiB,
the parser to a fixed viewport/eight scrollback rows, and lifetime output to
1 MiB. IPC requests have a 250 ms whole-frame deadline, check the shutdown flag
between reads, and reject incomplete/overlong frames. Descriptor reads open
nonblocking and reject non-regular files before reading. A startup guard owns
the child immediately after spawn, closes undrained PTY handles and performs
bounded process-group termination/reaping on every later setup failure. SIGTERM triggers a
four-second owned process-group shutdown, followed by SIGKILL and a two-second
reap deadline. The synthetic shell traps termination to reap its background
worker. systemd's `KillMode=control-group` supplies additional service cleanup.

Only a version and session epoch are persisted atomically; never a PID or input
queue. Every owner restart reports the previous epoch as `lost` without
spawning/adopting a shell. An explicit `start` creates a new epoch and empty
input state. Corrupt descriptors fail closed. This does not preserve a PTY
across owner death, VM reboot or machine restart.

The Linux user-service proof runs only in the disposable VM through
`tools/run_linux_service_fixture.py`. It uses a dedicated `lomi-service` UID
2001 account with `nologin`, distinct from SSH user `lomi-e0`. It tests a real
enabled systemd user unit with linger and `Restart=on-failure`; boot proof
checks a changed kernel boot ID, no service-account login session, current-boot
journal metadata and unit start timestamps. The driver cleans up the unit,
linger and user manager, then leaves the VM running. No service is registered
on the macOS host. Account/state are retained in the disposable VM only for
inspection; no production credentials or application data are used.

macOS/Linux native PTY tests do not qualify launchd or Windows SCM/ConPTY.
The fixture deliberately does not support escaped descendants, arbitrary
shell profiles, production resync/render semantics, unattended credential
storage or a complete installer.

Review regression coverage includes an injected post-spawn failure with a real
background worker, FIFO descriptor startup rejection, and a trickling IPC peer
while SIGTERM terminates the owner and its descendants. Current native tests
are one unit test plus six process integration tests on macOS and Linux.

The driver invalidates downstream evidence before new build/prepare/boot work,
records running/interrupted invocations before commands execute, and returns 130
on Ctrl-C. Its local subprocess runner cleans up the owned SSH process group.
Guest phases have a GNU `timeout`, absolute start deadline, exclusive phase lock
and matching completion token. If remote completion cannot be verified,
automatic cleanup is deferred rather than racing the still-running phase.
A later explicit cleanup first verifies its deadline and released guest lock.

`python3 tools/run_linux_service_fixture.py --phase native-validation` refreshes
only approved fixture source and runs native/driver regressions without service
registration or VM reboot. The original 40-check systemd/boot proof remains
labeled with its historical source snapshot. Review-fix native validation has
its own source/archival digests and does not claim a rerun of that lifecycle.
