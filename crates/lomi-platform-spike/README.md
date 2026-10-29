# Platform feasibility probes (S0.3a / E0)

These are synthetic fixtures, not a production Git service or qualified daemon.
No GUI, Tauri, Node, actual user repository, credentials or cloud service is
required. No service is registered by the commands below.

From the `lomi-remote` repository root:

```sh
cargo test -p lomi-platform-spike
cargo clippy -p lomi-platform-spike --all-targets -- -D warnings
cargo run -p lomi-platform-spike --bin pty-probe
```

## Observed evidence

2026-10-19, macOS 27.0.1 (26A434), arm64, interactive user session;
Rust 1.98.1 (48a229cea 2026-09-01), Apple Git 2.54.0 (Apple Git-157):

| Check | Result |
| --- | --- |
| Six Git tests, including 5-second FIFO deadline | passed, exit 0; 5.10s |
| Clippy with warnings denied | passed, exit 0 |
| Renderer-free PTY output and exact synthetic OSC7 CWD | passed, exit 0 |
| Shell survives a separate IPC client process disconnect | passed |
| Resize to 37 rows / 101 columns confirmed by native stty | passed |
| Ctrl-C trap, shell exit, synthetic background worker reaped | passed |
| launchd LaunchAgent / LaunchDaemon | not_run |
| Logout / lock / boot / service restart / locked secret storage | not_run |
| Linux systemd user + linger / Windows SCM + ConPTY | not_run |
| Linux / Windows Git isolation adapter and native tests | not_run; unavailable |

`pty-probe` prints each observed result and explicitly prints the unrun service
checks. Its IPC is a private temporary Unix socket with a five-byte handshake,
used only to prove that a separate client's lifetime does not own the PTY.
It is not the host's future IPC/authentication protocol. The shell explicitly
handles Ctrl-C and reaps a single known background worker; arbitrary process
forests and forceful service shutdown remain unqualified. OSC7 is emitted by the
controlled shell fixture, not discovered automatically for arbitrary shells.
This checks a byte substring, not a host parser/model or snapshot adapter. Both
the shell and client use a cleared environment with an explicit temporary HOME,
system-only PATH and C locale; the shell uses an absolute `/bin/sh -f -c` command
without user startup files.

## Git scope and rejection behavior

Only status (`--porcelain=v2 -z`) and whole-worktree diff are public operations.
Neither caller-supplied argv nor executable/environment is accepted. A pinned
open directory handle sets CWD before sandbox execution. Output is capped at
2 MiB, stderr at 16 KiB, and execution at five seconds. Any stderr, including an
optional clean filter failure followed by Git exit zero, rejects all output.
The original index identity must remain unchanged in the successful fixture.

The Seatbelt profile blocks fork, configured helper execution, network, and
filesystem writes (except `/dev/null`); content reads are limited to the fixture
root and the declared runtime paths. The initial exec exception permits only
`/Library/Developer/CommandLineTools/usr/bin/git`. Git and sandbox-exec must have
root-owned, non-writable, non-symlink ancestors and unchanged file identities.
There is no PATH lookup or executable fallback. Missing tools reject execution.

`/usr/bin/git` is an Apple developer-tool launcher on this machine. This command
failed to launch the selected Xcode Git because additional exec was denied:

```sh
/usr/bin/sandbox-exec -p '(version 1)(allow default)(deny process-fork)(deny process-exec)(allow process-exec (literal "/usr/bin/git"))' /usr/bin/git --version
```

Observed stderr: `can't exec '/Applications/Xcode.app/Contents/Developer/usr/bin/git'
(errno=Operation not permitted)`. The inherited design's fixed Command Line
Tools executable is therefore used instead. The tests do not widen process
execution to accommodate the launcher.

Adversarial fixtures cover clean and process filters during status and diff,
outside config includes, a config symlink, external alternate object storage,
a symlinked `.git`, denied config writes, denied HTTP Git transport, oversized
diff output and a FIFO config read with no writer. The HTTP transport test proves
no connection reached a loopback listener under the combined helper/network
policy; it does not separately qualify a direct socket syscall restriction.

Linux and Windows return `UnsupportedPlatform` before process execution. There
is no unisolated fallback. Their native tests are unrun; a cfg-gated rejection
test is available when a native runner is provided. The PTY executable likewise
returns exit 2 with `not_run` outside macOS.

## Qualification limits / next decisions

- Apple's deprecated sandbox-exec is an experiment, not a supported long-term
  security architecture. The profile begins with `allow default` and only
  restricts the stated process/file/network classes; a broader OS policy review
  is required before production.
- Runtime read allowances (`/System`, `/usr/lib`, `/usr/share`) still require a
  reviewed minimal runtime inventory, including developer-tool Git updates.
- A hardlink inside an allowed root aliases the same inode as an outside path;
  path-based Seatbelt does not establish provenance. Hardlinks, concurrent
  metadata/root replacement, and comprehensive repository identity admission
  remain unresolved. Do not enable production `git.read` from this result.
- Ordinary `.git` directories are the only fixtures. Linked worktrees and
  separately granted metadata directories are rejected. Full object/path/domain
  validation, pagination, cancellation/revoke checks and shared writer admission
  are outside this probe.
- No service registration, restart, real logout/boot, keyring unlock/locked
  storage, Windows SCM or Linux linger test was performed. E0.2 / S0.2 and
  cross-platform S0.3a remain open. A macOS ordinary-session pass does not qualify
  another OS or startup mode.

See [NATIVE-HARNESS.md](NATIVE-HARNESS.md) for reproducible macOS service-run
instructions and the remaining platform-specific harness requirements.
