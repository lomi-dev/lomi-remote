# Native Linux Git feasibility experiment

This executable is a synthetic security probe. It does not expose a production
Git service, advertise `git.read`, or qualify S0.3a. Its supported experimental
host is explicitly pinned: non-root Ubuntu 24.04.5 LTS, Linux
6.8.0-146-generic, aarch64, Landlock ABI **exactly 4**, Git 2.43.0 and the six
root-owned runtime file digests in `src/linux.rs`. Other OS/architectures,
kernels, ABI versions, runtime identities and failed setup reject execution.
There is no unsandboxed or alternative-Git fallback.

From the macOS development repository, with the existing disposable `lomi-e0`
Lima VM running:

```sh
python3 tools/run_linux_git_spike.py
```

The driver copies only explicitly inventoried source files and the Cargo lock
through a checked tar archive. It creates a fresh directory under
`/home/lomi-e0/lomi-git-source`, compiles native C header assertions, then builds,
lints and executes the Rust probe on Linux. It never installs packages, starts
services, enables linger, mounts host directories or reboots the VM. Build caches
and compiler temp files are placed beneath that fresh source directory. Earlier
development iterations reused the VM's existing Cargo cache; no credentials or
host environment files were transferred.

`artifacts/git-linux/evidence.json` records approved source hashes, exact argv,
deadlines, durations, exit codes, native OS/tool identity, runtime digests,
aggregate regressions and explicit qualification limits. A failed or interrupted
run remains incomplete. The driver prints aggregate results, not Git content.
Build/regression failure diagnostics concern synthetic fixtures only.

## Isolation route

1. The outer owner opens and pins the root directory and fixed runtime files.
   The runtime files must have root ownership, trusted permissions, the required
   regular/executable types, approved SHA-256 digests and unchanged bindings. Only a closed Status/Diff observation is used by the
   observation path. Caller environment and arbitrary Git argv are not accepted.
2. A fresh, single-threaded trusted broker executable receives only explicitly
   inherited pinned descriptors. It prepares argv/env and a private socket pair,
   Landlock rules and the syscall filter before forking the bootstrap child.
3. The child changes CWD with the pinned root fd, sets `NO_NEW_PRIVS`, enforces
   all ABI4 filesystem rights and TCP bind/connect rights, and applies resource
   limits. Root content is read-only. Only exact Git/interpreter/library/cache
   runtime files receive the required rights.
4. All inherited descriptors except stdio, Git and the private bootstrap socket
   are closed before interpreting repository content. Stdin is inert null and
   stdout/stderr are bounded pipes. The Git fd is close-on-exec. The child installs
   an architecture-checked seccomp allowlist with one execveat notification route,
   transfers the listener by SCM_RIGHTS, then closes its own listener/socket.
5. The broker accepts exactly the expected child PID, syscall, architecture,
   Git fd, pointer register values and `AT_EMPTY_PATH` flags, validates the
   notification ID, sends CONTINUE once and immediately closes its last listener.
   It never reads or authorizes path strings supplied by untrusted running code.
   At that point the child is still the trusted, single-threaded bootstrap;
   repository-controlled interpretation begins only in the approved Git image.
6. The outer owner bounds both broker ioctl and Git execution with a five-second
   wall deadline, two-MiB stdout and 16-KiB stderr limits. Any stderr, nonzero exit,
   setup error, changed binding, overflow or deadline rejects output. It signals
   the owned process group while its leader remains unreaped, then waits.
   Parent-death SIGKILL is armed and parent identity checked at both process
   boundaries. Thus forced loss of the owner also kills broker and Git.

No process/thread creation, general exec, socket creation/network use, metadata
mutation, mount/namespace operations, ptrace/process-memory access, io_uring,
unknown syscall or repository data write is permitted after sandbox installation.
Read-only opens and metadata queries are explicitly listed. `chdir` is needed by
Git's worktree setup; it does not widen Landlock's content grants. Fork/clone and
exec helpers remain denied even if configured Git filters or aliases name them.

Git startup unconditionally opens `/dev/null` O_RDWR. The only inert-device
exception is the verified root-owned character device major 1/minor 3, granted
READ_FILE|WRITE_FILE. O_RDWR opens rely on Landlock to reject regular-file writes;
O_WRONLY/create/truncate/append/tmpfile opens are denied by seccomp. Actual
write/writev syscalls are restricted to the two output pipe descriptor numbers.
This exception does not grant repository/runtime regular-file writes.

Runtime selection is fixed, not discovered by executing an arbitrary binary.
The interpreter path and dependencies were inspected from `/usr/bin/git` ELF
metadata on this VM. `/etc/ld.so.cache` was explicitly re-pinned after the separate
native-terminal workflow installed development Vim; its ownership, regular type
and new digest were verified, and the other five ELF digests remained unchanged.
No read grant was expanded to `/usr/lib` or another runtime subtree.

## Actual native checks

The native corpus exercises:

- Successful porcelain-v2 status and diff, with unchanged index identity.
- Direct denial of TCP/UDP/Unix socket creation, process/thread creation,
  execve, connect, ioctl, ptrace, process-memory access, io_uring, namespace/mount
  operations, metadata mutations and write opens.
- Listener closure before bootstrap approval, and closure after one CONTINUE.
  The latter intentionally makes the first trusted execveat fail EFAULT; its
  second attempt must fail ENOSYS with no listener remaining.
- A deliberately inherited private fd being closed before Git starts.
- Optional clean/process filters rejected during status and diff without helper
  markers or silently accepted fallback. Same-size content changes force the
  status fixture through content/filter evaluation; a size-only status result
  would not demonstrate attempted filter execution.
- Explicitly disabled fsmonitor, external diff/textconv and closed builtin argv
  taking precedence over a malicious shell alias.
- Outside config includes, config symlinks, alternate object stores and linked
  Git metadata refusal.
- Denied Git config writes and HTTP transport, with unchanged config and no
  connection arriving at a loopback listener.
- Output overflow, blocked FIFO deadline, ordinary root-path replacement and a
  deliberately mismatched passed runtime fd.
- SIGINT and forced SIGKILL of the outer owner, after observing the child image
  as `/usr/bin/git`; both must leave no owned process group alive.

The C fixture verifies manual syscall numbers, ioctl encodings, packed structure
sizes, ABI rights and non-root primitive availability against the actual Ubuntu
headers. Native Clippy runs with `-D warnings`. A macOS build checks only the
unsupported-platform stub and never substitutes for these native checks.

## Limits that prevent qualification

**ABI4 Landlock does not hide outside metadata.** The direct probe demonstrates
that outside file contents are denied while `newfstatat` metadata remains
observable. **A private inode hardlinked into the approved root remains
readable.** The corpus demonstrates this with a synthetic diff and reports both
limits explicitly. A preflight link-count scan cannot fix concurrent hardlink
creation or establish inode provenance over a mutable tree.

Directory-fd pinning and a final pathname identity check detect ordinary root
replacement; they do not establish a filesystem snapshot or defeat swap-back
races. This experiment does not protect against an independently malicious local
account owner/root, kernel compromise, credential sharing or arbitrary shell
execution. There is no qualified production policy for broader distributions,
architectures, kernel updates, linked worktrees, uncommon Git configuration,
large repositories or nonlocal filesystem stalls during trusted preflight.

The executable's `regression`, `cancel`, internal worker and fixed adversarial
probe variants are fixture entry points, not public RPC operations. No real user
repository, terminal payload, SSH key or production credential is used.

Primary references behind this route:

- [Linux 6.8 Landlock userspace API](https://docs.kernel.org/6.8/userspace-api/landlock.html):
  ABI rights, already-open descriptors and metadata limitations.
- [Linux v6.8 seccomp UAPI](https://github.com/torvalds/linux/blob/v6.8/include/uapi/linux/seccomp.h):
  listener protocol and the warning against CONTINUE over mutable untrusted
  pointers. This experiment confines CONTINUE to its trusted bootstrap only.
- [Linux v6.8 seccomp implementation](https://github.com/torvalds/linux/blob/v6.8/kernel/seccomp.c):
  replied notification preservation during listener teardown and ENOSYS when no
  listener exists. Both sides are also tested against the actual native kernel.
