# Linux Git read isolation experiment

This is a bounded native ARM64 Linux experiment for ordinary repositories. It
is not a production `git.read` adapter or an unconditional S0.3a qualification.
The historical `lomi-linux-git-spike` remains unchanged; its outside-metadata
and hardlink counterexamples motivated this separate implementation.

Run from the repository root on the development Mac:

```sh
python3 tools/run_linux_git_isolation_spike.py
```

The driver transfers inventory-approved source to a fresh directory in the
disposable native `lomi-e0` VM, builds with the locked dependencies, checks the
native ABI, runs Clippy and isolation regressions, and records exact operations
and runtime digests in `artifacts/git-linux-isolation/evidence.json`. It uses no
host mounts or real repository payload. Any run that times out, is interrupted,
or fails a check is incomplete. The runner records ownership intent before
installing a profile. A unique root-owned staging file is hard-linked to the
exact profile path, so cleanup can verify inode identity after interruption.
It checks the live kernel policy and leaves a preexisting file or policy alone.

## Isolation route

The source root is opened as a pinned directory. A bounded traversal uses
root-relative `openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, and
`RESOLVE_NO_MAGICLINKS`. Regular files must have one link before their contents
are read. File bytes are copied to sealed memfds with their mode and mtime;
symlink targets are copied as metadata without following them. Special files,
linked files, `.git/commondir`, object alternates, and unsafe config syntax are
rejected. Metadata, directory membership, and SHA-256 content are checked
during capture and again before Git and publication. A changed source returns
`Changed` and discards the output.

Bubblewrap 0.9.0 creates private user, mount, PID, network, IPC, and UTS
namespaces. The new root contains only the sealed repository, pinned Git and
ELF runtime, bootstrap, and an exact `/dev/null` device. Trusted bootstrap
sets snapshot timestamps and makes the mounts read-only while it has only
`CAP_SYS_ADMIN` and `CAP_SETPCAP`. It then clears every effective, permitted,
inheritable, bounding, and ambient capability and sets `no_new_privs` before
forking the broker. One seccomp user notification authorizes the fixed Git
`execveat`; other helper execution, new processes, network access, and writes
are denied. The launcher closes inherited host descriptors. Output, stderr,
runtime, and process ownership are bounded; owner loss and interruption are
tested on native Linux.

The VM requires a root-owned exact-path AppArmor development profile granting
`userns` to `/usr/bin/bwrap`. The driver checks its SHA-256 and installs/loads
only this profile through passwordless `sudo`; it does not change global userns
sysctls or use a setuid fallback. The pinned platform is Ubuntu 24.04.5 ARM64,
kernel `6.8.0-146-generic`, Rust 1.98.1, Git and runtime digests recorded in
the evidence, and `bubblewrap=0.9.0-1ubuntu0.3`. A different runtime or ABI
fails closed.

## Native result and limits

The 2026-10-19 native run passed build, Clippy, ABI assertions, 18 regression
groups, and owner-loss assertions. The regression groups cover positive status
and diff with unchanged source index; absence of outside open/stat/statx/access/
readlink; hardlink refusal before copy; special files, alternates, and unsafe
config refusal; source mutations; preserved file mode and mtime; filter and
compiled static helper denial; write and network denial; output and snapshot
limits; listener teardown; pinned-root path substitution, sealed manifest
validation, and timeout/process cleanup. The lifecycle test
observed private user/mount/PID/network namespaces and zero capability sets
before broker fork. Exact results and versions are in the JSON evidence file.

The experiment accepts a narrow class of small, ordinary repositories. Its
config grammar intentionally rejects some valid Git repositories. The
two-pass source check detects the tested races but does not prove an atomic
snapshot of a tree under arbitrary concurrent write/restore. This result must
not be represented as an unconditional filesystem transaction or as a complete
Git service.
