# Linux product host proof

Run `python3 tools/run_linux_product_host.py --run` on the prepared development
machine. It uses only the disposable Lima `lomi-e0` guest. It does not install a
service, enable autostart, reboot, enroll an account or change existing projects.

The driver freezes the approved source inventory and archive, verifies the
archive digest before extraction, builds and tests the product crates natively,
then copies the product binary into a UUID-owned private directory. Public VM
host-key material is obtained through the existing local hypervisor connection;
the two proof connections use that pinned key and disable SSH multiplexing.

The first connection creates a synthetic workspace and shell, sets an in-memory
counter through actual terminal input, closes the view and disconnects SSH. The
second connection verifies the same host runtime and terminal session and
increments the counter in that shell. Terminal bytes remain in memory. Evidence
contains totals, public synthetic identities, source/binary hashes and cleanup
results. Cleanup uses authenticated daemon stop and preserves the directory if
termination cannot be confirmed. Each invocation has a private target directory;
only Cargo's dependency download cache is shared. Cleanup covers executables and
working directories under the owned run root, including native test processes.

The first frozen run, `f380cb94-8729-4eda-bb1d-da25c20a3b3d`, passed 90 native
tests with one intentional subprocess entrypoint, both SSH phases and cleanup.
Its binary SHA-256 is
`c645ab3e667a04629f8cd980237e2f4f11a0e6807a56ccf3e75c3e14cb6c6693`.
That snapshot predates the dedicated PTY supervisor. The new frozen run,
`17d121ca-0ef2-4b34-b471-c1bd832e5fbd`, passes 117 native tests with one intentional
subprocess entrypoint, both independent SSH phases and confirmed cleanup. It
includes inherited-SIGCHLD, adopted-descendant, worker-loss, bounded final-output
and output-flood supervision regressions. Its binary SHA-256 is
`f7eebf599269db2e96f83b9c865bcc361c66eec0695b79142512694308fdb040`.
This proof does not qualify the full systemd/boot matrix or a product release.
