This disposable native Linux runtime proof uses only a fresh UUID directory in
`/home/lomi-e0` inside the isolated `lomi-e0` Lima VM. It changes no service,
profile, AppArmor rule, linger, VM boot setting or package installation. The
reviewed standalone `tests/git-wasi/host` source and exact lock remain unchanged.
Rust 1.98.1 builds Wasmtime 49.0.3 with two jobs, incremental compilation disabled
and dev debug information disabled to conserve the VM's limited disk. The build
requires at least 3 GiB free before starting (2 GiB estimate plus 1 GiB reserve)
and continuously checks a 1 GiB guest reserve. Mac physical free space is recorded
before and after; the runner refuses to start with less than 4 GiB free.

Run from the repository root:

```sh
python3 tools/run_linux_git_wasi_spike.py
# Optional: fresh input UUID using an already verified native host, without rebuilding:
python3 tools/run_linux_git_wasi_spike.py --prepared artifacts/git-wasi-linux/native-UUID.json
python3 -m unittest discover -s tests/git-wasi-linux -p test_runner.py -v
```

Each invocation creates a one-use UUID, copies only an explicit regular-file
inventory and verifies the archive digest before exclusive extraction. Proof
checks use explicit exceptions and remain active under Python optimization. The frozen
synthetic packed `.git` snapshot and expected JSON come from the successful trusted
native Mac Git proof; WASI module and snapshot hashes must match that proof.
Input links, hardlinks, special files and archive traversal are refused. Linux
capability probes then create exactly three new synthetic symlinks in the fixture
and verify their targets after execution. No real repository or operator data is
copied. Source, inputs and native binary are retained for inspection.

The guest Python worker owns each new POSIX process group, drains stdout and stderr
concurrently with 128 KiB per-stream limits, enforces a deadline, and kills the
owned group while the unreaped leader still anchors its identity. Leader exit is
observed using `waitid(WNOWAIT)` before group termination and final reap. Expected
WASI traps are completed native workers with exit 1. A transport failure, worker
failure, malformed completion envelope or unknown completion persists false and
blocks subsequent operations. This covers the fixed trusted Cargo/WASI processes;
it is not a general supervisor for descendants that deliberately escape ownership.

Twelve runtime groups compare status, unstaged/staged diff, log and show with Mac
native Git, verify read-only mmap, outside content and metadata denial including
actual symlinks, read-only filesystem operations, no environment/args/helper/TCP,
fuel, memory, output, stack, socket-import and initial memory/table limits, complete
policy probes and valid common-directory rejection. Every transferred file hash
and synthetic symlink must remain unchanged. A final exact-executable `/proc`
observation counts remaining native host processes without listing argv or env.
Evidence retains exact commands, versions, source/input/archive/lock/binary hashes,
aggregate outcomes and output sizes/digests; guest payload is compared in memory.
Only compiler diagnostics are retained in build logs.

This establishes native runtime feasibility only. Production Linux snapshot-broker
races and ownership policy, other architectures, production integration and latency
acceptance remain unqualified; `qualified` remains false. Windows reparse and ACL
guarantees are outside this Linux proof.

`test_worker_native.py` runs only with an explicit owned guest worker path on
Linux. Its four cases exercise expected nonzero completion, deadline cleanup of
a live descendant, capture-limit cleanup, and cleanup of a remaining process
group after direct-child EOF/exit before reap. Ordinary host discovery skips this
VM-only class; `test_runner.py` supplies six local harness regressions, including
actual `python -O` checks of digest, unsafe archive, changed file and changed link
rejection. The native ownership test is transferred separately with its own
explicit inventory and command ledger; no unrelated guest files are scanned.

Actual native run: Ubuntu 24.04.5 ARM64, Rust/Cargo 1.98.1,
`aarch64-unknown-linux-gnu`, Wasmtime 49.0.3. The standalone build took 60.611s.
Final runtime `66fd9bd1-ccb6-46d4-88d6-aeca725a424a` passed **12/12 groups**
with explicit validation checks active independently of Python optimization.
The initial successful runtime is retained as historical evidence; the final run
uses fresh inputs and hash-verifies the retained unchanged native binary/worker.
`artifacts/git-wasi-linux/attempts.json` links both runtimes and the separate
four-case native ownership proof. Six local harness tests pass, including the
optimized-Python regression; native ownership tests passed four of four.

Final evidence is
`artifacts/git-wasi-linux/native-66fd9bd1-ccb6-46d4-88d6-aeca725a424a.json`.
Source, input and archive digests, pinned lock hash, exact commands, output digests,
versions, timings and an independent zero-process observation are included. The
native host SHA256 is
`3acece788d8e890781a544ed6f30671e20da160256526c41c17c3d2ececfa580`.
The frozen guest SHA256 remains
`338bfaeeeebcf1e926214c940ddce31bf471b00bc2f6950c10612d250b3b1f4a`.
VM disk remained above the 1 GiB reserve. The new source/build/input directories
remain available for inspection; no unrelated resources were removed.
