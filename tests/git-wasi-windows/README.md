This disposable Windows experiment builds the already reviewed standalone
`tests/git-wasi/host` with its exact Cargo.lock and Rust 1.98.1 on the supplied
x64 Windows test machine. It installs no Git, service, toolchain, ACL or boot
configuration. Each preparation uses a fresh UUID directory in the SSH test
account's profile. Source and build directories are retained for inspection.

Run from the repository root:

```sh
python3 tools/run_windows_git_wasi_spike.py
python3 tools/run_windows_git_wasi_spike.py --prepared artifacts/windows-git-wasi/prepare-UUID.json
python3 -m unittest discover -s tests/git-wasi-windows -p test_runner.py -v
```

Preparation transfers only the standalone host manifest, lock, Rust source and
`Run-Bounded.ps1`. Runtime inputs are an explicit regular-file inventory of the
frozen synthetic packed repository, trusted native Mac Git structured result,
WASI modules and selected synthetic probes. Links and special files are refused;
no real repository, user data, environment or credential inventory is copied.
The fixture's `.git` directory is synthetic test data. Source inventory digests,
archive digests, native binary hash, commands, exits and bounded-output digests
are retained separately under private `artifacts/windows-git-wasi`.

The PowerShell helper drains stdout and stderr concurrently with 128 KiB per
stream capture limits and a process deadline. It starts only fixed Cargo or WASI
host commands, and targets only its exact child PID tree on timeout. The local
runner owns each SSH process group; uncertain remote completion stops subsequent
operations and preserves the new source/input directories. No remote deletion
is performed. Transport completion is tracked separately from typed worker
completion; helper failure or malformed/unknown completion blocks further remote
commands. These fixed trusted processes do not establish a general Windows Job
Object or escaped-descendant cleanup guarantee. Raw guest stdout/stderr is compared in memory and represented by
sizes and digests in evidence; build logs contain compiler diagnostics only.

The native cases compare status, unstaged/staged diffs, log and show with the
trusted Mac native Git JSON, verify read-only mmap behavior, capability denial
(outside path, writes, environment, arguments, process and TCP), fuel, memory,
output, stack, forbidden socket import, initial memory/table limits, and a valid
common-directory repository policy rejection. All transferred input hashes must
remain unchanged. The host intentionally inherits its native process environment
only to test that the guest cannot inherit a synthetic canary.

The symlink-dependent complete policy module is not run on Windows. Missing
escape entries in the portable denial snapshot are not evidence for actual
symlink escape protection. Windows snapshot acquisition races, reparse handling,
ACL isolation, other architectures and production repository integration remain
unqualified. This is runtime feasibility evidence; `qualified` remains false.

Actual supplied-host run: Windows 10.0.19044 x64, native MSVC Rust/Cargo 1.98.1,
Wasmtime 49.0.3. Preparation `336ba6ec-02c2-4812-a4fa-c0d391959285` built the
locked host successfully. Runtime `468e7008-2f0d-4195-9938-5bfa2022bbe4` passed
**11/11 groups** including all five structured Git operations. All transferred
input hashes were unchanged; an independent exact-executable process query found
zero live host processes. Evidence and exact command ledgers are in
`artifacts/windows-git-wasi/native-468e7008-2f0d-4195-9938-5bfa2022bbe4.json`,
linked by `artifacts/windows-git-wasi/attempts.json`. The failed initial local
preflight is preserved: it refused the upstream deliberately hardlinked outside
canary before any remote operation. The successful run uses the separately
inventoried static synthetic canary in this directory; hardlink rejection remains.

The native host executable SHA256 is
`70c6ed24c965e8787446c2ae1423ed727bcb7eaa932a868edd1d0ead000993ce`.
The unmodified guest SHA256 is
`338bfaeeeebcf1e926214c940ddce31bf471b00bc2f6950c10612d250b3b1f4a`.
The successful runtime evidence SHA256 is
`fb1df7c66684ce038d60704673453dd168e67abf2960571ecab15e006cbcf8d1`.
The host is a debug build; the main worker took about 76 seconds, dominated by
JIT compilation, within its 90-second process bound. This establishes feasibility,
not acceptable production latency. All unrun boundaries above remain unqualified.
