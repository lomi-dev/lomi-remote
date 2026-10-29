# Portable Git read E0: packed-repository WASI experiment

**Not qualified.** This is a bounded feasibility experiment for S0.3a, not an
adopted Git executor. It does not implement the service or accept user
repositories. Native macOS execution demonstrates packed-repository Git reads
through Rust Wasmtime with two small guest-only portability shims. Production
and cross-platform qualification remain open.

## Reproduce

From the `lomi-remote` repository root on macOS:

```sh
rustup target add --toolchain 1.98.1 wasm32-wasip1
python3 tools/run_git_wasi_spike.py
```

The script returns 0 only when exact structured native-reference comparisons,
adapter probes, security probes and the unchanged-snapshot check pass. The
positive **worker returns 0**; malicious resource workers must fail. The
target-install command does not change the
default toolchain. Guest and host are independent Cargo workspaces with their
own lockfiles; build targets and generated evidence live in ignored
`artifacts/git-wasi/`. Main workspace dependencies are unchanged.

Pins: Rust 1.98.1, gix 0.88.0, Wasmtime/wasmtime-wasi 49.0.3. Exact transitive
versions and registry checksums are in each subproject's `Cargo.lock`.

`artifacts/git-wasi/report.json` records the actual input digest, versions, exits, binary sizes,
unchanged-snapshot result, and raw runtime output. `expected.json` records native
Git reference results. Build logs, worker stdout/stderr, the generated packed
repository and snapshot are retained beside the report. On macOS the worker is
wrapped in `/usr/bin/time -l`, which records maximum resident set size and peak
memory footprint; these include module compilation and guest execution.

## Observed macOS result

Native execution on 2026-10-19, Apple Git 2.54.0 (Apple Git-157):

- Guest WASIp1 compilation: passed with only `sha1`, `status`, `revision`, and
  `blob-diff` gix features; networking/performance/parallel features disabled.
- Native reference fixture: packed repository, one-entry index, staged and
  unstaged changes, and one untracked file. Status is `MM tracked.txt` and
  `?? untracked.txt`.
- Stock Wasmtime execution failed at `gix-index-0.56.0/src/file/init.rs:81`,
  `An IO error occurred while opening the index`, caused by `unsupported`.
  After the mmap shim, filetime's generic WASM metadata reader panicked at
  `filetime-0.2.29/src/wasm.rs:11`. Both observed boundaries informed the shims.
- With both shims, status, staged/unstaged diffs, log and blob show match exact
  structured native Git references. The index is nonempty and commit/tree/blob
  data are packed. The staged blob remains a real loose Git object.
- Post-review positive-run guest binary: 2,149,439 bytes (release, stripped).
  Host: 70,689,040 bytes (debug). Measured worker maximum RSS 121,356,288 bytes;
  peak memory footprint 94,831,144 bytes; module compilation 21,989 ms. These
  observations include debug-host compiler overhead and concurrent machine
  load; they imply no production budget or performance claim. The generated
  report records the current exact measurements and input digest.
- Windows and Linux native runtime: **not run**.

The original initial debug guest exceeded the explicit 64 MiB module cap;
switching the fixture guest to its configured stripped release profile removed
that measurement artifact without increasing the cap.

## Isolation present in this checkpoint

The host parses no Git data. Wasmtime executes the guest with no inherited
environment, stdio, arguments, directories or networking capabilities. Only
the private copied snapshot is preopened, as read-only. Stdout/stderr use
capacity-bounded memory pipes. An explicit core WASIp1 import allowlist rejects
socket and unknown imports independently of dependency feature settings.

The Store caps memory at 128 MiB, table elements at 100,000, and instances,
tables and memories at one each. The Engine caps the Wasm stack at 512 KiB,
fuel at 100,000,000 and execution epoch at approximately five seconds. The
outer harness owns a worker process group with a 60-second deadline and 8 MiB
combined output bound, including module compilation. Cargo builds have a
separate 600-second deadline. Native
Git uses a fixed root-owned executable, cleared environment, private HOME,
empty template and disabled global/system configuration, attributes, external
diff and textconv. Snapshot copying limits entries/depth/bytes and rejects
symlinks, hardlinked files and special files. This is a macOS synthetic copy
broker only, not a cross-platform race-proof production filesystem broker.

## Audited portability patch boundary

Downloaded pinned sources confirm:

- gix-index `File::at` unconditionally calls memmap2
  `MmapOptions::map_copy_read_only` before decoding a real index.
- gix-pack index/data file open also uses mapped data. Lower-level
  `gix_index::State::from_bytes` and `gix_pack::{index,data}::File::from_data`
  exist, but routing the full high-level object database through them would
  expand the implementation.
- memmap2 0.9.11 `src/stub.rs` returns `Unsupported` for mapping on WASI.
  Its registry archive SHA-256 is
  `d1219ed1b7f229ee7104d281dd01d6802fe28bb6e95d292942c4daacdeb798c0`.

The **guest-local** `[patch.crates-io]` entries affect no main workspace or host
dependency. Each vendor directory retains its original licenses and a
`LOMI-PROVENANCE.json` with the original registry archive SHA-256 and every
upstream source file's SHA-256. The complete intentional patch inventory is:

| Package | Changed upstream files | New implementation |
| --- | --- | --- |
| memmap2 0.9.11 | `src/lib.rs`: WASI-only backend selection; `Cargo.toml`: WASI-only libc 0.2.191 | `src/wasi_readonly.rs` |
| filetime 0.2.29 | `src/lib.rs`: WASI-only backend selection and setter rejection | `src/wasi_readonly.rs` |

memmap2 reads an owned Vec with a 16 MiB per-map limit, checked offset/length,
metadata-length validation and exact reads. The allocation stays stable until
drop. WASI's `FileExt::read_at` is still unstable on Rust 1.98.1, so the shim
uses libc `pread`, which lowers to core WASI `fd_pread`. It only borrows the
descriptor: no seek, duplication, ownership or close. Mutable, copy-mutable,
executable and anonymous maps, flushing and protection changes remain
`Unsupported`. Native and other-WASM backends retain their original behavior.

filetime uses actual `Metadata::modified/accessed` values and
`FileTime::from_system_time`. Unavailable required timestamps trap instead of
inventing data; unavailable creation time is `None`. All public setters return
`Unsupported` on WASI. Archive SHA-256:
`5c287a33c7f0a620c38e641e7f60827713987b3c0f26e8ddc9462cc69cf75759`.

Focused adapter probes run in Wasmtime, checking offset/length, empty and end
maps, overflow, oversize, truncated ranges, stable allocation, unchanged file
offset and open borrowed descriptor, mutable/executable denial, actual
filesystem timestamps and all filetime setters. Input mutation during a read
is excluded by the private snapshot; this is not a shared mmap emulation.

Upstream sources:
[gix 0.88.0](https://github.com/GitoxideLabs/gitoxide/tree/gix-v0.88.0),
[Wasmtime 49.0.3](https://github.com/bytecodealliance/wasmtime/tree/v49.0.3),
[memmap2 0.9.11](https://crates.io/crates/memmap2/0.9.11).

The guest checks a small explicit config allowlist **before opening gix** and
rejects all attributes, includes, alternates, filters (including required),
textconv, diff drivers, fsmonitor, credential helpers and EOL/encoding settings.
The ordinary-repository profile also rejects `.git/commondir`, preventing gix
from resolving unchecked common config, attributes or objects. Its regression
fixture retains an allowed `.git/config` while native Git independently proves
that the common repository supplies a packed blob and a forbidden
`diff.external` config value. Both the policy probe and actual Git guest must
reject it with `unsupported Git metadata`; an ordinary repository is a positive
policy control. A focused before/after native policy check reproduced acceptance
without the `commondir` rejection and rejection with it.

Config probes append forbidden core assignments directly to one valid `[core]`
section, so a duplicate section cannot hide a key/value allowlist regression.
Forbidden sections, duplicate core headers, duplicate keys, missing required
keys and a complete config with `bare=true` are checked separately. The native
macOS harness now records 16 security probe groups, including the actual guest's
common-directory rejection. These checks retain the packed-repository exact
comparisons and both vendored source/file inventory checks.
The post-review run returned 0 with all 16 groups passing, positive worker exit
0 and common-directory guest exit 1. Guest SHA-256:
`338bfaeeeebcf1e926214c940ddce31bf471b00bc2f6950c10612d250b3b1f4a`.
The unchanged snapshot digest was
`a5f7e9bd7363e429cf7f227efda3245e7986bc762cc1b5a301f2d50b1963989f`.

Attributes are preserved in rejection fixtures. Its accepted Git shape is
deliberately limited to this single ASCII regular-file fixture; unsupported
tree/index/status shapes fail. No fallback to original bytes is accepted as
successful filter semantics. Diff references contain both complete byte
strings, native Git insertion/removal counts and canonical replacement ranges
for the fixed two-line fixture; this is not general patch-format compatibility.

The final harness records individual security probe outcomes: outside content
and metadata, absolute/relative/symlink escapes, writes/removes/renames,
inherited environment/args, process helper attempts, socket attempts and
explicit socket-import rejection, plus fuel exhaustion, memory, stack, output and
initial memory/table limits. Broker probes reject symlinks, hardlinks, FIFO,
excess depth, oversized files and excessive entries. Epoch interruption is
configured but was not reached before the independent fuel bound in the loop
probe. These are native macOS evidence only.

Remaining qualification includes a production race-resistant snapshot broker,
Windows reparse/ACL behavior and native Windows/Linux runtime evidence,
broader Git semantics and hostile-parser coverage, resource/latency budgets
under realistic repositories, dependency patch maintenance and upstream
review. Main services/apps/installers are unchanged and `qualified` remains
false even when every fixture check passes.
