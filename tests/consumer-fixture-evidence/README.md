# Bounded fixture evidence recorder

This adapter is prepared for **new successor runs only**. It is not integrated
with the frozen Prepared18 or five-case admission drivers. It does not modify
their sources, accepted evidence, operators, controllers, or process ownership.
It uses only Python's standard library and launches no children.
The corrected format is `consumer-fixture-evidence-v2`; the initial v1 source
freeze remains historical preparation evidence and is not overwritten.

## Instance API

```python
store = recording.EvidenceStore(new_run_path)  # creates an absent 0700 root
RecordedFixture = recording.fixture_class(base.Fixture)
evidence = store.scope()                     # Prepared18 successor
# evidence = store.scope("1-case-name")       # five-case successor
f = RecordedFixture(owned, lock, work, evidence, appointment, node,
                    recording_store=store, recording_scope="")
# For a case: recording_scope="1-case-name"; share ONE store across all cases.
# Exact constructor-produced SQL/JSON bytes, without any outside-file admission:
store.save_bytes("operator.candidate.sql", exact_derived_bytes)
# store.save_bytes("operator.candidate.sql", exact_derived_bytes, scope="1-case-name")
```

The subclass delegates command execution, SQL, capture, and cleanup to the frozen
base. Returned command/SQL strings and capture rows are unchanged. Its private
event-list copy compacts only large command stdout; SQL-record serialization
compacts only its stdout field. Stderr and small stdout remain inline.

The preservation boundary is the legacy helper's `text=True` decoding/newline
handling and, for command history, existing work/repository path replacement.
SQL stdout is the original helper-returned string. The format does **not** claim
original OS pipe bytes. Decompression restores exact strings without JSON
canonicalization, whitespace normalization, expected-value substitution, or
skipped captures. Ordinary catalog JSON has exactly the legacy serialization
and remains directly readable by frozen helpers, including function hex bytes.

After owned cleanup and all ordinary output writes:

```python
evidence_hashes = store.seal()
manifest["evidenceSha256"] = evidence_hashes
manifest["recordingComplete"] = not store.incomplete
manifest_sha = f.save("transition-manifest.json", manifest)
# Publish external completion only if no errors AND not store.incomplete.
reader = recording.EvidenceReader(new_run_path,
    expected_index_sha256=evidence_hashes["storage-index.json"])
assert reader.validate()  # plus unchanged source/operator/controller gates
logical_commands = reader.read("commands.json")
logical_sql_record = reader.read("sql-1.json")
exact_derived_bytes = reader.raw("operator.candidate.sql")
# For cases: reader.read("1-case-name/sql-1.json")
```

`save` returns the hash of the actual stored file. The index pin must come from
the independently pinned final manifest. A successful decoder is not itself a
runtime or qualification receipt.

## Storage and limits

Flat `blob-<sha256>.json` files contain exact serialized immutable outputs.
Read-only aliases hardlink only those new-run blobs, including aliases in direct
child case scopes. Flat `stdout-<sha256>.gz` files contain deterministic gzip
(`mtime=0`, level 1) under the pinned Python version. References carry stored and
logical SHA256 and byte lengths. Ref paths are root-relative names, never `..`.
`save_bytes` accepts only supplied immutable `bytes` and creates an internal
read-only `bytes-<sha256>.bin` CAS blob plus its read-only output alias. Binary,
UTF-8 SQL, and constructor-produced JSON bytes are preserved exactly, with
distinct closed `blob-bytes`/`alias-bytes` roles. It never registers an existing
file or reads an outside source path. Use `reader.raw` for byte outputs; their
file aliases remain ordinary directly readable files for frozen helpers.

Mutable commands, incremental results, and transition manifests are ordinary
files published through exclusive temporaries and atomic replacement. Growing
history versions are not accumulated in CAS. A changed immutable alias fails.
The store checks owned 0700 directories, regular files, symlinks, inode identity,
digest, and exact in-run link counts. These are private, single-writer runs;
concurrent mutation by another process with the same UID is unsupported and
must prevent admission. Do not move, copy, chmod, externally hardlink, or write
through published aliases during a run.

Hard ceilings are 256 MiB of unique allocated evidence blocks, 16 MiB per
serialized output or logical/stored stdout blob, and 4,096 names. Primary writes
reserve 8 MiB and eight names for failure/index/finalization. Temporary payload
allocation counts against the byte ceiling. Physical counts deduplicate file
inodes and include directory blocks; named logical sizes count aliases. APFS
metadata beyond reported `st_blocks` is not included. PostgreSQL data, private
work directories, and outer-controller artifacts are **outside** this evidence
budget and require separate resource admission. Constructor limits may be
reduced for pure tests, never increased past the ceilings.

The reader checks both hashes/lengths, bounds decompression before allocation,
rejects truncated/trailing/multiple gzip members and expansion beyond the
declared length, and decodes strict UTF-8. The index enumerates all blobs,
aliases, stdout refs, limits, and physical link counts. Manifest hashes include
the index and every blob/alias. Explicit self-reference exclusions are the index
from its own file list, transition manifest from its own hash closure, and
pending/final completion receipts, which the external controller hashes
independently. No other outputs may be written directly into the run.
The full index uses a closed typed schema: completion flags must be actual
matching booleans, limits/counters must be bounded integers, and file roles,
blob descriptors, alias targets, stdout refs, scopes, and physical link counts
must agree exactly. Unknown fields, duplicate JSON members, nonfinite numbers,
unknown roles/kinds, and mismatched maps fail even with a correctly pinned
index. A smaller declared item limit applies to every indexed file, inline
stdout, compressed/logical stdout, and the index/manifest/receipt files.

## Failure and successor integration

Budget/count/storage errors make the run incomplete. Event append never throws
an evidence error into cleanup; frozen cleanup commands continue using
`try_save`. A bounded reserved `recording-failure.json` records the incomplete
state and cleanup events when possible. A failure transition manifest forcibly
clears qualification flags. Any missing output, failure report, index, digest,
or cleanup proof prevents qualification; the reserve is not permission to omit
successful-run evidence. A deadline, disk error, or tampering can still prevent
failure evidence from being written. Owned cleanup remains the caller's duty.
The reserved cleanup report retains the latest eight events, each with its
fixture scope. Thus a fifth case's cleanup failure cannot be hidden behind
the first four cases' eight successful stop/status records. Earlier complete
case command files remain part of the independent indexed evidence.

New successor entrypoints must select this instance subclass without changing
module globals, retain existing source/operator/tool pins and SQL checks, and
pin this recorder plus their own new sources/controllers. Prepared18's direct
derived writes must become `store.save_bytes(name, raw)`, using the exact
already-admitted constructor bytes and checking the returned on-disk digest.
Direct writes still fail the output allowlist. The five-case successor must
route its group result/manifest
writes through the root store, reuse one root/budget/index for all cases, and
keep its fresh-cluster cleanup schedule. Both need a new controller namespace
that validates this format before the unchanged completion gates. The frozen
controllers' source hashes and runtime namespace checks must remain unchanged.

The pure tests import the actual frozen Fixture and use an in-memory fake runner;
they do not initialize ownership, execute PostgreSQL, or start any child. Run
under pinned Python with `-I -S -B`, private HOME/TMPDIR, and a controlled locale.
