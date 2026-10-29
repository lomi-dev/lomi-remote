# Native Windows private SQLite backup proof

Run `python3 tests/store-backup-windows/run_native.py` from the repository.
The harness uses the existing pinned Windows SSH host and bounded worker;
no services, startup entries, credentials, or real user data are changed.

It archives unchanged store/platform/protocol sources into an isolated
three-crate workspace. Its offline-derived lock must match the repository
lock's versions, sources, and checksums. Reports, input digests, and bounded
logs are written under `artifacts/store-backup-windows/`.

The store suite exercises checked backup and v1-to-v2 migration, including
an actual subprocess exit before schema commit followed by backup reuse.
The platform cases check current-user ownership and protected DACL before
bytes are written, no replacement, pinned directories/files, rejection of
other/public/reparse parents, hardlinks, foreign owners, and Win32 alias
names. Fixtures use UUID directories beneath `USERPROFILE`; the parent
security policy is never relaxed to accommodate a temporary directory.

Native MSVC Clippy and formatting are checked. Cleanup requires known
worker completion and zero processes under the exact owned extraction
path. Uncertain work is preserved. Qualification covers only the Windows
version/build recorded in each receipt.
