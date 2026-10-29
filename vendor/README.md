# Terminal engine source provenance

These are the published `alacritty_terminal` 0.26.0 and `vte` 0.15.0 crates.
`provenance.json` pins the original archive SHA-256, source commit, every
upstream file and each local patch. Apache-2.0 and MIT license files remain
inside their original packages. Cargo-generated lock/cache files are excluded.

The three patch artifacts in `patches/` describe the complete local changes:
read-only checkpoint accessors, bounded terminal metadata and OSC handling,
and synchronous dynamic-color replies. Dependency logs are compiled out by
the terminal wrapper. These changes define an experimental terminal profile;
they do not establish compatibility with arbitrary xterm applications.

Run `python3 tools/check_terminal_vendor.py` to check the working sources.
Pass `--archive-dir` containing both exact `.crate` files to compare the full
upstream source inventory with the pinned original archives as well.

Vendor packages are excluded from the root Cargo workspace. Their upstream
test suites have not been qualified here; the title-stack test expectation is
adapted from 4096 to the declared 64-entry limit. The host fixture exercises
that limit through actual terminal control sequences. Root workspace tests do
not imply that every upstream vendor test was run.
