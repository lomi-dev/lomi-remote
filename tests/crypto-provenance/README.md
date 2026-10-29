# Crypto extraction evidence

`source.json` records the complete Git inventory of
`lomi:src-tauri/crates/lomi-remote-crypto` at audited commit
`2cef452c39eb8b455c8d2ae1251310dc870c50bb`. Each imported entry records the
upstream blob SHA-256 and final destination SHA-256, with explicit adaptation
notes. The only omitted source file is its nested Cargo.lock, whose original
hash is recorded. New crate-local files have a separate added-source inventory.

The vendored Snow implementation, examples, vectors, upstream digests, licenses,
low-order DH protection and secret erasure patches are retained byte-for-byte.
A historical README relocation preserves its original bytes. The new README and
lib documentation distinguish historical live-profile qualification from the
unqualified Remote API 2/grant-context 3 product.

From the repository root:

```sh
python3 tools/check_crypto_source.py --source-repo ../lomi
python3 -m unittest discover -s tests/crypto-provenance -p 'test_*.py'
```

Without the optional source checkout, the checker verifies every destination
hash and rejects missing/extra files, patch drift, missing licenses, symlinks
and unexpected nested lockfiles. With `--source-repo`, it also independently
reads all pinned upstream Git blobs, including the excluded lockfile; uncommitted
source working-tree changes cannot influence the audit.

This inventory is development provenance. It is not a signed release manifest,
reproducible WASM/mobile artifact or supply-chain attestation. Browser-feature
compilation does not prove browser execution, Workers or cross-language ABI.
Enrollment proof state/replay storage and new Remote context are separate work.
