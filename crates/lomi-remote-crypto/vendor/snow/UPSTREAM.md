Snow 0.10.0 crates.io archive SHA-256: 599b506ccc4aff8cf7844bc42cf783009a434c1e26c964432560fb6d6ad02d82
Upstream https://github.com/mcginty/snow ; MIT OR Apache-2.0 (licenses retained).
Local changes: owned key Drop erasure; scoped DH/HMAC/HKDF/rekey buffers; non-Copy symmetric checkpoints; all-zero DH rejection; SHA-2 0.11 zeroize backend.
Only the selected XX/25519/ChaChaPoly/SHA256 profile is exercised by this project; qualification remains false.

The standalone workspace marker was removed for the enclosing native workspace.
The package test profile was removed because profiles belong to the native workspace root.
Rust 1.98 lint compatibility removes the retired match_on_vec_items allow and uses the configured integer suffix style for all-zero DH rejection.
Integrated Cargo.toml SHA-256: 3d366decd8240eb15435940b08efb8089c75840d24abb85d1c6dd264aa9fc59e
