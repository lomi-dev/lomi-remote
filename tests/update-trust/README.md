Run `cargo test -p lomi-update-trust --all-features` from the repository root.
The `durable.rs` integration target is feature gated because child-process crash
and lock-holder commands are absent from default builds. See
`../../crates/lomi-update-trust/README.md` for the trust lifecycle and limits.
Only synthetic public upstream test fixtures are used; target bytes are never
executed or installed.
