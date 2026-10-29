# Linux Git probe fixtures

`headers.c` compiles against the actual native Ubuntu ARM64 Linux headers. Its
static assertions cover manual seccomp/Landlock constants and structure layout;
it also queries ABI4 and seccomp USER_NOTIF availability without root.

Run from the repository root with the existing disposable VM:

```sh
python3 tools/run_linux_git_spike.py
```

The Rust corpus is in `crates/lomi-linux-git-spike/src/linux/fixtures.rs` so its
closed test probes can share the exact production-shaped sandbox bootstrap.
See that crate's README for command ownership, native evidence, source/runtime
pins and the observed hardlink/metadata limits. Successful synthetic probes
remain `qualified: false` and do not pass the complete S0.3a gate.
