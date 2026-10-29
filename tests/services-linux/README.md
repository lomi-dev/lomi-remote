Run native process tests with `cargo test -p lomi-service-fixture`.

The actual Ubuntu VM proof is `python3 tools/run_linux_service_fixture.py`.
It requires the parent-prepared dedicated Lima `lomi-e0` VM and its Rust toolchain.
The driver transfers only `source_inventory`-approved regular source files,
never host build outputs, real credentials or user application data. Each new
`all` or `transfer-build` invocation creates a unique
`/home/lomi-e0/lomi-source-<invocation-id>` directory, leaving stale source
trees untouched. Phase-only continuation commands reuse the root recorded in
the evidence file and fail closed if it is missing or malformed.
No host directories are mounted. VM operations and checks are recorded under
`artifacts/services-linux/evidence.json`, without PTY or environment dumps.

Service lifecycle setup is confined to the disposable guest and automatically
removed by the full driver. `guest_probe.py` refuses non-Linux/non-root/non-systemd
execution and requires the explicit disposable VM argument. Read the crate
README for scope and unqualified platforms.

`python3 -m unittest discover -s tests/services-linux -p 'test_*.py'` checks the
offline evidence aggregator. Reports retain all attempts; corrected attempts
explicitly supersede earlier observations. `finalComplete` requires all four
guest phases, and `allRequiredLatestPhasesPassed` evaluates their latest attempts.
Source inventory digests and archive byte digests have distinct labels. Initial
exact command arguments reconstructed from the archived executed runner are
marked with that provenance; later invocations record their argument lists.
The recorded Ubuntu 24.04.5 ARM64 run passed 40 latest guest checks, three native
process tests in the guest and three on macOS. This does not qualify Windows.

`python3 -m unittest discover -s tests/tools -p 'test_linux_service_runner.py'`
covers new-run invalidation, unique source roots, continuation root reuse,
interruption/exit 130, owned subprocess dispatch, bounded guest completion and
deferred cleanup. Native validation transfers `tools/owned_process.py` with
the driver and tests it supports. A new prepare/build invalidates
old downstream results before work; an unfinished invocation cannot reuse a
successful older proof. Historical attempts remain available for inspection.
