# Successor2 S5 source staging

`python3 scripts/s5_source_stage.py verify` checks the frozen eleven-source
closure against its pinned `freeze.json` and checks the trusted launcher
before reporting the 90-file staging manifest (88 pinned sources, `freeze.json`,
and the launcher). The manifest is recorded at
`staging/s5-successor2-source-manifest.json`; `launcher.py` maps to
`tests/consumer-private-positive-controller/trusted_launcher.py`.

`python3 scripts/s5_source_stage.py stage /path/to/new/staging-tree` copies
that exact closure into a new directory owned by the invoking unprivileged
user. The destination must not already exist. The staged tree contains source
files only. It does not create `admission.json` or `run-admission.json`.

This output does not qualify S5 or grant admission. Root installation,
admissions, and controller runtime remain disabled. The checker does not
install anything or execute controller, PostgreSQL, Node, or native code.
