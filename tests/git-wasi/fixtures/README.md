Fixtures are generated exclusively from literal synthetic strings by
`tools/run_git_wasi_spike.py`. No existing repository is accepted as input.

The base commit has `tracked.txt` containing `alpha\nbeta\n`. Its objects are
packed and redundant loose objects are removed. The nonempty index then holds
`alpha\nstaged\n`; the worktree holds `alpha\nworktree\n` and an untracked file.
Native Git captures status, staged/unstaged diff, log, and blob show before a
bounded copy creates the guest snapshot.

The generated index carries native filesystem metadata, so the complete input
digest is recorded for each run instead of asserted as a cross-run constant.
