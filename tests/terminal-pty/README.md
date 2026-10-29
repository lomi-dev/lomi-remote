# Bounded interactive Vim PTY evidence

This is an experimental Unix harness with actual PTY I/O, a sole Rust output
parser, host-owned replies, and structured xterm projection evidence. It is
separate from the synthetic state corpus and does not qualify arbitrary CLIs.

Run from the repository root:

```sh
cargo test -p lomi-terminal-pty-fixture
cargo clippy -p lomi-terminal-pty-fixture --all-targets -- -D warnings
cargo run -q -p lomi-terminal-pty-fixture -- --fixtures /tmp/lomi-vim-state-fixtures.json > /tmp/lomi-vim-observations.json
node tests/terminal-state/rust-oracle.mjs /tmp/lomi-vim-state-fixtures.json
```

The binary runs exactly:

```text
/usr/bin/vim -N -u NONE -U NONE -i NONE -n --noplugin -R syntheticfixture.txt
```

HOME and CWD are a fresh temporary directory containing a synthetic read-only
fixture. Environment inheritance is cleared. The only added environment values
are HOME, PATH=/usr/bin:/bin, TERM=xterm-256color, and LC_ALL=en_US.UTF-8 on macOS
or C.UTF-8 on Linux. Vim receives no user configuration, plugins, viminfo, or swap
files. Commands only navigate, echo markers, set the Normal ANSI colors with
`ctermfg=2 ctermbg=0`, redraw, and quit. The synthetic file is checked unchanged.

Milestones check startup in alternate screen with CJK/combining/emoji text,
normal navigation and scrolling, entry into command mode, a command-result
marker, ANSI color attributes, a resize from 12x60 to 14x72 acknowledged by Vim's
own `&lines` and `&columns`, and successful exit restoring the normal buffer.
At each milestone, repeated snapshots must preserve exact state and generate
no extra replies or input while the same child stays live. Each actual output
chunk and resize generates one ordered state delta. The existing Node oracle
attaches at every emitted state and applies the next delta without raw output
writes to xterm. Output chunk boundaries and event counts can vary by run.

The reader uses a nonblocking PTY on one thread. There is no unbounded output
queue, replay archive, reader thread, or client parser. Limits are 1 MiB total
PTY output, 8192-byte reads, 128 state events, 4096 bytes of driven input,
512 bytes per input write, 128 host replies / 8192 reply bytes, 8 seconds per
milestone, and 30 seconds overall. Structured artifacts must fit 32 MiB; only
synthetic snapshots are written when `--fixtures PATH` is requested. Standard
output contains counters/checks/version, and errors never include PTY bytes.
Version discovery separately runs `/usr/bin/vim --version` with a dedicated
process group, clean environment, 16 KiB output bound and two-second deadline.

The native PTY child must own its dedicated process group. A guard captures
that group before any wait; errors and panics kill that group and reap the
child. Tests force both paths with disposable PTY sleep processes. Successful
Vim runs verify clean exit and absence of the owned group before disarming the
guard. A separate regression pushes 70 terminal titles, pops the newest 64,
and confirms the stack is then empty, testing the actual vendored depth cap.

`macos-observations.json` records an actual macOS run with system Vim 9.1
(compiled August 8, 2026). Its seven milestones, clean exit and group cleanup
passed; the matching structured artifact passed the renderer oracle. Full
snapshots are regenerated in `/tmp` instead of checking several MiB into Git.
Linux interactive execution remains pending a separately available guest.
Windows, multi-hour soak, crash recovery and broader CLI compatibility remain
unqualified; every report explicitly sets `qualified: false`.
