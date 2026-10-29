# Self-owned macOS process-death capability fixture

Run `python3 tests/macos-process-death/run_native.py --run-native` on macOS.
The runner compiles a small frozen C source with the selected macOS SDK. It
retains the binary, source archive, compiler/SDK/header hashes, commands, logs
and JSON evidence under `~/.lomi-process-death-artifacts/<UUID>`.

The C parent forks exactly one child. The child retains its original session
and process group, uses a pipe handshake, exits cooperatively on control EOF,
and self-expires after three seconds. The parent never releases child identity
until its final owned wait. The Python runner owns the isolated fixture process
group through its retained child handle; bounded runner cleanup is limited to
that group. No installation, launchd operation, privileges or OS configuration
are involved.

The positive case obtains SDK `audit_token_t` using `task_name_for_pid` and
`task_info(TASK_AUDIT_TOKEN)`, checks token PID/UID, and sandwiches `getsid` and
`EVFILT_PROC` registration between `proc_pidpath_audittoken` checks. Registration
requires an `EV_ADD | EV_RECEIPT | EV_ONESHOT` receipt with zero error. Only then
may `proc_signal_with_audittoken(SIGKILL)` target that fixture child. Success
requires an actual matching `NOTE_EXIT`, registration cookie and identity,
followed by retained `waitid(WNOWAIT)` and final parent-owned `waitpid` death
confirmation. There are no raw numeric PID signals in the C fixture.

Natural exit before or during the handshake, invalid token, failed registration,
missing exit event and an incomplete PID-list observation produce **Unknown**,
never successful empty cleanup. Missing dynamically resolved audit APIs produce
**Unsupported**. Failure cases still require separate confirmed child cleanup;
cleanup does not upgrade their capability outcome.

This tests primitives for one known direct child. It does not prove a
fork-drain theorem, arbitrary-descendant containment, PID-reuse behavior, SID or
UID escape handling, or release support. `NOTE_TRACK` is unsupported and unused.
The macOS production module and default-off experimental feature are unchanged;
this fixture does not close full-session cleanup P1.
