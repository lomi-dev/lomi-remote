# lomi-windows-pty

Windows-only native ConPTY and Job ownership. Non-Windows targets expose no
backend. `TrustedSpawnProfile` is trusted local configuration: executable and
working directory must be absolute, arguments and environment are explicit,
and dimensions are checked before allocation. Operational errors contain only
closed metadata.

`Pty::spawn(profile, before_spawn)` creates the child suspended, acquires both
process handles immediately, and assigns the child to a non-breakaway
`KILL_ON_JOB_CLOSE` Job. It runs the final authorization callback after setup,
immediately before resume. Failures
before resume cannot execute the child; uncertain resume outcomes are distinct.
The retained process handle plus creation time supplies diagnostic identity;
no PID files, numeric-PID adoption or discovered-process termination is used.

`take_reader()` transfers an independent `Read + Send` output owner. Input
accepts at most 16 KiB; output chunks are at most 64 KiB. Each overlapped transfer
has one absolute 100 ms wait, without restarting the budget as bytes arrive.
Timeouts cancel I/O and retain its heap-owned OVERLAPPED, event, buffer and pipe
until completion; at most one pending operation exists per endpoint. A timed-out
write may have partial effects and must not be blindly retried as a new input.
The service records that outcome as unknown. The reader returns WouldBlock on
timeout and stores at most one chunk.

Shutdown terminates only the owned Job, verifies direct-child exit and zero
active Job processes, cancels/drains endpoint operations, then closes ConPTY on
a bounded closer thread while draining output. Failed thread creation retains
HPCON ownership for retry. Pathological kernel cancellation or ConPTY close
failure reports cleanup failure and retains backing resources rather than
freeing kernel-visible memory or blocking indefinitely. A process crash closes
the final non-inheritable Job handle and kills descendants. Natural exit uses
separate begin/poll shutdown operations so the independent reader can deliver
pending and closing output before exit publication.

Resize runs on a retained worker with an absolute 100 ms submission deadline.
Queued work is cancelled before entering the syscall after timeout. ConPTY
close waits for an in-flight resize to release its access. A global 32-slot
admission bound stays charged through uncertain cleanup, including failures
before a complete `Pty` exists; retained handles and workers cannot accumulate
without bound.

Native evidence and the synthetic fault harness are documented in
`tests/product-pty-windows/README.md`. The `proof-hooks` feature is for that
harness only and is excluded from production dependency features.
