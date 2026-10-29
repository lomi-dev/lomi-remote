# Prepared source: Windows Job-owned runner

Status: **PREPARED_NOT_EXECUTED**. These files have not been parsed, compiled,
loaded with Add-Type, or probed on Windows. Review the native declarations and
failure paths before authorizing any execution. Existing bounded runners are
unchanged. No PostgreSQL restriction is implemented here.

`Run-Owned.ps1` targets Windows PowerShell 5.1 / .NET Framework 4.8. Supply a
normalized absolute executable path, an argument array, a normalized absolute
working directory, and a complete environment dictionary. The environment is
case-insensitively checked for duplicate names and sorted; it never defaults to
the operator environment. Provide SystemRoot, ComSpec, TEMP, TMP, PATH, HOME,
USERPROFILE, tool directories, and any other required settings only as reviewed
caller values. An empty dictionary means an empty environment block. Windows
and the target application may synthesize their own internal defaults; the
runner does not read or copy operator variables.

The runner creates its own unnamed, noninheritable Job with kill-on-close and no
breakaway flags. It creates the child suspended with no console window and atomic
Job assignment through PROC_THREAD_ATTRIBUTE_JOB_LIST. It positively verifies
membership using IsProcessInJob with the exact retained Job handle before
resuming the primary thread. Unsupported platforms fail closed; there is no
post-creation-only assignment fallback. This requires Windows 10 or later. No
process lookup, PID signal, taskkill, or process-name cleanup is used.
The native attribute contract is documented in Microsoft's
[UpdateProcThreadAttribute reference](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute).

Only NUL stdin and the two pipe write handles are inherited using an explicit
STARTUPINFOEX handle list. Two background readers drain raw bytes concurrently.
Each keeps at most CaptureBytesPerStream bytes and discards further bytes while
continuing to drain. The supervisor checks overflow every iteration (at most a
10 ms polling interval) and terminates the owned Job immediately when observed,
then requires the same positive cleanup checks. The result exposes seven fields:

| Field | Meaning |
| --- | --- |
| exitCode | Signed process exit code after a positive retained-handle wait, otherwise null |
| timeout | Execution deadline expired before primary exit plus Job emptiness |
| overflow | At least one stream exceeded its byte capture limit |
| completionKnown | Native operations succeeded, primary exit was observed, Job was queried empty, both readers saw EOF and stopped |
| JobEmpty | A positive accounting query observed zero active Job processes |
| stdoutBase64 | Captured stdout byte prefix, Base64 encoded |
| stderrBase64 | Captured stderr byte prefix, Base64 encoded |

Validation errors throw before starting a child. Native setup or cleanup errors
produce an uncertain envelope; diagnostics and environment values are not mixed
into captured child output. Treat completionKnown=false as a blocked result,
even if exitCode is present. A timeout can have completionKnown=true when the
owned tree was positively terminated and drained; it still fails the caller's
test. Overflow also remains a separate caller-visible failure condition.

The execution deadline includes native setup. On timeout/error the runner
terminates the Job, then spends at most CleanupMilliseconds on process wait,
Job emptiness queries and reader joins. Setup/native calls themselves are
synchronous OS calls without per-call deadlines. Stream capture remains bounded
even for a writer that floods output. Command-line quoting follows Windows CRT
rules; command interpreters or applications with custom parsers need their own
reviewed argument conventions.

The deadline is checked immediately before ResumeThread. If setup has exhausted
the execution budget, the child remains suspended and the runner reports timeout
while terminating and positively collecting the owned Job. The supervisor also
checks expiry before accepting primary exit plus Job emptiness as completion.
The explicit RunWithPreResumeDelayForProbe entry point permits at most 1000 ms of
pre-resume delay for deterministic testing and returns a separate out parameter
counting actual ResumeThread attempts. The seven-field result remains unchanged.
Normal Run always supplies zero delay; no environment variable or operator
setting enables the delay.

If a reader misses EOF, the runner requests CancelSynchronousIo through its
retained thread handle. A cancellation can race a new synchronous read. In that
case a background reader and its owned read/thread handles may remain until EOF
or owner termination; the result explicitly reports uncertain completion. It
never closes a read handle while another thread might be using it. Do not reuse
an uncertain owner for further tests: preserve the evidence and stop. Closing
the Job handle requests termination but is never presented as proof of cleanup.

Atomic creation closes the create-before-assignment orphan window: a successfully
created process belongs to the kill-on-close Job before it can run, including
when the owner is terminated before the explicit membership verification.
Executable provenance, reparse points, untrusted programs, environment allowlists,
and a hostile process deliberately duplicating Job handles are outside scope.
Use controlled binaries and reviewed caller inputs.

`probe.ps1` is additive source for later explicit execution. Normal checks raw
binary output; Overflow checks bounded capture and early termination; Arguments
checks empty, embedded backslash/quote and trailing-backslash values; Environment
checks explicit values and omission of a deliberately set operator variable;
HandleInheritance checks that an unrelated, deliberately inheritable file handle
is excluded, using its file path as a witness rather than trusting handle-number
validity (the child may reuse that number for another object);
TimeoutGrandchild checks that a
grandchild held by the Job is gone after a timeout; AbruptOwner kills a retained
owner Process object only after its descendant has opened a marker. The marker
is an exclusive-open liveness witness, not a PID. AbruptOwner is deliberately
gated after descendant startup; it does not exercise every instant inside native
process creation. No early-owner-crash stress probe is included: it would need a
separately reviewed witness for processes killed before executing their first
instruction. Each invocation
requires explicit absolute paths and an explicit environment JSON file. These
probes must be reviewed and authorized separately; adding them does not run them.

PreResumeDeadline uses a 100 ms explicit probe delay with a 50 ms execution
budget. It requires timeout=true, a positive exit code observation, JobEmpty=true,
completionKnown=true, zero actual ResumeThread attempts, and absence of the
ChildMarker file. The positive attempt counter prevents a resumed child killed
before its marker write from falsely passing this regression check. It has not
been run.
