# Restricted one-shot Windows test launcher

Status: **PREPARED_NOT_EXECUTED**. These five additive files have not been parsed,
compiled, loaded, hashed or run. No Windows contact, PostgreSQL acquisition,
database initialization, SQL, server/session controller or authentication client
is included. The normal owned runner and immutable artifacts remain unchanged.
Target: Windows PowerShell 5.1 / .NET Framework 4.8, Windows 10 or newer with
atomic Job-list and handle-list support. Source review and independent Windows
qualification are required before admitting any native execution.

`RestrictedOwnedProcess.cs` defines a separate test-only
`Lomi.RestrictedPostgresTests.RestrictedOwnedRunner`; `Run-Restricted.ps1` is a
typed adapter. `Run` accepts exact executable/arguments/cwd, a complete explicit
IDictionary, current-user private UUID root, RAM-only `byte[]` stdin, execution
and cleanup budgets, and output byte limits. Null stdin is rejected; an empty
array explicitly supplies EOF. Limits are 64 KiB input, 64 KiB observed output
per stream, 360 seconds execution and 10 seconds cleanup. The native execution
stopwatch starts before token acquisition/setup; synchronous OS calls cannot be
individually interrupted. Validation and compilation also need an outer reviewed
native owner deadline; transport timeout never proves cleanup.

Require a normalized absolute local nonzero UUID root, exact current-user SID
owner, protected DACL with exactly one explicit SID FullControl OI/CI ACE and no
other rules, and no reparse ancestry. The cwd must be this root or a descendant.
Both native-helper admission and precompile PowerShell validation inspect the
raw security descriptor, not only the managed rule projection: protected owner,
exactly one ordinary noncallback AccessAllowed CommonAce for that SID, exact
FullControl mask 2032127 and only OI/CI flags (3). Extra callback/object ACEs are
rejected even when GetAccessRules omits them from its projection.
The executable is a regular nonreparse local absolute file with no reparse
ancestry and a retained shared-read guard during launch/supervision. Its exact
source/provenance hash remains the controller's responsibility; this API does
not accept arbitrary caller URLs or make a binary provenance claim. No
concurrent same-SID writers are admitted. A same-user process is not a sandbox
adversary; the token deliberately retains that user's filesystem access.

The complete caller environment must have exactly these eleven case-sensitive
names with raw CLR string keys/values: SystemRoot, WINDIR, ComSpec, PATH, HOME,
USERPROFILE, TEMP, TMP, APPDATA, LOCALAPPDATA, PSModulePath. `ElevenStringPrefix`
checks this actual dictionary and invokes the private pure formatter before
native setup. The formatter separately rejects case-insensitive duplicates,
NULs, invalid names and wrapped/nonstring values. Build the caller map using
`Dictionary<string,string>.Add([string]key,[string]value)` and avoid PowerShell
pipeline enumeration of dictionary entries. No environment is copied from the
operator. The thin adapter does not configure bootstrap TEMP/TMP; its caller
must supply private process-only values before compilation. Do not log the
invocation, payload, environment or a transcript.

The token policy follows the exact PostgreSQL 18.6 Windows implementation:
[restricted_token.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/common/restricted_token.c)
disables Administrators and Power Users, and
[win32security.c](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/port/win32security.c)
checks those two groups. The helper disables only `S-1-5-32-544` and
`S-1-5-32-547` using CreateRestrictedToken with DISABLE_MAX_PRIVILEGE. A present
group must become deny-only with enabled/default-enabled bits cleared; an absent
group stays absent. Other group attributes, user SID, primary-group SID and
session ID must remain unchanged. The token must remain primary, have no
restricting-SID list and retain no privilege except the documented optional
SeChangeNotifyPrivilege. It never disables an arbitrary primary group or the
user SID and does not reject primary-group/user equality merely for equality.

As in [PostgreSQL AddUserToTokenDacl](https://raw.githubusercontent.com/postgres/postgres/REL_18_6/src/common/exec.c),
the new restricted token alone receives a default DACL formed by copying existing
ACEs and appending an explicit GENERIC_ALL current-user ACE. A null original
default DACL becomes a user-only ACL. The caller token is never passed to
SetTokenInformation. The helper verifies the exact resulting DACL bytes and
user grant on both the new token and the actual suspended child's token. This
is a structural grant check; existing deny ACEs are not removed or bypassed.
Positive child file/pipe creation probes must establish usability. A final
caller-token snapshot checks that user/primary/session, groups, privileges and
default DACL remain unchanged. Only these new-token operations are authorized;
no account rights, logon, persistent policy or caller-token adjustment fallback.

`CreateProcessAsUserW` receives that restricted primary token with QUERY,
DUPLICATE, ASSIGN_PRIMARY and ADJUST_DEFAULT rights. Its STARTUPINFOEX has an
explicit Job list and exactly stdin-read/stdout-write/stderr-write in the
inherited handle list. Parent pipe ends, token and Job handles are noninheritable.
The process starts suspended with CREATE_NO_WINDOW and a complete Unicode
environment. The helper checks exact retained-Job membership and independently
queries the actual created process's token before ResumeThread. Unsupported
token rights, privileges, session/desktop conditions or atomic Job creation fail
closed. There is no post-creation Job assignment or ordinary/elevated-token
fallback. It does not call the existing runner's RunCore through reflection.

Two worker threads drain output concurrently, retaining no output bytes. Counts
saturate, and crossing a cap triggers owned Job termination. A separate writer
starts only after resume, pins its private copied input, handles partial writes
in at most 4 KiB chunks, closes its own pipe to send EOF and clears the copy on
termination. Never prefill the pipe synchronously while the child is suspended.
The parent supervises deadline/overflow/worker failure independently of blocked
writes. Worker cancellation uses retained duplicated thread handles, not thread
IDs. A cancellation can race a new synchronous I/O call; an unstopped worker
makes completion uncertain and retains its owned handles until the worker exits.
No other thread closes a handle while its worker may still be using it. Output
buffers and private input copies are cleared best effort; this does not erase
GC copies, kernel pipe buffers or page files. The caller must clear its own byte
array in a finally block and avoid secret command-line/environment values.

Cleanup uses the same retained Job, positive primary wait/exit query, accounting
zero and reader EOF/termination checks. Writer, readers and native waits share
one cleanup stopwatch. Closing the Job requests termination without proving it.
The narrow retained-process-handle termination fallback is only for a failed
native creation that nevertheless returned an unassigned process handle.
No PID lookup, process-name signal, taskkill, retry or deletion is used.

The new closed result contains exitCode, timeout, overflow, completionKnown,
JobEmpty, tokenVerifiedBeforeResume, defaultDaclVerifiedBeforeResume,
callerTokenUnchanged, stdinComplete, stdinEofSent, stdinBytesWritten,
stdoutBytesObserved, stderrBytesObserved, failureStage, failureCategory and
nativeError. It has no stdout/stderr Base64, SQL, input hash or raw exception.
`completionKnown` proves owned process/worker cleanup; early child input closure
can have known cleanup while `stdinComplete=false`. Application success also
requires successful token proof, complete input+EOF, exitCode=0, no timeout or
overflow, and failureCategory=None. For a rejected suspended child, known cleanup
does not imply it ran. Persist only a secret-free projection for a future SQL
stage: even stdin byte count can reveal private payload length. Probe inputs are
fixed nonsecret data, so their full typed result may be retained.

`RunForProbe` adds only an explicit RejectBeforeResume fault, bounded pre-resume
delay and actual native resume-attempt out counter. Normal Run always disables
these seams; environment values cannot enable them. Verification-fault cleanup
starts drainers after termination if needed, so zero resume attempts is paired
with positive Job/EOF cleanup, rather than an absent marker alone.

`probe.ps1` is source for one fresh root and one fresh owner process per mode.
It validates an empty exact private root before compilation, directs process-only
TEMP/TMP to `.bootstrap`, compiles the two public source files and constructs
the eleven-string map. Compiler bootstrap is outside the new restricted Job;
an already reviewed normal native owner must contain the whole probe PowerShell
process and compiler descendants. A future controller must compare copied source
bytes/hashes before loading it. If invoking PowerShell to run these scripts,
the owner must use explicit `-NoLogo -NoProfile -NonInteractive -ExecutionPolicy
Bypass -File` arguments; no inherited execution-policy preference is assumed.
Probe children themselves are a compiled executable, with no shell involved.

| Mode | Required evidence |
| --- | --- |
| Input | 65,536 deterministic bytes including NUL/nontext values; byte-for-byte check and EOF, fixed marker, exact count, zero output |
| Empty | Immediate EOF, complete input/closure, fixed marker |
| Token | Actual token proof; child independently checks deny-only BA/PU and creates a pipe/file; BA-only and PU-only synthetic files reject write access; unchanged parent's BA-only positive control required |
| BlockedWriter | Child started but never reads; >pipe-buffer input blocks; timeout with incomplete input, stopped writer, positive cleanup |
| EarlyClose | Child marks startup then closes stdin; incomplete input with InputIncomplete category, no timeout/overflow, positive cleanup; a blocked-writer timeout cannot pass |
| HandleInheritance | Owner's deliberately inheritable sentinel identifies a known file; child cannot identify that file using the same numeric handle (which may be reused) |
| Overflow | Both output streams write while stdin is checked; cap crossing triggers termination, no output retention, positive cleanup |
| StdoutOverflow / StderrOverflow | Each stream independently crosses its cap while the other remains empty; positive cleanup |
| PreResumeFault | Explicit fault after native actual-token/Job checks, actual ResumeThread attempts zero, marker absent, positive cleanup |
| PreResumeDeadline | 100 ms delay against 50 ms original execution budget, actual resume attempts zero, no marker, positive cleanup |
| TimeoutDescendant | Restricted child starts same-token descendant holding exclusive marker, deadline expires, marker positively reopens after Job-empty proof |
| InputRejected | Null and >64 KiB arrays fail before creation; zero resume attempts and no marker |
| CallbackAclRejected | Add an extra raw callback allow ACE for another SID to the disposable root; verify two raw ACEs, PowerShell raw-guard rejection and helper rejection before creation, zero resume attempts and no marker |

CallbackAclRejected is an unexecuted native-ACL fixture, not evidence that
callback ACE construction is supported on the target. It preserves the original
ordinary user ACE and appends a BA callback ACE with empty opaque payload using
SetFileSecurityW, scoped to the already validated private UUID root. Native
construction or raw readback failure is a failed qualification, never an assumed
rejection pass. The intentionally changed root remains retained; no ACL repair,
restoration, reuse or deletion follows. The raw callback fixture has not been
compiled, installed or observed on Windows.

The Token mode requires an owner with enabled BA membership to positively open
its BA-only witness before restriction. Otherwise it fails as unsupported; it
cannot pass merely because both original and restricted tokens lack access.
Synthetic witness ACLs are the only non-user-only ACLs changed, strictly beneath
the owned UUID root; installed/admin/operator objects are untouched. They remain
as evidence, with no deletion or restoration attempt. Result envelopes and closed
failure stage/category/line/HResult are emitted before assertions discard any
failure evidence; no raw exceptions are printed by the probe catch. Child errors
use only a fixed failure token, and their bytes are discarded by the helper.

Remaining native qualification points: CreateProcessAsUser privilege availability
(restricted-caller exemption does not guarantee SeIncreaseQuotaPrivilege), exact
default-DACL normalization and deny ACE behavior, token-group attribute stability
on actual child creation, same-session handle inheritance, explicit Job-list
support with this token, anonymous-pipe cancellation races, and descendant object
creation under the adjusted default DACL. Independent source review must precede
Windows parsing/compilation and every positive/negative probe. No PostgreSQL
session/authentication support is implied by a one-shot helper result.
