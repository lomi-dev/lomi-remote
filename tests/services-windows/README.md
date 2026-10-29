# Windows native service fixture (experimental; not a product daemon)

This fixture has no installer/activation/update path, authentication, sharing,
network listener, TUI, arbitrary command execution, or real credential store.
It creates only a new UUID service and its private synthetic ProgramData files.
The binary always reports `qualified=false`. Build checks are not native proof.
Native results below are limited to the explicitly recorded synthetic proof.

## Scope and safety boundary

`lomi-windows-service-fixture service UUID OPERATOR_SID` registers a real SCM
own-process service and Stop handler. It requires the LocalService token and
session ID 0. A private nonshared owner lock and a first-instance named pipe
reject another owner. Clients open with identification-only SQOS and verify the
pipe server PID against the exact running SCM service configuration before
sending input or trusting any response. The protected directory and pipe DACLs contain only
SYSTEM, LocalService (`S-1-5-19`), and the explicit operator SID; the pipe rejects
remote clients. The service validates the root DACL and rejects reparse points
for the root and state files. The elevated operator is deliberately trusted and
can change these synthetic test resources; this is not a hostile-admin boundary.
The parent is created atomically with an Administrators owner and a protected
SYSTEM/Administrators full-control DACL plus LocalService read/traverse. Existing
parents with unexpected ownership or DACL are rejected without repair or
ownership takeover. Native and script lifecycle paths validate the directory
chain and reject ProgramData ACLs granting untrusted replacement rights. This bounded preparatory
harness currently requires the standard `C:\ProgramData` location.

The fixed child is the same executable, never a shell. A direct `CreateProcessW`
starts it suspended with an empty environment. RAII immediately owns its process
and thread handles. The service attaches a kill-on-close Job Object before
`ResumeThread`, so even its fixed same-binary worker inherits the job. No child
may run before assignment. The child reports console size using native console
APIs and receives Ctrl+C using a native control handler. Input is restricted to
four fixed commands, at most 32 writes (<512 bytes total) into a 4096-byte pipe;
no raw console input is accepted from clients or replayed on attachment.

An independent reader thread drains ConPTY before any fallible process setup
and throughout `ClosePseudoConsole`. It feeds the existing bounded Rust terminal
model, keeping only counters and a 4 KiB synthetic marker tail. Output beyond
1 MiB, model failure, or unexpected terminal reply obligations fail the fixture
and terminate the job. No console payload is written to logs or evidence.
SCM Stop sets an atomic flag, including during the 250 ms whole-request IPC
budget. Responses require a bounded client ACK after the entire JSON frame has
been consumed; Stop cancels this wait, and no unbounded FlushFileBuffers is used.
Shutdown explicitly terminates the job, checks all active job processes
are gone, and waits for ConPTY close and drain completion with deadlines. A
job/child guard also covers partial startup errors. ConPTY ownership is retained
if its closer thread cannot be created, and pending close/drain remains an error
until completion is observed; a retry cannot turn a pending close into success. API failure/timeouts produce
failure evidence; they are not interpreted as cleanup proof.

Only a version/epoch descriptor persists. Restart reports the old epoch lost;
no PID is adopted and a new session requires explicit `start`. A RAM-generated
synthetic random payload is protected using user-scope DPAPI with
`CRYPTPROTECT_UI_FORBIDDEN`, without `CRYPTPROTECT_LOCAL_MACHINE`. Only ciphertext
is saved. A one-time bootstrap marker permits initial creation; an initialized
store with missing ciphertext fails closed. Reopening/decrypting after service
restart and a readable-ciphertext/decrypt-negative operator check are included.
The DPAPI artifact is test data, not a real user secret, and neither plaintext
nor ciphertext is printed. The wrapper is not a general crash-safe key store;
full host credential persistence and headless reboot remain separate acceptance
work. Zeroization is best-effort volatile clearing of owned buffers; Windows
and cryptographic provider internal copies are outside this fixture's control.

## Build and exact native commands

These commands are preparation, not permission to run on arbitrary hosts.
Run only on the specifically authorized Windows test machine. No script reboots
Windows, changes another service/session, modifies recovery policy, or registers
a host service on macOS/Linux. No operator password or key is accepted.

Build from an approved source-only snapshot in a fresh UUID test directory:

```powershell
cargo build --locked -p lomi-windows-service-fixture --features fixture-test-hooks
$run = [Guid]::NewGuid().ToString('D')
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$binary = (Resolve-Path '.\target\debug\lomi-windows-service-fixture.exe').Path
.\tests\services-windows\Install-Fixture.ps1 -DisposableSyntheticResources -RunId $run -OperatorSid $sid -Binary $binary
.\tests\services-windows\Test-Fixture.ps1 -DisposableSyntheticResources -RunId $run -OperatorSid $sid -Evidence '.\windows-fixture-evidence.json' -FaultInjection
.\tests\services-windows\Status-Fixture.ps1 -RunId $run -OperatorSid $sid
.\tests\services-windows\Remove-Fixture.ps1 -DisposableSyntheticResources -RunId $run -OperatorSid $sid
```

Install/Test/Remove require an elevated administrator. Install refuses an
existing UUID path/service, sets the directory ACL before writing files, creates
the service directly with LocalService and **manual** startup, and does not start
it. SCM transitions use nonwaiting ServiceController requests followed by explicit
wait deadlines. Test launches independent native client processes, checks resize/detach,
normal child exit, stopped service remaining stopped, restart/new epoch,
DPAPI positive/negative, Ctrl+C, and ControlStop with a live descendant. Its
class-only evidence is incomplete on any failure or uncertain cleanup. Stop
proof is tied to the current owner's epoch, so stale `last-stop.json` cannot
satisfy a failed stop. Cleanup verifies the exact service path/account and UUID
marker, stops it, removes only that service, and handles an already-absent exact service, then deletes only the enumerated
regular fixture files. Contents are validated before any SCM deletion. Unknown contents cause
preservation and an error. The marker is deleted last so interruptions after SCM
deletion can be retried. A crash between deleting the final marker and removing
its now-empty directory leaves an unmarked directory that requires manual
inspection; this fixture refuses to infer ownership from an unmarked path. It
leaves the shared empty parent directory and source/build snapshot intact.

`Status-Fixture.ps1` and the native `client UUID SID status` mode support later
independent SSH-client observations. A local named-pipe detach is exercised by
Test. A separate native proof below verifies normal SSH transport closure and
continuity through a fresh connection. Login independence, no-interactive-logon
headless boot, architecture coverage, abrupt network loss and abrupt owner death
remain explicitly unrun. Startup is manual;
there is no automatic boot registration or reboot action in this preparatory
harness. Cross-target `cargo check`/Clippy cannot validate SCM/ConPTY/DPAPI, DACL
canonicalization, Windows PowerShell argument handling, or account profiles.

## Pinned API provenance

Dependencies are exact `windows-service=0.8.1`, `windows-sys=0.61.2`,
`serde=1.0.229`, `serde_json=1.0.151`, `uuid=1.26.1`; Rust 1.98.1 edition 2024.
No production runtime Node/Python/portable-pty dependency is introduced.

- [Microsoft: Creating a Pseudoconsole session](https://learn.microsoft.com/en-us/windows/console/creating-a-pseudoconsole-session): separate channel servicing and draining through close, startup attributes, resize.
- [Microsoft: CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw): suspended process and extended startup info.
- [Microsoft: Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects): inherited membership and kill-on-close ownership.
- [Microsoft: CryptProtectData](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata): default user scope and UI prohibition.
- [Microsoft: CreateNamedPipeW](https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-createnamedpipew): explicit security, first-instance ownership, remote rejection.
- [Microsoft: Service User Accounts](https://learn.microsoft.com/en-us/windows/win32/services/service-user-accounts): service identity/account separation.
- [windows-service 0.8.1 docs](https://docs.rs/windows-service/0.8.1/windows_service/) and its packaged `examples/ping_service.rs`: dispatcher, control handler, status API.
- `windows-sys-0.61.2/src/Windows/Win32/{Security,System,Storage}` from the Cargo registry: exact generated ABI and feature names checked during implementation.

The `fixture-test-hooks` build plus `Test-Fixture.ps1 -FaultInjection` prepares
native delayed-reader/ACK Stop cancellation, squatted-server identification-token
ceiling, and acquired-ConPTY closer-spawn failure/retry regressions. They are not
native results until executed. A separate prepared policy regression intercepts
SCM Create (no service is installed), rejects a broadly writable precreated test
parent, checks failed-create cleanup and resumes a simulated interrupted removal:

```powershell
.\tests\services-windows\Test-PolicyRegression.ps1 -DisposableSyntheticResources -Binary $binary -WorkDirectory (Get-Location).Path
```

LocalService is a shared built-in account. This fixture does not claim isolation
from other LocalService processes or a per-service SID production boundary.

## Recorded native proof

The bounded proof completed on Windows 10 Enterprise LTSC build 19044 x64,
Rust/Cargo 1.98.1: **4/4 policy checks and 16/16 native service/fault checks**.
The actual SCM owner ran as LocalService in session 0. DPAPI reopen/isolation,
ConPTY resize/detach/Ctrl+C, job cleanup, delayed-reader acknowledgement, Stop
cancellation, and identification-only squatted-server regression passed. The
injected closer-thread failure/retry ran inside the real ready SCM owner; an
earlier operator/SSH foreground probe failed before child readiness and remains
a historical failed attempt, not a passed operator-console qualification.

Evidence is `artifacts/windows/native-9bc026e3-4ede-46eb-a61c-fa1f1de91565.json`;
`artifacts/windows/native-attempts.json` explicitly retains failed attempts and
their superseding result. Approved source snapshot is
`5171188f70bc4c8fbd4feca8a7e2986f`. The final read-only check independently
confirmed the exact UUID service absent, UUID directory absent, and zero
processes using its exact fixture executable path. The protected shared empty
parent directory and approved user source/build snapshots remain; no other
service, user session, credential store, default toolchain, boot setting, or
reboot was changed. The fixture still reports **`qualified=false`**. Headless
boot/SSH-login independence, other architectures and long soak remain unrun.

Runtime corrections included an explicit Windows PowerShell assembly load for
`ServiceController`, canonical allow-ACE ordering shared with .NET, and shared
mutable test state across nested PowerShell scripts. Startup diagnostics contain
only trust booleans and static stages; they contain no terminal output, secret,
ciphertext, or environment dump. The test coordinator uses process-only
PowerShell execution-policy bypass and never changes the machine/user policy.

Cleanup preservation is fail closed even when the native test SSH call times out
or its evidence is absent/malformed. The coordinator persists the attempt before
SSH and requires literal `cleanupVerified=true` before removal. PowerShell starts
with this flag false, tracks the observed owner epoch through each service start,
and only confirms a matching last-stop record with explicit cleanup/job-empty
booleans. SCM `Stopped` cannot overwrite a failed proof for that epoch. The
focused Python coordinator tests and in-memory `Test-CleanupRegression.ps1`
exercise missing/false proof, transport/parse errors, stale epochs, and the
explicit positive path without starting or deleting service resources.

The separate SSH-disconnect proof passed all three phases using the reviewed
immutable plan `ssh-disconnect-plan-024ed63f-3e57-4d10-bb27-619d3f6985cd.json`.
Evidence is `artifacts/windows/ssh-disconnect-024ed63f-3e57-4d10-bb27-619d3f6985cd.json`;
its exact commands, script digests, exits and aggregate observations are retained.
The first SSH process returned normally while SCM owned a ready child. After a
one-second gap, a fresh nonmultiplexed connection observed unchanged owner/session/
child/worker identities and zero replayed input, resized to 37x101, and verified
exactly the two expected fixed input writes. The third connection verified the
checkpoint's current-owner stop proof, removed the owned service and UUID directory,
and deleted the checkpoint. All three SSH commands exited zero. Independent
read-only absence proof is `artifacts/windows/ssh-disconnect-024-readonly-absence.json`:
service, UUID directory and checkpoint absent, with zero exact-path fixture processes.
This is a normal SSH disconnect proof; abrupt network loss and boot remain unrun.
The prototype remains `qualified=false`, and the separate native 16-case proof is
unchanged. No other SSH connection, user session, boot setting or logoff was involved.

`plan_ssh_disconnect.py` generates explicit commands without connecting.
`execute_ssh_disconnect.py` pins the reviewed plan digest, claims its UUID once,
and preserves resources on uncertain completion or an invalid initial owner proof.
Five focused executor tests cover sequencing and those failure paths.

The first SSH plan (`9e370469-0960-4cf4-a2dd-930db3c83501`) returned exit 1
before an initial owner proof. Its 8856-character encoded START argument exceeded
the default cmd.exe command budget, consistent with the immediate transport failure.
Verification and cleanup were deferred; a separate read-only observation established
service/directory/checkpoint absence and zero matching fixture processes. This
failed attempt remains incomplete and is superseded by the successful separate
024 attempt. The replacement removes unused START helper definitions and enforces
a 7600-character remote-command budget. `artifacts/windows/ssh-disconnect-attempts.json`
links both attempts without altering their original evidence.
