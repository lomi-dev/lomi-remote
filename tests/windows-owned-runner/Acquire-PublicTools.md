# Public Windows tool acquisition

Status: **PREPARED_NOT_EXECUTED**. This source has not been parsed, compiled,
loaded, downloaded, extracted, hashed, or executed locally or on Windows. It is
an additive proposal for Windows PowerShell 5.1 / .NET Framework 4.8. The four
existing runner files are unchanged. Windows execution belongs exclusively to
the Windows owner after source review.

`Acquire-PublicTools.ps1` accepts only `-OwnedRoot`. It always acquires exactly
these fixed public artifacts; callers cannot provide URLs, versions or hashes:

| Tool | Fixed archive | SHA-256 |
| --- | --- | --- |
| Node 22.22.3 | [node-v22.22.3-win-x64.zip](https://nodejs.org/download/release/v22.22.3/node-v22.22.3-win-x64.zip) | `6c8d54f635feff4df76c2ca80f45332eb2ff57d25226edce36592e51a177ee33` |
| Bun 1.4.2 baseline | [bun-windows-x64-baseline.zip](https://github.com/oven-sh/bun/releases/download/bun-v1.4.2/bun-windows-x64-baseline.zip) | `78c221c2376f79731ccf4e4af0b3bb46d81fefa3296c5abee09ad8a1b21e68c6` |

The pins were supplied from official-source research for October 19, 2026.
This preparation does not independently attest to their contents or availability.

The caller must prepare a fresh, empty, normalized absolute local directory whose
last component is a nonzero UUID in `D` format. Its owner must equal the current
Windows token user SID. Its DACL must be protected and have exactly one explicit
allow rule for that SID: FullControl, ContainerInherit and ObjectInherit, with no
propagation flags. No inherited rules or other trustees are accepted. The script
checks the complete raw security descriptor in both its pre-Add-Type PowerShell
validation and C# revalidation: protected current-SID owner, exactly one raw
ordinary noncallback access-allowed ACE for that SID, FullControl mask 2032127
and only OI/CI flags (3). Managed rule counts alone are insufficient because a
callback ACE can be absent from that projection. Extra, callback or object ACEs
are rejected even when the ordinary rule projection appears to contain one rule.
The script
rejects reparse points in the directory and its ancestors and impersonation or
delegation tokens. The caller must exclude concurrent writers, including other
processes running as that same user; the ACL does not isolate same-SID attackers.
The script does not create or repair ACLs and does not reuse a nonempty root.

PowerShell validates that initial state before compilation, creates only a
private `.compile` child, and sets this disposable process's TEMP/TMP to that
child. These are process-only settings, with no persistent environment change.
PowerShell 5.1 Add-Type compiler descendants and temporary files therefore belong
inside the same native Job and owned root. C# revalidates the root ACL and path
after compilation and accepts only the declared `.compile` child before starting
acquisition. Compiler residue is retained and treated as unknown: it is never
read, copied, hashed, deleted, or claimed cleaned. Compilation failures can leave
that child without an acquisition receipt; preserve the root and stop.

Launch a fresh PowerShell process through the source-reviewed `Run-Owned.ps1`
native runner, supplying the reviewed executable, argument array, working
directory, and complete explicit environment. The parent's atomic Job assignment
and exact retained-handle membership verification are required. The script also
uses native `IsProcessInJob` to require its own Job membership. The Job handle is
not inherited, so that child check proves membership in a Job; the exact parent
Job proof remains the caller's responsibility. An arbitrary Job membership is
not sufficient authorization. Do not invoke this directly in an operator shell.
The parent's deadline must encompass PowerShell startup and compilation, the
300-second acquisition budget, and the parent's bounded cleanup. Inspect its
positive completion/Job-empty result; a receipt alone cannot prove process cleanup.

Downloads are serial with no retries, use HttpClient streaming with a shared
300-second cancellation budget, and cap the archives at 60 MiB for Node and
100 MiB for Bun. Each read is at most 64 KiB. Its minimum interval is
ceil(actual bytes * 1000 / 1048576) milliseconds, approximately 1 MiB/s,
without credit carried to later reads. A full read costs 63 ms; a short 16 KiB
read costs 16 ms. [Stream.ReadAsync](https://learn.microsoft.com/en-us/dotnet/api/system.io.stream.readasync?view=netframework-4.8.1)
may return fewer bytes than requested; charging every short read as 64 KiB
would unnecessarily throttle the transfer below its intended rate. HTTP/TLS
buffering may produce short network bursts; this is application pacing, not a network QoS
guarantee. HTTPS/TLS 1.2 is mandatory, proxies/cookies/default credentials and
automatic decompression are disabled, and certificates use normal OS validation.
At most five redirects are accepted. Node stays on `nodejs.org`; Bun allows only
`github.com`, `release-assets.githubusercontent.com`,
`objects.githubusercontent.com`, and `github-releases.githubusercontent.com`.
No HTTP downgrade, custom port, URI credentials, or caller URL is permitted.

The archive must match its fixed SHA-256 before any extraction. ZipArchive checks
at most 20,000 entries, bounds entry-name lengths, rejects duplicate names without
regard to case, absolute/traversal/colon/backslash names, Unix special-file modes,
and DOS reparse attributes. Other ordinary archive files may exist, but only the
exact members `node-v22.22.3-win-x64/node.exe` and
`bun-windows-x64-baseline/bun.exe` are read. Each becomes a flat `node.exe` or
`bun.exe` under the root, using CreateNew; there is no general archive extraction.
Expanded executable caps are 100 MiB and 200 MiB, respectively. The script records
each extracted binary's SHA-256 and checks its PE signature and AMD64 machine
type statically. It never starts either binary and does not claim a version probe
or successful native execution. A later, separately reviewed Windows-owner step
must run each `--version` through the native owned runner.

All artifact writes use CreateNew and remain under the owned root. Success leaves
the declared `.compile` child, `node.zip`, `bun.zip`, `node.exe`, `bun.exe`, and a UTF-8
`acquisition-receipt.json` bounded to 8 KiB. The closed receipt contains only the
fixed artifact names, archive verification/hash/byte count, binary hash/byte
count, final HTTPS host, fixed stage, status and completion/cleanup indicators.
It records no redirected signed URL, exception detail, environment or account
data. `cleanupKnown=true` means managed acquisition handles were disposed; all
files and unknown compiler residue are deliberately retained. It does not mean
the Job is empty, compiler cleanup is known, or files were deleted. On any
uncertain failure, a best-effort `FAILED_UNCERTAIN` receipt
has both indicators false, the script fails, and the owner must preserve the
root and stop. Receipt creation itself can fail; absence or partial content is
also failure. Initial validation failures before root acceptance write nothing.

The 300-second deadline includes root checks, transfer, extraction and hashing
after entry into the acquisition method. PowerShell startup/compilation and
synchronous OS filesystem/disposal calls are not independently interruptible;
the outer native Job deadline is required as the hard execution bound.
No PostgreSQL, Python, npm installation, global installation, PATH policy,
operator environment/configuration dump, scheduling, account change or write
outside this root is part of this source. Nothing here authorizes contacting or
starting Windows, running checks, or acquiring tools on the streaming Mac.
