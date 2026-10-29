# Experimental private coalition ABI feasibility probe

Run `python3 tests/macos-coalition/run_native.py --run-native` on macOS.
This creates a private UUID artifact directory outside Documents, freezes source,
compiles the C fixture, then attempts two fresh jobs in each explicit domain:
`gui/<uid>` with `Aqua`, and `user/<uid>` with `Background`. A domain failure is
recorded; the runner never silently substitutes another domain. This is not an
actual headless-login, logout, boot or release qualification.

**Private ABI, experimental only.** `coalition_abi.h` is a minimal modified
projection of the pinned XNU declarations in `upstream/manifest.json`. It is not
SDK stable. The complete original headers, relevant implementation sources and
APSL-2.0 license are preserved under `upstream/`; the projection and its source
are available here under that license. The source pin is not asserted to be the
exact source of the running kernel. Actual kernel/macOS/SDK/compiler metadata and
strict runtime shape checks are recorded with each run.

The first C process queries itself, its known Python parent, and one retained
child. Each private `proc_pidinfo` flavor-20 query is bracketed by SDK audit-token
path checks. The result must be exactly 40 bytes, with reserved fields zero.
The child cooperates over pipes, performs `setsid`, then execs this same binary.
Its original four-second self-expiry survives exec. The parent closes the control
pipe and retains/reaps the child before advertising a result or exiting.
In the baseline mode, reparenting is explicitly **Unrun**.

The authorized read-only `coalition_info_resource_usage` experiment requests
only the source-supported 16-byte RESOURCE prefix (`tasks_started`,
`tasks_exited`). In a fresh isolated job, observed differences are compared with
`1,2,2,2,1` before fork, with a live child, after setsid, after exec, and after the
owned wait. Missing symbols, invalid IDs and query errors remain Unknown or
Unsupported with null counters; they never become zero. These observations do
not establish closed external admission, LaunchOnlyOnce semantics, or an
emptiness/fork-drain certificate.

Each launchd plist has a fresh UUID label, fixed absolute synthetic arguments,
`RunAtLoad=false`, `KeepAlive=false` and no demand triggers. Files are published
without replacement under the standard LaunchAgents directory. The runner
checks exact definitions and audits job/plist/state/override absence afterward.
The C controller holds an exclusive lifetime lock from before fork through
process exit. After exact bootout and manager absence, cleanup pins that lock's
inode and must acquire it before deleting the profile or confirming cleanup.
A complete result alone proves only the child's wait. Missing/malformed/busy
locks stay uncertain. Cleanup attempts every independently owned job even when
another job fails.
No `enable`, `disable`, global reset, permanent installation, credentials,
privilege changes or ordinary account creation is used.

**Never signal a coalition.** Coalition IDs can be shared with unrelated work.
The fixture neither lists coalition members nor signals by coalition or numeric
PID. Cleanup uses retained child ownership/cooperative expiry and only exact
UUID launchd jobs. Production code and its experimental feature remain unchanged.
Distinct IDs and observed counters are feasibility evidence only; arbitrary
process-tree containment and macOS P1 closure remain unqualified.

The driver rejects malformed identity/count evidence and cleanup failures, and
returns a failing exit status unless every attempted domain qualifies. Run the
non-native rejection tests with `python3 -B -m unittest discover -s
tests/macos-coalition -p test_runner.py`. SIGTERM and KeyboardInterrupt unwind
through bounded exact-resource cleanup. A hard SIGKILL/power loss cannot execute
that cleanup. Source/archive/binary and registration-intent journal writes use
file and directory durability barriers before external publication. The private
artifact journal retains exact labels/definition hashes for manual recovery;
`python3 tests/macos-coalition/run_native.py --run-native --recover UUID`
re-executes that exact generation's frozen driver after private ancestry, marker,
manifest and source checks. It takes the private run lock, validates all journal
identities against four fixed UUID/current-UID definitions before OS mutations,
and writes a separate recovery receipt. Unknown startup generations preserve
their journal. There is no power-loss recovery qualification or authorization for
a global reset. The native driver and owned
process helper execute from the frozen source tree with bytecode writes disabled,
and source/manifest/binary hashes are checked again before a passing receipt.

`python3 tests/macos-coalition/fault_native.py --run-native` exercises bounded
explicit pause hooks and signals only its own retained unreaped Python process
group. It tests live-recovery exclusion, TERM/KILL after child-wait results, and
KILL after the fsynced controller-exit checkpoint before proof-file deletion.
Every case invokes exact UUID recovery; no launchd job/descendant PID is signaled.
The checkpoint binds the observed lock inode and result hash, permitting retry
after partial deletion. An unknown extra profile entry is preserved. These are
process-interruption tests, not a simulated power-failure qualification.

## Bounded admission observations

`python3 tests/macos-coalition/run_native.py --run-native --experiment admission`
uses a nonforking controller with two explicit definitions in each domain:
LaunchOnlyOnce true and a false positive control, both with no demand triggers
and a one-second throttle. Every actual binary entry first creates its own
lifetime lock and immutable random-nonce record with SDK audit-token identity,
coalition IDs and counters. Only then does the exclusive controller gate run.
A refused fixture workload therefore still records the actual launchd entry.
Cleanup waits every recorded invocation lock and preserves unpaired/malformed
proofs as Unknown. The durable exit checkpoint includes every extra proof hash.

The finite phases are initial demand, three repeated demands while the original
controller is live, post-exit demand, then exact bootout/rebootstrap and demand.
Samples while the original controller remains live must report active=1 and
unchanged started/exited counters. The false control must record a second actual
entry; return codes alone never qualify the matrix. Both tested domains showed
no additional recorded invocation before rebootstrap for LaunchOnlyOnce=true,
but rebootstrap admitted another entry with a fresh coalition. The false control
reused its loaded-job coalition after exit, then got a fresh one on rebootstrap.
The OS build and local launchd.plist manual bytes/hash are retained in artifacts.

These observations do not prove absence of a spawn that dies before recording,
or protect against privileged external adoption/reconfiguration. A future host
must durably close generation admission and never resubmit/reuse that UUID after
closure; LaunchOnlyOnce alone does not establish that architecture. The separately scoped reparent mode below tests one retained synthetic family;
it does not prove arbitrary post-orphan identity continuity.

## Retained middle and self-expiring reparented leaf

`python3 tests/macos-coalition/run_native.py --run-native --experiment reparent`
uses two LaunchOnlyOnce jobs per domain: a normal case and an invalid-registration
control. The controller retains its direct middle child with WNOWAIT. The middle
owns its leaf, which installs its own handler and three-second alarm immediately
after fork. Timers are not inherited through fork. The leaf performs setsid and
exec while the middle still retains it; exec preserves that leaf's deadline.

Exec changes PIDversion (pinned `kern_exec.c` lines7096-7111), so the controller
acquires a fresh SDK audit token only after exec. It installs EVFILT_PROC NOTE_EXIT
with EV_RECEIPT and brackets registration with that token's path checks. Only an
accepted registration permits the middle to exit. After reparenting, no further
exec occurs; numeric read-only queries are bracketed by the same token. The
observed leaf PPID must be1, the bound NOTE_EXIT must arrive after cooperative
pipe closure, the controller must wait its own middle, and resource active counts
must follow1,3,2,1. The controller never claims parent-owned wait of an orphan.

If registration fails, the middle remains alive, retains and waits the leaf, and
reparenting remains Unrun. Missing events/identities/counters stay Unknown. The
normal and failure-control cases passed in both Aqua and Background domains.
This establishes narrow inherited-membership/true-death feasibility for these
synthetic families. Arbitrary descendant termination, dynamic private-ABI
support, fresh-token discovery, durable generation admission and production P1
qualification still require implementation and independent review.
