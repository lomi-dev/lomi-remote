# Experimental product macOS PTY fixture

This exercises `TerminalService::with_worker_in_profile(executable, profile)`
with the default-off `experimental-macos-coalition-cleanup` feature. It creates
only disposable current-user `user/UID` Background launchd jobs. It never changes
an enabled override, registers an autostart plist, or signals a coalition as a
whole. Production release qualification and the default macOS P1 remain open.

Run explicitly on macOS:

```sh
python3 -B tests/product-pty-macos/run_native.py --run-native
```

The controlled builder freezes actual compile inputs, verifies locked registry
content against the reviewed cache, uses fresh source mtimes and a unique final
Rust metadata nonce, checks inputs again after building, and copies the exact
pinned output. The driver and imported helpers then execute from the frozen tree
with bytecode writes disabled. Receipts, archives, binaries and bounded logs are
retained under `~/.lomi-pty-build/UUID`. The shared registry cache is derived from
the previously reviewed `fc701e76-d184-4c71-9f5f-51bdd99ba472` service receipt;
missing or changed seed inputs fail before any native job effect.

The fixture uses a fresh profile ending in `Library/Application Support/LomiRemote`,
longer than the canonical default profile. Only its socket moves to an exclusively
created `/private/tmp/lomi-pty-UID-UUID` directory. Profile, generation, socket
namespace and socket inodes are pinned in the journal. Cleanup requires a durable
removal-intent checkpoint and exact pins, including retry after unlink. No existing
namespace is adopted. Unit tests cover namespace collisions, symlinks, directory
and socket inode replacement, unsafe permissions/ACL grants, and absent-entry retry.

The current matrix covers actual PTY output with explicit stop, retained host
SIGKILL/IPC EOF, normal leader exit leaving a background child, and leader exit
leaving a double-forked, setsid, repeatedly exec'd orphan. Owned leaves arm their
own five-second expiry after each fork. Monotonic evidence must show the entire
leader-exit case completes within three seconds and cleanup precedes the final
leaf deadline by at least one second. An unrelated same-user manual sentinel
must stay alive and continue its heartbeat. A fifth case rejects the final
pre-spawn fence and proves no workload marker appears. Every cleaned generation
also refuses a fresh internal-controller invocation without changing its journal.
This is not a launchd rebootstrap/admission fault qualification.

Cleanup requires the original live controller's independent coalition count-one
certificate, own leader reap, PTY disposal, durable Closing proof, and release of
the exact controller lifetime-lock inode before exact job/plist removal. Native
recovery is teardown-only and is called before the first new fixture spawn and
after host EOF. It never bootstraps a retired generation or grants G. Unknown
states retain the journal and ownership; the driver does not force-bootout an
unresolved controller. Runtime profiles are removed only after proof and exact
job/plist/socket/override audits. The outer driver repeats bounded recovery on
child failure; unknown resources remain available for investigation.

Remaining qualification includes denied/truncated capability queries, churn,
rebootstrap demands, host crashes around G, controller crash quarantine, and
concurrent stop/recovery. A dead original controller cannot currently furnish the
live-controller count-one certificate. Its PID absence is never cleanup proof.
Privileged external coalition admission and broker-spawned external work remain
outside the certificate. No containment release claim follows from this fixture.

Proven cleaned history is retained for at most 64 eligible generations during
normal use. Recovery gathers at most 32 older candidates without mutation, then
collects those under profile-operation and generation-owner locks. Admission
uses a fresh stable streaming scan afterwards. A durable parent GC intent binds
the original generation/profile identities, public record, and exact file bytes
and inodes before deletion. Interrupted deletion resumes only from that intent;
unknown/live generations, unexpected files, mismatched locks and malformed
intents are retained. Removing an old journal cannot grant admission: controller
startup requires an existing unconsumed generation journal, and every new spawn
always allocates a fresh UUID. Large historical backlogs drain in bounded batches
without treating cleaned records as occupied PTY capacity.

The separate controller-death negative runs explicitly with:

```sh
python3 -B tests/product-pty-macos/controller_death.py --run-native
```

Before its only signal, an independent SDK observer binds the exact original
controller, no-fork workload and fixture-host identities to NOTE_EXIT knotes.
It requires resource count two and signals only the original controller audit
token. A fresh workload identity check after controller NOTE_EXIT must prove a
live orphan. The workload expires within twenty seconds; expiry is independent
fixture safety, never product cleanup success. Shutdown and recovery must report
uncertainty, retain unchanged admission-consumed journal bytes, and refuse replay.
One actual uncertain generation plus 31 held synthetic Prepared records exercise
the persisted reservation gate; this does not qualify 32 running jobs.

Only after independent true-exit proofs for all three processes, exact job
absence or a loaded job with no PID, and free pinned lifetime/owner locks may
separate operator cleanup
remove the UUID job and fixture paths. Its durable deletion manifest permits
partial-unlink retry; unknown extra entries block removal. Original Unknown bytes
remain immutable in the artifact receipt, and product cleanup is explicitly false.
LaunchOnlyOnce may remove the manager job automatically; absence never proves
product cleanup or a product bootout call. Reviewed source excludes its sole
manager-removal route unless durable Closing/disposal/leader/drain proofs exist.
Missing identity, exit or lock proof preserves resources and fails the run.
