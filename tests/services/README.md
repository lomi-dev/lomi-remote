# Native service qualification runbook (E0 draft)

No service registration commands have been executed by this spike. This document
is a manual acceptance procedure, not evidence that boot, logout, key storage or
native service lifecycle has passed.

## Available harness and evidence boundaries

Build the renderer-free native-session experiment from the repository root:

```sh
cargo build --locked -p lomi-platform-spike --bin pty-probe
cargo test --locked -p lomi-platform-spike
cargo clippy --locked -p lomi-platform-spike --all-targets -- -D warnings
```

On macOS, run the resulting executable directly:

```sh
./target/debug/pty-probe
```

The current executable runs synthetic shell fixtures, opens its own temporary
workspace and IPC socket, and exits after the experiment. Its standard output
contains check labels; do not collect terminal transcripts, full environment,
credentials, real workspace paths or application data as evidence. Use a
separate test OS account with no Lomi application profile or credentials. Close
all desktop renderers before running it. Do not open a user project.

This is an experiment binary, not `lomiremote`, an installer, a stable local API,
a persistent daemon, or an SCM service. In particular, an interactive success
does not prove unattended boot, keychain availability, DPAPI user binding, peer
ACLs, survival of logout, service restart behavior, or a terminal serialization
profile. The binary's final `not_run` line remains a qualification blocker.

The owner of the probe must verify clean explicit child environment, bounded
capture/model state and OSC7 parsing, two late attachments observing identical
state, output progress with no attachment, detach survival, native resize and
Ctrl-C cleanup. An IPC `ready` response alone does not prove shared snapshots.
An OSC7 substring match alone does not qualify an incremental CWD parser. A
bounded receive queue alone does not qualify a persistent bounded model.

## macOS: manual launchd smoke check

Use a disposable local account named `lomi-spike` and an absolute executable path
outside any application project. Build the binary above; install a copy at
`/usr/local/libexec/lomi-e0-pty-probe`, owned by root and not writable by the test
account. Before copying, independently verify the executable identity against
the build under test. This manual procedure requires administrator access on the
disposable test machine; no registration is performed by Cargo tests.

A manual **one-shot LaunchDaemon smoke check** can use this plist at
`/Library/LaunchDaemons/com.lomi.e0.pty-probe.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.lomi.e0.pty-probe</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/libexec/lomi-e0-pty-probe</string>
  </array>
  <key>UserName</key><string>lomi-spike</string>
  <key>RunAtLoad</key><true/>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>/var/tmp/lomi-e0-probe/result.txt</string>
  <key>StandardErrorPath</key><string>/var/tmp/lomi-e0-probe/error.txt</string>
</dict></plist>
```

The operator must first create `/var/tmp/lomi-e0-probe` owned by `lomi-spike`, mode
0700, and ensure the plist is root-owned, mode 0644. Do not set `KeepAlive`: the
harness is deliberately finite. The exact manual invocation is:

```sh
sudo plutil -lint /Library/LaunchDaemons/com.lomi.e0.pty-probe.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.lomi.e0.pty-probe.plist
sudo launchctl print system/com.lomi.e0.pty-probe
```

Inspect exit status and the check-only result. To repeat after a completed run:

```sh
sudo launchctl kickstart system/com.lomi.e0.pty-probe
```

For the distinct pre-login boot check, leave the job registered, reboot the
throwaway machine, and inspect the result using a separate administrative
account before logging `lomi-spike` in. Record OS build, architecture, executable
SHA-256, invocation context and per-check pass/fail; do not record PTY payload.
To stop and remove registration after the experiment:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.lomi.e0.pty-probe.plist
```

The operator then removes the experiment plist, executable copy and synthetic
result directory. Never remove workspace directories or an existing Lomi profile.
A successful one-shot LaunchDaemon run proves this fixture can run under launchd
in that account/context; it still does not prove a long-lived host survives
logout. That needs a separate persistent-owner harness and live-client test.

## Linux: not_run; native harness required

The current `pty-probe` explicitly exits with status 2 outside macOS. Running it
under systemd does not turn that refusal into qualification. First port and
review the synthetic fixture for the exact Linux target. Then use a dedicated
non-root test account and an independently reviewed `Type=oneshot` system unit
with an absolute `ExecStart` pointing to the qualified experiment binary. The
manual invocation after the operator installs that unit is:

```sh
sudo systemctl start lomi-e0-pty-probe.service
sudo systemctl show lomi-e0-pty-probe.service -p Result -p ExecMainStatus
```

Do not enable or install a unit as part of this spike. A later boot check requires
explicit operator registration, reboot before user login, result inspection and
cleanup. A user service with linger is a separate case: record whether linger is
enabled and test logout independently. Neither Linux case has been run here.

## Windows: not_run; SCM adapter and ConPTY fixture required

On a Windows build, the current `pty-probe.exe` reports `not_run` and exits 2:

```powershell
& .\target\debug\pty-probe.exe
$LASTEXITCODE
```

A console executable cannot be registered as a functioning SCM service by
pointing `sc.exe create` at it. This project currently has no service entrypoint
for this fixture; do not register this binary with SCM. The required deliverable
is a reviewed SCM adapter that enters the same synthetic harness from
`ServiceMain`, reports status, handles STOP, and cleans its ConPTY/process tree
in a Job Object. Its installation path and service-account SID must be fixed in
the reviewed native adapter before registration.

Once that adapter exists and an operator has explicitly registered the dedicated
`LomiRemoteE0Probe` service, the precise manual execution/inspection sequence is:

```powershell
sc.exe start LomiRemoteE0Probe
sc.exe queryex LomiRemoteE0Probe
sc.exe stop LomiRemoteE0Probe
sc.exe queryex LomiRemoteE0Probe
```

Do not infer boot support from manual start. A later explicit auto-start test
must reboot without interactive login and verify the same fixture under the
service identity, including child-tree cleanup and blocked remote execution when
storage is unavailable. DPAPI must be tested in that exact account's user scope;
no credential is created by this harness, and no DPAPI result is claimed.

## Evidence record

Record every unexecuted check as `not_run`, with the missing harness or machine.
Restarting a future owner must report the old session lost and must not replay
input or commands. The current finite harness does not implement session restore.

| Check | Current qualification |
| --- | --- |
| Interactive macOS native PTY smoke | Inspect actual probe run; limited to synthetic fixture |
| macOS LaunchDaemon/manual service invocation | not_run |
| macOS pre-login boot | not_run |
| macOS logout with persistent owner | not_run; persistent fixture missing |
| macOS locked keychain / explicit secret backend | not_run; no credentials in fixture |
| Linux systemd/system boot/user linger | not_run; native harness missing |
| Windows SCM/ConPTY/boot/DPAPI | not_run; native adapter missing |
| Production host/service capability | unqualified |
