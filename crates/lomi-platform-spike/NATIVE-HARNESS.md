# Native service qualification harness

Status: instructions prepared; **no service registration or boot test run**.
Use a disposable native macOS test machine or VM snapshot. This probe creates
only synthetic shell/temp-directory data. Keep service artifacts separate from
user profiles and do not feed it real credentials or repository paths.

## macOS launchd one-shot PTY smoke check

1. Build `cargo build -p lomi-platform-spike --bin pty-probe --release` on the
   native target. Record the commit, `sw_vers`, `uname -m`, `rustc --version` and
   the binary digest. Install the binary at an absolute test-only location.
2. Create an owned plist with the following content, replacing all three
   `/ABSOLUTE/...` paths. Use writable private log paths for the service user.

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>dev.lomi.platform-spike</string>
  <key>ProgramArguments</key><array><string>/ABSOLUTE/pty-probe</string></array>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>/ABSOLUTE/probe.stdout</string>
  <key>StandardErrorPath</key><string>/ABSOLUTE/probe.stderr</string>
</dict></plist>
```

3. For a user LaunchAgent smoke check, on that disposable test machine:

```sh
plutil -lint /ABSOLUTE/probe.plist
launchctl bootstrap gui/$(id -u) /ABSOLUTE/probe.plist
launchctl print gui/$(id -u)/dev.lomi.platform-spike
launchctl bootout gui/$(id -u)/dev.lomi.platform-spike
```

   Save stdout/stderr and launchctl's final exit code. This binary is one-shot;
   `last exit code = 0` plus all four `passed` lines prove only this synthetic PTY
   smoke run in the chosen domain. Its final `not_run` line is intentionally
   retained: service qualification requires the operator's separate evidence.

4. For a LaunchDaemon smoke run, an operator must install a root-owned plist in
   the test machine's LaunchDaemons directory, with an explicit unprivileged
   `UserName` and private writable log paths, then use `launchctl bootstrap
   system /ABSOLUTE/probe.plist`. Do not run the fixture shell as root. Collect
   evidence both before login and after reboot, and remove the plist and service
   with `launchctl bootout system/dev.lomi.platform-spike` when finished.

Neither one-shot check demonstrates continued PTY lifetime across logout or
restart, secret storage behavior, crashed-host recovery, or forceful process-tree
cleanup. Those need a persistent owner plus a real IPC client and independent
service/OS lifecycle observations. Do not mark E0.2 verified from this fixture.

## Linux systemd + linger

Not runnable by this macOS shell/Unix-socket fixture: it deliberately reports
`not_run` and exits 2 outside macOS. Implement the equivalent Linux fixture in a
native runner first, including the actual systemd user unit and persistent IPC
owner. Then collect baseline spawn/output/CWD/resize/Ctrl-C/process-tree results,
detach the IPC client, close SSH, log out, and reboot under enabled user linger.
Record the unit's actual service user, environment, restart/stop distinction,
process-group cleanup, journal and locked/unavailable secret-store results.
A process launched from an interactive shell does not qualify systemd boot.

## Windows SCM / ConPTY

Not runnable by this fixture. Implement a Windows-native ServiceMain/SCM harness
and ConPTY shell fixture with explicit service account, IPC authorization and
process-tree job lifetime. Register that native harness on a disposable Windows
VM; an ordinary console executable registered with `sc.exe` is not an SCM
implementation. Repeat spawn/CWD/resize/Ctrl-C/exit/tree cleanup, client detach,
stop/crash/restart, locked DPAPI storage and reboot with no login session. Keep
ConPTY/session/security failures as `failed` or `not_run`; a PowerShell console
run cannot substitute for the SCM evidence.
