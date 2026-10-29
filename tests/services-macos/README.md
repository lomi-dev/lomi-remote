# macOS E0 synthetic native proof

This fixture qualifies a temporary **LaunchAgent in the current user domain**
and a temporary legacy file keychain on the tested Mac. It does not qualify a
LaunchDaemon, boot before login, reboot, FileVault, locking the user's login
keychain, or a production credential provider.

Build and validate from the repository root:

```sh
cargo build --locked -p lomi-service-fixture -p lomi-macos-storage-fixture
cargo test --locked -p lomi-service-fixture -p lomi-macos-storage-fixture
python3 -m unittest discover -s tests/services-macos -v
python3 tools/run_macos_service_fixture.py --run-native
```

Only the final command mutates native service/keychain state. It registers a
UUID label from a private temporary plist in `user/<uid>` with
`LimitLoadToSessionType=Background`, then removes exactly that label. No sudo,
LaunchDaemon installation, logout or reboot is used. The owner and storage
executables are copied to the owned private directory before execution so
concurrent Cargo builds cannot overwrite an executing fixture. PTY bytes stay
inside the existing synthetic Rust owner. Distinct native IPC client processes
exit while the owner survives. Checks cover resize, detach, Ctrl-C, explicit
exit, owner restart, lost sessions, rejected input and no input replay. A live
synthetic session is stopped through launchctl bootout to verify owned process
group cleanup. The driver never signals a numeric PID read from storage or IPC.

The storage executable requires an explicit private parent directory and an
existing default-keychain reference before creating anything. It disables
Keychain UI in its own process, creates a UUID private keychain and item, and
passes the explicit non-null keychain reference for every operation. Password
and synthetic secret are random RAM values, absent from argv, environment and
reports. It reads, locks, verifies the native lock bit, requires authentication
or interaction denial with no returned data, unlocks, verifies the unlock bit,
and reads the same secret. It deletes only its own keychain. Read-only default
and search-list snapshots must compare equal after creation and deletion.
There are no default-keychain or search-list setters. Secret buffers are wiped
before release. A partial/unverified native cleanup preserves the private
resources and marks the evidence failed.

`artifacts/services-macos/evidence.json` records the latest invocation, exact
commands, exit codes, versions, binary/source hashes and cleanup checks.
UUID-named reports preserve prior invocations, including failures. A fresh failed
report is persisted before private setup, and setup failures or interrupts remove
owned temporary files. IPC uses one absolute monotonic deadline for connect,
send and all receives; polling passes its remaining budget to each probe and
rejects replies completed after that deadline. Regression tests cover setup copy
errors, changed binary hashes, setup interruption and a real slow-drip socket. Native
bootout is asynchronous, so the driver polls only its exact service target
until launchctl print returns 113. It verifies owner PIDs and live child group
members have disappeared before removing its private directory.

Observed complete proof: macOS 27.0.1 (26A434), Darwin 27.0.0 arm64,
CommandLineTools header SDK 27.0, rustc 1.98.1 (48a229cea 2026-09-01),
Python 3.14.7. The locked read returned **-25293 (`errSecAuthFailed`)**.
This is an observed denial, not a claim that every macOS version returns the
same status. The only accepted denials are -25293 and -25308
(`errSecInteractionNotAllowed`); success, not-found and unrelated errors fail.

API semantics were checked against local SDK 27.0 Security.framework headers
`SecKeychain.h` and `SecBase.h` and Apple primary sources:

- [SecKeychainCreate](https://developer.apple.com/documentation/security/seckeychaincreate(_:_:_:_:_:_:)) explicitly describes private temporary application keychains and the no-prompt parameter.
- [SecKeychainFindGenericPassword](https://developer.apple.com/documentation/security/seckeychainfindgenericpassword(_:_:_:_:_:_:_:_:)) specifies explicit-keychain scoping, allocated password buffer ownership, and authentication failure when decryption is denied.
- [errSecAuthFailed](https://developer.apple.com/documentation/security/errsecauthfailed) documents authorization/authentication failure.
- [Apple Security StorageManager.cpp](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/StorageManager.cpp), `shouldAddToSearchList`, excludes private keychain creation from search-list changes; only login/System keychains qualify. The fixture never uses those names and verifies current runtime snapshots as well.
- [Apple keychain API index](https://developer.apple.com/documentation/security/keychains) documents explicit lock/unlock/delete and interaction controls. The file-keychain APIs are deprecated; this is deliberately a bounded E0 probe rather than a production backend decision.

Sources inspected on 2026-10-19. Apple source `main` is supporting design
information; native runtime checks and versioned local headers are the evidence
for this machine.
