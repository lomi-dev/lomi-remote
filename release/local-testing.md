# Local installer testing

Run these commands from the `lomi-remote` checkout. This builds the same
release bundles and generated `curl | sh` installer locally. It does not
create a GitHub tag, run Actions or publish a release.

The local repository uses separate TUF signing keys, an HTTPS CA embedded
only in the explicit `local-release-test` build, and a loopback HTTPS server.
TLS, archive hashes, Linux bootstrap signatures, TUF verification, macOS
Developer ID signatures and Apple notarization remain enabled. Production
publication rejects local TLS builds. Private production signing material
is never copied to Linux; macOS still uses its existing Keychain identity.

## First setup

Python 3.11+, the repository Rust toolchain, Node for local catalog rendering,
OpenSSL 3 and the configured macOS signing/notarization identity are required
on the Mac. The Linux build host needs Python 3.11+, Rust, GCC, make, CMake,
pkg-config and OpenSSL development files. Linux installation also needs curl,
OpenSSL 3 and unzip. SSH authentication stays with OpenSSH; no passwords are
stored by the tooling.
SSH connections reuse a private OpenSSH control socket for ten minutes of
idle time, so a build does not repeatedly ask for the same account password.

```sh
python3 release/local_release.py init
```

State and test keys are private under `~/.local/share/lomi-remote-local`.
Initialization refuses to replace existing trust material. Keep this state
for subsequent builds and test updates.

Use a separate ordinary macOS account for the system Host and custodian.
Create it once in your own terminal; the password is entered interactively:

```sh
sudo sysadminctl -addUser lomi-remote-test \
  -fullName "Lomi Remote Test" \
  -home /Users/lomi-remote-test -shell /bin/zsh -password -
```

## Build and assemble

```sh
python3 release/local_release.py build --platform macos-aarch64
python3 release/local_release.py build --platform linux-x86_64 \
  --ssh test-user@192.168.1.192
python3 release/local_release.py assemble
```

The build captures the tracked working tree, including staged new files and
unstaged edits, in a private clean Git snapshot. Untracked files are excluded;
use `git add PATH` for a new source file that should be tested. No commit or
tag is required in your original checkout. Completed identical bundles are
reused. Cargo caches persist locally and on Linux. Set `CARGO_TARGET_DIR` to
an existing local cache when building macOS if desired.

`assemble` requires both completed bundles for the same snapshot and version.
Each source snapshot gets immutable artifact URLs. Promotion changes the
local latest pointer and retains older pinned artifacts.
Use `assemble --stage-only` to prepare a candidate without changing the
local latest version, for example while checking an older installation.
Run `assemble --snapshot ID` afterward to promote the verified candidate.

The build prints its snapshot ID. To repeat a captured build after editing
the working tree, pass `--snapshot ID` to both `build` and `assemble`.

## Start the local endpoint

In one terminal, keep this running:

```sh
python3 release/local_release.py serve --ssh test-user@192.168.1.192
```

It serves `https://127.0.0.1:18443/remote/` on the Mac. A reverse SSH tunnel
provides the same loopback address on Linux. The endpoint is not exposed to
the LAN or public internet. Both the server and tunnel stop with Ctrl-C.
The Linux test account's user services require an active login session unless
an administrator has separately enabled lingering.

## Run the actual installer

In a second Mac terminal:

```sh
python3 release/local_release.py install --account lomi-remote-test
```

This executes the generated `curl -fsSL ... | sh` pipeline with the local
HTTPS CA and explicit test account. macOS requests local administrator
authorization for its protected installation and services. The ordinary
`woro` installation and its profile are separate from the selected test UID.

To run the same pipeline on Linux from the Mac:

```sh
python3 release/local_release.py install --ssh test-user@192.168.1.192
```

Linux uses isolated locations under the test user's home:
`~/.local/share/lomi-remote-local-test/profile` and
`~/.local/lib/lomi-remote-local-test`.

A fresh Linux install prints the explicit `setup` command and does not start
or enroll a Host automatically. For a headless lifecycle test without account
enrollment or sharing, initialize the test profile and select its user service:

```sh
ssh test-user@192.168.1.192 'set -e
binary="$HOME/.local/lib/lomi-remote-local-test/lomiremote"
profile="$HOME/.local/share/lomi-remote-local-test/profile"
"$binary" --profile-dir "$profile" daemon start
"$binary" --profile-dir "$profile" daemon stop --confirm
"$binary" --profile-dir "$profile" service install --mode login --account test-user
"$binary" --profile-dir "$profile" service start'
```

Run the install command a second time to test maintenance of an existing
running installation, including service stop/start and retained profile data.
For a version upgrade, pass the same `--version X.Y.Z` to both build commands
and `assemble`. The override changes only the private snapshot. Installed
local builds use this local endpoint for `update --check` and updates; keep
`serve` running when exercising them. A local metadata `releaseUrl` follows
the production schema and is not evidence of a published GitHub release.

The equivalent macOS pipeline is:

```sh
export CURL_CA_BUNDLE="$HOME/.local/share/lomi-remote-local/tls/local-test-ca.pem"
export LOMI_REMOTE_ACCOUNT=lomi-remote-test
curl -fsSL https://127.0.0.1:18443/remote/install.sh | sh
```

Use the production command without these test environment variables for a
normal installation. Local development trust is separate; it is not a route
for replacing an existing production installation's trust state.
