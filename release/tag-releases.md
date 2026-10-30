# Tagged Host releases

The public source repository is https://github.com/lomi-dev/lomi-remote.
Pushing a stable `vX.Y.Z` tag starts `.github/workflows/release.yml`. The tag must
match `workspace.package.version` in `Cargo.toml`. The workflow builds the
configured platforms, verifies their bundles, signs TUF metadata and publishes
one complete GitHub Release. Failed builds leave the current release active.

## Publish a version

Update the workspace version, commit the change, then push the commit and tag:

```sh
git push origin main
git tag v0.1.0
git push origin v0.1.0
```

Use a new, increasing version for every published release. The example tag is
the first release; replace it with the version in Cargo.toml for later releases.
The workflow can also be dispatched manually for an existing tag. It refuses
to overwrite a published release. Linux x86_64 and ARM64 are always required.
macOS and Windows are included when their repository variables below are true.

## Install and update

Linux and macOS:

```sh
curl -fsSL https://lomi.dev/remote/install.sh | sh
```

Windows, after Windows signing is enabled:

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://lomi.dev/remote/install.ps1 | iex"
```

The installer selects the latest stable GitHub Release and the current OS/CPU.
An unsupported or unpublished platform fails with a clear message. Linux uses
an authenticated bootstrap; macOS uses Developer ID signatures and Apple
notarization; Windows requires Authenticode. All installed targets are checked
against the pinned TUF root and signed platform/schema policy.

macOS needs administrator access for its protected Host installation. The
installer prints the full path to the CLI if it is not on PATH. It does not
change shell profiles or run interactive account setup through piped stdin.

For an installed server, use that CLI path:

```sh
lomiremote update --check
lomiremote update --confirm
```

`--check --json` provides a machine-readable status and a nonzero exit code on
failure. To pin an update, use `update --version X.Y.Z --confirm`. The existing
maintenance path checks active sessions, waits its grace period, verifies
signed metadata, retains profile data and restarts the existing service mode.
Updates require an explicit command; no background update scheduler is added.

The installer shows a download progress bar in an interactive terminal and
plain stage messages in logs. Its completion line includes the verified
version and actual executable path. `NO_COLOR` disables completion colors.

### macOS service ownership recovery

Version 0.1.2 fixes protected install directories owned by `root:admin` and
uses the correct Security framework options for authenticating running peer
processes. The executable directory keeps its root ownership and permission
checks; custody state directories still require `root:wheel`.
If version 0.1.0 activated the program and then reported
`SERVICE_OWNERSHIP_CONFLICT`, rerun the public installation command for the same
account and Host mode. The updater verifies and reuses the initialized profile,
identity and trust state, then completes the missing service registration.

## Runners and signing

Linux uses GitHub-hosted Ubuntu 22.04 runners for both architectures. Its
bootstrap Ed25519 private key is the `LOMI_LINUX_BOOTSTRAP_KEY` repository secret.

macOS uses the self-hosted runner `woro-lomi-remote-release`, installed at
`~/Library/Application Support/LomiRemote/release-runner`. It runs as a login
LaunchAgent. The Mac must be online, logged in, and able to access the signing
key in its Keychain. Rosetta supports the Intel build on this Apple Silicon Mac.
Its working directory is `~/.local/share/lomi-remote-runner-work`; keep this
path free of spaces because GitHub's default Bash command does not quote its
temporary script path.
The LaunchAgent uses `SessionCreate=false` to inherit the GUI security session
that owns the Data Protection Keychain notarization profile. Reinstalling the
runner service restores its default plist; preserve this setting when doing so.
Public pull requests do not run the tag workflow. Repository write access can
run release code on this signing machine; restrict write access accordingly.

Public repository variables select the existing local Apple identity:

- `LOMI_MACOS_RELEASE_ENABLED=true`
- `LOMI_MACOS_TEAM_ID=C9JMAQ7GG3`
- `LOMI_MACOS_SIGNING_IDENTITY`: Developer ID fingerprint from macos-signing.json
- `LOMI_MACOS_NOTARY_PROFILE=lomi-remote-notarization`

Check the local setup with `python3 release/macos_signing.py check`. No Apple
private certificate or app-specific password is uploaded to GitHub.

### Remaining Windows step

`LOMI_WINDOWS_RELEASE_ENABLED=false` deliberately skips Windows builds. Obtain
a code-signing certificate and provision its private key in the release user's
Windows certificate store (`CurrentUser\My`). Hardware-backed certificates
need their vendor's signing provider available to `signtool`. The existing
builder signs the CLI, paired Host helper, updater and PowerShell installer,
timestamps them and verifies Authenticode before upload.

Provide native Windows x86_64 and ARM64 runners with the labels `self-hosted`,
`lomi-release`, and respectively `windows-x86_64` / `windows-aarch64`. Install
Rust, Bash, Windows SDK signing tools, OpenSSL 3, and the certificate/provider.
Set `LOMI_WINDOWS_SIGNER_THUMBPRINT` to its 40-hex thumbprint, then set
`LOMI_WINDOWS_RELEASE_ENABLED=true` and publish a new tag. Python 3.12 is
provisioned by the workflow. Until then, the public PowerShell command reports
that no Windows package is published; it does not install an unsigned binary.

## Trust keys and metadata refresh

The public trust root and index/bootstrap public keys are in `release/trust/`.
Private keys are outside Git, currently in
`~/Library/Application Support/LomiRemote/release-signing` (directory 0700,
files 0600). Back up this directory securely, especially `root.pem`.
The root private key is not uploaded to GitHub. Do not regenerate the public
root for an existing installation; use a properly signed TUF root rotation.

Online repository secrets are `LOMI_TUF_TARGETS_KEY`, `LOMI_TUF_SNAPSHOT_KEY`,
`LOMI_TUF_TIMESTAMP_KEY`, and `LOMI_RELEASE_INDEX_KEY`. Each has a separate
Ed25519 key. `refresh-release-metadata.yml` renews metadata daily without
rebuilding or changing the release binaries. The signed index and timestamp
expire after seven days; monitor workflow failures before they expire.

Metadata files have immutable names. Refresh uploads them before replacing the
signed recovery envelope, then the primary `release-index.json` envelope. Both
the gateway and refresh job can recover from the recovery copy if GitHub's
delete-before-upload replacement of the primary is interrupted. A recovering
refresh restores the primary before touching its sole valid recovery copy.
The detached
`.sig` is optional audit evidence. Old cached indexes keep referring to their
existing metadata.

## Stable download gateway

`release/gateway/worker.mjs` is deployed as `lomi-remote-release-gateway` on
Cloudflare. Its public bindings and exact routes are in `wrangler.jsonc`.
The gateway verifies the signed index with the pinned Ed25519 public key and
maps conventional metadata/target paths to GitHub Release assets. Small files
are fully hashed before delivery. Large files use Cloudflare's native
[FixedLengthStream](https://developers.cloudflare.com/workers/runtime-apis/streams/transformstream/)
to enforce the signed size and provide Content-Length with minimal Worker CPU
work; installers and TUF clients verify their hashes. GitHub asset redirects
are followed internally with a host allowlist.
The update client itself receives files directly from its pinned HTTPS origin.

Installed binaries use `https://lomi.dev/remote/releases/` to track latest.
Initial installers use `.../releases/vX.Y.Z/` so an in-flight install stays on
one version. Latest and explicit-tag indexes are rechecked after 60 seconds;
only unexpired, verified cached indexes can be used during an upstream outage.
Only the latest release receives scheduled metadata renewal. Old downloaded
installers can expire; download a fresh installer from the stable command.

No Coolify restart is needed when a tag is published. The routes only cover the
two installer scripts and `/remote/releases/*`; the website and cloud services
keep their existing deployments.

## Local verification

```sh
python3 -m unittest discover -s release -p 'test_*.py'
node --test release/gateway/worker.test.mjs release/bootstrap/render.test.mjs
python3 release/ci_build.py --tag v0.1.2 --check
```

These checks cover signing, archive integrity, version-pinned origins, gateway
verification and interrupted metadata promotion. Native build, notarization,
service activation and rollback still need their platform-specific validation.
