# macOS signing and notarization

Lomi Remote uses the existing Developer ID Application identity for Team ID
`C9JMAQ7GG3` and the Keychain profile `lomi-remote-notarization`. Public defaults
live in `macos-signing.json`; no password, private key, or exported certificate
belongs in that file or GitHub variables.

## Check this Mac

```sh
python3 release/macos_signing.py check
```

The check resolves an available Developer ID identity, confirms its Team ID,
and checks the notarization profile before any compilation starts. It rejects
an ambiguous certificate name; use a full certificate fingerprint to select
one exact identity. The checked-in fingerprint selects the current Remote
certificate from the two certificates installed for the same team.

Xcode account selection and `notarytool` profiles are separate. A profile is a
local Keychain item holding credentials. A missing-profile error means that
item is unavailable in the selected Keychain. An authentication error means
the stored credentials need attention.

To create or replace the profile, run this in your own terminal:

```sh
xcrun notarytool store-credentials "lomi-remote-notarization" \
  --team-id C9JMAQ7GG3
```

Enter the Apple ID belonging to that team and its app-specific password at
the interactive prompts. The normal Apple account password is not used.
The command validates the credentials before saving them. Do not paste the
password into chat, source, command-line arguments, or workflow variables.

If the profile and identity are in another Keychain, use `--keychain` when
creating the profile and set `LOMI_MACOS_KEYCHAIN` to that Keychain's absolute
path for checks and builds. It must be unlocked for the runner account.

## Build the signed release

Run the existing release builder on the native target Mac. Its macOS signing
options now inherit the public defaults, so repeating them is unnecessary:

```sh
python3 release/build_release.py \
  --platform macos-aarch64 \
  --release-origin https://YOUR_RELEASE_ORIGIN/lomi/ \
  --target-name macos/aarch64/lomiremote \
  --minimum-profile-schema MINIMUM_SUPPORTED_SCHEMA \
  --public-root /offline/release-root.json \
  --public-root-sha256 INDEPENDENTLY_RECORDED_ROOT_SHA256 \
  --output /reviewed/macos-aarch64
```

The origin, schema, root file and digest above are placeholders. The existing
public Host origin/client pins and a clean committed source tree are still
required; see [release build inputs](README.md#release-build-inputs). An Intel
release uses `macos-x86_64` and its matching target on an Intel release runner.

The builder checks signing credentials first, signs the CLI, updater and shell
installer with the hardened runtime and a secure timestamp, and verifies their
signatures and Team IDs. It temporarily enables owner write access when signing
read-only files and restores their original permissions. `ditto` preserves the
shell installer's extended-attribute signature in the ZIP.

Notarization waits for Apple's response and requires an explicit `Accepted`
status and a submission identifier. A successful tool exit alone is not enough.
The adjacent `.notarization.json` receipt records the exact archive SHA-256,
submission ID and status. Rejections retain diagnostic evidence and fail the
build; a timeout also fails and must be investigated before resubmitting.
The installation entry is produced only after accepted notarization.

An exclusive `.notarization.pending` record prevents overlapping submissions
of the same archive. An interrupted command retains that record if its final
receipt could not be saved; inspect Apple's submission history before removing
it and trying again. Failed CI jobs retain the receipt and diagnostic log.

This distribution contains standalone executables and a shell installer in a
ZIP. It does not claim an offline stapled ticket: `stapler` does not support
stapling a ZIP or a standalone executable. Apple registers the notarized code
for online checks. See [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

Apple notarization and the TUF update signatures are separate. This command
does not generate a TUF root, sign update metadata, approve a complete release,
or publish installation assets.

## GitHub Actions

The manual release workflow runs the same signing preflight and builder. Its
macOS runner must have the identity/private key and profile in its own unlocked
Keychain; a profile on a developer laptop is not automatically copied to a
GitHub-hosted Mac.

The public repository variables are:

| Variable | Purpose |
| --- | --- |
| `LOMI_MACOS_SIGNING_IDENTITY` | Exact Developer ID certificate fingerprint |
| `LOMI_MACOS_TEAM_ID` | `C9JMAQ7GG3` |
| `LOMI_MACOS_NOTARY_PROFILE` | `lomi-remote-notarization` |
| `LOMI_MACOS_KEYCHAIN` | Optional absolute Keychain path on the runner |

An existing `LOMI_MACOS_SIGNING_IDENTITY` secret remains a fallback for older
runner configurations. Workflow arguments override the environment and public
defaults. The release runner also needs the existing `self-hosted`,
`lomi-release` and platform labels, public TUF-root file, release-set manifest
and compile-time Host pins documented in the main release guide.

## Verification without building a release

To check the available certificate while notarization credentials are being
configured, run `python3 release/macos_signing.py check --signing-only`.
The `sign FILE` and `notarize ARCHIVE` commands support testing on a copied
artifact; they do not turn an arbitrary local build into a release-ready bundle.

Run the focused regression suite with:

```sh
python3 -m unittest discover -s release -p 'test_macos_signing.py'
```
