Run `python3 tests/product-keychain-macos/run_native.py` on macOS with the
installed Xcode macOS 26.5 SDK. The harness freezes explicit source, manifest,
lockfile and ABI header hashes before compilation, records commands and exits,
retains read-only copies of those exact inputs and verifies originals before,
across copying, and after compilation/native execution. Compilation uses the
shared workspace originals, rather than the retained audit copies. The fixture
binary is also hashed before and after native execution. It uses the shared
target directory, two jobs, no incremental cache, and no debug information.

The native fixture creates a UUID custom file Keychain and private profiles
under its newly owned private directory. Its random Keychain password, static
encryption keys and random synthetic bundle remain in memory or anonymous helper
pipes. It reads only default/search-list configuration for before/after equality;
it never reads production Keychain secrets or sets default/search-list values.
It deletes only its own item/Keychain and profiles. Failures preserve evidence
and any incompletely cleaned owned resources for inspection.

The product provider uses the same installed executable's private helper route
for each Keychain operation. Each fresh helper disables process-local legacy
Security UI before any other Security call. The parent fixture unlocks its own
Keychain with the RAM-only random password; this tests visibility in the same
Security session, not cross-session access. The native checks cover empty and
maximum-sized bundles, replacement/reopen, exclusive provider locking, profile
binding, lock denial and unlock recovery, ciphertext tampering, malformed and
missing keys without automatic regeneration, and ciphertext preservation.
The profile-binding check installs the same original 32-byte key into a second
owned test account and requires authentication failure for the copied ciphertext
under that second profile. A separate check substitutes a valid but different
32-byte key in the original account, requires authentication failure for both
read and replacement with unchanged ciphertext, then restores the original key
and confirms a successful read. Key copies stay in wiping RAM-only buffers.
Targeted filesystem fault tests cover failure before rename, uncertainty after
rename, and replaced profile/lock objects. File fsync, atomic rename and directory
fsync establish process-crash discipline; no unconditional power-loss durability
is claimed. There is no login-Keychain, signing upgrade, launch-agent, reboot or
power-loss qualification here.
