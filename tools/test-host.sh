#!/bin/sh
# Run Rust tests the way the private-profile fixtures expect.
#
# Many fixtures create profile directories with tempfile::tempdir(), which uses
# the process umask. The platform layer requires profile directories to be
# exactly 0700 and the IPC socket path to stay under 100 bytes, so a default
# umask (022) or a long macOS $TMPDIR produces INVALID_PROFILE failures that are
# unrelated to the code under test.
#
# Usage: tools/test-host.sh [cargo test arguments...]
#   tools/test-host.sh -p lomi-host
#   tools/test-host.sh -p lomi-host --lib real_tls_noise_terminal_lifecycle
set -eu
cd "$(dirname "$0")/.."
umask 077
base="${LOMI_TEST_TMP:-/tmp/lr-$(id -u)}"
mkdir -p "$base"
chmod 700 "$base"
TMPDIR="$base/"
export TMPDIR
# The real TLS/Noise/PTY fixtures busy-wait cooperatively; oversubscribing the
# CPU starves them into spurious timeouts. Keep the test threads modest.
# On Linux the PTY supervisor tests also share process-global SIGCHLD/child state,
# so parallel real-PTY fixtures interfere (a stale owner snapshot); run serially.
if [ "$(uname -s)" = "Linux" ]; then
  RUST_TEST_THREADS="${RUST_TEST_THREADS:-1}"
else
  RUST_TEST_THREADS="${RUST_TEST_THREADS:-4}"
fi
export RUST_TEST_THREADS
# Set LOMI_ONLINE=1 on machines without a pre-populated cargo registry.
if [ -n "${LOMI_ONLINE:-}" ]; then
  exec cargo test --locked "$@"
fi
exec cargo test --offline --locked "$@"
