#!/bin/bash
# Runs the shared core vectors (crates/lomi-remote-core/test-vectors) in every compilation:
# native Rust, WASM (Node), iOS simulator (aarch64-apple-ios-sim) and an Android arm64 device or
# emulator (adb). Simulator/emulator steps are skipped when none is booted unless REQUIRE_DEVICES=1.
# IOS_SIM=<udid> picks the simulator (default: first booted); ANDROID_NDK_HOME as in build-remote-core.sh.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
skip() { echo "SKIPPED: $1" >&2; [ "${REQUIRE_DEVICES:-0}" != 1 ] || exit 1; }

echo "== native"
cargo test --locked -p lomi-remote-core

echo "== wasm"
node packages/remote-core-wasm/scripts/build.mjs --check
node --test packages/remote-core-wasm/test/vectors.test.mjs

echo "== ios simulator"
SIM="${IOS_SIM:-$(xcrun simctl list devices booted | grep -o '[0-9A-F]\{8\}-[0-9A-F-]\{27\}' | head -1 || true)}"
if [ -n "$SIM" ]; then
  IPHONEOS_DEPLOYMENT_TARGET=16.4 CARGO_TARGET_AARCH64_APPLE_IOS_SIM_RUNNER="xcrun simctl spawn $SIM" \
    cargo test --locked -p lomi-remote-core --target aarch64-apple-ios-sim --test shared_vectors
else skip "no booted iOS simulator (xcrun simctl boot <udid>)"; fi

echo "== android arm64"
ADB="${ANDROID_HOME:-$HOME/Library/Android/sdk}/platform-tools/adb"
if [ -x "$ADB" ] && [ "$("$ADB" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')" = arm64-v8a ]; then
  NDK="${ANDROID_NDK_HOME:-${ANDROID_HOME:-$HOME/Library/Android/sdk}/ndk/27.1.12297006}"
  BIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
  [ "$(uname -s)" != Linux ] || BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
  t=aarch64-linux-android
  EXE="$(env CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER="$BIN/${t}24-clang" CC_aarch64_linux_android="$BIN/${t}24-clang" \
    AR_aarch64_linux_android="$BIN/llvm-ar" cargo test --locked -p lomi-remote-core --target "$t" --test shared_vectors --no-run 2>&1 \
    | tee /dev/stderr | sed -n 's/.*Executable .*(\(.*\))/\1/p')"
  "$ADB" push "$EXE" /data/local/tmp/shared_vectors >/dev/null
  "$ADB" shell chmod +x /data/local/tmp/shared_vectors
  "$ADB" shell /data/local/tmp/shared_vectors
else skip "no arm64 Android device/emulator on adb"; fi
