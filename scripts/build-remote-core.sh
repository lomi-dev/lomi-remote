#!/bin/bash
# Builds lomi-remote-core for desktop, WASM, iOS and Android; prints artifact sizes.
# Android needs an NDK (ANDROID_NDK_HOME or $ANDROID_HOME/ndk/<ver>); skipped if absent unless REQUIRE_ANDROID=1.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
OUT="${OUT:-$ROOT/target/remote-core-dist}"
rm -rf "$OUT"; mkdir -p "$OUT"
size() { printf '%-60s %8d bytes\n' "$1" "$(wc -c < "$1")"; }

echo "== desktop"
cargo build --locked --release -p lomi-remote-core
size target/release/liblomi_remote_core.a

echo "== wasm"
cargo rustc --locked --release -p lomi-remote-core --lib --target wasm32-unknown-unknown --features browser --crate-type cdylib
wasm-bindgen target/wasm32-unknown-unknown/release/lomi_remote_core.wasm --target web --out-dir "$OUT/wasm" --out-name remote_core
W="$OUT/wasm/remote_core_bg.wasm"
size "$W"
gzip -9 -c "$W" > "$W.gz"; size "$W.gz"
brotli -q 11 -c "$W" > "$W.br"; size "$W.br"

echo "== ios"
export IPHONEOS_DEPLOYMENT_TARGET=16.4
for t in aarch64-apple-ios aarch64-apple-ios-sim; do
  cargo build --locked --release -p lomi-remote-core --target "$t"
  size "target/$t/release/liblomi_remote_core.a"
done
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/liblomi_remote_core.a \
  -library target/aarch64-apple-ios-sim/release/liblomi_remote_core.a \
  -output "$OUT/LomiRemoteCore.xcframework" >/dev/null
echo "$OUT/LomiRemoteCore.xcframework"

echo "== android"
NDK="${ANDROID_NDK_HOME:-}"
[ -n "$NDK" ] || NDK="$(ls -d "${ANDROID_HOME:-$HOME/Library/Android/sdk}"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
BIN="$NDK/toolchains/llvm/prebuilt/darwin-x86_64/bin"
[ "$(uname -s)" != Linux ] || BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
if [ ! -x "$BIN/aarch64-linux-android24-clang" ]; then
  echo "Android NDK not found (set ANDROID_NDK_HOME); compiling staticlib only, no .so link" >&2
  [ "${REQUIRE_ANDROID:-0}" != 1 ] || exit 1
  for t in aarch64-linux-android x86_64-linux-android; do
    rustup target add "$t"
    cargo rustc --locked --release -p lomi-remote-core --lib --target "$t" --crate-type staticlib
    size "target/$t/release/liblomi_remote_core.a"
  done
  exit 0
fi
for t in aarch64-linux-android x86_64-linux-android; do
  rustup target add "$t"
  u="$(echo "$t" | tr '[:lower:]-' '[:upper:]_')"
  env "CARGO_TARGET_${u}_LINKER=$BIN/${t}24-clang" "CC_${t//-/_}=$BIN/${t}24-clang" "AR_${t//-/_}=$BIN/llvm-ar" \
    RUSTFLAGS='-C link-arg=-Wl,-z,max-page-size=16384' \
    cargo build --locked --release -p lomi-remote-core --target "$t"
  size "target/$t/release/liblomi_remote_core.so"
done
