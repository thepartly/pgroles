#!/usr/bin/env bash
set -euo pipefail

wasm_pack_bin="${WASM_PACK_BIN:-wasm-pack}"
# Honour a relocated Cargo target directory. A relative CARGO_TARGET_DIR is
# relative to the invocation directory (the repository root), so anchor it
# there before wasm-pack resolves --out-dir against the crate directory.
target_dir="${CARGO_TARGET_DIR:-target}"
case "$target_dir" in
  /*) ;;
  *) target_dir="$PWD/$target_dir" ;;
esac
parity_dir="$target_dir/wasm-parity"

cargo build -p pgroles-wasm --example analyze_fixture
"$wasm_pack_bin" build crates/pgroles-wasm \
  --target nodejs \
  --release \
  --out-dir "$parity_dir"
node crates/pgroles-wasm/tests/wasm_parity.mjs \
  "$target_dir/debug/examples/analyze_fixture" \
  "$parity_dir" \
  crates/pgroles-wasm/tests/fixtures
