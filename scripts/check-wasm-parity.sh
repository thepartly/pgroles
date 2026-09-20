#!/usr/bin/env bash
set -euo pipefail

wasm_pack_bin="${WASM_PACK_BIN:-wasm-pack}"
parity_dir="target/wasm-parity"

cargo build -p pgroles-wasm --example analyze_fixture
"$wasm_pack_bin" build crates/pgroles-wasm \
  --target nodejs \
  --release \
  --out-dir "../../$parity_dir"
node crates/pgroles-wasm/tests/wasm_parity.mjs \
  target/debug/examples/analyze_fixture \
  "$parity_dir" \
  crates/pgroles-wasm/tests/fixtures
