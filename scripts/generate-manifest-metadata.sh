#!/usr/bin/env bash
set -euo pipefail

mkdir -p docs/public/generated crates/pgroles-wasm
RUSTC_WRAPPER= cargo run -q -p pgroles-core --example manifest_metadata \
  > docs/public/generated/manifest-metadata.json
node docs/scripts/generate-manifest-types.mjs \
  docs/public/generated/manifest-metadata.json \
  crates/pgroles-wasm/policy-authoring.d.ts
