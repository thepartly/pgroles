#!/usr/bin/env bash
set -euo pipefail

mkdir -p docs/public/generated crates/pgroles-wasm
RUSTC_WRAPPER= cargo run -q -p pgroles-core --example manifest_metadata \
  > docs/public/generated/manifest-metadata.json
RUSTC_WRAPPER= cargo run -q -p pgroles-core --example review_artifact_schema \
  > docs/public/generated/review-artifact.schema.json
node docs/scripts/generate-manifest-types.mjs \
  docs/public/generated/manifest-metadata.json \
  crates/pgroles-wasm/policy-authoring.d.ts
