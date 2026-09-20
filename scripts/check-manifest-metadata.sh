#!/usr/bin/env bash
set -euo pipefail

metadata_file=docs/public/generated/manifest-metadata.json
types_file=crates/pgroles-wasm/policy-authoring.d.ts
temporary_metadata=$(mktemp)
temporary_types=$(mktemp)
trap 'rm -f "$temporary_metadata" "$temporary_types"' EXIT

RUSTC_WRAPPER= cargo run -q -p pgroles-core --example manifest_metadata > "$temporary_metadata"
node docs/scripts/generate-manifest-types.mjs "$temporary_metadata" "$temporary_types"
diff -u "$metadata_file" "$temporary_metadata"
diff -u "$types_file" "$temporary_types"
