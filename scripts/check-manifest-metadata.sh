#!/usr/bin/env bash
set -euo pipefail

metadata_file=docs/public/generated/manifest-metadata.json
review_schema_file=docs/public/generated/review-artifact.schema.json
types_file=crates/pgroles-wasm/policy-authoring.d.ts
temporary_metadata=$(mktemp)
temporary_review_schema=$(mktemp)
temporary_types=$(mktemp)
trap 'rm -f "$temporary_metadata" "$temporary_review_schema" "$temporary_types"' EXIT

RUSTC_WRAPPER= cargo run -q -p pgroles-core --example manifest_metadata > "$temporary_metadata"
RUSTC_WRAPPER= cargo run -q -p pgroles-core --example review_artifact_schema > "$temporary_review_schema"
node docs/scripts/generate-manifest-types.mjs "$temporary_metadata" "$temporary_types"
status=0
diff -u "$metadata_file" "$temporary_metadata" || status=1
diff -u "$review_schema_file" "$temporary_review_schema" || status=1
diff -u "$types_file" "$temporary_types" || status=1
if [ "$status" -ne 0 ]; then
  echo "generated metadata is stale; run scripts/generate-manifest-metadata.sh" >&2
fi
exit "$status"
