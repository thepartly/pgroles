#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT
python3 "$repo_root/examples/monitoring/test-rules.py" "$tmpdir"
# Docker keeps the PromQL evaluator version consistent locally and in CI.
docker run --rm --entrypoint promtool \
  -v "$repo_root/examples/monitoring:/reference:ro" \
  prom/prometheus:v3.2.1 check rules /reference/rules.yaml /reference/expected.yaml
docker run --rm --entrypoint promtool -v "$tmpdir:/tests:ro" -w /tests \
  prom/prometheus:v3.2.1 test rules tests.yaml
