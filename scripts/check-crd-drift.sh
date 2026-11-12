#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

cargo run --bin crdgen -- --output-dir "$tmpdir"

failed=0

check_drift() {
  local committed="$1"
  local generated="$2"

  if ! diff -u "$committed" "$generated" >/dev/null 2>&1; then
    echo "::error::${committed} is out of date. Regenerate with: cargo run --bin crdgen -- --output-dir charts/pgroles-operator/crds/"
    diff -u "$committed" "$generated" || true
    failed=1
  fi
}

for crd in "$tmpdir"/*.yaml; do
  name="$(basename "$crd")"
  check_drift "charts/pgroles-operator/crds/$name" "$crd"
done

# k8s/ copies
check_drift "k8s/crd.yaml" "$tmpdir/postgrespolicies.pgroles.io.yaml"
check_drift "k8s/postgrespolicyplan-crd.yaml" "$tmpdir/postgrespolicyplans.pgroles.io.yaml"
check_drift "k8s/postgrespolicycandidate-crd.yaml" "$tmpdir/postgrespolicycandidates.pgroles.io.yaml"
check_drift "k8s/ephemeralaccesspolicy-crd.yaml" "$tmpdir/ephemeralaccesspolicies.pgroles.io.yaml"
check_drift "k8s/ephemeralaccessrequest-crd.yaml" "$tmpdir/ephemeralaccessrequests.pgroles.io.yaml"
check_drift "k8s/postgresdatabase-crd.yaml" "$tmpdir/postgresdatabases.pgroles.io.yaml"

if [ "$failed" -ne 0 ]; then
  exit 1
fi
