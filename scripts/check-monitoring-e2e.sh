#!/usr/bin/env bash
# Disposable cluster: never uses or modifies the caller's kubeconfig/context.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PGROLES_TELEMETRY_SMOKE_BIN="${PGROLES_TELEMETRY_SMOKE_BIN:-$repo_root/target/debug/examples/telemetry-smoke}"
if [[ ! -x "$PGROLES_TELEMETRY_SMOKE_BIN" ]]; then
  echo "Build first: SQLX_OFFLINE=true cargo build -p pgroles-operator --example telemetry-smoke" >&2
  exit 1
fi
tmpdir="$(mktemp -d)"
cluster="pgroles-monitoring-$(date +%s)-$$"
export KUBECONFIG="$tmpdir/kubeconfig"
kubectl() { command kubectl --request-timeout=30s "$@"; }
cleanup() {
  if [[ "${success:-0}" != 1 ]]; then
    kubectl -n pgroles-monitoring get pods || true
    kubectl -n pgroles-monitoring logs deployment/pgroles-policy-state || true
    kubectl -n pgroles-monitoring logs deployment/pgroles-collector || true
  fi
  kind delete cluster --name "$cluster"
  rm -rf "$tmpdir"
}
trap cleanup EXIT
kind create cluster --name "$cluster" --image kindest/node:v1.32.2 --wait 120s
kubectl apply -f "$repo_root/k8s/crd.yaml"
kubectl wait --for=condition=Established crd/postgrespolicies.pgroles.io --timeout=60s
kubectl apply -k "$repo_root/examples/monitoring"
kubectl -n pgroles-monitoring rollout status deployment/pgroles-policy-state --timeout=180s
kubectl -n pgroles-monitoring rollout status deployment/pgroles-collector --timeout=180s
python3 "$repo_root/examples/monitoring/test-extraction.py"
success=1
