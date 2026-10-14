#!/usr/bin/env bash
# Requires the disposable plan-lifecycle E2E fixture.
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
if [ -n "${PGROLES_TEST_PG_CONTAINER:-}" ]; then
  pg_query() { docker exec "$PGROLES_TEST_PG_CONTAINER" psql -U postgres -d pgroles_test -tAc "$1"; }
fi
# Later scripts share this fixture, so a failed assertion must not leave the
# policy reconciling or the roles behind.
cleanup() {
  kubectl delete pgr plan-authority-policy --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl delete secret plan-authority-credentials --ignore-not-found >/dev/null 2>&1 || true
  pg_query 'DROP ROLE IF EXISTS pln_member; DROP ROLE IF EXISTS pln_executor; DROP ROLE IF EXISTS pln_grantor; DROP ROLE IF EXISTS pln_group;' >/dev/null 2>&1 || true
}
trap cleanup EXIT

pg_query "CREATE ROLE pln_group; CREATE ROLE pln_member; CREATE ROLE pln_grantor;
  CREATE ROLE pln_executor LOGIN PASSWORD 'pln-test-password';
  GRANT pln_group TO pln_grantor WITH ADMIN TRUE;
  GRANT pln_group TO pln_member WITH INHERIT FALSE, SET FALSE GRANTED BY pln_grantor;"
python3 - <<'PY_SECRET' | kubectl apply -f -
import base64, json, subprocess
from urllib.parse import urlsplit, urlunsplit
secret = json.loads(subprocess.check_output(["kubectl", "get", "secret", "postgres-credentials", "-o", "json"]))
url = urlsplit(base64.b64decode(secret["data"]["DATABASE_URL"]).decode())
value = urlunsplit((url.scheme, "pln_executor:pln-test-password@" + url.netloc.rsplit("@", 1)[-1], url.path, url.query, url.fragment))
print(json.dumps({"apiVersion":"v1", "kind":"Secret", "metadata":{"name":"plan-authority-credentials"}, "stringData":{"DATABASE_URL":value}}))
PY_SECRET
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: plan-authority-policy}
spec:
  connection: {secretRef: {name: plan-authority-credentials}}
  interval: 2s
  mode: apply
  approval: auto
  roles:
    - {name: pln_group, external: true}
    - {name: pln_member, external: true}
    - {name: pln_grantor, external: true}
  memberships:
    - role: pln_group
      exclusive: true
      members:
        - {name: pln_grantor, admin: true}
        - {name: pln_member, inherit: false}
YAML
wait_for_ready_status_reason plan-authority-policy True Reconciled
kubectl patch pgr plan-authority-policy --type=json -p='[{"op":"remove","path":"/spec/memberships/0/members/1"}]'
wait_for_ready_status_reason plan-authority-policy False ExecutorAuthority
plan="$(wait_for_current_plan_ref plan-authority-policy)"
wait_for_plan_phase "$plan" Pending
[[ "$(get_plan_sql "$plan")" == *'REVOKE "pln_group" FROM "pln_member" GRANTED BY "pln_grantor";'* ]]
test "$(pg_query "SELECT pg_has_role('pln_member','pln_group','MEMBER');")" = t
# Failure status must stay coherent during scheduled retries. Do not assert
# that every resourceVersion is fixed: other legitimate writers may update it.
failure_status() {
  kubectl get pgr plan-authority-policy -o json | python3 -c 'import json,sys; s=json.load(sys.stdin)["status"]; s.pop("lastHandledReconcileAt",None); s.pop("last_handled_reconcile_at",None); print(json.dumps(s,sort_keys=True))'
}
initial_failure="$(failure_status)"
sleep 6
test "$(failure_status)" = "$initial_failure"
for pass in 1 2 3; do
  kubectl annotate pgr plan-authority-policy reconcile.pgroles.io/requestedAt="pending-$pass-$(date +%s)" --overwrite
  sleep 3
  test "$(wait_for_current_plan_ref plan-authority-policy)" = "$plan"
  test "$(kubectl get pgplan "$plan" -o jsonpath='{.status.phase}')" = Pending
done
test "$(kubectl get pgplan -l pgroles.io/policy=plan-authority-policy -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')" = 1
approve_plan "$plan"
# Emulate an Approved artifact retained from the older controller.
kubectl patch pgplan "$plan" --subresource=status --type=merge -p='{"status":{"phase":"Approved"}}'
for pass in 1 2 3; do
  kubectl annotate pgr plan-authority-policy reconcile.pgroles.io/requestedAt="approved-$pass-$(date +%s)" --overwrite
  sleep 3
  test "$(wait_for_current_plan_ref plan-authority-policy)" = "$plan"
  test "$(kubectl get pgplan "$plan" -o jsonpath='{.status.phase}')" = Approved
done
test "$(kubectl get pgplan -l pgroles.io/policy=plan-authority-policy -o json | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')" = 1
test "$(pg_query "SELECT pg_has_role('pln_member','pln_group','MEMBER');")" = t
pg_query 'GRANT pln_grantor TO pln_executor WITH INHERIT TRUE, SET FALSE;'
wait_for_ready_status_reason plan-authority-policy True Reconciled
wait_for_plan_phase "$plan" Applied
test "$(pg_query "SELECT pg_has_role('pln_member','pln_group','MEMBER');")" = f
echo 'Blocked Pending/Approved plan deduplication and ordinary-executor recovery passed.'
