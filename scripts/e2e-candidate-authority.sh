#!/usr/bin/env bash
# Runs only against the disposable plan-lifecycle E2E fixture.
set -euo pipefail
source "$(dirname "$0")/e2e-helpers.sh"
if [ -n "${PGROLES_TEST_PG_CONTAINER:-}" ]; then
  pg_query() { docker exec "$PGROLES_TEST_PG_CONTAINER" psql -U postgres -d pgroles_test -tAc "$1"; }
fi
review_sql() {
  local name="$1"
  for attempt in 1 2 3 4 5; do
    if value="$(get_plan_sql "$name")"; then printf '%s' "$value"; return 0; fi
    sleep 2
  done
  return 1
}
pg_query "CREATE ROLE cau_group; CREATE ROLE cau_member; CREATE ROLE cau_grantor;
  CREATE ROLE cau_executor LOGIN PASSWORD 'cau-test-password';
  GRANT cau_group TO cau_grantor WITH ADMIN TRUE;
  GRANT cau_group TO cau_member WITH INHERIT FALSE, SET FALSE GRANTED BY cau_grantor;"
python3 - <<'PY_SECRET' | kubectl apply -f -
import base64, json, subprocess
from urllib.parse import urlsplit, urlunsplit
secret = json.loads(subprocess.check_output(["kubectl", "get", "secret", "postgres-credentials", "-o", "json"]))
url = urlsplit(base64.b64decode(secret["data"]["DATABASE_URL"]).decode())
value = urlunsplit((url.scheme, "cau_executor:cau-test-password@" + url.netloc.rsplit("@", 1)[-1], url.path, url.query, url.fragment))
print(json.dumps({"apiVersion":"v1", "kind":"Secret", "metadata":{"name":"candidate-authority-credentials"}, "stringData":{"DATABASE_URL":value}}))
PY_SECRET
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicy
metadata: {name: candidate-authority-policy}
spec:
  connection: {secretRef: {name: candidate-authority-credentials}}
  interval: 2s
  mode: apply
  approval: auto
  roles:
    - {name: cau_group, external: true}
    - {name: cau_member, external: true}
    - {name: cau_grantor, external: true}
  memberships:
    - role: cau_group
      exclusive: true
      members:
        - {name: cau_grantor, admin: true}
        - {name: cau_member, inherit: false}
YAML
wait_for_ready_status_reason candidate-authority-policy True Reconciled
kubectl apply -f - <<'YAML'
apiVersion: pgroles.io/v1alpha1
kind: PostgresPolicyCandidate
metadata: {name: candidate-authority-preview}
spec:
  policyRef: {name: candidate-authority-policy}
  content:
    roles:
      - {name: cau_group, external: true}
      - {name: cau_member, external: true}
      - {name: cau_grantor, external: true}
    memberships:
      - role: cau_group
        exclusive: true
        members: [{name: cau_grantor, admin: true}]
YAML
wait_for_candidate_condition candidate-authority-preview Ready False ExecutorAuthority
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.phase}')" = Planned
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = Blocked
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.issues[0].code}')" = ForeignGrantorMembershipRevoke
plan="$(wait_for_candidate_plan_ref candidate-authority-preview)"
sql="$(review_sql "$plan")"
[[ "$sql" == *'REVOKE "cau_group" FROM "cau_member" GRANTED BY "cau_grantor";'* ]]
[[ "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}')" == *'cau_grantor'* ]]
test "$(pg_query "SELECT pg_has_role('cau_member','cau_group','MEMBER');")" = t
# Granting authority changes eligibility, without executing the candidate.
pg_query 'GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;'
wait_for_candidate_condition candidate-authority-preview Ready True Planned
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.issues[*].code}')" = ""
assert_review_unchanged() {
  test "$(wait_for_candidate_plan_ref candidate-authority-preview)" = "$plan"
  test "$(review_sql "$plan")" = "$sql"
  test "$(pg_query "SELECT pg_has_role('cau_member','cau_group','MEMBER');")" = t
}
assert_unavailable() {
  wait_for_candidate_condition candidate-authority-preview Ready False BlockedByActivePolicy
  test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority}')" = ""
  assert_review_unchanged
}
assert_fresh() {
  wait_for_ready_status_reason candidate-authority-policy True Reconciled
  wait_for_candidate_condition candidate-authority-preview Ready True Planned
  test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.status.executorAuthority.eligibility}')" = NoKnownBlockers
  assert_review_unchanged
}
assert_review_unchanged
# Suspension never enters planning under database locks.
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":true}}'
assert_unavailable
version="$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.metadata.resourceVersion}')"
kubectl annotate pgr candidate-authority-policy reconcile.pgroles.io/requestedAt="suspended-$(date +%s)" --overwrite
sleep 4
test "$(kubectl get pgcand candidate-authority-preview -o jsonpath='{.metadata.resourceVersion}')" = "$version"
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"suspend":false}}'
assert_fresh
# Parent connection failure also happens before candidate planning.
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"connection":{"secretRef":{"name":"candidate-authority-missing"}}}}'
assert_unavailable
kubectl patch pgr candidate-authority-policy --type=merge -p='{"spec":{"connection":{"secretRef":{"name":"candidate-authority-credentials"}}}}'
assert_fresh
# Induce external drift without changing the parent content/base pin. Losing
# grantor authority blocks enforcement and invalidates the old preview. Recovery
# must apply the parent plan normally; deleting or canceling it would mask the
# lifecycle behavior this regression depends on.
pg_query 'REVOKE cau_grantor FROM cau_executor GRANTED BY postgres;'
pg_query 'GRANT cau_group TO cau_member WITH INHERIT TRUE GRANTED BY cau_grantor;'
wait_for_ready_status_reason candidate-authority-policy False ExecutorAuthority
assert_unavailable
parent_plan="$(wait_for_current_plan_ref candidate-authority-policy)"
wait_for_plan_phase "$parent_plan" Pending
pg_query 'GRANT cau_grantor TO cau_executor WITH INHERIT TRUE, SET FALSE;'
assert_fresh
wait_for_plan_phase "$parent_plan" Applied
kubectl delete pgcand candidate-authority-preview --wait=true
kubectl delete pgr candidate-authority-policy --wait=true
kubectl delete secret candidate-authority-credentials
pg_query 'DROP ROLE cau_member; DROP ROLE cau_executor; DROP ROLE cau_grantor; DROP ROLE cau_group;'
echo 'Candidate shared preflight, retained review SQL, parent failure freshness and recovery passed.'
